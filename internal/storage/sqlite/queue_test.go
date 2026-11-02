package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/micromdm/nanomdm/mdm"
	npush "github.com/micromdm/nanomdm/push"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
)

type failedPush struct{}

func (failedPush) Push(context.Context, []string) (map[string]*npush.Response, error) {
	return map[string]*npush.Response{"device": {Err: errors.New("APNs unavailable")}}, nil
}

func TestQueueHistorySurvivesPushFailureAndRestart(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/commands.db"
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := mdmcore.DeviceInformationCommand()
	if err != nil {
		t.Fatal(err)
	}
	if err = mdmcore.Enqueue(ctx, db.NanoStorage(nil), failedPush{}, []string{"device"}, cmd); err != nil {
		t.Fatal("queued command incorrectly reported as failed:", err)
	}
	db.Close()
	db, err = OpenExisting(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	history, err := db.ListCommands(ctx, "device", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].Status != "Queued" || !history[0].Pending() {
		t.Fatalf("history after restart: %+v", history)
	}
	store := db.NanoStorage(nil)
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{ID: "device"}
	next, err := store.RetrieveNextCommand(r, false)
	if err != nil || next == nil || next.CommandUUID != cmd.CommandUUID {
		t.Fatalf("pending queue: %+v %v", next, err)
	}
	if err = store.StoreCommandReport(r, &mdm.CommandResults{CommandUUID: cmd.CommandUUID, Status: "NotNow", Raw: []byte("test report")}); err != nil {
		t.Fatal(err)
	}
	if next, err = store.RetrieveNextCommand(r, true); err != nil || next != nil {
		t.Fatalf("skip NotNow: %+v %v", next, err)
	}
	if err = store.StoreCommandReport(r, &mdm.CommandResults{CommandUUID: cmd.CommandUUID, Status: "Acknowledged", Raw: []byte("test report")}); err != nil {
		t.Fatal(err)
	}
	history, _ = db.ListCommands(ctx, "device", 10)
	if history[0].Status != "Acknowledged" {
		t.Fatalf("report not recorded: %+v", history)
	}
	if next, err = store.RetrieveNextCommand(r, false); err != nil || next != nil {
		t.Fatalf("ack queue: %+v %v", next, err)
	}
	if err = db.CommandResult(ctx, "device", cmd.CommandUUID, "NotNow", ""); err != nil {
		t.Fatal(err)
	}
	history, _ = db.ListCommands(ctx, "device", 10)
	if history[0].Status != "Acknowledged" {
		t.Fatal("late NotNow erased terminal result")
	}
}

func TestQueueAndReportRollbackWithHistory(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store := db.NanoStorage(nil)
	cmd, err := mdmcore.DeviceInformationCommand()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.sql.Exec(`CREATE TRIGGER fail_history BEFORE INSERT ON command_history BEGIN SELECT RAISE(ABORT,'history unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnqueueCommand(ctx, []string{"device", "device"}, cmd); err == nil {
		t.Fatal("queue accepted missing history")
	}
	var count int
	if err = db.sql.QueryRow(`SELECT count(*) FROM nano_kv WHERE bucket='queue'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("partial queue survived history failure")
	}
	if _, err = db.sql.Exec(`DROP TRIGGER fail_history`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnqueueCommand(ctx, []string{"device", "device"}, cmd); err != nil {
		t.Fatal(err)
	}
	if _, err = db.sql.Exec(`CREATE TRIGGER fail_result BEFORE UPDATE ON command_history BEGIN SELECT RAISE(ABORT,'result unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{ID: "device"}
	if err = store.StoreCommandReport(r, &mdm.CommandResults{CommandUUID: cmd.CommandUUID, Status: "Acknowledged", Raw: []byte("test report")}); err == nil {
		t.Fatal("report accepted failed history")
	}
	next, err := store.RetrieveNextCommand(r, false)
	if err != nil || next == nil || next.CommandUUID != cmd.CommandUUID {
		t.Fatalf("report lost queued command: %+v %v", next, err)
	}
	history, err := db.ListCommands(ctx, "device", 10)
	if err != nil || len(history) != 1 || history[0].Status != "Queued" {
		t.Fatalf("partial result: %+v %v", history, err)
	}
}

func TestDeployRecordedAfterAcknowledgementUsesResult(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "device", UDID: "device"}); err != nil {
		t.Fatal(err)
	}
	id, err := db.SaveProfile(ctx, Profile{Identifier: "com.example.test", UUID: "profile", Name: "test", Data: []byte("test"), Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CommandSent(ctx, "device", "early-ack", "InstallProfile"); err != nil {
		t.Fatal(err)
	}
	if err = db.CommandResult(ctx, "device", "early-ack", "Acknowledged", ""); err != nil {
		t.Fatal(err)
	}
	if err = db.MarkDeploySent(ctx, "device", id, "early-ack", "version"); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = db.sql.QueryRow(`SELECT status FROM profile_deploys WHERE device_id='device'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "installed" {
		t.Fatalf("early acknowledgement lost: %s", state)
	}
}

func TestOperatorIntentReplayAfterRestartAndConflict(t *testing.T) {
	ctx := mdmcore.WithCommandIntent(context.Background(), "session/action/retry-key")
	path := t.TempDir() + "/intent.db"
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	cmd, _ := mdmcore.InstallProfileCommand([]byte("profile-v1"))
	if err = mdmcore.Enqueue(ctx, db.NanoStorage(nil), nil, []string{"device"}, cmd); err != nil {
		t.Fatal(err)
	}
	uuid := cmd.CommandUUID
	db.Close()
	db, err = OpenExisting(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repeated, _ := mdmcore.InstallProfileCommand([]byte("profile-v1"))
	if err = mdmcore.Enqueue(ctx, db.NanoStorage(nil), nil, []string{"device"}, repeated); err != nil {
		t.Fatal(err)
	}
	if repeated.CommandUUID != uuid {
		t.Fatal("retry generated different command UUID")
	}
	rows, err := db.ListCommands(ctx, "device", 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("retry history: %+v %v", rows, err)
	}
	changed, _ := mdmcore.InstallProfileCommand([]byte("profile-v2"))
	if err = mdmcore.Enqueue(ctx, db.NanoStorage(nil), nil, []string{"device"}, changed); err == nil {
		t.Fatal("changed content accepted under same key")
	}
	if err = mdmcore.Enqueue(ctx, db.NanoStorage(nil), nil, []string{"other-device"}, repeated); err == nil {
		t.Fatal("changed targets accepted under same key")
	}
	if err = db.CommandResult(ctx, "device", uuid, "Acknowledged", ""); err != nil {
		t.Fatal(err)
	}
	if err = mdmcore.Enqueue(ctx, db.NanoStorage(nil), nil, []string{"device"}, repeated); err != nil {
		t.Fatal(err)
	}
	rows, _ = db.ListCommands(ctx, "device", 10)
	if len(rows) != 1 || rows[0].Status != "Acknowledged" {
		t.Fatal("replay reset acknowledged command")
	}
}

func TestDisableCancelsParentAndUserChannelCommands(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store := db.NanoStorage(nil).(*nanoStore)
	if _, err := db.SQL().Exec(`INSERT INTO nano_kv(bucket,k,v) VALUES('enrollments','parent.user_ch.child',X'31')`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"parent", "child", "other"} {
		cmd, _ := mdmcore.DeviceInformationCommand()
		if _, err := store.EnqueueNotifiedCommand(ctx, []string{id}, cmd, true); err != nil {
			t.Fatal(err)
		}
	}
	req := mdm.NewRequestWithContext(ctx, nil)
	req.EnrollID = &mdm.EnrollID{ID: "parent"}
	if err := store.Disable(req); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"parent", "child"} {
		req.EnrollID = &mdm.EnrollID{ID: id}
		if cmd, err := store.RetrieveNextCommand(req, false); err != nil || cmd != nil {
			t.Fatalf("disabled queue %s: %+v %v", id, cmd, err)
		}
		history, err := db.ListCommands(ctx, id, 10)
		if err != nil || len(history) != 1 || history[0].Status != "Cancelled" || history[0].NotificationStatus != "resolved" {
			t.Fatalf("disabled history: %+v %v", history, err)
		}
		cmd, _ := mdmcore.DeviceInformationCommand()
		if _, err := store.EnqueueNotifiedCommand(ctx, []string{id}, cmd, true); err == nil {
			t.Fatal("disabled enrollment accepted new work")
		}
	}
	history, _ := db.ListCommands(ctx, "other", 10)
	if history[0].Status != "Queued" {
		t.Fatal("unrelated device was cancelled")
	}
}

func TestDisableRollbackPreservesPendingWork(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	store := db.NanoStorage(nil)
	cmd, _ := mdmcore.DeviceInformationCommand()
	if _, err := store.EnqueueCommand(ctx, []string{"device"}, cmd); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`CREATE TRIGGER reject_cancel BEFORE UPDATE ON command_history BEGIN SELECT RAISE(ABORT,'history unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{ID: "device"}
	if err := store.Disable(r); err == nil {
		t.Fatal("disable succeeded despite failed cancellation")
	}
	var disabled int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM nano_kv WHERE bucket='enrollments' AND k='device.disabled'`).Scan(&disabled); err != nil || disabled != 0 {
		t.Fatalf("partial disable: %d %v", disabled, err)
	}
	next, err := store.RetrieveNextCommand(r, false)
	if err != nil || next == nil || next.CommandUUID != cmd.CommandUUID {
		t.Fatalf("queue lost on rollback: %v %v", next, err)
	}
}
