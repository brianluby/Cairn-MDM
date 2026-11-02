package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
)

func TestNotificationLeaseRetryAndExhaustion(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	s := db.NanoStorage(nil).(*nanoStore)
	cmd, err := mdmcore.DeviceInformationCommand()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.EnqueueNotifiedCommand(ctx, []string{"device"}, cmd, true); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a, err := s.ClaimPush(ctx, "", now)
	if err != nil || a == nil {
		t.Fatalf("claim: %+v %v", a, err)
	}
	if other, err := s.ClaimPush(ctx, "", now); err != nil || other != nil {
		t.Fatal("active lease claimed twice")
	}
	// Simulate a crash while the first network attempt was in flight.
	now = now.Add(31 * time.Second)
	b, err := s.ClaimPush(ctx, "", now)
	if err != nil || b == nil {
		t.Fatalf("crash recovery: %+v %v", b, err)
	}
	if err = s.FinishPush(ctx, *a, "", now); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = db.sql.QueryRow(`SELECT state FROM push_outbox`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "pending" {
		t.Fatal("late worker overwrote replacement lease")
	}
	if err = s.FinishPush(ctx, *b, "failed", now); err != nil {
		t.Fatal(err)
	}
	if other, err := s.ClaimPush(ctx, "", now); err != nil || other != nil {
		t.Fatal("retry ignored backoff")
	}
	for i := 0; i < 4; i++ {
		now = now.Add(6 * time.Minute)
		a, err = s.ClaimPush(ctx, "", now)
		if err != nil || a == nil {
			t.Fatalf("retry %d: %+v %v", i, a, err)
		}
		if err = s.FinishPush(ctx, *a, "failed", now); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(time.Hour)
	if a, err = s.ClaimPush(ctx, "", now); err != nil || a != nil {
		t.Fatal("retry exceeded six attempts")
	}
	h, err := db.ListCommands(ctx, "device", 5)
	if err != nil {
		t.Fatal(err)
	}
	if h[0].NotificationStatus != "exhausted" || h[0].NotificationAttempts != 6 || h[0].Status != "Queued" {
		t.Fatalf("retry state: %+v", h)
	}
}

func TestNoNotificationForExplicitNoPushOrResolvedCommand(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	s := db.NanoStorage(nil).(*nanoStore)
	cmd, _ := mdmcore.DeviceInformationCommand()
	if _, err := s.EnqueueNotifiedCommand(ctx, []string{"device"}, cmd, false); err != nil {
		t.Fatal(err)
	}
	if a, err := s.ClaimPush(ctx, "", time.Now()); err != nil || a != nil {
		t.Fatal("no-push scheduled a notification")
	}
	cmd, _ = mdmcore.DeviceInformationCommand()
	if _, err := s.EnqueueNotifiedCommand(ctx, []string{"device"}, cmd, true); err != nil {
		t.Fatal(err)
	}
	if err := db.CommandResult(ctx, "device", cmd.CommandUUID, "Acknowledged", ""); err != nil {
		t.Fatal(err)
	}
	if a, err := s.ClaimPush(ctx, "", time.Now()); err != nil || a != nil {
		t.Fatal("acknowledged command notified again")
	}
}

func TestNotificationIntentFailureRollsBackQueue(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	s := db.NanoStorage(nil).(*nanoStore)
	if _, err := db.sql.Exec(`CREATE TRIGGER fail_notification BEFORE INSERT ON push_outbox BEGIN SELECT RAISE(ABORT,'notification storage unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	cmd, _ := mdmcore.DeviceInformationCommand()
	if _, err := s.EnqueueNotifiedCommand(ctx, []string{"device"}, cmd, true); err == nil {
		t.Fatal("accepted command without notification intent")
	}
	for _, query := range []string{`SELECT count(*) FROM command_history`, `SELECT count(*) FROM nano_kv WHERE bucket='queue'`} {
		var count int
		if err := db.sql.QueryRow(query).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatal("partial queue survived notification failure")
		}
	}
}
