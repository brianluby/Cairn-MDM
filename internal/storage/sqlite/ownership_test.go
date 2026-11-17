package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
)

// ownedDevice seeds the full chain for one device: an owner-authorized grant,
// an ISSUED certificate for it, the device authenticating with that certificate,
// and a pushable device row. Returns the grant ID.
func ownedDevice(t *testing.T, db *DB, deviceID string, owner directory.DirectoryIdentity, assignGroup int64, leaf []byte) int64 {
	t.Helper()
	ctx := context.Background()
	encoded, _ := json.Marshal(owner)
	var assign any
	if assignGroup != 0 {
		assign = assignGroup
	}
	res, err := db.sql.Exec(`INSERT INTO enrollment_grants(token_hash,label,platform,owner,created_by,expires_at,max_uses,owner_identity,actor_subject,actor_provider,assign_group_id)
		VALUES(?,?,?,?,?,?,1,?,?,?,?)`, HashGrantToken(deviceID+"-"+string(leaf)), "dev", "macos", owner.UPN, "admin", future(), string(encoded), "local:"+strings.Repeat("a", 64), "local", assign)
	if err != nil {
		t.Fatal(err)
	}
	grant, _ := res.LastInsertId()
	txn := "txn-" + string(leaf)
	if _, _, err = db.BeginIssuance(ctx, grant, txn, "spki-"+txn, "req-"+txn); err != nil {
		t.Fatal(err)
	}
	if err = db.CompleteIssuance(ctx, grant, txn, "spki-"+txn, "req-"+txn, "serial-"+txn, leaf); err != nil {
		t.Fatal(err)
	}
	if _, err = db.sql.Exec(`INSERT INTO cert_auth(enrollment_id,sha256) VALUES(?,?)`, deviceID, LeafHash(leaf)); err != nil {
		t.Fatal(err)
	}
	if err = db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: deviceID, UDID: deviceID, Name: "Mac " + deviceID}); err != nil {
		t.Fatal(err)
	}
	if err = db.DeviceTokenUpdated(ctx, deviceID); err != nil {
		t.Fatal(err)
	}
	return grant
}

func TestBindDeviceOwnerFollowsIssuedCertificate(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	group, err := db.CreateGroup(ctx, "Lynchburg site", "")
	if err != nil {
		t.Fatal(err)
	}
	owner := directory.DirectoryIdentity{DirectoryID: "dzsec", ObjectID: strings.Repeat("b", 32), UPN: "person@example.org", AccountName: "person"}
	grant := ownedDevice(t, db, "UDID-1", owner, group, []byte("leaf-one"))

	if _, err = db.BindDeviceOwner(ctx, "UDID-unknown"); !errors.Is(err, ErrNoOwner) {
		t.Fatalf("unknown device bound: %v", err)
	}
	bound, err := db.BindDeviceOwner(ctx, "UDID-1")
	if err != nil || bound.GrantID != grant || bound.Owner != owner {
		t.Fatalf("bind %+v %v", bound, err)
	}
	groups, err := db.DeviceGroups(ctx, "UDID-1")
	if err != nil || len(groups) != 1 || groups[0].ID != group {
		t.Fatalf("explicit group not applied: %+v %v", groups, err)
	}
	var audits int
	if err = db.sql.QueryRow(`SELECT count(*) FROM audit_log WHERE action IN ('device.owner-bind','group.device-add')`).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("audit rows %d %v", audits, err)
	}
	if _, err = db.BindDeviceOwner(ctx, "UDID-1"); err != nil {
		t.Fatal(err)
	}
	if err = db.sql.QueryRow(`SELECT count(*) FROM audit_log WHERE action IN ('device.owner-bind','group.device-add','device.owner-change')`).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("idempotent rebind audited again: %d", audits)
	}

	// A device authenticating with a non-Cairn certificate (external SCEP, legacy
	// import) has no verified owner even though it is enrolled.
	if err = db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "UDID-legacy", UDID: "UDID-legacy"}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.sql.Exec(`INSERT INTO cert_auth(enrollment_id,sha256) VALUES('UDID-legacy','deadbeef')`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.BindDeviceOwner(ctx, "UDID-legacy"); !errors.Is(err, ErrNoOwner) {
		t.Fatalf("legacy device bound: %v", err)
	}

	// Re-enrollment under a later grant for another owner moves ownership and audits it.
	other := directory.DirectoryIdentity{DirectoryID: "dzsec", ObjectID: strings.Repeat("c", 32), UPN: "other@example.org", AccountName: "other"}
	later := ownedDevice(t, db, "UDID-1", other, 0, []byte("leaf-two"))
	if _, err = db.sql.Exec(`UPDATE cert_auth SET created_at=datetime('now','+1 minute') WHERE sha256=?`, LeafHash([]byte("leaf-two"))); err != nil {
		t.Fatal(err)
	}
	bound, err = db.BindDeviceOwner(ctx, "UDID-1")
	if err != nil || bound.GrantID != later || bound.Owner.UPN != "other@example.org" {
		t.Fatalf("owner did not follow the newer certificate: %+v %v", bound, err)
	}
	if err = db.sql.QueryRow(`SELECT count(*) FROM audit_log WHERE action='device.owner-change'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("owner change audit %d %v", audits, err)
	}
}

func TestDirectoryMembershipsFeedDeploymentAndSurviveUnavailable(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	group, err := db.CreateGroup(ctx, "Lynchburg", "")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := db.SaveProfile(ctx, Profile{Identifier: "com.example.wifi", UUID: "p1", Name: "Lynchburg Wi-Fi", Data: []byte("x"), UpdatedAt: "2026-01-01 00:00:00"})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AssignProfile(ctx, group, profile); err != nil {
		t.Fatal(err)
	}
	scope := directory.DirectoryScope{DirectoryID: "dzsec", ObjectID: strings.Repeat("d", 32), Kind: "group", Mode: "nested", Name: "Lynchburg Users", DN: "CN=Lynchburg Users,DC=example,DC=org"}
	if err = db.SaveDirectoryProfileRule(ctx, group, scope, "admin", "local"); err != nil {
		t.Fatal(err)
	}
	rules, _ := db.ListDirectoryProfileRules(ctx)
	owner := directory.DirectoryIdentity{DirectoryID: "dzsec", ObjectID: strings.Repeat("b", 32), UPN: "person@example.org"}
	ownedDevice(t, db, "UDID-1", owner, 0, []byte("leaf"))
	if _, err = db.BindDeviceOwner(ctx, "UDID-1"); err != nil {
		t.Fatal(err)
	}

	if todo, err := db.ProfilesToDeploy(ctx, "UDID-1"); err != nil || len(todo) != 0 {
		t.Fatalf("profiles before membership: %d %v", len(todo), err)
	}
	added, err := db.ReplaceDirectoryMemberships(ctx, "UDID-1", []int64{rules[0].ID})
	if err != nil || len(added) != 1 || added[0] != group {
		t.Fatalf("replace %v %v", added, err)
	}
	if todo, err := db.ProfilesToDeploy(ctx, "UDID-1"); err != nil || len(todo) != 1 || todo[0].ID != profile {
		t.Fatalf("directory member not entitled: %+v %v", todo, err)
	}
	if ids, err := db.GroupDeviceIDs(ctx, group); err != nil || len(ids) != 1 || ids[0] != "UDID-1" {
		t.Fatalf("group fan-out missed directory member: %v %v", ids, err)
	}
	if devs, err := db.GroupDirectoryDevices(ctx, group); err != nil || len(devs) != 1 {
		t.Fatalf("directory members %v %v", devs, err)
	}
	if manual, err := db.GroupDevices(ctx, group); err != nil || len(manual) != 0 {
		t.Fatal("directory membership leaked into manual membership")
	}
	ms, err := db.DeviceDirectoryMemberships(ctx, "UDID-1")
	if err != nil || len(ms) != 1 || ms[0].Scope.Name != "Lynchburg Users" || ms[0].GroupName != "Lynchburg" {
		t.Fatalf("memberships %+v %v", ms, err)
	}
	ev, err := db.DeviceDirectoryEvaluation(ctx, "UDID-1")
	if err != nil || ev.Status != "ok" || !ev.EvaluatedAt.Valid {
		t.Fatalf("evaluation %+v %v", ev, err)
	}

	// Simulate a sent deploy, then an unavailable directory: nothing moves.
	if err = db.MarkDeploySent(ctx, "UDID-1", profile, "cmd-1", "2026-01-01 00:00:00"); err != nil {
		t.Fatal(err)
	}
	if err = db.RecordDirectoryUnavailable(ctx, "UDID-1", "timeout"); err != nil {
		t.Fatal(err)
	}
	ev, _ = db.DeviceDirectoryEvaluation(ctx, "UDID-1")
	if ev.Status != "unavailable" || ev.Detail != "timeout" || !ev.EvaluatedAt.Valid {
		t.Fatalf("unavailable record lost last good evaluation: %+v", ev)
	}
	if ms, _ = db.DeviceDirectoryMemberships(ctx, "UDID-1"); len(ms) != 1 {
		t.Fatal("unavailable evaluation changed memberships")
	}

	// Owner leaves the scope: membership goes, the installed/sent deploy stays.
	if _, err = db.ReplaceDirectoryMemberships(ctx, "UDID-1", nil); err != nil {
		t.Fatal(err)
	}
	if ms, _ = db.DeviceDirectoryMemberships(ctx, "UDID-1"); len(ms) != 0 {
		t.Fatal("membership not removed")
	}
	deploys, err := db.DeviceDeploys(ctx, "UDID-1")
	if err != nil || len(deploys) != 1 {
		t.Fatalf("deploy record removed with membership: %v %v", deploys, err)
	}
	// A rule deleted by the administrator cascades its memberships.
	if _, err = db.ReplaceDirectoryMemberships(ctx, "UDID-1", []int64{rules[0].ID}); err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteDirectoryProfileRule(ctx, rules[0].ID, "admin", "local"); err != nil {
		t.Fatal(err)
	}
	if ms, _ = db.DeviceDirectoryMemberships(ctx, "UDID-1"); len(ms) != 0 {
		t.Fatal("deleted rule left memberships behind")
	}
}

func TestLeafHashBackfillOnOpen(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/backfill.db"
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	owner := directory.DirectoryIdentity{DirectoryID: "dzsec", ObjectID: strings.Repeat("b", 32), UPN: "person@example.org"}
	ownedDevice(t, db, "UDID-1", owner, 0, []byte("old-leaf"))
	if _, err = db.sql.Exec(`UPDATE cert_issuance SET leaf_sha256=''`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var hash string
	if err = db.sql.QueryRow(`SELECT leaf_sha256 FROM cert_issuance`).Scan(&hash); err != nil || hash != LeafHash([]byte("old-leaf")) {
		t.Fatalf("backfill %q %v", hash, err)
	}
	if _, err = db.BindDeviceOwner(ctx, "UDID-1"); err != nil {
		t.Fatalf("bind after backfill: %v", err)
	}
}
