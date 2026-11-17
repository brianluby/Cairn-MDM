package sqlite

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/push"
)

func apnsSnapshot(t *testing.T, db *DB) string {
	t.Helper()
	var out string
	for _, q := range []string{
		`SELECT k,hex(v) FROM nano_kv WHERE bucket='pushcert' ORDER BY k`,
		`SELECT key,value FROM settings ORDER BY key`,
		`SELECT topic,not_after||subject||loaded_by FROM apns_topics ORDER BY topic`,
		`SELECT action,target||result FROM audit_log ORDER BY id`,
		`SELECT CAST(id AS TEXT),COALESCE(request_id,'')||fingerprint||COALESCE(hex(previous_cert),'')||COALESCE(hex(previous_key),'') FROM apns_changes ORDER BY id`,
	} {
		rows, err := db.sql.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var a, b string
			if err := rows.Scan(&a, &b); err != nil {
				t.Fatal(err)
			}
			out += fmt.Sprintf("%s=%s\n", a, b)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	return out
}

func TestAPNSRenewalAtomicAndPreservesDefault(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	first, second := "com.apple.mgmt.External.first", "com.apple.mgmt.External.second"
	now := time.Now()
	c1, k1, _ := genPushCert(t, first, now.Add(-time.Hour), now.Add(24*time.Hour))
	c2, k2, _ := genPushCert(t, second, now.Add(-time.Hour), now.Add(48*time.Hour))
	for _, v := range []struct{ c, k []byte }{{c1, k1}, {c2, k2}} {
		if _, err := db.SaveAPNSCertificate(ctx, v.c, v.k, APNSWriteOptions{Actor: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := db.GetSetting(ctx, push.SettingTopic); got != first {
		t.Fatal("second import changed default")
	}
	_, oldToken, err := db.NanoStorage(nil).RetrievePushCert(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	newCert, newKey, _ := genPushCert(t, second, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	opts := APNSWriteOptions{RenewTopic: second, Actor: "operator", Provider: "cli"}
	before := apnsSnapshot(t, db)
	// Fail after material and metadata writes: the transaction must roll back all.
	if _, err := db.sql.Exec(`CREATE TRIGGER fail_apns_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveAPNSCertificate(ctx, newCert, newKey, opts); err == nil {
		t.Fatal("audit failure accepted")
	}
	if got := apnsSnapshot(t, db); got != before {
		t.Fatal("partial renewal survived failed audit")
	}
	if _, err := db.sql.Exec(`DROP TRIGGER fail_apns_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveAPNSCertificate(ctx, newCert, newKey, opts); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetSetting(ctx, push.SettingTopic); got != first {
		t.Fatal("renewal changed default")
	}
	if got, _ := db.GetSetting(ctx, push.SettingNotAfter); got != now.Add(24*time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339) {
		t.Fatalf("default expiry changed: %s", got)
	}
	if stale, err := db.NanoStorage(nil).IsPushCertStale(ctx, second, oldToken); err != nil || !stale {
		t.Fatalf("provider not invalidated: %v %v", stale, err)
	}
	cert, _, err := db.NanoStorage(nil).RetrievePushCert(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 1 {
		t.Fatal("other topic damaged")
	}
	var saved []byte
	if err := db.sql.QueryRow(`SELECT v FROM nano_kv WHERE bucket='pushcert' AND k=?`, first+".pem").Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved, c1) {
		t.Fatal("other certificate changed")
	}
	// Renewing the default updates its cached expiry without selecting another topic.
	nc, nk, _ := genPushCert(t, first, now.Add(-time.Hour), now.Add(400*24*time.Hour))
	info, err := db.SaveAPNSCertificate(ctx, nc, nk, APNSWriteOptions{RenewTopic: first, Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetSetting(ctx, push.SettingNotAfter); got != info.NotAfter.UTC().Format(time.RFC3339) {
		t.Fatal("default expiry stale")
	}
}

func TestAPNSRejectsUnsafeReplacementWithoutMutation(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now()
	topic := "com.apple.mgmt.External.original"
	c, k, other := genPushCert(t, topic, now.Add(-time.Hour), now.Add(48*time.Hour))
	if _, err := db.SaveAPNSCertificate(ctx, c, k, APNSWriteOptions{Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	short, sk, _ := genPushCert(t, topic, now.Add(-time.Hour), now.Add(24*time.Hour))
	wrong, wk, _ := genPushCert(t, "com.apple.mgmt.External.wrong", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	for _, tc := range []struct {
		name string
		c, k []byte
		o    APNSWriteOptions
	}{
		{"implicit overwrite", c, k, APNSWriteOptions{Actor: "test"}},
		{"wrong topic", wrong, wk, APNSWriteOptions{RenewTopic: topic, Actor: "test"}},
		{"unknown topic", wrong, wk, APNSWriteOptions{RenewTopic: "com.apple.mgmt.External.wrong", Actor: "test"}},
		{"wrong key", c, other, APNSWriteOptions{RenewTopic: topic, Actor: "test"}},
		{"shorter expiry", short, sk, APNSWriteOptions{RenewTopic: topic, Actor: "test"}},
		{"same certificate", c, k, APNSWriteOptions{RenewTopic: topic, Actor: "test"}},
		{"default change", c, k, APNSWriteOptions{RenewTopic: topic, MakeDefault: true, Actor: "test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := apnsSnapshot(t, db)
			if _, err := db.SaveAPNSCertificate(ctx, tc.c, tc.k, tc.o); err == nil {
				t.Fatal("accepted invalid operation")
			}
			if apnsSnapshot(t, db) != before {
				t.Fatal("invalid operation mutated state")
			}
		})
	}
}

func TestAPNSReceiptReplayAndRecoveryMaterial(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now()
	topic := "com.apple.mgmt.External.receipt"
	c, k, _ := genPushCert(t, topic, now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := db.SaveAPNSCertificate(ctx, c, k, APNSWriteOptions{Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	nc, nk, _ := genPushCert(t, topic, now.Add(-time.Hour), now.Add(48*time.Hour))
	opts := APNSWriteOptions{Actor: "test", RequestID: "saved-request", RenewTopic: topic}
	if _, err := db.SaveAPNSCertificate(ctx, nc, nk, opts); err != nil {
		t.Fatal(err)
	}
	var pc, pk []byte
	if err := db.sql.QueryRow(`SELECT previous_cert,previous_key FROM apns_changes WHERE request_id=?`, opts.RequestID).Scan(&pc, &pk); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pc, c) || !bytes.Equal(pk, k) {
		t.Fatal("previous pair not retained")
	}
	receipt, err := db.APNSInstallReceipt(ctx, opts.RequestID)
	if err != nil || receipt == nil || receipt.Topic != topic || receipt.Actor != "test" || receipt.InstalledAt.IsZero() {
		t.Fatalf("receipt: %+v %v", receipt, err)
	}
	before := apnsSnapshot(t, db)
	if _, err := db.SaveAPNSCertificate(ctx, nc, nk, opts); err != nil {
		t.Fatal(err)
	}
	if before != apnsSnapshot(t, db) {
		t.Fatal("replay changed state")
	}
	later, lk, _ := genPushCert(t, topic, now.Add(-time.Hour), now.Add(72*time.Hour))
	if _, err := db.SaveAPNSCertificate(ctx, later, lk, opts); err == nil {
		t.Fatal("request ID reused for different certificate")
	}
	if before != apnsSnapshot(t, db) {
		t.Fatal("conflict changed state")
	}
}
