package renew

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

type sentCommands struct{ lists, installs []string }

func (c *sentCommands) SendProfileListAs(_ context.Context, uuid, id string) error {
	c.lists = append(c.lists, id)
	return nil
}
func (c *sentCommands) SendInstallProfileAs(_ context.Context, uuid string, _ []byte, id string) error {
	c.installs = append(c.installs, id)
	return nil
}

// testCA is the CA the service under test trusts.
var testCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// leaf returns a certificate for cn signed by signer, or self-signed when
// signer is nil.
func leaf(t *testing.T, cn string, signer *x509.Certificate, signerKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * time.Minute)}
	if signer == nil {
		signer, signerKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func testService(t *testing.T, opts Options) (*Service, *sqlite.DB, *sentCommands) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir()+"/renew.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	testCA.cert, testCA.key = ca, key
	opts.Anchors = []*x509.Certificate{ca}
	opts.ServerURL = "https://cairn.example.org/mdm"
	opts.Profile = func(Target) ([]byte, error) { return []byte("profile"), nil }
	if opts.RenewBefore == 0 {
		opts.RenewBefore = 60 * 24 * time.Hour
	}
	sent := &sentCommands{}
	s, err := New(db, sent, opts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s, db, sent
}

// addDevice records an enrolled device that checks in with a certificate
// expiring at notAfter.
func addDevice(t *testing.T, db *sqlite.DB, id, host string, notAfter time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: id, UDID: id, Name: id}); err != nil {
		t.Fatal(err)
	}
	hash := "hash-" + id
	for _, q := range []string{
		`INSERT INTO cert_auth(enrollment_id, sha256) VALUES(?1, ?2)`,
		`INSERT INTO device_identity_certs(sha256, not_after, common_name, last_accepted) VALUES(?2, ?3, ?1, datetime('now'))`,
		`UPDATE devices SET checkin_host=?4 WHERE id=?1`,
		`INSERT INTO nano_kv(bucket, k, v) VALUES('enrollments', ?1 || '.topic', 'com.apple.mgmt.External.test')`,
	} {
		if _, err := db.SQL().ExecContext(ctx, q, id, hash, notAfter.UTC().Format(time.RFC3339), host); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSweepStartsOnlyWhatIsDue(t *testing.T) {
	day := 24 * time.Hour
	s, db, sent := testService(t, Options{ExpiredGrace: 180 * day, Hosts: []string{"mdm.legacy.example"}})
	now := time.Now()
	addDevice(t, db, "far-off", "", now.Add(200*day))
	addDevice(t, db, "due", "cairn.example.org", now.Add(20*day))
	addDevice(t, db, "expired-in-grace", "mdm.legacy.example:443", now.Add(-90*day))
	addDevice(t, db, "expired-past-grace", "", now.Add(-200*day))
	addDevice(t, db, "unknown-host", "10.0.0.5:8444", now.Add(20*day))
	ctx := context.Background()
	s.Sweep(ctx)
	if got := strings.Join(sent.lists, ","); got != "due,expired-in-grace" {
		t.Fatalf("renewals started for %q, want due,expired-in-grace", got)
	}
	// Nothing starts twice while an attempt is open.
	s.Sweep(ctx)
	if len(sent.lists) != 2 {
		t.Fatalf("a second sweep started more: %v", sent.lists)
	}
	// A failed attempt rests for a day before the next one.
	if err := db.FailRenewal(ctx, "due", "test"); err != nil {
		t.Fatal(err)
	}
	s.Sweep(ctx)
	if len(sent.lists) != 2 {
		t.Fatalf("a failed renewal was retried at once: %v", sent.lists)
	}
	if _, err := db.SQL().ExecContext(ctx, `UPDATE device_renewals SET updated_at=datetime('now','-2 days') WHERE device_id='due'`); err != nil {
		t.Fatal(err)
	}
	s.Sweep(ctx)
	if len(sent.lists) != 3 || sent.lists[2] != "due" {
		t.Fatalf("the failed renewal was not retried after a day: %v", sent.lists)
	}
	c, _, _ := db.RenewalCandidate(ctx, "unknown-host")
	if st := s.Status(c); !strings.Contains(st.Blocked, "10.0.0.5:8444") || !strings.Contains(st.Blocked, "server_hosts") {
		t.Fatalf("blocked reason = %q", st.Blocked)
	}
	if err := s.Renew(ctx, "expired-past-grace", "admin"); err == nil {
		t.Fatal("a device past the grace period was renewed by hand")
	}
}

func TestManualOnlyLeavesTheScheduleOff(t *testing.T) {
	s, db, sent := testService(t, Options{ManualOnly: true})
	addDevice(t, db, "due", "", time.Now().Add(24*time.Hour))
	ctx := context.Background()
	s.Sweep(ctx)
	if got := s.RenewalCommand(ctx, "due"); got != "" || len(sent.lists) != 0 {
		t.Fatalf("manual-only started a renewal: %q %v", got, sent.lists)
	}
	if err := s.Renew(ctx, "due", "admin"); err != nil {
		t.Fatal(err)
	}
	last, _, _ := db.LastRenewal(ctx, "due")
	if got := s.RenewalCommand(ctx, "due"); got == "" || got != last.CommandUUID || last.Actor != "admin" {
		t.Fatalf("renewal command %q, attempt %+v", got, last)
	}
}

// A lookup that finds no enrollment profile, or more than one, stops the
// attempt before anything is installed.
func TestProfileListWithoutOneEnrollmentProfileFails(t *testing.T) {
	s, db, sent := testService(t, Options{})
	addDevice(t, db, "dev", "", time.Now().Add(24*time.Hour))
	ctx := context.Background()
	if err := s.Renew(ctx, "dev", "admin"); err != nil {
		t.Fatal(err)
	}
	last, _, _ := db.LastRenewal(ctx, "dev")
	s.ProfileList(ctx, "dev", last.CommandUUID, []mdmcore.InstalledProfile{{Identifier: "wifi", PayloadTypes: []string{"com.apple.wifi.managed"}}})
	last, _, _ = db.LastRenewal(ctx, "dev")
	if last.State != "failed" || !strings.Contains(last.Error, "0 profiles") || len(sent.installs) != 0 {
		t.Fatalf("attempt %+v installs %v", last, sent.installs)
	}
}

// The device installed the profile and switched certificates, but its answer
// never arrived, the attempt was closed and a second one began. The new
// certificate from the first attempt is still accepted; one of someone's own
// making is not, and leaves no trace on the device's record.
func TestCertificateFromAClosedAttemptIsStillAccepted(t *testing.T) {
	s, db, _ := testService(t, Options{})
	addDevice(t, db, "dev", "", time.Now().Add(24*time.Hour))
	ctx := context.Background()
	if err := s.Renew(ctx, "dev", "admin"); err != nil {
		t.Fatal(err)
	}
	first, _, _ := db.LastRenewal(ctx, "dev")
	s.ProfileList(ctx, "dev", first.CommandUUID, []mdmcore.InstalledProfile{{Identifier: "enroll", PayloadTypes: []string{"com.apple.mdm"}}})
	if err := db.FailRenewal(ctx, "dev", "The device did not answer within 7 days."); err != nil {
		t.Fatal(err)
	}
	if err := s.Renew(ctx, "dev", "admin"); err != nil {
		t.Fatal(err)
	}
	s.Presented(ctx, "dev", leaf(t, "dev", nil, nil))
	if got, _, _ := db.LastRenewal(ctx, "dev"); got.State != "lookup" || got.Error != "" {
		t.Fatalf("a self-signed certificate changed the record: %+v", got)
	}
	if assoc, _ := db.SQL().QueryContext(ctx, `SELECT 1 FROM cert_auth WHERE enrollment_id='dev' AND sha256<>'hash-dev'`); assoc.Next() {
		assoc.Close()
		t.Fatal("a self-signed certificate was associated")
	} else {
		assoc.Close()
	}
	s.Presented(ctx, "dev", leaf(t, "dev", testCA.cert, testCA.key))
	rows, err := db.DeviceRenewals(ctx, "dev", 5)
	if err != nil || len(rows) != 2 {
		t.Fatalf("attempts: %v %v", rows, err)
	}
	if rows[1].State != "renewed" || rows[0].State != "failed" || !strings.Contains(rows[0].Error, "earlier renewal completed") {
		t.Fatalf("first attempt %q, second %q (%s)", rows[1].State, rows[0].State, rows[0].Error)
	}
}

// With a key check, a certificate from the CA in the device's name is not
// enough: it has to be for the key the check knows.
func TestKeyCheckDecidesWhichNewCertificateIsTheRenewal(t *testing.T) {
	var allowed *x509.Certificate
	s, db, _ := testService(t, Options{KeyCheck: func(_ context.Context, deviceID string, cert *x509.Certificate, since time.Time) error {
		if deviceID != "dev" || since.After(time.Now()) {
			return errors.New("unexpected arguments")
		}
		if allowed == nil || !cert.Equal(allowed) {
			return errors.New("its key did not use this device's renewal challenge")
		}
		return nil
	}})
	addDevice(t, db, "dev", "", time.Now().Add(24*time.Hour))
	ctx := context.Background()
	if err := s.Renew(ctx, "dev", "admin"); err != nil {
		t.Fatal(err)
	}
	first, _, _ := db.LastRenewal(ctx, "dev")
	s.ProfileList(ctx, "dev", first.CommandUUID, []mdmcore.InstalledProfile{{Identifier: "enroll", PayloadTypes: []string{"com.apple.mdm"}}})

	// Someone else got a certificate with this device's name.
	s.Presented(ctx, "dev", leaf(t, "dev", testCA.cert, testCA.key))
	got, _, _ := db.LastRenewal(ctx, "dev")
	if got.State == "renewed" || !strings.Contains(got.Error, "renewal challenge") {
		t.Fatalf("a certificate for another key ended the renewal: %+v", got)
	}
	allowed = leaf(t, "dev", testCA.cert, testCA.key)
	s.Presented(ctx, "dev", allowed)
	if got, _, _ = db.LastRenewal(ctx, "dev"); got.State != "renewed" {
		t.Fatalf("the device's own certificate was not accepted: %+v", got)
	}
}
