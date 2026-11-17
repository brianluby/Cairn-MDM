package sqlite

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

func observedTestCert(t *testing.T, cn string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestObservedIdentityCertificates(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	associate := func(device string, cert *x509.Certificate) {
		sum := sha256.Sum256(cert.Raw)
		if _, err := db.sql.Exec(`INSERT INTO cert_auth(enrollment_id, sha256) VALUES(?,?)`, device, hex.EncodeToString(sum[:])); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"PHONE", "MAC"} {
		if _, err := db.sql.Exec(`INSERT INTO devices(id, name) VALUES(?,?)`, id, id); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()

	// A certificate no enrollment uses is not recorded: the endpoint that
	// reports it is open to anyone.
	stranger := observedTestCert(t, "stranger", now.Add(time.Hour))
	if err := db.ObserveIdentityCertificate(ctx, stranger, true); err != nil {
		t.Fatal(err)
	}
	var n int
	if db.sql.QueryRow(`SELECT count(*) FROM device_identity_certs`).Scan(&n); n != 0 {
		t.Fatalf("recorded %d certificates no enrollment uses", n)
	}

	expired := observedTestCert(t, "PHONE", now.Add(-48*time.Hour))
	associate("PHONE", expired)
	for i := 0; i < 3; i++ {
		if err := db.ObserveIdentityCertificate(ctx, expired, false); err != nil {
			t.Fatal(err)
		}
	}
	older := observedTestCert(t, "MAC-old", now.Add(5*24*time.Hour))
	current := observedTestCert(t, "MAC", now.Add(200*24*time.Hour))
	associate("MAC", older)
	associate("MAC", current)
	if err := db.ObserveIdentityCertificate(ctx, older, true); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`UPDATE device_identity_certs SET last_accepted=datetime('now','-10 days') WHERE subject LIKE '%MAC-old%'`); err != nil {
		t.Fatal(err)
	}
	if err := db.ObserveIdentityCertificate(ctx, current, true); err != nil {
		t.Fatal(err)
	}

	got, err := db.ObservedDeviceCertificates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ObservedCertificate{}
	for _, c := range got {
		by[c.DeviceID] = c
	}
	if len(got) != 2 {
		t.Fatalf("devices = %d, want one row per device: %+v", len(got), got)
	}
	if p := by["PHONE"]; p.NotAfter.After(now) || p.Refusals != 3 || p.LastRefused == "" || p.LastAccepted != "" {
		t.Errorf("phone = %+v", p)
	}
	if m := by["MAC"]; m.Serial != current.SerialNumber.Text(16) || m.NotAfter.Before(now.Add(100*24*time.Hour)) {
		t.Errorf("mac shows %+v, want the certificate it presented most recently", m)
	}

	// A device that has checked out is no longer watched.
	if _, err := db.sql.Exec(`UPDATE devices SET checked_out_at=datetime('now') WHERE id='PHONE'`); err != nil {
		t.Fatal(err)
	}
	if got, _ = db.ObservedDeviceCertificates(ctx); len(got) != 1 {
		t.Errorf("checked-out device still listed: %+v", got)
	}
}
