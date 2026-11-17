package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
)

func TestRenewalAttemptsResolveDeviceAndDeviceCertificatesList(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "D1", UDID: "D1", Name: "Field Mac"}); err != nil {
		t.Fatal(err)
	}
	// An issued certificate the device authenticates with.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0x1f3a), Subject: pkix.Name{CommonName: "p@example.org"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	sum := sha256.Sum256(der)
	hash := hex.EncodeToString(sum[:])
	if _, err := db.sql.Exec(`INSERT INTO scep_certs(serial, name, cert_pem, not_after) VALUES(?, 'p', ?, ?)`, "7994", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), tmpl.NotAfter.UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`INSERT INTO cert_auth(enrollment_id, sha256) VALUES('D1', ?)`, hash); err != nil {
		t.Fatal(err)
	}
	certs, err := db.DeviceCertificates(ctx)
	if err != nil || len(certs) != 1 || certs[0].DeviceID != "D1" || certs[0].Serial != "1f3a" || certs[0].Revoked || certs[0].DeviceName != "Field Mac" {
		t.Fatalf("device certificates %+v %v", certs, err)
	}
	if _, err := db.sql.Exec(`INSERT INTO revoked_certs(serial, reason) VALUES('1f3a', 1)`); err != nil {
		t.Fatal(err)
	}
	certs, _ = db.DeviceCertificates(ctx)
	if len(certs) != 1 || !certs[0].Revoked {
		t.Fatalf("revocation not reflected %+v", certs)
	}
	if err := db.DeviceCheckedOut(ctx, "D1"); err != nil {
		t.Fatal(err)
	}
	if certs, _ = db.DeviceCertificates(ctx); len(certs) != 0 {
		t.Fatal("checked-out device still listed")
	}
	_ = db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "D1", UDID: "D1", Name: "Field Mac"})

	// A refused renewal signed by that certificate is attributed to the device.
	if err := db.RecordRenewalAttempt(ctx, RenewalAttempt{SPKISHA256: "spki", SignerSerial: "1f3a", SignerSHA256: hash, SignerSubject: "CN=p@example.org", SignerExpires: tmpl.NotAfter.UTC().Format(time.RFC3339), Reason: "renewal not implemented"}); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordRenewalAttempt(ctx, RenewalAttempt{SignerSerial: "ffff", SignerSHA256: "unknown", Reason: "renewal not implemented"}); err != nil {
		t.Fatal(err)
	}
	recent, err := db.ListRenewalAttempts(ctx, time.Now().Add(-time.Hour), 10)
	if err != nil || len(recent) != 2 {
		t.Fatalf("recent %+v %v", recent, err)
	}
	mine, err := db.DeviceRenewalAttempts(ctx, "D1", 10)
	if err != nil || len(mine) != 1 || mine[0].DeviceName != "Field Mac" || mine[0].EnrollmentID != "D1" {
		t.Fatalf("device attempts %+v %v", mine, err)
	}
	if old, _ := db.ListRenewalAttempts(ctx, time.Now().Add(time.Hour), 10); len(old) != 0 {
		t.Fatal("future window returned rows")
	}
}
