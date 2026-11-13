package sqlite

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"time"
)

// RenewalAttempt is a recorded, refused renewal-style SCEP request.
type RenewalAttempt struct {
	ID            int64
	ObservedAt    string
	SPKISHA256    string
	SignerSerial  string
	SignerSHA256  string
	SignerSubject string
	SignerExpires string
	EnrollmentID  string // device that authenticates with the signer, if known
	DeviceName    string
	Reason        string
}

// RecordRenewalAttempt stores a refused attempt, resolving the device from the
// signer certificate's MDM authentication association when one exists.
func (db *DB) RecordRenewalAttempt(ctx context.Context, a RenewalAttempt) error {
	var enrollment string
	_ = db.sql.QueryRowContext(ctx, `SELECT enrollment_id FROM cert_auth WHERE sha256=? LIMIT 1`, a.SignerSHA256).Scan(&enrollment)
	_, err := db.sql.ExecContext(ctx, `INSERT INTO renewal_attempts(spki_sha256, signer_serial, signer_sha256, signer_subject, signer_expires, enrollment_id, reason)
		 VALUES(?,?,?,?,?,?,?)`, a.SPKISHA256, a.SignerSerial, a.SignerSHA256, a.SignerSubject, a.SignerExpires, enrollment, a.Reason)
	return err
}

const renewalCols = `r.id, r.observed_at, r.spki_sha256, r.signer_serial, r.signer_sha256, r.signer_subject, r.signer_expires, r.enrollment_id,
	COALESCE(NULLIF(d.name,''), NULLIF(d.serial,''), r.enrollment_id), r.reason`

// ListRenewalAttempts returns attempts observed since the given time, newest first.
func (db *DB) ListRenewalAttempts(ctx context.Context, since time.Time, limit int) ([]RenewalAttempt, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT `+renewalCols+` FROM renewal_attempts r LEFT JOIN devices d ON d.id = r.enrollment_id
		 WHERE r.observed_at >= ? ORDER BY r.observed_at DESC, r.id DESC LIMIT ?`, since.UTC().Format("2006-01-02 15:04:05"), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRenewals(rows)
}

// DeviceRenewalAttempts returns a device's attempts, newest first.
func (db *DB) DeviceRenewalAttempts(ctx context.Context, deviceID string, limit int) ([]RenewalAttempt, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT `+renewalCols+` FROM renewal_attempts r LEFT JOIN devices d ON d.id = r.enrollment_id
		 WHERE r.enrollment_id = ? ORDER BY r.observed_at DESC, r.id DESC LIMIT ?`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRenewals(rows)
}

func scanRenewals(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]RenewalAttempt, error) {
	var out []RenewalAttempt
	for rows.Next() {
		var a RenewalAttempt
		if err := rows.Scan(&a.ID, &a.ObservedAt, &a.SPKISHA256, &a.SignerSerial, &a.SignerSHA256, &a.SignerSubject, &a.SignerExpires, &a.EnrollmentID, &a.DeviceName, &a.Reason); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeviceCertificate is an identity certificate the embedded CA issued that an
// enrolled device still authenticates with.
type DeviceCertificate struct {
	DeviceID   string
	DeviceName string
	Serial     string
	SHA256     string
	NotAfter   time.Time
	Revoked    bool
}

// DeviceCertificates lists the embedded CA's issued certificates that an enrolled
// device still authenticates with, so the operator can see which device
// certificates are nearing expiry. Devices enrolled through an external CA have
// no row here. SQLite cannot hash DER, so each issued PEM is parsed once.
func (db *DB) DeviceCertificates(ctx context.Context) ([]DeviceCertificate, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT cert_pem FROM scep_certs ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	var pems [][]byte
	for rows.Next() {
		var p []byte
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return nil, err
		}
		pems = append(pems, p)
	}
	rows.Close()
	var out []DeviceCertificate
	for _, p := range pems {
		block, _ := pem.Decode(p)
		if block == nil {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(leaf.Raw)
		h := hex.EncodeToString(sum[:])
		// One statement at a time: the pool is a single connection.
		var revoked int
		_ = db.sql.QueryRowContext(ctx, `SELECT count(*) FROM revoked_certs WHERE serial=?`, leaf.SerialNumber.Text(16)).Scan(&revoked)
		drows, err := db.sql.QueryContext(ctx, `SELECT d.id, COALESCE(NULLIF(d.name,''), NULLIF(d.serial,''), d.id)
			 FROM cert_auth ca JOIN devices d ON d.id = ca.enrollment_id
			 WHERE ca.sha256 = ? AND d.checked_out_at IS NULL`, h)
		if err != nil {
			return nil, err
		}
		for drows.Next() {
			c := DeviceCertificate{Serial: leaf.SerialNumber.Text(16), SHA256: h, NotAfter: leaf.NotAfter.UTC(), Revoked: revoked > 0}
			if err := drows.Scan(&c.DeviceID, &c.DeviceName); err != nil {
				drows.Close()
				return nil, err
			}
			out = append(out, c)
		}
		drows.Close()
	}
	return out, nil
}

// ObservedCertificate is the identity certificate a device last presented at
// check-in, from any CA.
type ObservedCertificate struct {
	DeviceID     string
	DeviceName   string
	Serial       string
	Issuer       string
	NotAfter     time.Time
	LastAccepted string
	LastRefused  string
	Refusals     int
}

// ObserveIdentityCertificate records the certificate presented on a check-in
// and whether its signature was accepted. Certificates not associated with an
// enrollment are ignored: the check-in endpoint is reachable without
// authentication and must not be a way to add rows.
func (db *DB) ObserveIdentityCertificate(ctx context.Context, cert *x509.Certificate, accepted bool) error {
	if cert == nil {
		return nil
	}
	sum := sha256.Sum256(cert.Raw)
	h := hex.EncodeToString(sum[:])
	col, bump := "last_accepted", 0
	if !accepted {
		col, bump = "last_refused", 1
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO device_identity_certs(sha256, subject, issuer, serial, not_after, `+col+`, refusals)
		SELECT ?,?,?,?,?,datetime('now'),? WHERE EXISTS (SELECT 1 FROM cert_auth WHERE sha256=?)
		ON CONFLICT(sha256) DO UPDATE SET `+col+`=datetime('now'), refusals=refusals+?`,
		h, cert.Subject.String(), cert.Issuer.CommonName, cert.SerialNumber.Text(16), cert.NotAfter.UTC().Format(time.RFC3339), bump, h, bump)
	return err
}

// ObservedDeviceCertificates returns, for each enrolled device that has
// presented a certificate, the one it presented most recently.
func (db *DB) ObservedDeviceCertificates(ctx context.Context) ([]ObservedCertificate, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT d.id, COALESCE(NULLIF(d.name,''), NULLIF(d.serial,''), d.id),
			c.serial, c.issuer, c.not_after, COALESCE(c.last_accepted,''), COALESCE(c.last_refused,''), c.refusals
		FROM device_identity_certs c
		JOIN cert_auth ca ON ca.sha256 = c.sha256
		JOIN devices d ON d.id = ca.enrollment_id
		WHERE d.checked_out_at IS NULL
		ORDER BY d.id, MAX(COALESCE(c.last_accepted,''), COALESCE(c.last_refused,'')) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ObservedCertificate
	seen := map[string]bool{}
	for rows.Next() {
		var o ObservedCertificate
		var notAfter string
		if err := rows.Scan(&o.DeviceID, &o.DeviceName, &o.Serial, &o.Issuer, &notAfter, &o.LastAccepted, &o.LastRefused, &o.Refusals); err != nil {
			return nil, err
		}
		if seen[o.DeviceID] {
			continue
		}
		seen[o.DeviceID] = true
		o.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
		out = append(out, o)
	}
	return out, rows.Err()
}
