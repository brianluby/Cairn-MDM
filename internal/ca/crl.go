package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// crlValidity is how long a generated CRL is good for (NextUpdate - ThisUpdate).
// The CRL is regenerated on every fetch, so this only bounds how long a relying
// party may cache one.
const crlValidity = 24 * time.Hour

// Revoke marks the certificate with the given serial (lowercase hex, as recorded
// by the issuance path: SerialNumber.Text(16)) as revoked with an RFC 5280
// CRLReason code. Revoking an already-revoked serial is a no-op — the original
// revocation time and reason stand.
func (c *CA) Revoke(ctx context.Context, serialHex string, reason int) error {
	serial, ok := new(big.Int).SetString(serialHex, 16)
	if !ok {
		return fmt.Errorf("ca: revoke: %q is not a hex serial", serialHex)
	}
	if _, err := c.depot.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO revoked_certs (serial, reason) VALUES (?, ?)`,
		serial.Text(16), reason); err != nil {
		return fmt.Errorf("ca: record revocation: %w", err)
	}
	return nil
}

// GenerateCRL builds and signs a fresh DER-encoded CRL covering every serial in
// revoked_certs. The signer is c.cert/c.key — the CA that issues the leaves, so
// relying parties verify the CRL with the same certificate that signed the leaf.
func (c *CA) GenerateCRL(ctx context.Context) ([]byte, error) {
	rows, err := c.depot.db.QueryContext(ctx,
		`SELECT serial, reason, revoked_at FROM revoked_certs ORDER BY serial`)
	if err != nil {
		return nil, fmt.Errorf("ca: read revoked_certs: %w", err)
	}
	defer rows.Close()

	var entries []x509.RevocationListEntry
	for rows.Next() {
		var serialHex, revokedAt string
		var reason int
		if err := rows.Scan(&serialHex, &reason, &revokedAt); err != nil {
			return nil, fmt.Errorf("ca: scan revoked cert: %w", err)
		}
		serial, ok := new(big.Int).SetString(serialHex, 16)
		if !ok {
			return nil, fmt.Errorf("ca: stored serial %q is not hex", serialHex)
		}
		when, err := time.Parse("2006-01-02 15:04:05", revokedAt)
		if err != nil {
			return nil, fmt.Errorf("ca: stored revoked_at %q: %w", revokedAt, err)
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: when.UTC(),
			ReasonCode:     reason,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ca: iterate revoked_certs: %w", err)
	}

	now := time.Now().UTC()
	tmpl := &x509.RevocationList{
		// Unix seconds is monotonic across regenerations, satisfying RFC 5280's
		// requirement that CRL numbers increase, without a persisted counter.
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(crlValidity),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, c.cert, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: sign CRL: %w", err)
	}
	return der, nil
}

// CRLHandler serves the CRL in DER form, regenerating it per request. At Cairn's
// scale (tens of devices) regeneration is cheap; add caching only if that changes.
func (c *CA) CRLHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		der, err := c.GenerateCRL(r.Context())
		if err != nil {
			http.Error(w, "crl generation failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(der)
	})
}

// IsRevoked reports whether serialHex is in revoked_certs and when it was revoked.
func (c *CA) IsRevoked(ctx context.Context, serialHex string) (revokedAt string, revoked bool, err error) {
	serial, ok := new(big.Int).SetString(serialHex, 16)
	if !ok {
		return "", false, fmt.Errorf("ca: %q is not a hex serial", serialHex)
	}
	err = c.depot.db.QueryRowContext(ctx, `SELECT revoked_at FROM revoked_certs WHERE serial=?`, serial.Text(16)).Scan(&revokedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return revokedAt, true, nil
}
