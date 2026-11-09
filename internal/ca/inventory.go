package ca

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
)

// IssuedCert is one certificate the embedded CA has signed.
type IssuedCert struct {
	Serial   string // lowercase hex, as the issuance path records it
	SHA256   string // hex SHA-256 of the DER (NanoMDM's cert-auth hash)
	NotAfter string
	Subject  string
}

// Fingerprint is the hex SHA-256 of the issuing CA certificate.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return hex.EncodeToString(sum[:])
}

// IssuedForKey scans every certificate this CA has recorded and returns those
// whose SubjectPublicKeyInfo hashes to spkiHex, with the total scanned. This is
// the embedded CA's enumeration primitive: the depot is the only signer, every
// signature goes through Put, and the scan is complete by construction. It is
// not a transaction-scoped lookup.
func (c *CA) IssuedForKey(ctx context.Context, spkiHex string) (matches []IssuedCert, scanned int, err error) {
	rows, err := c.depot.db.QueryContext(ctx, `SELECT cert_pem FROM scep_certs ORDER BY created_at, serial`)
	if err != nil {
		return nil, 0, fmt.Errorf("ca: read issued certificates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var pemBytes []byte
		if err := rows.Scan(&pemBytes); err != nil {
			return nil, scanned, err
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, scanned, fmt.Errorf("ca: issued certificate record is not PEM")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, scanned, fmt.Errorf("ca: parse issued certificate: %w", err)
		}
		scanned++
		// Same derivation as issue.Identity so the match is exact.
		pkix, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return nil, scanned, err
		}
		spki := sha256.Sum256(pkix)
		if hex.EncodeToString(spki[:]) != spkiHex {
			continue
		}
		der := sha256.Sum256(leaf.Raw)
		matches = append(matches, IssuedCert{
			Serial:   new(big.Int).Set(leaf.SerialNumber).Text(16),
			SHA256:   hex.EncodeToString(der[:]),
			NotAfter: leaf.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
			Subject:  leaf.Subject.String(),
		})
	}
	return matches, scanned, rows.Err()
}
