package push

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Public certificates from https://www.apple.com/certificateauthority/.
// These anchors are independent of the certificates uploaded by an operator.
//
//go:embed trust/apple-root.der
var appleRootDER []byte

//go:embed trust/apple-aai2.der
var appleAAI2DER []byte

type CertificateInfo struct {
	Topic       string
	Subject     string
	Fingerprint string
	NotAfter    time.Time
}

type CertificateWriteOptions struct {
	RequestID   string
	RenewTopic  string
	MakeDefault bool
	Actor       string
	Provider    string
}

type InstallReceipt struct {
	CertificateInfo
	InstalledAt time.Time
	Actor       string
}

type CertificateStore interface {
	APNSInstallReceipt(context.Context, string) (*InstallReceipt, error)
	SaveAPNSCertificate(context.Context, []byte, []byte, CertificateWriteOptions) (CertificateInfo, error)
}

// InstallCertificate is the shared CLI/web entry point. Invalid input never
// reaches the transactional store.
func InstallCertificate(ctx context.Context, store CertificateStore, certPEM, keyPEM []byte, opts CertificateWriteOptions) (CertificateInfo, error) {
	info, err := VerifyAppleCertificate(certPEM, keyPEM, time.Now())
	if err != nil {
		return info, err
	}
	return store.SaveAPNSCertificate(ctx, certPEM, keyPEM, opts)
}

// ValidatePair checks the identity, usage and validity of a certificate/key pair.
// It does not establish issuer trust; VerifyAppleCertificate does that separately.
func ValidatePair(certPEM, keyPEM []byte, now time.Time) (CertificateInfo, error) {
	var info CertificateInfo
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return info, fmt.Errorf("APNs certificate/key pair invalid: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return info, err
	}
	uidOID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	count := 0
	for _, a := range leaf.Subject.Names {
		if a.Type.Equal(uidOID) {
			count++
			info.Topic, _ = a.Value.(string)
		}
	}
	if count != 1 || !strings.HasPrefix(info.Topic, "com.apple.mgmt.") || strings.ContainsAny(info.Topic, "\r\n\t /\\") || len(info.Topic) > 255 || len(info.Topic) <= len("com.apple.mgmt.") {
		return CertificateInfo{}, fmt.Errorf("certificate must have exactly one Apple MDM topic UID")
	}
	if now.Before(leaf.NotBefore) {
		return info, fmt.Errorf("certificate is not yet valid")
	}
	if !now.Before(leaf.NotAfter) {
		return info, fmt.Errorf("certificate has expired")
	}
	client := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			client = true
		}
	}
	if leaf.IsCA || !client || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return info, fmt.Errorf("certificate must be a non-CA TLS client signing identity")
	}
	mdmOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 3, 2}
	mdm := false
	for _, e := range leaf.Extensions {
		if e.Id.Equal(mdmOID) {
			mdm = true
		}
	}
	if !mdm {
		return info, fmt.Errorf("certificate is missing the Apple MDM push extension")
	}
	h := sha256.Sum256(leaf.Raw)
	info.Subject, info.Fingerprint, info.NotAfter = leaf.Subject.String(), hex.EncodeToString(h[:]), leaf.NotAfter
	return info, nil
}

// VerifyAppleCertificate verifies against bundled Apple PKI anchors, not the
// system trust store or an uploaded root. No AIA network fetch is performed.
// Revocation and APNs connectivity still require separate operational checks.
func VerifyAppleCertificate(certPEM, keyPEM []byte, now time.Time) (CertificateInfo, error) {
	info, err := ValidatePair(certPEM, keyPEM, now)
	if err != nil {
		return info, err
	}
	pair, _ := tls.X509KeyPair(certPEM, keyPEM)
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	root, err := x509.ParseCertificate(appleRootDER)
	if err != nil {
		return info, fmt.Errorf("bundled Apple root: %w", err)
	}
	issuer, err := x509.ParseCertificate(appleAAI2DER)
	if err != nil {
		return info, fmt.Errorf("bundled Apple issuer: %w", err)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(issuer)
	for _, der := range pair.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return info, err
		}
		intermediates.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return info, fmt.Errorf("certificate does not verify against Apple PKI: %w", err)
	}
	return info, nil
}
