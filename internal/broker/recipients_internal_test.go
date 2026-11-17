package broker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
)

// mkRSA builds a self-signed RSA leaf with the given key usage.
func mkRSA(t *testing.T, cn string, ku x509.KeyUsage, isCA bool) *x509.Certificate {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		KeyUsage:              ku,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// mkEC builds a self-signed EC CA (the shape of an OpenXPKI root).
func mkEC(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The OpenXPKI shape that broke the first real relay: an RSA keyEncipherment RA
// plus an EC root, both returned by GetCACert. The RA must be selected and the EC
// root excluded — pkcs7 cannot encrypt to an EC recipient.
func TestEncryptionRecipientsExcludesECRootPrefersRA(t *testing.T) {
	ra := mkRSA(t, "Internal RA", x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, false)
	root := mkEC(t, "OpenXPKI Root DUMMY CA")

	got, err := encryptionRecipients([]*x509.Certificate{ra, root})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Subject.CommonName != "Internal RA" {
		t.Fatalf("want [Internal RA], got %v", subjects(got))
	}
}

// A direct single-CA RSA backend (no keyEncipherment leaf): fall back to the RSA cert.
func TestEncryptionRecipientsFallsBackToRSA(t *testing.T) {
	ca := mkRSA(t, "Direct RSA CA", x509.KeyUsageCertSign, true)
	got, err := encryptionRecipients([]*x509.Certificate{ca})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Subject.CommonName != "Direct RSA CA" {
		t.Fatalf("want [Direct RSA CA], got %v", subjects(got))
	}
}

// No RSA recipient at all → a clear error, never a silent EC encryption attempt.
func TestEncryptionRecipientsNoRSAErrors(t *testing.T) {
	root := mkEC(t, "EC only")
	if _, err := encryptionRecipients([]*x509.Certificate{root}); err == nil {
		t.Fatal("want error when no RSA recipient is present")
	}
}

func subjects(certs []*x509.Certificate) []string {
	out := make([]string, len(certs))
	for i, c := range certs {
		out[i] = c.Subject.CommonName
	}
	return out
}
