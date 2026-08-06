package ca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	scep "github.com/smallstep/scep"

	"github.com/nickpdawson/cairn-mdm/internal/ca"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// makeRootAndIssuer builds an offline root and an issuer signed by it, returning the
// root cert PEM, issuer cert PEM, and issuer key PEM (as the two-tier import would).
func makeRootAndIssuer(t *testing.T) (rootPEM, issuerCertPEM, issuerKeyPEM []byte) {
	t.Helper()
	now := time.Now()
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Offline Root"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Online Issuer"},
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, rootCert, &issuerKey.PublicKey, rootKey) // signed by ROOT
	if err != nil {
		t.Fatal(err)
	}
	return pemCert(rootDER), pemCert(issuerDER),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(issuerKey)})
}

func TestTwoTierImportAndChain(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rootPEM, issuerPEM, issuerKeyPEM := makeRootAndIssuer(t)
	authority, err := ca.Ensure(ctx, db.SQL(), ca.Options{
		ImportRootCertPEM:   rootPEM,
		ImportIssuerCertPEM: issuerPEM,
		ImportIssuerKeyPEM:  issuerKeyPEM,
	})
	if err != nil {
		t.Fatalf("two-tier Ensure: %v", err)
	}

	// The profile installs both the root (anchor) and the issuer (intermediate).
	profileCerts := authority.ProfileCertsDER()
	if len(profileCerts) != 2 {
		t.Fatalf("ProfileCertsDER len = %d, want 2 (root + issuer)", len(profileCerts))
	}
	rootCert, _ := x509.ParseCertificate(profileCerts[0])
	issuerCert, _ := x509.ParseCertificate(profileCerts[1])
	if rootCert.Subject.CommonName != "Offline Root" || issuerCert.Subject.CommonName != "Online Issuer" {
		t.Fatalf("profile certs = %q,%q; want root,issuer", rootCert.Subject.CommonName, issuerCert.Subject.CommonName)
	}
	// RootPEM (the trust anchor) is the ROOT, not the issuer.
	ab, _ := pem.Decode(authority.RootPEM())
	anchor, _ := x509.ParseCertificate(ab.Bytes)
	if anchor.Subject.CommonName != "Offline Root" {
		t.Errorf("RootPEM anchor = %q, want the offline root", anchor.Subject.CommonName)
	}

	// Issue a leaf through the Broker + embedded backend, and prove the chain:
	// leaf -> issuer -> root.
	raw, hash := sqlite.NewGrantToken()
	gid, err := db.CreateGrant(ctx, sqlite.Grant{
		Label: "t", Platform: "macos", Owner: "ndawson@dzsec.net",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05"),
	}, hash)
	if err != nil {
		t.Fatal(err)
	}
	br := issue.NewBroker(authority.EmbeddedBackend(), db, resolver{db}, issue.DefaultPolicy())

	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, k)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	leaf, err := br.SignCSRContext(ctx, &scep.CSRReqMessage{CSR: csr, ChallengePassword: raw})
	if err != nil {
		t.Fatalf("SignCSRContext: %v", err)
	}
	if err := leaf.CheckSignatureFrom(issuerCert); err != nil {
		t.Fatalf("leaf not signed by the issuer: %v", err)
	}
	if err := issuerCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("issuer not signed by the root: %v", err)
	}
	if iss, _ := db.GetIssuance(ctx, gid); iss.State != sqlite.IssuanceIssued {
		t.Fatalf("issuance state = %q, want ISSUED", iss.State)
	}
}

// A single-tier CA (generate) must have no root and install just its own cert.
func TestSingleTierHasNoRoot(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	authority, err := ca.Ensure(ctx, db.SQL(), ca.Options{CommonName: "Solo CA", KeyBits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if got := authority.ProfileCertsDER(); len(got) != 1 {
		t.Fatalf("single-tier ProfileCertsDER len = %d, want 1", len(got))
	}
}
