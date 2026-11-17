package ca

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/issue"
)

func TestRevokeAndGenerateCRL(t *testing.T) {
	ca, _ := testCA(t)
	ctx := context.Background()

	// Serials as the issuance path records them: SerialNumber.Text(16).
	if err := ca.Revoke(ctx, "2a", int(issue.RevokeKeyCompromise)); err != nil {
		t.Fatalf("revoke 2a: %v", err)
	}
	if err := ca.Revoke(ctx, "ff01", int(issue.RevokeSuperseded)); err != nil {
		t.Fatalf("revoke ff01: %v", err)
	}
	// Re-revoking is a no-op, not an error.
	if err := ca.Revoke(ctx, "2a", int(issue.RevokeUnspecified)); err != nil {
		t.Fatalf("re-revoke 2a: %v", err)
	}
	// Garbage serials are rejected.
	if err := ca.Revoke(ctx, "not-hex", 0); err == nil {
		t.Error("revoke accepted a non-hex serial")
	}

	der, err := ca.GenerateCRL(ctx)
	if err != nil {
		t.Fatalf("generate CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if err := crl.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("CRL does not verify against the issuing CA: %v", err)
	}
	if crl.NextUpdate.Before(crl.ThisUpdate) {
		t.Error("NextUpdate precedes ThisUpdate")
	}

	got := map[string]int{}
	for _, e := range crl.RevokedCertificateEntries {
		got[e.SerialNumber.Text(16)] = e.ReasonCode
	}
	if len(got) != 2 {
		t.Fatalf("CRL has %d entries, want 2: %v", len(got), got)
	}
	if got["2a"] != int(issue.RevokeKeyCompromise) {
		t.Errorf("serial 2a reason = %d, want %d (original revocation must stand)", got["2a"], issue.RevokeKeyCompromise)
	}
	if got["ff01"] != int(issue.RevokeSuperseded) {
		t.Errorf("serial ff01 reason = %d, want %d", got["ff01"], issue.RevokeSuperseded)
	}
}

func TestGenerateCRLEmpty(t *testing.T) {
	ca, _ := testCA(t)

	der, err := ca.GenerateCRL(context.Background())
	if err != nil {
		t.Fatalf("generate empty CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse empty CRL: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Errorf("empty CRL has %d entries", len(crl.RevokedCertificateEntries))
	}
	if err := crl.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("empty CRL does not verify against the issuing CA: %v", err)
	}
}

func TestCRLHandler(t *testing.T) {
	ca, _ := testCA(t)
	if err := ca.Revoke(context.Background(), "1b", 0); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	srv := httptest.NewServer(ca.CRLHandler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CRL handler status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/pkix-crl" {
		t.Errorf("Content-Type = %q, want application/pkix-crl", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		t.Fatalf("handler body is not a DER CRL: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Text(16) != "1b" {
		t.Errorf("served CRL entries = %+v, want the single serial 1b", crl.RevokedCertificateEntries)
	}
}

func TestEmbeddedBackendRevoke(t *testing.T) {
	ca, _ := testCA(t)
	b := ca.EmbeddedBackend()

	if !b.Capabilities().CanRevoke {
		t.Fatal("embedded backend does not advertise CanRevoke")
	}
	if err := b.Revoke(context.Background(), "3c", issue.RevokeSuperseded); err != nil {
		t.Fatalf("backend revoke: %v", err)
	}
	der, err := ca.GenerateCRL(context.Background())
	if err != nil {
		t.Fatalf("generate CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Text(16) != "3c" {
		t.Errorf("CRL entries = %+v, want the single serial 3c", crl.RevokedCertificateEntries)
	}
}
