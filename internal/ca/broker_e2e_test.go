package ca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	scep "github.com/smallstep/scep"

	"github.com/nickpdawson/cairn-mdm/internal/ca"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// resolver adapts the sqlite grant lookup to issue.GrantResolver (the same wiring
// cmd/cairn/pki.go uses).
type resolver struct{ db *sqlite.DB }

func (r resolver) LookupForIssuance(ctx context.Context, challenge string) (issue.GrantFacts, error) {
	info, err := r.db.LookupGrantForIssuance(ctx, challenge)
	if err != nil {
		return issue.GrantFacts{}, err
	}
	cn := info.Owner
	if cn == "" {
		cn = fmt.Sprintf("cairn-device-%d", info.ID)
	}
	return issue.GrantFacts{GrantID: info.ID, Owner: info.Owner, CommonName: cn, Platform: info.Platform}, nil
}

// TestEmbeddedBrokerEndToEnd drives the whole chain: a grant's token is the SCEP
// challenge, the Broker reconstructs the cert (ignoring the hostile CSR), the
// embedded CA signs it, and the issuance is recorded ISSUED — with an idempotent
// retry returning the same certificate.
func TestEmbeddedBrokerEndToEnd(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	authority, err := ca.Ensure(ctx, db.SQL(), ca.Options{CommonName: "Test CA", Organization: "Cairn", KeyBits: 2048})
	if err != nil {
		t.Fatal(err)
	}

	raw, hash := sqlite.NewGrantToken()
	gid, err := db.CreateGrant(ctx, sqlite.Grant{
		Label: "t", Platform: "macos", Owner: "ndawson@dzsec.net",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05"),
	}, hash)
	if err != nil {
		t.Fatal(err)
	}

	broker := issue.NewBroker(authority.EmbeddedBackend(), db, resolver{db}, issue.DefaultPolicy())

	// Device keypair + a hostile CSR whose subject/SANs the Broker must ignore.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "attacker-owned"}, DNSNames: []string{"evil.example"},
	}, k)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := broker.SignCSRContext(ctx, &scep.CSRReqMessage{CSR: csr, ChallengePassword: raw})
	if err != nil {
		t.Fatalf("SignCSRContext: %v", err)
	}
	// Signed by our CA, carrying the reconstructed identity (owner), not the CSR's.
	if err := leaf.CheckSignatureFrom(authority.Certificate()); err != nil {
		t.Fatalf("issued leaf is not signed by the CA: %v", err)
	}
	if leaf.Subject.CommonName != "ndawson@dzsec.net" {
		t.Errorf("issued CN = %q, want reconstructed owner (not the attacker CN)", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "ndawson@dzsec.net" {
		t.Errorf("issued SANs dns=%v email=%v, want only the owner email", leaf.DNSNames, leaf.EmailAddresses)
	}
	iss, err := db.GetIssuance(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if iss.State != sqlite.IssuanceIssued || iss.CertSerial == "" || len(iss.LeafDER) == 0 {
		t.Fatalf("issuance = %+v, want ISSUED with serial+leaf", iss)
	}

	// Idempotent retry (same key ⇒ same txn) returns the same certificate.
	leaf2, err := broker.SignCSRContext(ctx, &scep.CSRReqMessage{CSR: csr, ChallengePassword: raw})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if leaf.SerialNumber.Cmp(leaf2.SerialNumber) != 0 {
		t.Fatalf("retry issued a different serial (%s vs %s) — double issuance", leaf.SerialNumber, leaf2.SerialNumber)
	}
}
