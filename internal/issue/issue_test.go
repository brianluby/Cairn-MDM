package issue

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	scep "github.com/smallstep/scep"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// --- Reconstruction (the "reconstruct, don't validate" rule) ---

func TestReconstructUserCertHasExactlyOwnerSAN(t *testing.T) {
	k := genKey(t)
	g := GrantFacts{GrantID: 1, CommonName: "device-abc", Owner: "ndawson@dzsec.net", Platform: "macos"}
	tmpl, err := Reconstruct(DefaultPolicy(), g, k.Public(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.Subject.CommonName != "device-abc" {
		t.Errorf("CN = %q, want the server-chosen device-abc", tmpl.Subject.CommonName)
	}
	if len(tmpl.EmailAddresses) != 1 || tmpl.EmailAddresses[0] != "ndawson@dzsec.net" {
		t.Errorf("email SANs = %v, want exactly the owner", tmpl.EmailAddresses)
	}
	if len(tmpl.DNSNames) != 0 || len(tmpl.IPAddresses) != 0 || len(tmpl.URIs) != 0 {
		t.Errorf("reconstructed template must carry no DNS/IP/URI SANs, got %v/%v/%v", tmpl.DNSNames, tmpl.IPAddresses, tmpl.URIs)
	}
	if len(tmpl.ExtKeyUsage) != 1 || tmpl.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("EKU = %v, want exactly clientAuth", tmpl.ExtKeyUsage)
	}
	if tmpl.IsCA {
		t.Error("reconstructed leaf must not be a CA")
	}
	if len(tmpl.SubjectKeyId) == 0 {
		t.Error("SubjectKeyId must be derived from the public key")
	}
}

func TestReconstructDeviceCertHasNoSAN(t *testing.T) {
	k := genKey(t)
	g := GrantFacts{GrantID: 2, CommonName: "loaner-01", Owner: "", Platform: "ios"} // user-less device
	tmpl, err := Reconstruct(DefaultPolicy(), g, k.Public(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpl.EmailAddresses) != 0 {
		t.Errorf("a user-less device cert must carry no owner SAN, got %v", tmpl.EmailAddresses)
	}
}

func TestRequestHashStableAcrossTime(t *testing.T) {
	k := genKey(t)
	g := GrantFacts{GrantID: 7, CommonName: "dev", Owner: "u@x"}
	t1, _ := Reconstruct(DefaultPolicy(), g, k.Public(), time.Now())
	t2, _ := Reconstruct(DefaultPolicy(), g, k.Public(), time.Now().Add(48*time.Hour))
	if RequestHash(t1, g.GrantID) != RequestHash(t2, g.GrantID) {
		t.Fatal("RequestHash must be stable across reconstructions at different times (idempotency)")
	}
}

// --- Broker (real sqlite store, fake backend/resolver) ---

func newDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mkGrant(t *testing.T, db *sqlite.DB) int64 {
	t.Helper()
	_, hash := sqlite.NewGrantToken()
	id, err := db.CreateGrant(context.Background(), sqlite.Grant{
		Label: "t", Platform: "macos", Owner: "ndawson@dzsec.net",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05"),
	}, hash)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type fixedResolver struct{ g GrantFacts }

func (r fixedResolver) LookupForIssuance(context.Context, string) (GrantFacts, error) {
	return r.g, nil
}

type errResolver struct{ err error }

func (r errResolver) LookupForIssuance(context.Context, string) (GrantFacts, error) {
	return GrantFacts{}, r.err
}

// fakeBackend signs whatever template signFrom returns, so a test can make it honest
// (sign the intent) or malicious (sign an attacker-chosen template).
type fakeBackend struct {
	cap      Capability
	err      error
	status   IssueStatus
	signFrom func(intent *x509.Certificate) *x509.Certificate // nil => sign the intent
	pub      any
}

func (b *fakeBackend) Capabilities() Capability { return b.cap }
func (b *fakeBackend) Reconcile(context.Context, string, string) (IssueResult, error) {
	return IssueResult{Status: StatusAmbiguous}, nil
}
func (b *fakeBackend) Revoke(context.Context, string, RevokeReason) error { return nil }
func (b *fakeBackend) Issue(_ context.Context, req IssueRequest) (IssueResult, error) {
	if b.err != nil {
		return IssueResult{}, b.err
	}
	if b.status != StatusIssued {
		return IssueResult{Status: b.status}, nil
	}
	tmpl := req.Template
	if b.signFrom != nil {
		tmpl = b.signFrom(req.Template)
	}
	// caller's issue_test signLeaf needs *testing.T; sign inline here instead.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true, BasicConstraintsValid: true}
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(99)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, req.PublicKey, caKey)
	if err != nil {
		return IssueResult{}, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return IssueResult{Status: StatusIssued, Leaf: leaf, Serial: leaf.SerialNumber.Text(16)}, nil
}

func embeddedCap() Capability {
	return Capability{Name: "embedded", AtomicIssue: true, VerifiesReconstruction: false}
}

func newCSR(t *testing.T, k *ecdsa.PrivateKey) *scep.CSRReqMessage {
	t.Helper()
	// A hostile CSR: attacker-chosen subject/SANs. The Broker must ignore all of it.
	tmpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "attacker-owned"},
		DNSNames:       []string{"evil.example"},
		EmailAddresses: []string{"victim@dzsec.net"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return &scep.CSRReqMessage{CSR: csr, ChallengePassword: "tok"}
}

func TestBrokerHappyPathIssuesAndRecords(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	gid := mkGrant(t, db)
	k := genKey(t)

	be := &fakeBackend{cap: embeddedCap(), status: StatusIssued}
	br := NewBroker(be, db, fixedResolver{GrantFacts{GrantID: gid, CommonName: "dev-1", Owner: "ndawson@dzsec.net"}}, DefaultPolicy())

	leaf, err := br.SignCSRContext(ctx, newCSR(t, k))
	if err != nil {
		t.Fatalf("SignCSRContext: %v", err)
	}
	// The issued leaf carries the RECONSTRUCTED identity, not the CSR's.
	if leaf.Subject.CommonName != "dev-1" {
		t.Errorf("issued CN = %q, want reconstructed dev-1 (not attacker CN)", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "ndawson@dzsec.net" {
		t.Errorf("issued SANs = dns:%v email:%v, want only the owner email", leaf.DNSNames, leaf.EmailAddresses)
	}
	// The issuance is recorded ISSUED with the serial.
	iss, err := db.GetIssuance(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if iss.State != sqlite.IssuanceIssued || iss.CertSerial == "" || len(iss.LeafDER) == 0 {
		t.Fatalf("issuance = %+v, want ISSUED with serial+leaf", iss)
	}
}

func TestBrokerRetryReturnsCachedLeaf(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	gid := mkGrant(t, db)
	k := genKey(t)
	be := &fakeBackend{cap: embeddedCap(), status: StatusIssued}
	br := NewBroker(be, db, fixedResolver{GrantFacts{GrantID: gid, CommonName: "dev-1", Owner: "u@x"}}, DefaultPolicy())

	first, err := br.SignCSRContext(ctx, newCSR(t, k))
	if err != nil {
		t.Fatal(err)
	}
	second, err := br.SignCSRContext(ctx, newCSR(t, k)) // identical retry (same key)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Fatalf("retry returned a different serial (%s vs %s) — double issuance", first.SerialNumber, second.SerialNumber)
	}
}

func TestBrokerQuarantinesCSREchoingBackend(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	gid := mkGrant(t, db)
	k := genKey(t)
	// A malicious/broken backend that IGNORES the intent and signs the attacker's CN.
	evil := &fakeBackend{cap: embeddedCap(), status: StatusIssued, signFrom: func(intent *x509.Certificate) *x509.Certificate {
		bad := *intent
		bad.Subject = pkix.Name{CommonName: "attacker-owned"}
		bad.EmailAddresses = []string{"victim@dzsec.net"}
		return &bad
	}}
	br := NewBroker(evil, db, fixedResolver{GrantFacts{GrantID: gid, CommonName: "dev-1", Owner: "real@x"}}, DefaultPolicy())

	if _, err := br.SignCSRContext(ctx, newCSR(t, k)); err == nil {
		t.Fatal("a backend that honored the CSR instead of the intent must be rejected")
	}
	iss, err := db.GetIssuance(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if iss.State != sqlite.IssuanceQuarantined {
		t.Fatalf("state = %q, want QUARANTINED after a leaf-vs-intent mismatch", iss.State)
	}
}

func TestBrokerBackendErrorQuarantines(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	gid := mkGrant(t, db)
	k := genKey(t)
	be := &fakeBackend{cap: embeddedCap(), err: errors.New("ca timeout")}
	br := NewBroker(be, db, fixedResolver{GrantFacts{GrantID: gid, CommonName: "dev-1"}}, DefaultPolicy())

	if _, err := br.SignCSRContext(ctx, newCSR(t, k)); err == nil {
		t.Fatal("a backend error is ambiguous and must not succeed")
	}
	iss, _ := db.GetIssuance(ctx, gid)
	if iss.State != sqlite.IssuanceQuarantined {
		t.Fatalf("state = %q, want QUARANTINED after an ambiguous backend error", iss.State)
	}
}

func TestBrokerGrantLookupFailFailsClosed(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	k := genKey(t)
	be := &fakeBackend{cap: embeddedCap(), status: StatusIssued}
	br := NewBroker(be, db, errResolver{errors.New("unknown challenge")}, DefaultPolicy())
	if _, err := br.SignCSRContext(ctx, newCSR(t, k)); err == nil {
		t.Fatal("an unresolvable challenge must fail closed")
	}
}

// buildSANWithOtherName returns a raw SAN extension value carrying the owner
// rfc822Name AND a Microsoft UPN otherName — the smuggle the reviewer flagged:
// Go's typed EmailAddresses/DNSNames fields never surface the otherName, so a naive
// verify would pass it. verifyLeafMatchesIntent must reject it.
func buildSANWithOtherName(t *testing.T, ownerEmail, upn string) []byte {
	t.Helper()
	msUPN := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	// value: [0] EXPLICIT UTF8String(upn)
	utf8, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(upn)})
	if err != nil {
		t.Fatal(err)
	}
	explicit0, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: utf8})
	if err != nil {
		t.Fatal(err)
	}
	oidDER, err := asn1.Marshal(msUPN)
	if err != nil {
		t.Fatal(err)
	}
	// GeneralName otherName = [0] IMPLICIT { type-id, value }
	gnOther, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(oidDER, explicit0...)})
	if err != nil {
		t.Fatal(err)
	}
	// GeneralName rfc822Name = [1] IA5String(ownerEmail)
	gnEmail, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte(ownerEmail)})
	if err != nil {
		t.Fatal(err)
	}
	// GeneralNames ::= SEQUENCE { rfc822Name, otherName }
	san, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(gnEmail, gnOther...)})
	if err != nil {
		t.Fatal(err)
	}
	return san
}

func TestBrokerQuarantinesSmuggledOtherNameUPN(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	gid := mkGrant(t, db)
	k := genKey(t)
	// The email SAN matches intent, but a UPN otherName is smuggled alongside it.
	evil := &fakeBackend{cap: embeddedCap(), status: StatusIssued, signFrom: func(intent *x509.Certificate) *x509.Certificate {
		bad := *intent
		bad.EmailAddresses = nil // replaced by the raw ExtraExtensions SAN
		bad.ExtraExtensions = []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: buildSANWithOtherName(t, "real@x", "administrator@dzsec.net"),
		}}
		return &bad
	}}
	br := NewBroker(evil, db, fixedResolver{GrantFacts{GrantID: gid, CommonName: "dev-1", Owner: "real@x"}}, DefaultPolicy())

	if _, err := br.SignCSRContext(ctx, newCSR(t, k)); err == nil {
		t.Fatal("a leaf carrying a smuggled otherName UPN must be rejected (AD/EAP-TLS escalation)")
	}
	iss, _ := db.GetIssuance(ctx, gid)
	if iss.State != sqlite.IssuanceQuarantined {
		t.Fatalf("state = %q, want QUARANTINED after an otherName smuggle", iss.State)
	}
}

func TestBrokerQuarantinesUnknownEKU(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	gid := mkGrant(t, db)
	k := genKey(t)
	msSmartcardLogon := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
	evil := &fakeBackend{cap: embeddedCap(), status: StatusIssued, signFrom: func(intent *x509.Certificate) *x509.Certificate {
		bad := *intent
		bad.UnknownExtKeyUsage = []asn1.ObjectIdentifier{msSmartcardLogon} // widens purpose; ExtKeyUsage stays [clientAuth]
		return &bad
	}}
	br := NewBroker(evil, db, fixedResolver{GrantFacts{GrantID: gid, CommonName: "dev-1", Owner: "real@x"}}, DefaultPolicy())

	if _, err := br.SignCSRContext(ctx, newCSR(t, k)); err == nil {
		t.Fatal("a leaf carrying an unknown (Smartcard-Logon) EKU must be rejected")
	}
	iss, _ := db.GetIssuance(ctx, gid)
	if iss.State != sqlite.IssuanceQuarantined {
		t.Fatalf("state = %q, want QUARANTINED after an unknown-EKU smuggle", iss.State)
	}
}

// brokerCeilingPolicy is DefaultPolicy plus a broker-lane validity ceiling.
func brokerCeilingPolicy(days int) Policy {
	p := DefaultPolicy()
	p.MaxLeafValidity = time.Duration(days) * 24 * time.Hour
	return p
}

// widenValidity returns a signFrom that stretches the leaf's validity window
// [now-back, now+fwd] around the current time.
func widenValidity(back, fwd time.Duration) func(*x509.Certificate) *x509.Certificate {
	return func(intent *x509.Certificate) *x509.Certificate {
		out := *intent
		now := time.Now()
		out.NotBefore = now.Add(-back)
		out.NotAfter = now.Add(fwd)
		return &out
	}
}

// A backend cert longer-lived than our own LeafValidity but within the broker ceiling
// is ACCEPTED — the backend owns validity in broker mode; a bounded longer lifetime is
// a policy choice, not an escalation.
func TestBrokerCeilingAcceptsLongerBackendValidity(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	gid := mkGrant(t, db)
	k := genKey(t)
	be := &fakeBackend{cap: embeddedCap(), status: StatusIssued, signFrom: widenValidity(time.Minute, 120*24*time.Hour)}
	br := NewBroker(be, db, fixedResolver{GrantFacts{GrantID: gid, CommonName: "dev-1", Owner: "u@x"}}, brokerCeilingPolicy(400))

	if _, err := br.SignCSRContext(ctx, newCSR(t, k)); err != nil {
		t.Fatalf("SignCSRContext: %v (120d cert should be within a 400d ceiling)", err)
	}
	if iss, _ := db.GetIssuance(ctx, gid); iss.State != sqlite.IssuanceIssued {
		t.Fatalf("state = %q, want ISSUED", iss.State)
	}
}

// Beyond the ceiling still quarantines — the check stays a hard upper bound.
func TestBrokerCeilingRejectsBeyondCeiling(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	gid := mkGrant(t, db)
	k := genKey(t)
	be := &fakeBackend{cap: embeddedCap(), status: StatusIssued, signFrom: widenValidity(time.Minute, 500*24*time.Hour)}
	br := NewBroker(be, db, fixedResolver{GrantFacts{GrantID: gid, CommonName: "dev-1", Owner: "u@x"}}, brokerCeilingPolicy(400))

	if _, err := br.SignCSRContext(ctx, newCSR(t, k)); err == nil {
		t.Fatal("expected quarantine: 500d cert exceeds the 400d ceiling")
	}
	if iss, _ := db.GetIssuance(ctx, gid); iss.State != sqlite.IssuanceQuarantined {
		t.Fatalf("state = %q, want QUARANTINED", iss.State)
	}
}

// Embedded mode (no ceiling set) stays strict: a cert longer than our own LeafValidity
// is quarantined, because embedded Cairn sets the validity itself.
func TestEmbeddedStaysStrictWithoutCeiling(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	gid := mkGrant(t, db)
	k := genKey(t)
	be := &fakeBackend{cap: embeddedCap(), status: StatusIssued, signFrom: widenValidity(time.Minute, 120*24*time.Hour)}
	br := NewBroker(be, db, fixedResolver{GrantFacts{GrantID: gid, CommonName: "dev-1", Owner: "u@x"}}, DefaultPolicy())

	if _, err := br.SignCSRContext(ctx, newCSR(t, k)); err == nil {
		t.Fatal("expected quarantine: 120d cert exceeds the embedded 60d LeafValidity ceiling")
	}
	if iss, _ := db.GetIssuance(ctx, gid); iss.State != sqlite.IssuanceQuarantined {
		t.Fatalf("state = %q, want QUARANTINED", iss.State)
	}
}

// An already-expired backend cert is quarantined even though its span is small and
// within the ceiling.
func TestBrokerRejectsExpiredLeaf(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	gid := mkGrant(t, db)
	k := genKey(t)
	// window [now-10d, now-1d]: short span, but already expired.
	be := &fakeBackend{cap: embeddedCap(), status: StatusIssued, signFrom: widenValidity(10*24*time.Hour, -24*time.Hour)}
	br := NewBroker(be, db, fixedResolver{GrantFacts{GrantID: gid, CommonName: "dev-1", Owner: "u@x"}}, brokerCeilingPolicy(400))

	if _, err := br.SignCSRContext(ctx, newCSR(t, k)); err == nil {
		t.Fatal("expected quarantine: leaf is already expired")
	}
	if iss, _ := db.GetIssuance(ctx, gid); iss.State != sqlite.IssuanceQuarantined {
		t.Fatalf("state = %q, want QUARANTINED", iss.State)
	}
}
