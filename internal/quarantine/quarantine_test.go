package quarantine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/ca"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// heldAfterSigning reproduces the real quarantine path: the grant is bound, the
// embedded CA signs (so the certificate is in its record), and the attempt is then
// quarantined because authorization changed after signing.
func heldAfterSigning(t *testing.T, db *sqlite.DB, authority *ca.CA, owner string) (grantID int64, serial, spki string) {
	t.Helper()
	ctx := context.Background()
	_, hash := sqlite.NewGrantToken()
	grantID, err := db.CreateGrant(ctx, sqlite.Grant{Owner: owner, Platform: "macos", ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05")}, hash)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	txn, spki, err := issue.Identity(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := issue.Reconstruct(issue.DefaultPolicy(), issue.GrantFacts{GrantID: grantID, Owner: owner, CommonName: owner}, &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reqHash := issue.RequestHash(tmpl, grantID)
	if _, _, err = db.BeginIssuance(ctx, grantID, txn, spki, reqHash); err != nil {
		t.Fatal(err)
	}
	res, err := authority.EmbeddedBackend().Issue(ctx, issue.IssueRequest{TxnID: txn, SPKISHA256: spki, PublicKey: &key.PublicKey, Template: tmpl, GrantID: grantID, RequestHash: reqHash})
	if err != nil || res.Status != issue.StatusIssued {
		t.Fatalf("issue %+v %v", res, err)
	}
	if err = db.QuarantineIssuance(ctx, grantID, txn, spki, reqHash, "authorization changed after signing", "embedded", res.Serial); err != nil {
		t.Fatal(err)
	}
	return grantID, res.Serial, spki
}

func newAuthority(t *testing.T) (*sqlite.DB, *ca.CA) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir()+"/q.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	authority, err := ca.Ensure(ctx, db.SQL(), ca.Options{CommonName: "Q CA", Organization: "Cairn", KeyBits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	return db, authority
}

func TestResolutionRequiresOrderAndCoverage(t *testing.T) {
	ctx := context.Background()
	db, authority := newAuthority(t)
	grantID, serial, spki := heldAfterSigning(t, db, authority, "person@example.org")
	svc := New(db, authority, []string{"radius-b.example.org", "radius-a.example.org"})

	// Steps cannot be skipped.
	if _, err := svc.Enumerate(ctx, grantID, "local:nick"); !errors.Is(err, sqlite.ErrResolutionOrder) {
		t.Fatalf("enumerate before fence: %v", err)
	}
	if _, _, err := svc.ConfirmRejected(ctx, grantID, "local:nick"); !errors.Is(err, sqlite.ErrResolutionOrder) {
		t.Fatalf("confirm before enumerate: %v", err)
	}
	if err := svc.Release(ctx, grantID, "local:nick"); !errors.Is(err, sqlite.ErrResolutionOrder) {
		t.Fatalf("release before evidence: %v", err)
	}

	fence, err := svc.Fence(ctx, grantID, "local:nick")
	if err != nil || fence.CAFingerprint != authority.Fingerprint() || fence.SPKISHA256 != spki || !fence.AtomicSigner {
		t.Fatalf("fence %+v %v", fence, err)
	}
	enum, err := svc.Enumerate(ctx, grantID, "local:nick")
	if err != nil || !enum.Complete || len(enum.Serials) != 1 || enum.Serials[0].Serial != serial || enum.Scanned != 1 || len(enum.Discrepancy) != 0 {
		t.Fatalf("enumerate %+v %v", enum, err)
	}

	// The device had authenticated to MDM with the held certificate.
	if _, err := db.SQL().Exec(`INSERT INTO cert_auth(enrollment_id, sha256) VALUES('UDID-held', ?)`, enum.Serials[0].SHA256); err != nil {
		t.Fatal(err)
	}
	m, missing, err := svc.ConfirmRejected(ctx, grantID, "local:nick")
	if err != nil || len(missing) != 2 || m == nil {
		t.Fatalf("confirm without rejections: %+v %v %v", m, missing, err)
	}
	if _, ok, _ := authority.IsRevoked(ctx, serial); !ok {
		t.Fatal("confirm did not revoke the serial")
	}
	var assoc int
	_ = db.SQL().QueryRow(`SELECT count(*) FROM cert_auth WHERE sha256=?`, enum.Serials[0].SHA256).Scan(&assoc)
	if assoc != 0 {
		t.Fatal("MDM association survived confirmation")
	}
	res, _ := db.GetQuarantineResolution(ctx, grantID)
	if res.Step() != 2 {
		t.Fatalf("incomplete confirmation advanced the step: %d", res.Step())
	}
	if err := svc.Release(ctx, grantID, "local:nick"); !errors.Is(err, sqlite.ErrResolutionOrder) {
		t.Fatalf("release after incomplete confirmation: %v", err)
	}

	// A rejection observed before revocation does not count; one per point after it does.
	stale := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	_ = db.InsertRadiusRejection(ctx, sqlite.RadiusRejection{Serial: serial, AcceptancePoint: "radius-a.example.org", ObservedAt: stale})
	if _, missing, err = svc.ConfirmRejected(ctx, grantID, "local:nick"); err != nil || len(missing) != 2 {
		t.Fatalf("stale rejection counted: %v %v", missing, err)
	}
	fresh := time.Now().UTC().Format(time.RFC3339)
	_ = db.InsertRadiusRejection(ctx, sqlite.RadiusRejection{Serial: serial, AcceptancePoint: "radius-a.example.org", ObservedAt: fresh, Source: "freeradius post-auth"})
	if _, missing, err = svc.ConfirmRejected(ctx, grantID, "local:nick"); err != nil || len(missing) != 1 || !strings.Contains(missing[0], "radius-b") {
		t.Fatalf("partial coverage: %v %v", missing, err)
	}
	_ = db.InsertRadiusRejection(ctx, sqlite.RadiusRejection{Serial: serial, AcceptancePoint: "radius-b.example.org", ObservedAt: fresh})
	m, missing, err = svc.ConfirmRejected(ctx, grantID, "local:nick")
	if err != nil || len(missing) != 0 || len(m.Serials) != 1 || len(m.Serials[0].Rejections) != 2 || m.MDMOnly {
		t.Fatalf("full coverage: %+v %v %v", m, missing, err)
	}
	if problems, err := svc.Validate(ctx, grantID); err != nil || len(problems) != 0 {
		t.Fatalf("validate %v %v", problems, err)
	}

	// Evidence content is checked at release, not just row presence.
	if _, err := db.SQL().Exec(`UPDATE quarantine_resolutions SET rejection_manifest='{"acceptance_points":["radius-a.example.org","radius-b.example.org"],"serials":[],"format":1}' WHERE grant_id=?`, grantID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Release(ctx, grantID, "local:nick"); !errors.Is(err, ErrEvidence) {
		t.Fatalf("forged rejection manifest released: %v", err)
	}
	if _, _, err = svc.ConfirmRejected(ctx, grantID, "local:nick"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Release(ctx, grantID, "local:nick"); err != nil {
		t.Fatalf("release %v", err)
	}
	held, _ := db.ListQuarantined(ctx)
	if len(held) != 0 {
		t.Fatal("released hold still listed")
	}
	iss, _ := db.GetIssuance(ctx, grantID)
	if iss.State != sqlite.IssuanceQuarantined {
		t.Fatal("release changed the terminal issuance state")
	}
	if err := svc.Release(ctx, grantID, "local:nick"); err == nil {
		t.Fatal("double release")
	}
	var audits int
	_ = db.SQL().QueryRow(`SELECT count(*) FROM audit_log WHERE action LIKE 'quarantine.%'`).Scan(&audits)
	if audits < 4 {
		t.Fatalf("audit rows %d", audits)
	}
}

func TestReleaseRefusedWhenCARecordGrewAndForExternalBackend(t *testing.T) {
	ctx := context.Background()
	db, authority := newAuthority(t)
	grantID, serial, spki := heldAfterSigning(t, db, authority, "p@example.org")
	svc := New(db, authority, nil) // MDM-only deployment
	if _, err := svc.Fence(ctx, grantID, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Enumerate(ctx, grantID, "a"); err != nil {
		t.Fatal(err)
	}
	m, missing, err := svc.ConfirmRejected(ctx, grantID, "a")
	if err != nil || len(missing) != 0 || !m.MDMOnly {
		t.Fatalf("mdm-only confirm %+v %v %v", m, missing, err)
	}
	// Another certificate for the same key appears in the CA record after enumeration.
	_, hash := sqlite.NewGrantToken()
	other, _ := db.CreateGrant(ctx, sqlite.Grant{Owner: "p@example.org", Platform: "macos", ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05")}, hash)
	key := reconstructKey(t, db, grantID)
	tmpl, _ := issue.Reconstruct(issue.DefaultPolicy(), issue.GrantFacts{GrantID: other, Owner: "p@example.org", CommonName: "p@example.org"}, key, time.Now())
	if _, err := authority.EmbeddedBackend().Issue(ctx, issue.IssueRequest{TxnID: "t2", SPKISHA256: spki, PublicKey: key, Template: tmpl, GrantID: other, RequestHash: "r2"}); err != nil {
		t.Fatal(err)
	}
	err = svc.Release(ctx, grantID, "a")
	if !errors.Is(err, ErrEvidence) || !strings.Contains(err.Error(), "appeared after enumeration") {
		t.Fatalf("release with grown CA record: %v", err)
	}
	_ = serial
	// External-backend holds cannot be fenced or enumerated here.
	_, hash = sqlite.NewGrantToken()
	ext, _ := db.CreateGrant(ctx, sqlite.Grant{Owner: "x@example.org", Platform: "ios", ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05")}, hash)
	if _, _, err := db.BeginIssuance(ctx, ext, "tx", "spkix", "rx"); err != nil {
		t.Fatal(err)
	}
	if err := db.QuarantineIssuance(ctx, ext, "tx", "spkix", "rx", "backend pending", "external-scep", "tx"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Fence(ctx, ext, "a"); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("external fence: %v", err)
	}
	none := New(db, nil, nil)
	if _, err := none.Fence(ctx, grantID, "a"); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("fence without authority: %v", err)
	}
}

// reconstructKey recovers the public key of a held attempt from the CA record so
// the test can issue a second certificate for the same key.
func reconstructKey(t *testing.T, db *sqlite.DB, grantID int64) any {
	t.Helper()
	_ = grantID
	var pemBytes []byte
	if err := db.SQL().QueryRow(`SELECT cert_pem FROM scep_certs ORDER BY created_at LIMIT 1`).Scan(&pemBytes); err != nil {
		t.Fatal(err)
	}
	return publicKeyFromPEM(t, pemBytes)
}

func publicKeyFromPEM(t *testing.T, pemBytes []byte) any {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf.PublicKey
}
