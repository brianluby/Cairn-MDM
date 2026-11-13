package broker_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	scep "github.com/smallstep/scep"

	"github.com/nickpdawson/cairn-mdm/internal/broker"
	"github.com/nickpdawson/cairn-mdm/internal/ca"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

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

// makeRA builds a self-signed RSA RA identity (RSA is required: SCEP encrypts the
// reply to the envelope signer via PKCS#7 key transport).
func makeRA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cairn-ra:pkiclient"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// backendServer stands up a real SCEP CA (Cairn CA #2) as the "backend" the broker
// relays to, returning the running URL and the backend CA certificate.
func backendServer(t *testing.T) (url string, backendCA *ca.CA) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "backend.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	backendCA, err = ca.Ensure(ctx, db.SQL(), ca.Options{CommonName: "Backend CA", Organization: "Backend", KeyBits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	h, err := backendCA.SCEPHandler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL + "/scep", backendCA
}

func cairnSide(t *testing.T, be issue.CABackend, owner string) (*issue.Broker, *sqlite.DB, int64, string) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "cairn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	raw, hash := sqlite.NewGrantToken()
	gid, err := db.CreateGrant(ctx, sqlite.Grant{
		Label: "t", Platform: "macos", Owner: owner,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05"),
	}, hash)
	if err != nil {
		t.Fatal(err)
	}
	pol := issue.DefaultPolicy()
	pol.LeafValidity = 400 * 24 * time.Hour // >= the backend's 365-day leaf, so the span check passes
	return issue.NewBroker(be, db, resolver{db}, pol), db, gid, raw
}

func deviceCSR(t *testing.T, cn, email string) *scep.CSRReqMessage {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	if email != "" {
		req.EmailAddresses = []string{email}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, req, k)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return &scep.CSRReqMessage{CSR: csr}
}

// TestBrokerRelayIssues drives the whole Lane B chain: Cairn Broker → SCEP client
// (RA-signed) → backend SCEP CA → leaf returns → verified against intent → ISSUED.
// The backend copies the CSR subject, so the device CSR carries the reconstructed
// identity (CN=owner, SAN=owner) and the returned leaf matches intent.
func TestBrokerRelayIssues(t *testing.T) {
	ctx := context.Background()
	url, backendCA := backendServer(t)
	raCert, raKey := makeRA(t)
	be, err := broker.New(broker.Config{URL: url, RACert: raCert, RAKey: raKey})
	if err != nil {
		t.Fatal(err)
	}
	owner := "ndawson@dzsec.net"
	br, db, gid, tok := cairnSide(t, be, owner)

	msg := deviceCSR(t, owner, owner)
	msg.ChallengePassword = tok
	leaf, err := br.SignCSRContext(ctx, msg)
	if err != nil {
		t.Fatalf("SignCSRContext: %v", err)
	}
	if err := leaf.CheckSignatureFrom(backendCA.Certificate()); err != nil {
		t.Fatalf("issued leaf is not signed by the backend CA: %v", err)
	}
	if leaf.Subject.CommonName != owner {
		t.Errorf("issued CN = %q, want %q", leaf.Subject.CommonName, owner)
	}
	iss, err := db.GetIssuance(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if iss.State != sqlite.IssuanceIssued || iss.CertSerial == "" {
		t.Fatalf("issuance = %+v, want ISSUED via the relay", iss)
	}
}

// TestBrokerRelayQuarantinesMismatch: the backend copies the CSR subject, so a device
// CSR with the WRONG subject yields a leaf whose CN != the reconstructed intent. The
// Broker's post-verify catches it and quarantines — the fail-closed guarantee through
// a backend that honored the CSR instead of the intent.
func TestBrokerRelayQuarantinesMismatch(t *testing.T) {
	ctx := context.Background()
	url, _ := backendServer(t)
	raCert, raKey := makeRA(t)
	be, err := broker.New(broker.Config{URL: url, RACert: raCert, RAKey: raKey})
	if err != nil {
		t.Fatal(err)
	}
	br, db, gid, tok := cairnSide(t, be, "ndawson@dzsec.net")

	msg := deviceCSR(t, "attacker-owned", "victim@dzsec.net") // != reconstructed intent
	msg.ChallengePassword = tok
	if _, err := br.SignCSRContext(ctx, msg); err == nil {
		t.Fatal("a backend leaf that honored the CSR (not the intent) must be rejected")
	}
	iss, err := db.GetIssuance(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	if iss.State != sqlite.IssuanceQuarantined {
		t.Fatalf("state = %q, want QUARANTINED on leaf-vs-intent mismatch", iss.State)
	}
}

// A pinned backend issues when the endpoint's CA is the pinned one and refuses,
// before sending any request, when it is a different CA.
func TestBackendPinsCAChain(t *testing.T) {
	url, backendCA := backendServer(t)
	_, otherCA := backendServer(t)
	raCert, raKey := makeRA(t)
	pol := issue.Policy{LeafValidity: 24 * time.Hour, Backdate: 5 * time.Minute, MaxLeafValidity: 400 * 24 * time.Hour}
	request := func() issue.IssueRequest {
		key, err := issue.NewServerKey(issue.KeyRSA2048)
		if err != nil {
			t.Fatal(err)
		}
		req, err := issue.ServerKeyedRequest(pol, issue.GrantFacts{Owner: "alice@example.org", CommonName: "alice"}, key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	pinned, err := broker.New(broker.Config{URL: url, RACert: raCert, RAKey: raKey, Anchors: []*x509.Certificate{backendCA.Certificate()}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := pinned.Issue(context.Background(), request())
	if err != nil || res.Status != issue.StatusIssued || res.Leaf == nil {
		t.Fatalf("pinned to the right CA: status %v, err %v", res.Status, err)
	}

	wrong, err := broker.New(broker.Config{URL: url, RACert: raCert, RAKey: raKey, Anchors: []*x509.Certificate{otherCA.Certificate()}})
	if err != nil {
		t.Fatal(err)
	}
	res, err = wrong.Issue(context.Background(), request())
	if err == nil || res.Status != issue.StatusFailedClean || res.Leaf != nil {
		t.Fatalf("pinned to another CA: status %v, err %v; want a clean refusal", res.Status, err)
	}
}
