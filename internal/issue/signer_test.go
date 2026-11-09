package issue

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

func selfSigned(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func issuedBy(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func signedBody(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData([]byte("envelope"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	raw, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type recordingObserver struct{ got []RenewalAttempt }

func (r *recordingObserver) RecordRenewalAttempt(_ context.Context, a RenewalAttempt) error {
	r.got = append(r.got, a)
	return nil
}

func TestSignerMiddlewareAndRenewalRefusal(t *testing.T) {
	caCert, caKey := selfSigned(t, "Cairn CA")
	device, deviceKey := issuedBy(t, caCert, caKey, "device")
	temp, tempKey := selfSigned(t, "temporary signer")

	var seen *x509.Certificate
	h := SignerExtractMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = SignerFromContext(r.Context())
		if r.Method == http.MethodPost {
			body := new(bytes.Buffer)
			body.ReadFrom(r.Body)
			if body.Len() == 0 {
				t.Error("middleware consumed the body")
			}
		}
	}))
	req := httptest.NewRequest("POST", "/scep?operation=PKIOperation", bytes.NewReader(signedBody(t, device, deviceKey)))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen == nil || seen.Subject.CommonName != "device" {
		t.Fatalf("signer not extracted: %v", seen)
	}
	seen = nil
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/scep?operation=GetCACert", nil))
	if seen != nil {
		t.Fatal("non-PKIOperation request got a signer")
	}

	// Broker: a request signed by a Cairn-issued identity is refused before any
	// grant lookup and recorded; a temporary self-signed signer proceeds normally.
	db := newDB(t)
	grant := mkGrant(t, db)
	obs := &recordingObserver{}
	lookups := 0
	resolver := countingResolver{inner: fixedResolver{g: GrantFacts{GrantID: grant, Owner: "ndawson@dzsec.net", CommonName: "ndawson@dzsec.net"}}, n: &lookups}
	b := NewBroker(&fakeBackend{cap: embeddedCap(), status: StatusIssued}, db, resolver, DefaultPolicy()).WithIssuer(caCert).WithRenewalObserver(obs)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := newCSR(t, k)

	ctx := context.WithValue(context.Background(), signerKey{}, device)
	if _, err := b.SignCSRContext(ctx, csr); !errors.Is(err, ErrRenewalUnsupported) {
		t.Fatalf("renewal accepted: %v", err)
	}
	if lookups != 0 {
		t.Fatal("renewal attempt consulted the grant")
	}
	if len(obs.got) != 1 || obs.got[0].SignerSerial != "63" || obs.got[0].SignerSubject != "CN=device" {
		t.Fatalf("attempt not recorded: %+v", obs.got)
	}
	_ = tempKey
	ctx = context.WithValue(context.Background(), signerKey{}, temp)
	if _, err := b.SignCSRContext(ctx, csr); err != nil {
		t.Fatalf("initial enrollment with temporary signer refused: %v", err)
	}
	if lookups == 0 {
		t.Fatal("initial enrollment skipped the grant lookup")
	}
	// Without a configured issuer the broker cannot classify and never refuses.
	plain := NewBroker(&fakeBackend{cap: embeddedCap(), status: StatusIssued}, db, resolver, DefaultPolicy())
	if _, err := plain.SignCSRContext(context.WithValue(context.Background(), signerKey{}, device), csr); errors.Is(err, ErrRenewalUnsupported) {
		t.Fatal("refused without an issuer configured")
	}
}

type countingResolver struct {
	inner GrantResolver
	n     *int
}

func (c countingResolver) LookupForIssuance(ctx context.Context, ch string) (GrantFacts, error) {
	*c.n++
	return c.inner.LookupForIssuance(ctx, ch)
}
