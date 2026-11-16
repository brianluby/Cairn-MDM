package challenge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

const secret = "0123456789abcdef0123456789abcdef-lookup"

func testService(t *testing.T, opts Options) (*Service, *sqlite.DB, http.Handler) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir()+"/challenge.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	opts.Secret = secret
	s, err := New(db, opts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /scep-challenge/{name}/{keyid}/{challenge}", s.Handler())
	return s, db, mux
}

// ask plays the CA: one lookup, returning the status and body.
func ask(h http.Handler, token, remote, name, keyID, challenge string) (int, string) {
	r := httptest.NewRequest("GET", "/scep-challenge/"+name+"/"+keyID+"/"+challenge, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if remote != "" {
		r.RemoteAddr = remote
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

const keyA, keyB = "07:49:29:57:21:0D:4A:B7:F4:F2:8C:5E:04:B9:C6:80:3E:90:98:71", "AA:49:29:57:21:0D:4A:B7:F4:F2:8C:5E:04:B9:C6:80:3E:90:98:71"

func TestEnrollmentChallengeWorksOnceForOneNameAndKey(t *testing.T) {
	ctx := context.Background()
	s, db, h := testService(t, Options{})
	challenge, err := s.ForEnrollment(ctx, "", "devices.mdm.example.org", "alice@example.org")
	if err != nil {
		t.Fatal(err)
	}
	var stored int
	db.SQL().QueryRow(`SELECT count(*) FROM scep_challenges WHERE challenge_sha256=? OR note=?`, challenge, challenge).Scan(&stored)
	if stored != 0 {
		t.Fatal("the challenge is stored in the clear")
	}
	if code, _ := ask(h, "", "", "C02ABC.devices.mdm.example.org", keyA, challenge); code != 404 {
		t.Fatalf("lookup without the secret = %d", code)
	}
	if code, _ := ask(h, strings.Repeat("x", 40), "", "C02ABC.devices.mdm.example.org", keyA, challenge); code != 404 {
		t.Fatalf("lookup with a wrong secret = %d", code)
	}
	// Refusals spend nothing.
	for _, name := range []string{"administrator", "C02ABC.devices.other.example.org", ".devices.mdm.example.org", "devices.mdm.example.org"} {
		if code, _ := ask(h, secret, "", name, keyA, challenge); code != 404 {
			t.Fatalf("name %q accepted", name)
		}
	}
	if code, _ := ask(h, secret, "", "C02ABC.devices.mdm.example.org", keyA, "not-the-challenge"); code != 404 {
		t.Fatal("an unknown challenge was accepted")
	}
	code, body := ask(h, secret, "", "C02ABC.devices.mdm.example.org", keyA, challenge)
	if code != 200 || body != challenge {
		t.Fatalf("first lookup = %d %q; a CA that compares needs the challenge back", code, body)
	}
	// The CA may evaluate one request twice; nobody else may use the challenge.
	if code, _ = ask(h, secret, "", "C02ABC.devices.mdm.example.org", strings.ToLower(strings.ReplaceAll(keyA, ":", "")), challenge); code != 200 {
		t.Fatalf("repeat by the same key = %d", code)
	}
	if code, _ = ask(h, secret, "", "C02ABC.devices.mdm.example.org", keyB, challenge); code != 404 {
		t.Fatal("a second key used the challenge")
	}
	if code, _ = ask(h, secret, "", "C02XYZ.devices.mdm.example.org", keyA, challenge); code != 404 {
		t.Fatal("a second name used the challenge")
	}
}

func TestChallengeExpiresAndSourceIsChecked(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	s, _, h := testService(t, Options{Now: func() time.Time { return now }, AllowedSources: []netip.Prefix{netip.MustParsePrefix("10.0.5.0/24")}})
	challenge, err := s.ForEnrollment(ctx, "C02ABC.devices.mdm.example.org", "devices.mdm.example.org", "")
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := ask(h, secret, "192.0.2.9:4000", "C02ABC.devices.mdm.example.org", keyA, challenge); code != 404 {
		t.Fatal("a lookup from another address was answered")
	}
	// The serial was fixed by the grant, so no other device's name fits.
	if code, _ := ask(h, secret, "10.0.5.7:4000", "C02XYZ.devices.mdm.example.org", keyA, challenge); code != 404 {
		t.Fatal("another serial used a challenge made for one device")
	}
	now = now.Add(25 * time.Hour)
	if code, _ := ask(h, secret, "10.0.5.7:4000", "C02ABC.devices.mdm.example.org", keyA, challenge); code != 404 {
		t.Fatal("an expired challenge was accepted")
	}
}

func TestRenewedKeyIsTheOneThatUsedTheChallenge(t *testing.T) {
	ctx := context.Background()
	s, _, h := testService(t, Options{})
	started := time.Now().Add(-time.Minute)
	challenge, err := s.ForRenewal(ctx, "DEVICE1", "C02ABC.devices.mdm.example.org")
	if err != nil {
		t.Fatal(err)
	}
	mine, theirs := testCert(t), testCert(t)
	id, err := KeyID(mine)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RenewedKey(ctx, "DEVICE1", mine, started); err == nil {
		t.Fatal("a key was accepted before any challenge was used")
	}
	if code, _ := ask(h, secret, "", "C02XYZ.devices.mdm.example.org", id, challenge); code != 404 {
		t.Fatal("a renewal challenge was used for another name")
	}
	if code, _ := ask(h, secret, "", "C02ABC.devices.mdm.example.org", id, challenge); code != 200 {
		t.Fatalf("renewal lookup = %d", code)
	}
	if err = s.RenewedKey(ctx, "DEVICE1", mine, started); err != nil {
		t.Fatalf("the device's own key: %v", err)
	}
	if err = s.RenewedKey(ctx, "DEVICE1", theirs, started); err == nil {
		t.Fatal("a certificate for another key was accepted as the renewal")
	}
	if err = s.RenewedKey(ctx, "DEVICE2", mine, started); err == nil {
		t.Fatal("the key was accepted for another device")
	}
}

func TestSpentChallengeStopsAnsweringWhenItExpiresOrIsClosed(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	s, db, h := testService(t, Options{Now: func() time.Time { return now }})
	started := now.Add(-time.Minute)
	const name = "C02ABC.devices.mdm.example.org"
	mine := testCert(t)
	id, err := KeyID(mine)
	if err != nil {
		t.Fatal(err)
	}
	use := func() (string, int) {
		t.Helper()
		challenge, err := s.ForRenewal(ctx, "DEVICE1", name)
		if err != nil {
			t.Fatal(err)
		}
		if code, _ := ask(h, secret, "", name, id, challenge); code != 200 {
			t.Fatalf("first lookup = %d", code)
		}
		code, _ := ask(h, secret, "", name, id, challenge)
		return challenge, code
	}

	expiring, code := use()
	if code != 200 {
		t.Fatal("the CA could not evaluate a pending request a second time")
	}
	now = now.Add(8 * 24 * time.Hour)
	if code, _ = ask(h, secret, "", name, id, expiring); code != 404 {
		t.Fatal("a spent challenge was accepted after it expired")
	}

	closing, _ := use()
	unused, err := s.ForRenewal(ctx, "DEVICE1", name)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CloseSCEPChallenges(ctx, "DEVICE1"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{closing, unused} {
		if code, _ = ask(h, secret, "", name, id, c); code != 404 {
			t.Fatal("a closed challenge was accepted")
		}
	}
	// Closing does not erase which key the renewal's certificate went to.
	if err = s.RenewedKey(ctx, "DEVICE1", mine, started); err != nil {
		t.Fatalf("the record of the renewed key was lost: %v", err)
	}
}

func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "C02ABC.devices.mdm.example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// TestKeyIDMatchesACertificateFile compares KeyID with the identifier a CA
// recorded for a real certificate. Set CAIRN_KEYID_CERT to a file holding the
// identifier, a tab, and the PEM certificate; the test is skipped without it.
func TestKeyIDMatchesACertificateFile(t *testing.T) {
	path := os.Getenv("CAIRN_KEYID_CERT")
	if path == "" {
		t.Skip("CAIRN_KEYID_CERT not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, pemText, _ := strings.Cut(string(raw), "\t")
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		t.Fatal("no certificate in the file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := KeyID(cert)
	if err != nil || got != normalizeKeyID(want) {
		t.Fatalf("KeyID = %s, CA recorded %s (%v)", got, normalizeKeyID(want), err)
	}
}
