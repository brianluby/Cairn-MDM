package push

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/smallstep/pkcs7"
)

// TestPushcertRequestDecryptRoundTrip drives request against a fake
// mdmcert.download, then simulates the emailed reply (a hex-encoded PKCS7
// envelope encrypted to the submitted cert) and decrypts it.
func TestPushcertRequestDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Fake mdmcert.download: validate the payload, capture the encryption cert.
	var gotReq struct{ CSR, Email, Key, Encrypt string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("bad request: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	m := RequestManager{Root: filepath.Join(dir, "requests"), URL: srv.URL}
	r, err := m.Create("mdm@example.org", "US", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Submit(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}

	// The service saw a well-formed request.
	if gotReq.Key != VendorAPIKey || gotReq.Email != "mdm@example.org" {
		t.Fatalf("service got %+v", gotReq)
	}
	csrPEM, err := base64.StdEncoding.DecodeString(gotReq.CSR)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(cb.Bytes)
	if err != nil {
		t.Fatalf("submitted CSR does not parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "mdm@example.org" {
		t.Errorf("CSR email = %v", csr.EmailAddresses)
	}

	// Artifacts on disk.
	pcDir, _ := m.Directory(r.ID)
	for _, f := range []string{"push.key", "push.csr", "encrypt.crt", "encrypt.key"} {
		if _, err := os.Stat(filepath.Join(pcDir, f)); err != nil {
			t.Errorf("missing artifact %s: %v", f, err)
		}
	}

	// Simulate the emailed reply: encrypt a payload to the submitted cert,
	// hex-encode it like the real service does.
	encCertPEM, err := base64.StdEncoding.DecodeString(gotReq.Encrypt)
	if err != nil {
		t.Fatal(err)
	}
	eb, _ := pem.Decode(encCertPEM)
	encCert, err := x509.ParseCertificate(eb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(base64.StdEncoding.EncodeToString([]byte("<plist>signed push request</plist>")))
	envelope, err := pkcs7.Encrypt(payload, []*x509.Certificate{encCert})
	if err != nil {
		t.Fatal(err)
	}
	p7Path := filepath.Join(dir, "mdm_signed_request.p7")
	if err := os.WriteFile(p7Path, []byte(hex.EncodeToString(envelope)), 0o600); err != nil {
		t.Fatal(err)
	}

	// Decrypt recovers the exact Apple-ready payload.
	out, err := m.Decrypt(r.ID, []byte(hex.EncodeToString(envelope)))
	if err != nil {
		t.Fatal(err)
	}

	if string(out) != string(payload) {
		t.Errorf("decrypted %q, want %q", out, payload)
	}
}
