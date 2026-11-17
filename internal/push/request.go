package push

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/smallstep/pkcs7"
	"io"
	"math/big"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultRequestURL = "https://mdmcert.download/api/v1/signrequest"

// Published vendor-service client key, not an operator credential.
const VendorAPIKey = "f847aea2ba06b41264d587b229e2712c89b1490a1208b7ff1aafab5bb40d47bc"

type Request struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
	RenewTopic   string    `json:"renew_topic,omitempty"`
	AppleAccount string    `json:"apple_account,omitempty"`
}

type RequestManager struct {
	Root   string
	URL    string
	Client *http.Client
}

func (m RequestManager) Directory(id string) (string, error) {
	b, err := hex.DecodeString(id)
	if err != nil || len(b) != 16 {
		return "", errors.New("invalid request ID")
	}
	return filepath.Join(m.Root, id), nil
}

// Create persists new keys before any network request. Each attempt gets its own
// directory; an old request is never overwritten or implicitly selected.
func (m RequestManager) Create(email, country, cn string) (Request, error) {
	return m.CreateForTopic(email, country, cn, "", "")
}

func (m RequestManager) CreateForTopic(email, country, cn, topic, appleAccount string) (Request, error) {
	var r Request
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email {
		return r, errors.New("a registered email address is required")
	}
	if cn == "" {
		cn = "mdm-push." + strings.SplitN(email, "@", 2)[1]
	}
	if err := os.MkdirAll(m.Root, 0700); err != nil {
		return r, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return r, err
	}
	r = Request{ID: hex.EncodeToString(id[:]), Email: email, CreatedAt: time.Now().UTC(), RenewTopic: topic, AppleAccount: appleAccount}
	dir, _ := m.Directory(r.ID)
	if err := os.Mkdir(dir, 0700); err != nil {
		return r, err
	}
	key, csr, err := newPushCSR(cn, country, email)
	if err != nil {
		return r, err
	}
	encKey, encCert, err := newEncryptionCert(cn + " (mdmcert decrypt)")
	if err != nil {
		return r, err
	}
	if err = writeKeyPEM(filepath.Join(dir, "push.key"), key); err != nil {
		return r, err
	}
	if err = writeKeyPEM(filepath.Join(dir, "encrypt.key"), encKey); err != nil {
		return r, err
	}
	for name, data := range map[string][]byte{"push.csr": csr, "encrypt.crt": encCert} {
		if err = writeExclusive(filepath.Join(dir, name), data, 0600); err != nil {
			return r, err
		}
	}
	data, _ := json.Marshal(r)
	err = writeExclusive(filepath.Join(dir, "request.json"), data, 0600)
	return r, err
}

// List exposes only request metadata. No private material leaves this service.
func (m RequestManager) List() ([]Request, error) {
	entries, err := os.ReadDir(m.Root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Request
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := m.Directory(e.Name()); err != nil {
			continue
		}
		r, err := m.Load(e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// SavePublicArtifact accepts only the two public artifacts used by the wizard.
// Exclusive creation prevents another browser tab replacing a reviewed upload.
func (m RequestManager) SavePublicArtifact(id, name string, data []byte) error {
	if name != "push_request.plist" && name != "certificate.pem" {
		return errors.New("unsupported artifact")
	}
	if _, err := m.Load(id); err != nil {
		return err
	}
	dir, _ := m.Directory(id)
	return writeExclusive(filepath.Join(dir, name), data, 0600)
}

func (m RequestManager) PublicArtifact(id, name string) ([]byte, error) {
	if name != "push_request.plist" && name != "certificate.pem" {
		return nil, errors.New("unsupported artifact")
	}
	if _, err := m.Load(id); err != nil {
		return nil, err
	}
	dir, _ := m.Directory(id)
	return os.ReadFile(filepath.Join(dir, name))
}

// Preview verifies Apple's certificate against the private key of THIS request.
func (m RequestManager) Preview(id string, cert []byte) (CertificateInfo, error) {
	r, err := m.Load(id)
	if err != nil {
		return CertificateInfo{}, err
	}
	dir, _ := m.Directory(id)
	key, err := os.ReadFile(filepath.Join(dir, "push.key"))
	if err != nil {
		return CertificateInfo{}, err
	}
	info, err := VerifyAppleCertificate(cert, key, time.Now())
	if err != nil {
		return info, err
	}
	if r.RenewTopic != "" && r.RenewTopic != info.Topic {
		return info, errors.New("certificate topic differs from the selected renewal; renew the existing Apple entry")
	}
	return info, nil
}

func (m RequestManager) Install(ctx context.Context, store CertificateStore, id, fingerprint, actor, provider string, makeDefault bool) (CertificateInfo, error) {
	r, err := m.Load(id)
	if err != nil {
		return CertificateInfo{}, err
	}
	cert, err := m.PublicArtifact(id, "certificate.pem")
	if err != nil {
		return CertificateInfo{}, err
	}
	info, err := m.Preview(id, cert)
	if err != nil {
		return info, err
	}
	if info.Fingerprint != fingerprint {
		return info, errors.New("certificate preview has changed; review it again")
	}
	dir, _ := m.Directory(id)
	key, err := os.ReadFile(filepath.Join(dir, "push.key"))
	if err != nil {
		return info, err
	}
	return InstallCertificate(ctx, store, cert, key, CertificateWriteOptions{RequestID: id, RenewTopic: r.RenewTopic, MakeDefault: makeDefault, Actor: actor, Provider: provider})
}

func (m RequestManager) Load(id string) (Request, error) {
	var r Request
	dir, err := m.Directory(id)
	if err != nil {
		return r, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(data, &r); err != nil {
		return r, err
	}
	if r.ID != id {
		return r, errors.New("request identity mismatch")
	}
	return r, nil
}

// Submit reuses persisted request material, including after a network timeout.
// It never retries automatically: a lost response may already have sent email.
func (m RequestManager) Submit(ctx context.Context, id string) error {
	r, err := m.Load(id)
	if err != nil {
		return err
	}
	dir, _ := m.Directory(id)
	csr, err := os.ReadFile(filepath.Join(dir, "push.csr"))
	if err != nil {
		return err
	}
	enc, err := os.ReadFile(filepath.Join(dir, "encrypt.crt"))
	if err != nil {
		return err
	}
	payload := map[string]string{"csr": base64.StdEncoding.EncodeToString(csr), "email": r.Email, "key": VendorAPIKey, "encrypt": base64.StdEncoding.EncodeToString(enc)}
	data, _ := json.Marshal(payload)
	url := m.URL
	if url == "" {
		url = DefaultRequestURL
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cairn/pushcert")
	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("submission outcome unknown; request %s is preserved, check email before resubmitting: %w", id, err)
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
	if err != nil {
		return fmt.Errorf("submission response incomplete; request %s preserved: %w", id, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vendor returned HTTP %d; request %s preserved (check registration before retrying)", resp.StatusCode, id)
	}
	return nil
}

func (m RequestManager) Decrypt(id string, attachment []byte) ([]byte, error) {
	if _, err := m.Load(id); err != nil {
		return nil, err
	}
	dir, _ := m.Directory(id)
	return DecryptRequestDirectory(dir, attachment)
}

// DecryptRequestDirectory also supports the old CLI's flat request directory.
// The payload may be a base64-encoded plist; return it unchanged for Apple.
func DecryptRequestDirectory(dir string, attachment []byte) ([]byte, error) {
	if len(attachment) > 1<<20 {
		return nil, errors.New("signed request attachment exceeds 1 MiB")
	}
	cert, key, err := loadEncryptionIdentity(dir)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(attachment)))
	if err != nil {
		return nil, fmt.Errorf("attachment is not hex encoded: %w", err)
	}
	p7, err := pkcs7.Parse(raw)
	if err != nil {
		return nil, err
	}
	content, err := p7.Decrypt(cert, key)
	if err != nil {
		return nil, errors.New("attachment does not match the selected request or is invalid")
	}
	return content, nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// newPushCSR generates the APNs keypair and a PEM CSR carrying the email.
func newPushCSR(commonName, country, email string) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
			Country:    []string{country},
		},
		EmailAddresses: []string{email},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// newEncryptionCert generates a short-lived self-signed cert used only so
// mdmcert.download can encrypt its reply to us.
func newEncryptionCert(commonName string) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 3, 0), // plenty for an email round-trip
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// loadEncryptionIdentity reads encrypt.crt/encrypt.key written by request.
func loadEncryptionIdentity(dir string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "encrypt.crt"))
	if err != nil {
		return nil, nil, fmt.Errorf("read encryption cert (run 'pushcert request' first): %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "encrypt.key"))
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, fmt.Errorf("encrypt.crt is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("encrypt.key is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		if k8, err8 := x509.ParsePKCS8PrivateKey(kb.Bytes); err8 == nil {
			if rk, ok := k8.(*rsa.PrivateKey); ok {
				return cert, rk, nil
			}
		}
		return nil, nil, err
	}
	return cert, key, nil
}

func writeKeyPEM(path string, key *rsa.PrivateKey) error {
	return writeExclusive(path,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
}
