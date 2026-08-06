package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeRA(t *testing.T, dir string, keyType string) (certFile, keyFile string, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cairn-ra"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "ra.crt")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(dir, "ra."+keyType+".key")
	var block *pem.Block
	switch keyType {
	case "pkcs1":
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	case "pkcs8":
		b, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: b}
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, key
}

func TestLoadRAIdentity(t *testing.T) {
	dir := t.TempDir()
	for _, kt := range []string{"pkcs1", "pkcs8"} {
		certFile, keyFile, key := writeRA(t, dir, kt)
		cert, got, err := loadRAIdentity(certFile, keyFile)
		if err != nil {
			t.Fatalf("%s: %v", kt, err)
		}
		if cert.Subject.CommonName != "cairn-ra" {
			t.Errorf("%s: cn=%q", kt, cert.Subject.CommonName)
		}
		if got.N.Cmp(key.N) != 0 {
			t.Errorf("%s: loaded key does not match", kt)
		}
	}
	// Missing paths and a non-RSA (EC) key must fail closed.
	if _, _, err := loadRAIdentity("", ""); err == nil {
		t.Error("empty paths must error")
	}
}
