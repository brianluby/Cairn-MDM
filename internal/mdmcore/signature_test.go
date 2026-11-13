package mdmcore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

// A check-in signed with an expired device certificate is refused, and the
// observer is told about the device's certificate, not the CA that travels
// with it in the signature.
func TestRefusedSignatureReportsTheDeviceCertificate(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore: time.Now().Add(-400 * 24 * time.Hour), NotAfter: time.Now().Add(400 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	sign := func(notAfter time.Time) (header string, body []byte, leaf *x509.Certificate) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "DEVICE-UDID"},
			NotBefore: notAfter.Add(-100 * 24 * time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ = x509.ParseCertificate(der)
		body = []byte("<plist>check-in</plist>")
		sd, err := pkcs7.NewSignedData(body)
		if err != nil {
			t.Fatal(err)
		}
		if err = sd.AddSignerChain(leaf, key, []*x509.Certificate{caCert}, pkcs7.SignerInfoConfig{}); err != nil {
			t.Fatal(err)
		}
		sd.Detach()
		raw, err := sd.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw), body, leaf
	}
	type seen struct {
		cert     *x509.Certificate
		accepted bool
	}
	var got []seen
	verify := signatureVerifier(nil, func(c *x509.Certificate, ok bool) { got = append(got, seen{c, ok}) })

	header, body, expired := sign(time.Now().Add(-24 * time.Hour))
	if _, err := verify(header, body); err == nil {
		t.Fatal("a signature from an expired certificate was accepted")
	}
	header, body, valid := sign(time.Now().Add(24 * time.Hour))
	if _, err := verify(header, body); err != nil {
		t.Fatalf("valid signature refused: %v", err)
	}
	if len(got) != 2 || got[0].accepted || !got[0].cert.Equal(expired) || !got[1].accepted || !got[1].cert.Equal(valid) {
		t.Fatalf("observer saw %d certificates; want the expired device certificate refused, then the valid one accepted", len(got))
	}
}
