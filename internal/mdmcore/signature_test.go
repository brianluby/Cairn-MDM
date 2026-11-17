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
	verify := signatureVerifier(nil, func(c *x509.Certificate, ok bool) { got = append(got, seen{c, ok}) }, 0, time.Now)

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

// testSigner signs check-in bodies with a certificate of the given validity.
// A Mac states no signing time in its signature; an iPhone does.
func testSigner(t *testing.T) func(notBefore, notAfter time.Time, signingTime bool) (header string, body []byte) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore: time.Now().Add(-800 * 24 * time.Hour), NotAfter: time.Now().Add(800 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	return func(notBefore, notAfter time.Time, signingTime bool) (string, []byte) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "DEVICE"},
			NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		body := []byte("<plist>check-in</plist>")
		sd, err := pkcs7.NewSignedData(body)
		if err != nil {
			t.Fatal(err)
		}
		if signingTime {
			err = sd.AddSigner(leaf, key, pkcs7.SignerInfoConfig{})
		} else {
			err = sd.SignWithoutAttr(leaf, key, pkcs7.SignerInfoConfig{})
		}
		if err != nil {
			t.Fatal(err)
		}
		sd.Detach()
		raw, err := sd.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw), body
	}
}

// Expiry is judged the same way for every device: by the server's clock, not
// by whether the device chose to state a signing time.
func TestExpiryRuleIsTheSameWithOrWithoutSigningTime(t *testing.T) {
	sign := testSigner(t)
	now := time.Now()
	day := 24 * time.Hour
	ignore := func(*x509.Certificate, bool) {}
	for _, withTime := range []bool{true, false} {
		expired, body := sign(now.Add(-100*day), now.Add(-10*day), withTime)
		if _, err := signatureVerifier(nil, ignore, 0, time.Now)(expired, body); err == nil {
			t.Errorf("signing time %v: expired certificate accepted with no grace", withTime)
		}
		if _, err := signatureVerifier(nil, ignore, 30*day, time.Now)(expired, body); err != nil {
			t.Errorf("signing time %v: certificate expired 10 days ago refused inside a 30-day grace: %v", withTime, err)
		}
		if _, err := signatureVerifier(nil, ignore, 5*day, time.Now)(expired, body); err == nil {
			t.Errorf("signing time %v: certificate expired 10 days ago accepted past a 5-day grace", withTime)
		}
		// Grace opens the date check only. The signature still has to be good.
		if _, err := signatureVerifier(nil, ignore, 30*day, time.Now)(expired, []byte("<plist>another body</plist>")); err == nil {
			t.Errorf("signing time %v: a signature over a different body was accepted", withTime)
		}
		future, body := sign(now.Add(day), now.Add(100*day), withTime)
		if _, err := signatureVerifier(nil, ignore, 30*day, time.Now)(future, body); err == nil {
			t.Errorf("signing time %v: a certificate that is not valid yet was accepted", withTime)
		}
		valid, body := sign(now.Add(-day), now.Add(day), withTime)
		if _, err := signatureVerifier(nil, ignore, 0, time.Now)(valid, body); err != nil {
			t.Errorf("signing time %v: valid certificate refused: %v", withTime, err)
		}
	}
}
