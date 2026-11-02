package push

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestAppleVerifierRequiresTrustedChainAndMDMUsage(t *testing.T) {
	now := time.Now()
	key := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	rkey, ikey, lkey := key(), key(), key()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)}
	sign := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, k *ecdsa.PrivateKey) []byte {
		b, e := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, k)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	rder := sign(root, root, &rkey.PublicKey, rkey)
	root, _ = x509.ParseCertificate(rder)
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic issuer"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(36 * time.Hour)}
	ider := sign(issuer, root, &ikey.PublicKey, rkey)
	issuer, _ = x509.ParseCertificate(ider)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "synthetic MDM", ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "com.apple.mgmt.External.synthetic"}}}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 3, 2}, Value: []byte{5, 0}}}}
	kder, _ := x509.MarshalPKCS8PrivateKey(lkey)
	kpem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	encode := func() []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sign(leaf, issuer, &lkey.PublicKey, ikey)})
	}
	cpem := encode()
	if _, err := VerifyAppleCertificate(cpem, kpem, now); err == nil {
		t.Fatal("synthetic issuer trusted by production Apple bundle")
	}
	oldRoot, oldIssuer := appleRootDER, appleAAI2DER
	appleRootDER, appleAAI2DER = rder, ider
	t.Cleanup(func() { appleRootDER, appleAAI2DER = oldRoot, oldIssuer })
	if _, err := VerifyAppleCertificate(cpem, kpem, now); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAppleCertificate(cpem, kpem, leaf.NotAfter); err == nil {
		t.Fatal("accepted at expiry boundary")
	}
	if _, err := VerifyAppleCertificate(cpem, kpem, leaf.NotBefore.Add(-time.Second)); err == nil {
		t.Fatal("accepted before validity")
	}
	leaf.ExtraExtensions = nil
	if _, err := VerifyAppleCertificate(encode(), kpem, now); err == nil {
		t.Fatal("missing MDM usage accepted")
	}
}
