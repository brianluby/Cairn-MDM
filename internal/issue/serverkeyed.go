package issue

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"
)

// Server-keyed issuance is for credentials whose client cannot generate or hold
// a key in the system keychain (OpenVPN Connect on iOS): Cairn makes the key,
// has the backend certify it, and hands both to the device inside a profile.
// The certificate content is still reconstructed from policy and verified
// directory facts; nothing about the subject comes from outside the server.

// Key types for server-generated keys.
const (
	KeyRSA2048 = "rsa2048"
	KeyP256    = "p256"
)

// NewServerKey generates a private key of the given type.
func NewServerKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case "", KeyRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return nil, fmt.Errorf("issue: unknown key type %q", keyType)
}

// ServerKeyedRequest builds the request for a backend to certify key for the
// identity in facts. The CSR repeats the reconstructed subject and SAN so a
// relaying backend (an external CA that reads the CSR) is asked for exactly the
// intent; VerifyLeaf then checks what came back.
func ServerKeyedRequest(pol Policy, facts GrantFacts, key crypto.Signer, now time.Time) (IssueRequest, error) {
	if facts.CommonName == "" {
		return IssueRequest{}, errors.New("issue: server-keyed issuance requires a common name")
	}
	pub := key.Public()
	txnID, spki, err := Identity(pub)
	if err != nil {
		return IssueRequest{}, err
	}
	tmpl, err := Reconstruct(pol, facts, pub, now)
	if err != nil {
		return IssueRequest{}, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: tmpl.Subject.CommonName},
		EmailAddresses: tmpl.EmailAddresses,
	}, key)
	if err != nil {
		return IssueRequest{}, fmt.Errorf("issue: build CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return IssueRequest{}, err
	}
	return IssueRequest{
		TxnID: txnID, SPKISHA256: spki, PublicKey: pub, DeviceCSR: csr,
		Template: tmpl, RequestHash: RequestHash(tmpl, 0),
	}, nil
}

// VerifyLeaf checks that a certificate a backend returned carries exactly the
// requested identity for the requested key. A mismatch means the backend issued
// something other than the intent and the caller must quarantine the attempt.
func VerifyLeaf(leaf *x509.Certificate, req IssueRequest, pol Policy, now time.Time) error {
	if leaf == nil || req.Template == nil {
		return errors.New("issue: verify needs a leaf and the request it answers")
	}
	return verifyLeafMatchesIntent(leaf, req.Template, req.SPKISHA256, pol, now)
}
