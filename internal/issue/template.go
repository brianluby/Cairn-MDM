package issue

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"time"

	"github.com/micromdm/scep/v2/cryptoutil"
)

// Reconstruct builds the authoritative certificate template from server Policy +
// verified GrantFacts + the device public key. This is the load-bearing security
// rule ("reconstruct, don't validate"): the subject, SANs, EKU, key usage, validity,
// and extensions are ALL constructed here — never copied from, or merely compared
// against, the CSR. The only device-derived input is the public key (proof-of-
// possession is verified by the SCEP envelope). The backend signs THIS template.
//
// A USER certificate carries exactly one canonical rfc822Name (the owner); a
// user-less DEVICE certificate carries none. Either way the device's requested
// subject/SANs/extensions are discarded. The certificate is clientAuth-only,
// CA:FALSE, short-lived.
//
// SerialNumber is intentionally left nil — the CA backend assigns the serial as part
// of signing (an authority decision, not a template input).
func Reconstruct(pol Policy, g GrantFacts, pub crypto.PublicKey, now time.Time) (*x509.Certificate, error) {
	if pub == nil {
		return nil, errors.New("issue: reconstruct requires a public key")
	}
	if g.CommonName == "" && g.Owner == "" {
		return nil, errors.New("issue: reconstruct requires a server-chosen CommonName or Owner")
	}
	skid, err := cryptoutil.GenerateSubjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	cn := g.CommonName
	if cn == "" {
		cn = g.Owner
	}
	tmpl := &x509.Certificate{
		Subject:   pkix.Name{CommonName: cn},
		NotBefore: now.Add(-pol.Backdate),
		NotAfter:  now.Add(pol.LeafValidity),
		// digitalSignature is the correct, sufficient usage for TLS/EAP-TLS client
		// authentication (the handshake signs with the key). keyEncipherment is only
		// for deprecated RSA key-transport and is meaningless for EC keys, so it is
		// omitted.
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          skid,
	}
	// Owner is the ONLY SAN, and only for a user certificate. A user-less device
	// certificate carries no SAN. The CSR's SANs are never consulted.
	if g.Owner != "" {
		tmpl.EmailAddresses = []string{g.Owner}
	}
	// CRL distribution point, so a relying party can fetch revocation (policy, not CSR).
	if pol.CRLDistributionPoint != "" {
		tmpl.CRLDistributionPoints = []string{pol.CRLDistributionPoint}
	}
	return tmpl, nil
}
