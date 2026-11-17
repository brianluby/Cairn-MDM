package issue

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// Identity derives the stable per-attempt identifiers from the device public key.
// txnID matches the SCEP transaction id derivation (base64 of the SHA-256 subject
// key id), so an idempotent SCEP retry maps to the same attempt with no extra
// plumbing; spkiSHA256 is the hex SHA-256 of the SubjectPublicKeyInfo.
func Identity(pub crypto.PublicKey) (txnID, spkiSHA256 string, err error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(der)
	// The SCEP transaction id in smallstep/scep is the base64 of the public key's
	// SHA-256 subject key id, which is sha256(SPKI). Deriving it the same way keeps
	// our idempotency key aligned with the transport's transaction id.
	return base64.StdEncoding.EncodeToString(sum[:]), fmt.Sprintf("%x", sum), nil
}

// RequestHash is a domain-separated hash over the RECONSTRUCTED template's STABLE,
// security-relevant fields plus the grant id. It must be stable across SCEP retries
// (which reconstruct with a different NotBefore/NotAfter), so time-varying validity
// bounds are deliberately EXCLUDED — only the fields fixed by policy+grant+key are
// hashed. The same grant + same key + same policy yields the same hash (safe retry);
// a different reconstructed intent yields a different hash. The raw CSR is never
// hashed.
func RequestHash(tmpl *x509.Certificate, grantID int64) string {
	h := sha256.New()
	h.Write([]byte("cairn-issue-reqhash-v1\x00"))
	var gid [8]byte
	binary.BigEndian.PutUint64(gid[:], uint64(grantID))
	h.Write(gid[:])
	h.Write([]byte(tmpl.Subject.CommonName))
	h.Write([]byte{0})
	for _, e := range tmpl.EmailAddresses {
		h.Write([]byte(e))
		h.Write([]byte{0})
	}
	h.Write(tmpl.SubjectKeyId)
	return fmt.Sprintf("%x", h.Sum(nil))
}
