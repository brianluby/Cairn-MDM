package issue

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

var (
	oidSAN              = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidEKU              = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidSubjectKeyId     = asn1.ObjectIdentifier{2, 5, 29, 14}
)

// verifyLeafMatchesIntent asserts the returned certificate carries EXACTLY the
// reconstructed identity and nothing more — the enforcement that keeps
// "reconstruct, don't validate" honest through a backend that does not itself
// guarantee it. It deliberately does NOT rely on Go's typed accessors (which
// silently drop otherName/directoryName/registeredID SANs and file unknown EKU
// OIDs under UnknownExtKeyUsage); it parses the raw SAN extension and checks the
// full EKU/KeyUsage/validity/public-key/critical-extension surface. A mismatch is a
// hostile or broken backend and the caller quarantines.
func verifyLeafMatchesIntent(leaf, tmpl *x509.Certificate, wantSPKISHA256 string, pol Policy, now time.Time) error {
	if leaf.Subject.CommonName != tmpl.Subject.CommonName {
		return fmt.Errorf("CN %q != intent %q", leaf.Subject.CommonName, tmpl.Subject.CommonName)
	}
	// The certified public key MUST be the one that proved possession.
	spkiDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("leaf public key: %w", err)
	}
	if sum := sha256.Sum256(spkiDER); fmt.Sprintf("%x", sum) != wantSPKISHA256 {
		return errors.New("leaf certifies a different public key than proved possession")
	}
	// SANs: parse the RAW extension. Only rfc822Name ([1]) entries are permitted and
	// the multiset must equal the intended owner set exactly. otherName ([0], e.g. an
	// AD UPN), directoryName ([4]), registeredID ([8]), etc. — which Go's typed
	// fields never surface — are rejected.
	emails, err := leafSANRfc822Only(leaf)
	if err != nil {
		return fmt.Errorf("SAN: %w", err)
	}
	if !equalStringSet(emails, tmpl.EmailAddresses) {
		return fmt.Errorf("SAN rfc822 set %v != intent %v", emails, tmpl.EmailAddresses)
	}
	if leaf.IsCA {
		return errors.New("leaf asserts CA:TRUE")
	}
	// EKU: exactly clientAuth, AND no unrecognized EKU OIDs (MS Smartcard Logon and
	// friends land in UnknownExtKeyUsage, not ExtKeyUsage).
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return fmt.Errorf("EKU %v != [clientAuth]", leaf.ExtKeyUsage)
	}
	if len(leaf.UnknownExtKeyUsage) != 0 {
		return fmt.Errorf("leaf carries unrecognized EKU OIDs %v", leaf.UnknownExtKeyUsage)
	}
	// KeyUsage must equal the reconstructed intent exactly.
	if leaf.KeyUsage != tmpl.KeyUsage {
		return fmt.Errorf("KeyUsage %d != intent %d", leaf.KeyUsage, tmpl.KeyUsage)
	}
	// Validity must not exceed the policy lifetime (a hostile or misconfigured backend
	// must not widen a short-lived intent into a long-lived credential). Embedded mode
	// sets the validity itself, so the ceiling is our own LeafValidity (+skew/tolerance).
	// Broker mode lets the backend CA set validity: MaxLeafValidity, when configured, is
	// the accepted ceiling — a longer-but-bounded backend lifetime is a policy choice,
	// not an escalation. The check stays a hard upper bound either way.
	maxSpan := pol.LeafValidity + pol.Backdate + time.Hour // small tolerance
	if pol.MaxLeafValidity > 0 {
		maxSpan = pol.MaxLeafValidity
	}
	if span := leaf.NotAfter.Sub(leaf.NotBefore); span > maxSpan {
		return fmt.Errorf("validity span %s exceeds policy max %s", span, maxSpan)
	}
	// The leaf must be currently valid: not already expired, and not starting further in
	// the future than our backdate tolerance (a backend clock far ahead is suspect).
	if !leaf.NotAfter.After(now) {
		return fmt.Errorf("leaf already expired (notAfter %s <= now %s)", leaf.NotAfter.UTC(), now.UTC())
	}
	if leaf.NotBefore.After(now.Add(pol.Backdate + time.Hour)) {
		return fmt.Errorf("leaf not yet valid (notBefore %s > now %s + tolerance)", leaf.NotBefore.UTC(), now.UTC())
	}
	// Reject unexpected CRITICAL extensions (certificate policies, name constraints,
	// MS cert templates, …). Only the reconstructed set may be critical.
	for _, e := range leaf.Extensions {
		if !e.Critical {
			continue
		}
		switch {
		case e.Id.Equal(oidBasicConstraints), e.Id.Equal(oidKeyUsage), e.Id.Equal(oidEKU),
			e.Id.Equal(oidSAN), e.Id.Equal(oidSubjectKeyId):
			// allowed
		default:
			return fmt.Errorf("unexpected critical extension %v", e.Id)
		}
	}
	return nil
}

// leafSANRfc822Only decodes the certificate's SAN extension and returns the
// rfc822Name values, erroring if ANY GeneralName is not an rfc822Name ([1]). A
// missing SAN extension is valid (a user-less device certificate) and yields nil.
func leafSANRfc822Only(leaf *x509.Certificate) ([]string, error) {
	var raw []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidSAN) {
			raw = e.Value
			break
		}
	}
	if raw == nil {
		return nil, nil
	}
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return nil, err
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, errors.New("SAN is not a SEQUENCE")
	}
	var emails []string
	rest := seq.Bytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &gn)
		if err != nil {
			return nil, err
		}
		if gn.Class != asn1.ClassContextSpecific {
			return nil, fmt.Errorf("unexpected SAN element (class %d, tag %d)", gn.Class, gn.Tag)
		}
		if gn.Tag != 1 { // rfc822Name = [1] IA5String
			return nil, fmt.Errorf("disallowed SAN GeneralName type [%d] (only rfc822Name permitted)", gn.Tag)
		}
		emails = append(emails, string(gn.Bytes))
	}
	return emails, nil
}

// equalStringSet reports multiset (order-independent) equality.
func equalStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
		if m[s] < 0 {
			return false
		}
	}
	return true
}
