package issue

import "time"

// Policy holds the server-side issuance rules. Every certificate field except the
// public key is built from Policy + the grant — never copied from the CSR.
type Policy struct {
	// LeafValidity is the issued certificate lifetime. Start conservative
	// (e.g. ~60 days) and tighten only after a renewal soak.
	LeafValidity time.Duration
	// Backdate shifts NotBefore into the past to tolerate clock skew.
	Backdate time.Duration
	// MaxLeafValidity, when > 0, is the ceiling the returned-leaf verifier enforces on
	// the certificate's validity span. It exists for the broker lane: the backend CA
	// sets the actual validity, and a longer-than-our-own lifetime is a policy
	// preference, not a security escalation — so the operator can accept up to this
	// ceiling without per-deployment backend-profile tuning. When 0 (embedded mode, or
	// unset) the verifier falls back to LeafValidity+Backdate+1h, since Cairn sets the
	// validity itself. It never relaxes the anti-escalation checks (public-key binding,
	// identity, IsCA, exact EKU/KeyUsage, no unexpected critical extensions) or the
	// expired / not-yet-valid checks.
	MaxLeafValidity time.Duration
	// CRLDistributionPoint, when set, is written into each leaf's CRL distribution
	// points so relying parties (RADIUS) know where to fetch revocation. Empty omits
	// the extension.
	CRLDistributionPoint string
}

// GrantFacts are the authoritative, server-verified facts about the grant being
// redeemed for issuance. They come from the grant record (created by an authenticated
// authority), never from the device.
type GrantFacts struct {
	GrantID int64
	// Owner is the canonical directory identity bound to a USER certificate (a
	// single rfc822Name / UPN). Empty for a user-less DEVICE certificate.
	Owner string
	// CommonName is the subject CN the server intends for this certificate. For a
	// per-device certificate this is the device-scoped name the grant was minted
	// with; it is server-chosen, not device-asserted.
	CommonName string
	// Platform is informational (macos/ios).
	Platform string
}

// DefaultPolicy returns a conservative default policy.
func DefaultPolicy() Policy {
	return Policy{LeafValidity: 60 * 24 * time.Hour, Backdate: 5 * time.Minute}
}
