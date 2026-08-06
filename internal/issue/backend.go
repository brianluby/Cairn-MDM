// Package issue is Cairn's enrollment-authorization core: the Broker that sits
// between the SCEP transport and a certificate-authority backend. It reconstructs
// the certificate from server policy + the grant (never trusting the CSR beyond its
// public key and proof-of-possession), drives the cert_issuance state machine, and
// delegates the cryptographic signing to a CABackend. Embedded and external CA
// backends plug in below the reconstruction layer, so reconstruction and the state
// machine protect both by construction.
//
// See docs/enrollment-authorization.md for the design and the CA-backend capability
// model (§19 of the private protocol spec).
package issue

import (
	"context"
	"crypto"
	"crypto/x509"
)

// Capability describes what guarantees a CABackend provides. The Broker reads it
// and fails closed (quarantines) when a needed capability is absent — it never
// weakens the protocol to accommodate a weaker backend.
type Capability struct {
	// Name identifies the backend for logs/audit, e.g. "embedded" | "external-scep".
	Name string
	// AtomicIssue is true when signed/not-signed is a single local atomic fact
	// (Cairn is the signer). Such a backend never returns StatusPending/Ambiguous.
	AtomicIssue bool
	// CanReconcile is true when the backend can re-derive an attempt's outcome by
	// transaction id (used to resolve an ambiguous/in-flight attempt).
	CanReconcile bool
	// CanPoll is true when the backend understands a PENDING/poll flow (e.g. SCEP
	// GetCert).
	CanPoll bool
	// CanRevoke is true when the backend can revoke by serial.
	CanRevoke bool
	// VerifiesReconstruction is true when the backend guarantees the returned leaf
	// equals the reconstructed intent (so the Broker's post-verify is redundant).
	// When false the Broker MUST verify and quarantine on mismatch.
	VerifiesReconstruction bool
}

// RevokeReason is an RFC 5280 CRLReason code passed to CABackend.Revoke.
type RevokeReason int

const (
	// RevokeUnspecified: no stated reason (CRLReason 0).
	RevokeUnspecified RevokeReason = 0
	// RevokeKeyCompromise: the leaf's private key is (suspected) compromised
	// (CRLReason 1).
	RevokeKeyCompromise RevokeReason = 1
	// RevokeSuperseded: the certificate has been replaced (CRLReason 4).
	RevokeSuperseded RevokeReason = 4
)

// IssueStatus is the outcome class of a backend Issue/Reconcile call.
type IssueStatus int

const (
	// StatusIssued: a certificate was signed; Leaf/Serial are set.
	StatusIssued IssueStatus = iota
	// StatusPending: the authority accepted the request but has not signed
	// (SCEP PENDING). The Broker quarantines (fail-closed) unless it can resolve.
	StatusPending
	// StatusFailedClean: the authority definitively did NOT sign (proven). Safe to
	// mark FAILED (a fresh grant may retry).
	StatusFailedClean
	// StatusAmbiguous: the outcome is unknown (a response lost after the CA may have
	// signed). The Broker quarantines and never retries as a fresh issuance.
	StatusAmbiguous
)

// IssueRequest is what the Broker hands a backend. The only device-derived inputs
// the backend may trust for CONTENT are absent: it signs the reconstructed Template.
// DeviceCSR is relayed only so an external CA can re-verify proof-of-possession; its
// subject/SAN/extensions are never used.
type IssueRequest struct {
	TxnID       string           // stable per attempt (deterministic from the public key)
	SPKISHA256  string           // sha256 of the SubjectPublicKeyInfo
	PublicKey   crypto.PublicKey // the only trusted CSR-derived input (+ PoP)
	DeviceCSR   *x509.CertificateRequest
	Template    *x509.Certificate // the reconstructed intent; the backend signs THIS
	GrantID     int64
	RequestHash string
}

// IssueResult is a backend's outcome.
type IssueResult struct {
	Status IssueStatus
	Leaf   *x509.Certificate
	Chain  []*x509.Certificate
	Serial string
}

// CABackend is the certificate-authority capability interface. Backends provide the
// required capabilities to differing degrees; the Broker fails closed where a
// capability is missing.
type CABackend interface {
	// Capabilities returns the backend's declared capability level.
	Capabilities() Capability
	// Issue signs the reconstructed Template (never the CSR's fields) for the given
	// public key, returning the outcome class. An embedded backend returns only
	// StatusIssued/StatusFailedClean; an external one may also return
	// StatusPending/StatusAmbiguous.
	Issue(ctx context.Context, req IssueRequest) (IssueResult, error)
	// Reconcile re-derives the outcome of an attempt by transaction id (idempotent),
	// used to resolve an in-flight/ambiguous attempt. Only meaningful when
	// Capabilities().CanReconcile; otherwise it may return StatusAmbiguous.
	Reconcile(ctx context.Context, txnID, spkiSHA256 string) (IssueResult, error)
	// Revoke marks the certificate with the given serial (lowercase hex) revoked
	// for the given RFC 5280 reason. Only meaningful when Capabilities().CanRevoke;
	// otherwise it returns an error.
	Revoke(ctx context.Context, serial string, reason RevokeReason) error
}
