package issue

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	scep "github.com/smallstep/scep"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// IssuanceStore is the cert_issuance state machine the Broker drives. It is
// satisfied by *sqlite.DB.
type IssuanceStore interface {
	BeginIssuance(ctx context.Context, grantID int64, txnID, spki, requestHash string) (sqlite.Issuance, bool, error)
	CompleteIssuance(ctx context.Context, grantID int64, txnID, spki, requestHash, certSerial string, leafDER []byte) error
	FailIssuance(ctx context.Context, grantID int64, txnID, spki, requestHash, reason string) error
	QuarantineIssuance(ctx context.Context, grantID int64, txnID, spki, requestHash, reason, backend, backendTxn string) error
}

// GrantResolver maps a presented SCEP challenge to the authoritative facts of the
// grant it authorizes, WITHOUT consuming the grant. Proof-of-possession is provided
// by the SCEP envelope; single-use is enforced downstream by the cert_issuance
// UNIQUE(grant_id) claim, so lookup here must not spend the grant.
type GrantResolver interface {
	LookupForIssuance(ctx context.Context, challenge string) (GrantFacts, error)
}

// Broker sits between the SCEP transport and a CABackend. It reconstructs the
// certificate from policy+grant, drives the cert_issuance state machine, and
// delegates signing — failing closed (quarantine) on any ambiguity. It implements
// scepserver.CSRSignerContext.
type Broker struct {
	backend  CABackend
	store    IssuanceStore
	grants   GrantResolver
	policy   Policy
	now      func() time.Time
	issuer   *x509.Certificate // CA that signs our identities; nil disables renewal detection
	renewals RenewalObserver   // may be nil
}

// NewBroker constructs a Broker.
func NewBroker(backend CABackend, store IssuanceStore, grants GrantResolver, policy Policy) *Broker {
	return &Broker{backend: backend, store: store, grants: grants, policy: policy, now: time.Now}
}

// ErrIssuancePending is returned while an attempt is in flight (SCEP retry) or
// ambiguous; the SCEP transport maps a non-nil error to a CertRep FAILURE, so a
// client sees "not yet" and retries, matching the idempotent recovery model.
var ErrIssuancePending = errors.New("issue: issuance pending or unresolved")

// SignCSRContext implements scepserver.CSRSignerContext.
func (b *Broker) SignCSRContext(ctx context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
	if m == nil || m.CSR == nil || m.CSR.PublicKey == nil {
		return nil, errors.New("issue: nil CSR/public key")
	}
	// 0. A request signed with an identity this CA issued is a renewal attempt.
	//    Renewal is a reviewed lifecycle this release does not implement; refuse
	//    before any grant is consulted and record the attempt for the operator.
	if signer := SignerFromContext(ctx); signer != nil && b.issuer != nil && signer.CheckSignatureFrom(b.issuer) == nil {
		if b.renewals != nil {
			_, spki, _ := Identity(m.CSR.PublicKey)
			sum := sha256.Sum256(signer.Raw)
			_ = b.renewals.RecordRenewalAttempt(ctx, RenewalAttempt{
				SPKISHA256: spki, SignerSerial: signer.SerialNumber.Text(16), SignerSHA256: hex.EncodeToString(sum[:]),
				SignerSubject: signer.Subject.String(), SignerExpires: signer.NotAfter.UTC().Format(time.RFC3339),
				Reason: "renewal not implemented",
			})
		}
		return nil, ErrRenewalUnsupported
	}
	// 1. Resolve the grant from the challenge (LOOKUP, not consume). The only trusted
	//    device input is the public key + proof-of-possession (the SCEP envelope).
	g, err := b.grants.LookupForIssuance(ctx, m.ChallengePassword)
	if err != nil {
		return nil, fmt.Errorf("issue: grant lookup: %w", err) // fail-closed
	}
	// 2. Derive the stable identity, reconstruct the intent, compute the request hash.
	pub := m.CSR.PublicKey
	txnID, spki, err := Identity(pub)
	if err != nil {
		return nil, err
	}
	tmpl, err := Reconstruct(b.policy, g, pub, b.now())
	if err != nil {
		return nil, err
	}
	reqHash := RequestHash(tmpl, g.GrantID)

	// 3. Atomic claim on the grant (single-use at issuance; idempotent under retry).
	iss, idem, err := b.store.BeginIssuance(ctx, g.GrantID, txnID, spki, reqHash)
	if err != nil {
		// ErrIssuanceConflict (grant already bound to a different request) or
		// ErrGrantInvalid — both fail-closed.
		return nil, fmt.Errorf("issue: begin: %w", err)
	}
	if idem {
		switch iss.State {
		case sqlite.IssuanceIssued:
			return x509.ParseCertificate(iss.LeafDER) // cached leaf — retry-safe
		case sqlite.IssuanceIssuing:
			return nil, ErrIssuancePending
		default: // FAILED or QUARANTINED — terminal, never reissue
			return nil, fmt.Errorf("issue: attempt is terminal (%s)", iss.State)
		}
	}

	// Recheck immediately before delegating signing. A directory failure or owner
	// change before signing is a clean rejection; no backend has run yet.
	fresh, err := b.grants.LookupForIssuance(ctx, m.ChallengePassword)
	if err != nil || fresh != g {
		if e := b.store.FailIssuance(ctx, g.GrantID, txnID, spki, reqHash, "authorization changed before signing"); e != nil {
			return nil, e
		}
		return nil, errors.New("issue: current owner authorization unavailable")
	}
	// 4. Fresh ISSUING binding → delegate the sign to the backend.
	name := b.backend.Capabilities().Name
	res, err := b.backend.Issue(ctx, IssueRequest{
		TxnID: txnID, SPKISHA256: spki, PublicKey: pub, DeviceCSR: m.CSR,
		Template: tmpl, GrantID: g.GrantID, RequestHash: reqHash,
	})
	if err != nil {
		// A transport/unknown error is AMBIGUOUS: the CA may have signed. Quarantine
		// (never FAILED, never retried as fresh).
		_ = b.store.QuarantineIssuance(ctx, g.GrantID, txnID, spki, reqHash, "backend-error: "+err.Error(), name, txnID)
		return nil, fmt.Errorf("issue: backend error (quarantined): %w", err)
	}

	switch res.Status {
	case StatusIssued:
		if res.Leaf == nil || res.Serial == "" {
			_ = b.store.QuarantineIssuance(ctx, g.GrantID, txnID, spki, reqHash, "issued-without-leaf", name, txnID)
			return nil, errors.New("issue: backend reported ISSUED without leaf/serial (quarantined)")
		}
		// Post-verify the returned leaf equals the reconstructed intent unless the
		// backend guarantees it. Mismatch ⇒ quarantine (a backend that honored the CSR).
		if !b.backend.Capabilities().VerifiesReconstruction {
			if err := verifyLeafMatchesIntent(res.Leaf, tmpl, spki, b.policy, b.now()); err != nil {
				_ = b.store.QuarantineIssuance(ctx, g.GrantID, txnID, spki, reqHash, "leaf-mismatch: "+err.Error(), name, txnID)
				return nil, fmt.Errorf("issue: returned leaf != intent (quarantined): %w", err)
			}
		}
		// A completed sign followed by lost eligibility is ambiguous authority:
		// retain the issued outcome under quarantine, never release it as success.
		fresh, authErr := b.grants.LookupForIssuance(ctx, m.ChallengePassword)
		if authErr != nil || fresh != g {
			_ = b.store.QuarantineIssuance(ctx, g.GrantID, txnID, spki, reqHash, "authorization changed after signing", name, res.Serial)
			return nil, errors.New("issue: authorization changed after signing (quarantined)")
		}
		if err := b.store.CompleteIssuance(ctx, g.GrantID, txnID, spki, reqHash, res.Serial, res.Leaf.Raw); err != nil {
			return nil, err
		}
		return res.Leaf, nil
	case StatusFailedClean:
		_ = b.store.FailIssuance(ctx, g.GrantID, txnID, spki, reqHash, "backend definitive reject")
		return nil, errors.New("issue: backend definitively rejected")
	case StatusPending, StatusAmbiguous:
		_ = b.store.QuarantineIssuance(ctx, g.GrantID, txnID, spki, reqHash, "backend "+statusName(res.Status), name, res.Serial)
		return nil, ErrIssuancePending
	default:
		_ = b.store.QuarantineIssuance(ctx, g.GrantID, txnID, spki, reqHash, "backend unknown status", name, "")
		return nil, ErrIssuancePending
	}
}

func statusName(s IssueStatus) string {
	switch s {
	case StatusIssued:
		return "issued"
	case StatusPending:
		return "pending"
	case StatusFailedClean:
		return "failed-clean"
	case StatusAmbiguous:
		return "ambiguous"
	default:
		return "unknown"
	}
}

// verifyLeafMatchesIntent lives in verify.go.
