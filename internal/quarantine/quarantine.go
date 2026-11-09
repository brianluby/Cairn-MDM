// Package quarantine drives the evidence-gated release of a held certificate
// issuance: fence the signer, enumerate every certificate the lineage may have
// received, prove each one is rejected by every relying service, then release.
// Each step stores a manifest the backend or server produced; release
// re-validates manifest content, never row presence. There is no force release.
//
// The embedded CA is the only backend that can produce the fence and
// enumeration manifests today (it is Cairn's own atomic signer and records every
// signature). Holds from an external SCEP backend stay quarantined here until
// that backend offers verifiable primitives; the console says so.
package quarantine

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/ca"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// ErrBackendUnavailable means the backend behind the hold offers no verifiable
// primitive for the requested step; the hold stays.
var ErrBackendUnavailable = errors.New("quarantine: the certificate backend cannot produce this evidence; the hold remains")

// ErrEvidence means stored evidence failed content validation at release.
var ErrEvidence = errors.New("quarantine: stored evidence does not satisfy the release contract")

// Store is the persistence the service needs. *sqlite.DB satisfies it.
type Store interface {
	GetIssuance(ctx context.Context, grantID int64) (sqlite.Issuance, error)
	GetGrant(ctx context.Context, id int64) (sqlite.Grant, error)
	GetQuarantineResolution(ctx context.Context, grantID int64) (sqlite.QuarantineResolution, error)
	RecordFence(ctx context.Context, grantID int64, manifest, actor string) error
	RecordEnumeration(ctx context.Context, grantID int64, manifest, actor string) error
	RecordRejection(ctx context.Context, grantID int64, manifest, actor string) error
	RecordRelease(ctx context.Context, grantID int64, actor string) error
	RadiusRejectionsForSerial(ctx context.Context, serial string) ([]sqlite.RadiusRejection, error)
	RemoveCertAuthByHash(ctx context.Context, sha256Hex string) (int64, error)
}

// FenceManifest is the backend-produced proof that no signer can still complete
// the held attempt.
type FenceManifest struct {
	Backend        string `json:"backend"`
	CAFingerprint  string `json:"ca_fingerprint"`
	GrantID        int64  `json:"grant_id"`
	TxnID          string `json:"txn_id"`
	SPKISHA256     string `json:"spki_sha256"`
	BindingState   string `json:"binding_state"`
	AtomicSigner   bool   `json:"atomic_signer"`
	CheckedAt      string `json:"checked_at"`
	Justification  string `json:"justification"`
	ManifestFormat int    `json:"format"`
}

// EnumerationManifest is the complete list of certificates the lineage may hold.
type EnumerationManifest struct {
	Backend     string          `json:"backend"`
	SPKISHA256  string          `json:"spki_sha256"`
	Scanned     int             `json:"scanned"`
	Complete    bool            `json:"complete"`
	Serials     []ca.IssuedCert `json:"serials"`
	Cached      *ca.IssuedCert  `json:"cached_leaf,omitempty"`
	SnapshotAt  string          `json:"snapshot_at"`
	Source      string          `json:"source"`
	Reconciled  bool            `json:"reconciled"`
	Reconciler  string          `json:"reconciler"`
	Discrepancy []string        `json:"discrepancy,omitempty"`
	Format      int             `json:"format"`
}

// SerialEvidence is the per-serial rejection record.
type SerialEvidence struct {
	Serial           string                   `json:"serial"`
	SHA256           string                   `json:"sha256"`
	RevokedAt        string                   `json:"revoked_at"`
	MDMAssocsRemoved int64                    `json:"mdm_associations_removed"`
	Rejections       []sqlite.RadiusRejection `json:"rejections"`
}

// RejectionManifest is step 3: every serial revoked, MDM associations removed,
// and an observed Access-Reject from every configured acceptance point.
type RejectionManifest struct {
	AcceptancePoints []string         `json:"acceptance_points"`
	Serials          []SerialEvidence `json:"serials"`
	CheckedAt        string           `json:"checked_at"`
	MDMOnly          bool             `json:"mdm_only"`
	Format           int              `json:"format"`
}

// Service performs the steps.
type Service struct {
	store            Store
	authority        *ca.CA // nil when the signer is not the embedded CA
	acceptancePoints []string
	now              func() time.Time
}

// New builds a Service. authority may be nil (broker/external deployments).
func New(store Store, authority *ca.CA, acceptancePoints []string) *Service {
	pts := append([]string(nil), acceptancePoints...)
	sort.Strings(pts)
	return &Service{store: store, authority: authority, acceptancePoints: pts, now: time.Now}
}

// AcceptancePoints lists the configured relying RADIUS servers.
func (s *Service) AcceptancePoints() []string { return append([]string(nil), s.acceptancePoints...) }

// EmbeddedBackend reports whether this service can produce fence and
// enumeration evidence itself.
func (s *Service) EmbeddedBackend() bool { return s.authority != nil }

func (s *Service) held(ctx context.Context, grantID int64) (sqlite.Issuance, error) {
	iss, err := s.store.GetIssuance(ctx, grantID)
	if err != nil {
		return iss, fmt.Errorf("quarantine: no issuance for grant %d", grantID)
	}
	if iss.State != sqlite.IssuanceQuarantined {
		return iss, fmt.Errorf("quarantine: grant %d is %s, not QUARANTINED", grantID, iss.State)
	}
	return iss, nil
}

// Fence produces and records the fence manifest. For the embedded CA the fence
// is a fact of the storage model: the grant's binding is terminal (UNIQUE
// grant_id, QUARANTINED) and the signer is local and atomic, so no attempt for
// this grant can still complete. An external backend has no verifiable fence.
func (s *Service) Fence(ctx context.Context, grantID int64, actor string) (*FenceManifest, error) {
	iss, err := s.held(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if s.authority == nil || (iss.Backend != "" && iss.Backend != "embedded") {
		return nil, ErrBackendUnavailable
	}
	m := &FenceManifest{
		Backend: "embedded", CAFingerprint: s.authority.Fingerprint(), GrantID: grantID, TxnID: iss.TxnID, SPKISHA256: iss.SPKISHA256,
		BindingState: string(iss.State), AtomicSigner: true, CheckedAt: s.now().UTC().Format(time.RFC3339),
		Justification:  "cert_issuance.grant_id is UNIQUE and this binding is terminal; the embedded CA signs synchronously in-process, so no signer can still complete an attempt for this grant",
		ManifestFormat: 1,
	}
	body, _ := json.Marshal(m)
	if err := s.store.RecordFence(ctx, grantID, string(body), actor); err != nil {
		return nil, err
	}
	return m, nil
}

// Enumerate scans the embedded CA's complete issued-certificate record for every
// certificate carrying the held attempt's public key and reconciles the result
// with Cairn's own issuance row.
func (s *Service) Enumerate(ctx context.Context, grantID int64, actor string) (*EnumerationManifest, error) {
	iss, err := s.held(ctx, grantID)
	if err != nil {
		return nil, err
	}
	res, err := s.store.GetQuarantineResolution(ctx, grantID)
	if err != nil {
		return nil, err
	}
	if res.Step() < 1 {
		return nil, sqlite.ErrResolutionOrder
	}
	if s.authority == nil || (iss.Backend != "" && iss.Backend != "embedded") {
		return nil, ErrBackendUnavailable
	}
	matches, scanned, err := s.authority.IssuedForKey(ctx, iss.SPKISHA256)
	if err != nil {
		return nil, err
	}
	m := &EnumerationManifest{
		Backend: "embedded", SPKISHA256: iss.SPKISHA256, Scanned: scanned, Complete: true, Serials: matches,
		SnapshotAt: s.now().UTC().Format(time.RFC3339), Source: "scep_certs full scan by public key", Reconciled: true,
		Reconciler: "cert_issuance row for this grant", Format: 1,
	}
	// Reconcile with what the issuance row itself remembers.
	if len(iss.LeafDER) > 0 {
		cached := describeDER(iss.LeafDER)
		m.Cached = &cached
		if !containsSerial(matches, cached.Serial) {
			m.Discrepancy = append(m.Discrepancy, "cached leaf serial "+cached.Serial+" not found in the CA record")
			m.Serials = append(m.Serials, cached)
		}
	}
	if iss.CertSerial != "" && !containsSerial(m.Serials, iss.CertSerial) {
		m.Discrepancy = append(m.Discrepancy, "issuance row serial "+iss.CertSerial+" not found in the CA record")
	}
	body, _ := json.Marshal(m)
	if err := s.store.RecordEnumeration(ctx, grantID, string(body), actor); err != nil {
		return nil, err
	}
	return m, nil
}

// ConfirmRejected revokes every enumerated certificate at the embedded CA,
// removes any MDM certificate-authentication association for it, and collects
// the observed Access-Rejects reported by each configured acceptance point. It
// records the manifest only when every serial is covered; otherwise it returns
// what is missing and records nothing.
func (s *Service) ConfirmRejected(ctx context.Context, grantID int64, actor string) (*RejectionManifest, []string, error) {
	if _, err := s.held(ctx, grantID); err != nil {
		return nil, nil, err
	}
	res, err := s.store.GetQuarantineResolution(ctx, grantID)
	if err != nil {
		return nil, nil, err
	}
	if res.Step() < 2 {
		return nil, nil, sqlite.ErrResolutionOrder
	}
	var enum EnumerationManifest
	if err := json.Unmarshal([]byte(res.EnumerationManifest), &enum); err != nil || !enum.Complete {
		return nil, nil, ErrEvidence
	}
	if s.authority == nil {
		return nil, nil, ErrBackendUnavailable
	}
	m := &RejectionManifest{AcceptancePoints: s.acceptancePoints, CheckedAt: s.now().UTC().Format(time.RFC3339), MDMOnly: len(s.acceptancePoints) == 0, Format: 1}
	var missing []string
	for _, c := range enum.Serials {
		if err := s.authority.Revoke(ctx, c.Serial, 1); err != nil { // keyCompromise: the holder is unknown
			return nil, nil, err
		}
		revokedAt, ok, err := s.authority.IsRevoked(ctx, c.Serial)
		if err != nil || !ok {
			return nil, nil, fmt.Errorf("quarantine: revocation of %s not recorded", c.Serial)
		}
		removed, err := s.store.RemoveCertAuthByHash(ctx, c.SHA256)
		if err != nil {
			return nil, nil, err
		}
		ev := SerialEvidence{Serial: c.Serial, SHA256: c.SHA256, RevokedAt: revokedAt, MDMAssocsRemoved: removed}
		observed, err := s.store.RadiusRejectionsForSerial(ctx, c.Serial)
		if err != nil {
			return nil, nil, err
		}
		revoked, _ := time.Parse("2006-01-02 15:04:05", revokedAt)
		for _, p := range s.acceptancePoints {
			var found *sqlite.RadiusRejection
			for i := range observed {
				at, perr := time.Parse(time.RFC3339, observed[i].ObservedAt)
				if observed[i].AcceptancePoint == p && perr == nil && !at.Before(revoked.Add(-time.Minute)) {
					found = &observed[i]
					break
				}
			}
			if found == nil {
				missing = append(missing, fmt.Sprintf("serial %s: no observed Access-Reject from %s after revocation", c.Serial, p))
				continue
			}
			ev.Rejections = append(ev.Rejections, *found)
		}
		m.Serials = append(m.Serials, ev)
	}
	if len(missing) > 0 {
		return m, missing, nil
	}
	body, _ := json.Marshal(m)
	if err := s.store.RecordRejection(ctx, grantID, string(body), actor); err != nil {
		return nil, nil, err
	}
	return m, nil, nil
}

// Release re-validates every stored manifest's content and coverage, then
// records the release. The device must re-enroll with a new grant; nothing is
// reissued.
func (s *Service) Release(ctx context.Context, grantID int64, actor string) error {
	iss, err := s.held(ctx, grantID)
	if err != nil {
		return err
	}
	res, err := s.store.GetQuarantineResolution(ctx, grantID)
	if err != nil {
		return err
	}
	if res.Step() != 3 {
		return sqlite.ErrResolutionOrder
	}
	problems := s.validate(ctx, iss, res)
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrEvidence, strings.Join(problems, "; "))
	}
	return s.store.RecordRelease(ctx, grantID, actor)
}

// Validate reports why the stored evidence would not release, without changing
// anything. Empty means release would succeed.
func (s *Service) Validate(ctx context.Context, grantID int64) ([]string, error) {
	iss, err := s.held(ctx, grantID)
	if err != nil {
		return nil, err
	}
	res, err := s.store.GetQuarantineResolution(ctx, grantID)
	if err != nil {
		return nil, err
	}
	return s.validate(ctx, iss, res), nil
}

func (s *Service) validate(ctx context.Context, iss sqlite.Issuance, res sqlite.QuarantineResolution) []string {
	var problems []string
	var fence FenceManifest
	if res.FenceManifest == "" || json.Unmarshal([]byte(res.FenceManifest), &fence) != nil {
		problems = append(problems, "fence manifest missing or unreadable")
	} else {
		switch {
		case s.authority == nil || fence.Backend != "embedded":
			problems = append(problems, "fence manifest is not from a verifiable backend")
		case fence.CAFingerprint != s.authority.Fingerprint():
			problems = append(problems, "fence manifest names a different CA")
		case fence.GrantID != iss.GrantID || fence.TxnID != iss.TxnID || fence.SPKISHA256 != iss.SPKISHA256:
			problems = append(problems, "fence manifest does not match the held attempt")
		case !fence.AtomicSigner || fence.BindingState != string(sqlite.IssuanceQuarantined):
			problems = append(problems, "fence manifest does not prove a terminal, atomically signed binding")
		}
	}
	var enum EnumerationManifest
	if res.EnumerationManifest == "" || json.Unmarshal([]byte(res.EnumerationManifest), &enum) != nil {
		problems = append(problems, "enumeration manifest missing or unreadable")
		return problems
	}
	if !enum.Complete || !enum.Reconciled || enum.SPKISHA256 != iss.SPKISHA256 || enum.Backend != "embedded" {
		problems = append(problems, "enumeration manifest is not complete, reconciled and bound to this attempt")
	}
	if len(enum.Discrepancy) > 0 {
		problems = append(problems, "enumeration found discrepancies: "+strings.Join(enum.Discrepancy, "; "))
	}
	// Re-scan now: the CA record must not have grown since enumeration.
	if s.authority != nil {
		current, _, err := s.authority.IssuedForKey(ctx, iss.SPKISHA256)
		if err != nil {
			problems = append(problems, "cannot re-scan the CA record: "+err.Error())
		} else {
			for _, c := range current {
				if !containsSerial(enum.Serials, c.Serial) {
					problems = append(problems, "certificate "+c.Serial+" appeared after enumeration")
				}
			}
		}
	}
	var rej RejectionManifest
	if res.RejectionManifest == "" || json.Unmarshal([]byte(res.RejectionManifest), &rej) != nil {
		problems = append(problems, "rejection manifest missing or unreadable")
		return problems
	}
	if strings.Join(rej.AcceptancePoints, ",") != strings.Join(s.acceptancePoints, ",") {
		problems = append(problems, "rejection manifest covers a different set of acceptance points than configured")
	}
	covered := map[string]bool{}
	for _, ev := range rej.Serials {
		covered[ev.Serial] = true
		if s.authority != nil {
			if _, ok, err := s.authority.IsRevoked(ctx, ev.Serial); err != nil || !ok {
				problems = append(problems, "serial "+ev.Serial+" is not revoked")
			}
		}
		for _, p := range s.acceptancePoints {
			found := false
			for _, r := range ev.Rejections {
				if r.AcceptancePoint == p && r.Serial == ev.Serial {
					found = true
				}
			}
			if !found {
				problems = append(problems, "serial "+ev.Serial+" lacks an observed rejection from "+p)
			}
		}
	}
	for _, c := range enum.Serials {
		if !covered[c.Serial] {
			problems = append(problems, "enumerated serial "+c.Serial+" has no rejection evidence")
		}
	}
	return problems
}

func containsSerial(list []ca.IssuedCert, serial string) bool {
	for _, c := range list {
		if c.Serial == serial {
			return true
		}
	}
	return false
}

// describeDER summarizes a cached leaf for the enumeration manifest.
func describeDER(der []byte) ca.IssuedCert {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return ca.IssuedCert{Serial: "unparseable"}
	}
	sum := sha256.Sum256(der)
	return ca.IssuedCert{Serial: new(big.Int).Set(leaf.SerialNumber).Text(16), SHA256: hex.EncodeToString(sum[:]), NotAfter: leaf.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), Subject: leaf.Subject.String()}
}
