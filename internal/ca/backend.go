package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"

	"github.com/nickpdawson/cairn-mdm/internal/issue"
)

// embeddedBackend adapts the embedded CA to the issue.CABackend interface. Cairn is
// the signer, so "signed / not-signed" is a single local atomic fact (AtomicIssue).
// It signs the Broker's RECONSTRUCTED template — never the device CSR's fields.
type embeddedBackend struct{ ca *CA }

// EmbeddedBackend returns this CA as an issue.CABackend for the Broker.
func (c *CA) EmbeddedBackend() issue.CABackend { return embeddedBackend{ca: c} }

func (embeddedBackend) Capabilities() issue.Capability {
	return issue.Capability{
		Name:        "embedded",
		AtomicIssue: true, // local signer: no lost external ack, no PENDING/ambiguous
		// Cairn signs the reconstructed template directly, so the returned leaf equals
		// the intent by construction; the Broker's post-verify remains a safety net
		// (VerifiesReconstruction=false keeps it running).
		VerifiesReconstruction: false,
		CanReconcile:           false,
		CanRevoke:              true, // local revoked_certs table + self-served CRL
	}
}

// Revoke records the serial as revoked; the next generated CRL includes it.
func (b embeddedBackend) Revoke(ctx context.Context, serial string, reason issue.RevokeReason) error {
	return b.ca.Revoke(ctx, serial, int(reason))
}

// Issue signs the reconstructed template with the CA key, assigning an
// authority-chosen serial. It never consults the CSR's requested fields.
func (b embeddedBackend) Issue(_ context.Context, req issue.IssueRequest) (issue.IssueResult, error) {
	if req.Template == nil || req.PublicKey == nil {
		return issue.IssueResult{}, errors.New("ca: embedded issue requires a template and public key")
	}
	serial, err := b.ca.depot.Serial()
	if err != nil {
		return issue.IssueResult{}, err
	}
	tmpl := *req.Template // copy; the serial is the authority's decision, not a template input
	tmpl.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, b.ca.cert, req.PublicKey, b.ca.key)
	if err != nil {
		return issue.IssueResult{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return issue.IssueResult{}, err
	}
	if err := b.ca.depot.Put(leaf.Subject.CommonName, leaf); err != nil {
		return issue.IssueResult{}, err
	}
	chain := []*x509.Certificate{b.ca.cert} // issuer
	if b.ca.root != nil {
		chain = append(chain, b.ca.root) // + offline root (two-tier)
	}
	return issue.IssueResult{
		Status: issue.StatusIssued,
		Leaf:   leaf,
		Serial: serial.Text(16),
		Chain:  chain,
	}, nil
}

// Reconcile is a no-op for the embedded backend: issuance is atomic and local, so
// there is no lost external outcome to re-derive. The Broker records the result
// synchronously in the same request.
func (embeddedBackend) Reconcile(context.Context, string, string) (issue.IssueResult, error) {
	return issue.IssueResult{Status: issue.StatusAmbiguous}, errors.New("ca: embedded backend has no external reconcile")
}
