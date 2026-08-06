// Package broker implements the external CA backend (Lane B): an issue.CABackend
// that relays enrollment to a backend SCEP CA (OpenXPKI, NDES, …) as a SCEP client,
// signing the SCEP envelope with an RA identity. The device does grant-gated SCEP to
// Cairn; Cairn relays the device's CSR (its self-signature is the proof-of-possession
// the backend re-verifies) but never trusts the CSR's content — the Broker
// reconstructs the intent and post-verifies the returned leaf. The backend SCEP is
// never exposed to devices.
//
// Because a reply lost after the CA may have signed is unrecoverable without a poll,
// this backend's guarantee is quarantine-fallback (AtomicIssue=false): any ambiguity
// is quarantined, never retried as a fresh issuance.
//
// Deployment note: the backend CA must authorize Cairn's RA as an enrollment signer
// (the RA envelope signature is the authorization). Cairn cannot inject a per-request
// challenge into the device's CSR (it does not hold the device key), so the backend
// must not require a challengePassword for RA-signed requests.
package broker

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	kitlog "github.com/go-kit/kit/log"
	scepclient "github.com/micromdm/scep/v2/client"
	scep "github.com/smallstep/scep"

	"github.com/nickpdawson/cairn-mdm/internal/issue"
)

// Config configures a SCEP-relay backend.
type Config struct {
	URL    string            // backend SCEP endpoint
	RACert *x509.Certificate // RA identity: signs the envelope, decrypts the reply
	RAKey  crypto.PrivateKey
}

// scepBackend relays enrollment to a backend SCEP CA.
type scepBackend struct {
	url     string
	raCert  *x509.Certificate
	raKey   crypto.PrivateKey
	client  scepclient.Client
	caCerts []*x509.Certificate // backend CA chain (recipient + reply verify), fetched lazily
}

// New constructs a SCEP-relay issue.CABackend.
func New(cfg Config) (issue.CABackend, error) {
	if cfg.URL == "" || cfg.RACert == nil || cfg.RAKey == nil {
		return nil, errors.New("broker: URL, RA cert and RA key are required")
	}
	cl, err := scepclient.New(cfg.URL, kitlog.NewNopLogger())
	if err != nil {
		return nil, fmt.Errorf("broker: scep client: %w", err)
	}
	return &scepBackend{url: cfg.URL, raCert: cfg.RACert, raKey: cfg.RAKey, client: cl}, nil
}

func (*scepBackend) Capabilities() issue.Capability {
	return issue.Capability{
		Name:        "external-scep",
		AtomicIssue: false, // a lost reply after signing is ambiguous → quarantine-fallback
		// Reconcile (SCEP poll) is not yet implemented; a PENDING/ambiguous outcome is
		// quarantined and resolved out-of-band. The reconciler will flip these true.
		CanReconcile: false,
		CanPoll:      false,
		CanRevoke:    false,
		// The Broker verifies the returned leaf against the reconstructed intent, so a
		// backend that honored the CSR subject is caught and quarantined.
		VerifiesReconstruction: false,
	}
}

// recipients fetches (once) the backend CA chain used to encrypt the request and
// verify the reply signature.
func (b *scepBackend) recipients(ctx context.Context) ([]*x509.Certificate, error) {
	if len(b.caCerts) > 0 {
		return b.caCerts, nil
	}
	resp, certNum, err := b.client.GetCACert(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("broker: GetCACert: %w", err)
	}
	var certs []*x509.Certificate
	if certNum > 1 {
		// Multiple certs (CA + RA chain) are returned as a PKCS#7 degenerate.
		certs, err = scep.CACerts(resp)
		if err != nil {
			return nil, fmt.Errorf("broker: parse CA certs: %w", err)
		}
	} else {
		// A single CA cert is returned as a raw DER certificate.
		c, err := x509.ParseCertificate(resp)
		if err != nil {
			return nil, fmt.Errorf("broker: parse CA cert: %w", err)
		}
		certs = []*x509.Certificate{c}
	}
	if len(certs) == 0 {
		return nil, errors.New("broker: backend returned no CA certificates")
	}
	b.caCerts = certs
	return certs, nil
}

// Issue relays the device CSR to the backend CA and maps the SCEP reply to an outcome
// class. Pre-dispatch failures (unreachable backend, un-buildable request) are clean
// (nothing was signed); a transport error or unparseable reply AFTER dispatch is
// ambiguous (the CA may have signed) and the caller quarantines.
func (b *scepBackend) Issue(ctx context.Context, req issue.IssueRequest) (issue.IssueResult, error) {
	if req.DeviceCSR == nil {
		return issue.IssueResult{Status: issue.StatusFailedClean}, errors.New("broker: issue requires the device CSR")
	}
	recips, err := b.recipients(ctx)
	if err != nil {
		// GetCACert happens before any PKCSReq → nothing signed → clean failure.
		return issue.IssueResult{Status: issue.StatusFailedClean}, err
	}
	pkiMsg, err := scep.NewCSRRequest(req.DeviceCSR, &scep.PKIMessage{
		MessageType: scep.PKCSReq,
		Recipients:  recips,
		SignerKey:   b.raKey,
		SignerCert:  b.raCert,
	})
	if err != nil {
		return issue.IssueResult{Status: issue.StatusFailedClean}, fmt.Errorf("broker: build PKCSReq: %w", err)
	}

	// Dispatch. From here a lost/garbled reply is AMBIGUOUS (the CA may have signed).
	respBytes, err := b.client.PKIOperation(ctx, pkiMsg.Raw)
	if err != nil {
		return issue.IssueResult{Status: issue.StatusAmbiguous}, fmt.Errorf("broker: PKIOperation: %w", err)
	}
	respMsg, err := scep.ParsePKIMessage(respBytes, scep.WithCACerts(recips))
	if err != nil {
		return issue.IssueResult{Status: issue.StatusAmbiguous}, fmt.Errorf("broker: parse reply: %w", err)
	}

	switch respMsg.PKIStatus {
	case scep.SUCCESS:
		if err := respMsg.DecryptPKIEnvelope(b.raCert, b.raKey); err != nil {
			// A certificate was issued but we cannot read it → ambiguous.
			return issue.IssueResult{Status: issue.StatusAmbiguous}, fmt.Errorf("broker: decrypt reply: %w", err)
		}
		leaf := respMsg.CertRepMessage.Certificate
		if leaf == nil {
			return issue.IssueResult{Status: issue.StatusAmbiguous}, errors.New("broker: SUCCESS reply carried no certificate")
		}
		return issue.IssueResult{Status: issue.StatusIssued, Leaf: leaf, Serial: leaf.SerialNumber.Text(16)}, nil
	case scep.PENDING:
		return issue.IssueResult{Status: issue.StatusPending}, nil
	case scep.FAILURE:
		return issue.IssueResult{Status: issue.StatusFailedClean}, fmt.Errorf("broker: backend FAILURE (%v)", respMsg.FailInfo)
	default:
		return issue.IssueResult{Status: issue.StatusAmbiguous}, fmt.Errorf("broker: unknown pkiStatus %q", respMsg.PKIStatus)
	}
}

// Reconcile is not yet implemented (SCEP CertPoll). A quarantined attempt is resolved
// out-of-band until the reconciler lands; this keeps the backend fail-closed.
func (*scepBackend) Reconcile(context.Context, string, string) (issue.IssueResult, error) {
	return issue.IssueResult{Status: issue.StatusAmbiguous}, errors.New("broker: reconcile not implemented")
}

// Revoke is out of scope for the SCEP relay (CanRevoke=false): SCEP has no
// revocation operation. Revoke at the backend CA itself (e.g. OpenXPKI).
func (*scepBackend) Revoke(context.Context, string, issue.RevokeReason) error {
	return errors.New("broker: revoke via the backend CA is out of scope (revoke at OpenXPKI)")
}
