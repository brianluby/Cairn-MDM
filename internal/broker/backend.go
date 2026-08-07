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
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"

	kitlog "github.com/go-kit/kit/log"
	scepclient "github.com/micromdm/scep/v2/client"
	"github.com/smallstep/pkcs7"
	scep "github.com/smallstep/scep"
	"github.com/smallstep/scep/cryptoutil"

	"github.com/nickpdawson/cairn-mdm/internal/issue"
)

// SCEP signed-attribute OIDs (Verisign SCEP arc). Redeclared here because
// smallstep/scep keeps them unexported; buildRelayRequest sets them directly so it
// can override the transaction-ID encoding the library hardcodes.
var (
	oidSCEPmessageType   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPsenderNonce   = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPtransactionID = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
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

// encryptionRecipients selects the SCEP request-encryption target(s) from a
// GetCACert response. SCEP encrypts the request to the CA/RA certificate that
// will decrypt it; any chain certs (offline root, intermediates) returned
// alongside it are trust anchors for verifying the reply, not recipients.
//
// pkcs7 enveloping supports only RSA recipients, so non-RSA anchors must be
// filtered out — OpenXPKI in particular pairs an RSA "Internal RA" (the real
// recipient) with an EC root, and handing the EC root to the enveloper fails the
// whole request. Prefer a keyEncipherment cert (the canonical SCEP RA/encryption
// cert); fall back to any RSA cert (covers direct single-CA backends).
func encryptionRecipients(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	var keyEnc, rsaAny []*x509.Certificate
	for _, c := range certs {
		if c.PublicKeyAlgorithm != x509.RSA {
			continue
		}
		rsaAny = append(rsaAny, c)
		if c.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			keyEnc = append(keyEnc, c)
		}
	}
	switch {
	case len(keyEnc) > 0:
		return keyEnc, nil
	case len(rsaAny) > 0:
		return rsaAny, nil
	default:
		return nil, errors.New("broker: backend GetCACert returned no RSA encryption recipient")
	}
}

// relayTransactionID derives a deterministic, broadly-interoperable SCEP transaction
// ID from the device public key: the hex-encoded RFC 5280 key identifier (SHA-1 of
// the SubjectPublicKey). smallstep/scep's NewCSRRequest base64-encodes this same
// identifier and pads it with '=', which fails a default OpenXPKI transaction_id
// validator (\A(\w+:)?[0-9a-zA-Z_-]{16,128}(:\d+)?\z — base64url/hex, no padding).
// Hex satisfies that validator and stays deterministic, so the backend still dedups
// idempotent resubmissions of the same enrollment onto one workflow.
func relayTransactionID(pub crypto.PublicKey) (string, error) {
	id, err := cryptoutil.GenerateSubjectKeyID(pub)
	if err != nil {
		return "", fmt.Errorf("broker: transaction id: %w", err)
	}
	return hex.EncodeToString(id), nil
}

// buildRelayRequest constructs the signed+enveloped SCEP PKCSReq that relays the
// device CSR to the backend CA. It mirrors smallstep/scep NewCSRRequest — encrypt
// the device CSR to the recipient, sign the envelope with the RA identity, attach
// the SCEP signed attributes — but overrides the transaction-ID encoding (hex, see
// relayTransactionID), which the library computes internally with no override hook.
// The device's own CSR self-signature is the proof-of-possession the backend
// re-verifies; the RA signature is the enrollment authorization.
func buildRelayRequest(csr *x509.CertificateRequest, recipients []*x509.Certificate, raCert *x509.Certificate, raKey crypto.PrivateKey) ([]byte, error) {
	tid, err := relayTransactionID(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	env, err := pkcs7.Encrypt(csr.Raw, recipients)
	if err != nil {
		return nil, fmt.Errorf("broker: encrypt CSR: %w", err)
	}
	sd, err := pkcs7.NewSignedData(env)
	if err != nil {
		return nil, fmt.Errorf("broker: new signed data: %w", err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("broker: sender nonce: %w", err)
	}
	cfg := pkcs7.SignerInfoConfig{ExtraSignedAttributes: []pkcs7.Attribute{
		{Type: oidSCEPtransactionID, Value: tid},
		{Type: oidSCEPmessageType, Value: scep.PKCSReq},
		{Type: oidSCEPsenderNonce, Value: nonce},
	}}
	if err := sd.AddSigner(raCert, raKey, cfg); err != nil {
		return nil, fmt.Errorf("broker: add signer: %w", err)
	}
	raw, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("broker: finish signed data: %w", err)
	}
	return raw, nil
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
	// SCEP encrypts the request to the CA/RA cert that decrypts it — not to the
	// whole chain. Trust anchors (offline root/intermediate) are not recipients,
	// and pkcs7 can only encrypt to RSA keys, so an EC root (OpenXPKI pairs an RSA
	// RA with an EC root) must be excluded or NewCSRRequest fails. Still nothing
	// signed at this point → clean failure.
	encTo, err := encryptionRecipients(recips)
	if err != nil {
		return issue.IssueResult{Status: issue.StatusFailedClean}, err
	}
	rawReq, err := buildRelayRequest(req.DeviceCSR, encTo, b.raCert, b.raKey)
	if err != nil {
		return issue.IssueResult{Status: issue.StatusFailedClean}, fmt.Errorf("broker: build PKCSReq: %w", err)
	}

	// Dispatch. From here a lost/garbled reply is AMBIGUOUS (the CA may have signed).
	respBytes, err := b.client.PKIOperation(ctx, rawReq)
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
