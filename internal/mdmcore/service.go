// Package mdmcore embeds NanoMDM as a library: it assembles the check-in and
// command service chain and exposes it as an HTTP handler Cairn mounts on its
// own listener. Unlike v1 — which ran NanoMDM as a separate container and
// talked to it over HTTP + its MySQL schema — the service here is composed
// in-process against a storage.AllStorage we provide.
package mdmcore

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	nlog "github.com/micromdm/nanolib/log"
	httpmdm "github.com/micromdm/nanomdm/http/mdm"
	"github.com/micromdm/nanomdm/service"
	"github.com/micromdm/nanomdm/service/certauth"
	"github.com/micromdm/nanomdm/service/nanomdm"
	"github.com/micromdm/nanomdm/storage"
	"github.com/smallstep/pkcs7"
)

// Core holds the assembled MDM service and its HTTP handler.
type Core struct {
	store   storage.AllStorage
	handler http.Handler
	events  *EventService // nil when no projector/recorder configured
	// identity is told about the certificate on every signed check-in.
	identity atomic.Pointer[IdentityObserver]
	// lifecycle follows identity certificates through renewal; nil when
	// renewal is not configured.
	lifecycle atomic.Pointer[Lifecycle]
	// expiredGrace is how long past its expiry an identity certificate may
	// still check in, to be renewed and for nothing else. Zero refuses it.
	expiredGrace time.Duration
	now          func() time.Time
	// issuers are the CA certificates a device identity certificate may chain
	// to. Until TrustIssuers is called every check-in is refused.
	issuers atomic.Pointer[x509.CertPool]
}

// Options tune the check-in service.
type Options struct {
	// ExpiredGrace lets a device whose identity certificate expired no longer
	// ago than this keep checking in so it can be renewed. Zero refuses every
	// expired certificate.
	ExpiredGrace time.Duration
}

// IdentityObserver receives the identity certificate presented on a check-in
// and whether its signature was accepted.
type IdentityObserver func(cert *x509.Certificate, accepted bool)

// OnIdentity registers the observer for check-in certificates.
func (c *Core) OnIdentity(fn IdentityObserver) { c.identity.Store(&fn) }

// TrustIssuers sets the CA certificates that may have issued a device identity
// certificate: the configured CA's chain, and any older CA whose devices were
// imported. A check-in signed with a certificate from anywhere else is refused
// before it reaches enrollment, so nobody can register a device, or answer as
// one, with a certificate they made themselves.
func (c *Core) TrustIssuers(certs []*x509.Certificate) {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	c.issuers.Store(pool)
}

var (
	errNoIssuers     = errors.New("no identity certificate issuers are configured")
	errUnknownIssuer = errors.New("identity certificate was not issued by a configured CA")
)

// issuedByTrusted reports whether leaf chains to a trusted issuer, through any
// CA certificates the device sent along. Dates are the caller's business (the
// expiry rule and its grace period), so the chain is judged at a moment inside
// the certificate's own validity.
func (c *Core) issuedByTrusted(leaf *x509.Certificate, bundled []*x509.Certificate) error {
	roots := c.issuers.Load()
	if roots == nil {
		return errNoIssuers
	}
	intermediates := x509.NewCertPool()
	for _, b := range bundled {
		if b != leaf && b.IsCA {
			intermediates.AddCert(b)
		}
	}
	at := c.now()
	if at.After(leaf.NotAfter) {
		at = leaf.NotAfter
	}
	if at.Before(leaf.NotBefore) {
		at = leaf.NotBefore
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("%w: %v", errUnknownIssuer, err)
	}
	return nil
}

// New assembles the NanoMDM service chain:
//
//	CertExtractMdmSignatureMiddleware  (pulls the device identity cert out of
//	                                    the Mdm-Signature header — required for
//	                                    SignMessage=true enrollments)
//	  └─ certauth                      (binds each request's cert to its
//	                                    enrollment; rejects mismatches)
//	       └─ nanomdm                  (the check-in/command protocol core)
//
// It intentionally does not mount NanoMDM's HTTP command API — Cairn enqueues
// commands in-process through its own authenticated API, so the API-key surface
// v1 exposed does not exist here.
func New(store storage.AllStorage, logger nlog.Logger, proj DeviceProjector, rec CommandRecorder, slog *slog.Logger, opts ...Options) *Core {
	c := &Core{store: store, now: time.Now}
	for _, o := range opts {
		c.expiredGrace = o.ExpiredGrace
	}
	var svc service.CheckinAndCommandService = nanomdm.New(store, nanomdm.WithLogger(logger.With("service", "nanomdm")))
	// Wrap the core with the projector, then certauth on the outside. certauth
	// gates first, so the projection only runs for cert-authenticated requests
	// and records state after the core service has persisted it.
	var events *EventService
	if proj != nil || rec != nil {
		events = NewEventService(svc, proj, rec, slog)
		events.onProfileList = func(ctx context.Context, id, uuid string, profiles []InstalledProfile) {
			if l := c.lifecycle.Load(); l != nil {
				(*l).ProfileList(ctx, id, uuid, profiles)
			}
		}
		svc = events
	}
	c.events = events
	// Inside certificate authorization: limit what an expired certificate may do.
	svc = &expiryGate{next: svc, core: c}
	svc = certauth.New(svc, store, certauth.WithLogger(logger.With("service", "certauth")))
	// Outside it: a renewed certificate has to be associated before it is checked.
	svc = &presenter{next: svc, core: c}

	h := httpmdm.CheckinAndCommandHandler(svc, logger.With("handler", "mdm"))
	observe := func(cert *x509.Certificate, accepted bool) {
		if fn := c.identity.Load(); fn != nil && cert != nil {
			(*fn)(cert, accepted)
		}
	}
	verified := httpmdm.CertExtractMdmSignatureMiddleware(h, signatureVerifier(slog, observe, c.expiredGrace, c.now, c.issuedByTrusted))
	c.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verified.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), checkInHostKey{}, r.Host)))
	})
	return c
}

// errIdentityExpired refuses a check-in signed with an identity certificate
// that is past its expiry and past any grace period.
var errIdentityExpired = errors.New("identity certificate expired")

// signatureVerifier checks the Mdm-Signature on a check-in and applies the
// expiry rule itself. The signature library refuses an expired certificate
// only when the device states a signing time, and Macs state none, so on its
// own it lets some expired certificates through and stops others. Here every
// device gets the same answer: a certificate inside its validity is accepted,
// one that expired within the grace period is accepted so the device can be
// renewed, and anything older is refused and logged with the reason.
//
// trusted decides whether the certificate came from a CA this server accepts.
// A certificate that did not is refused like a bad signature: it proves
// nothing about any device, so nothing is recorded against one.
func signatureVerifier(log *slog.Logger, observe IdentityObserver, grace time.Duration, now func() time.Time, trusted func(leaf *x509.Certificate, bundled []*x509.Certificate) error) httpmdm.MdmSignatureVerifierFunc {
	return func(header string, body []byte) (*x509.Certificate, error) {
		cert, presented, err := verifySignature(header, body, trusted)
		if err == nil {
			t := now()
			switch {
			case t.Before(cert.NotBefore.Add(-clockSkew)):
				err = errors.New("identity certificate is not valid yet")
			case t.After(cert.NotAfter) && (grace <= 0 || t.After(cert.NotAfter.Add(grace))):
				err = errIdentityExpired
			}
		}
		if err == nil {
			observe(cert, true)
			return cert, nil
		}
		attrs := []any{"err", err}
		if cert != nil {
			// The signature is good and the dates are not. Only then is the
			// refusal counted against the certificate: a request that proves
			// nothing must not change what Cairn records about a device.
			observe(cert, false)
		}
		if presented != nil {
			attrs = append(attrs, "certificate", presented.Subject.CommonName, "serial", presented.SerialNumber.Text(16),
				"expired", now().After(presented.NotAfter), "not_after", presented.NotAfter.UTC().Format(time.RFC3339))
		}
		if log != nil {
			msg := "device check-in refused: signature not accepted; a device refused for an expired identity certificate must enroll again"
			if errors.Is(err, errUnknownIssuer) || errors.Is(err, errNoIssuers) {
				msg = "device check-in refused: its certificate does not come from a CA this server accepts; if the device was enrolled under another CA, add that CA to [ca] identity_ca_files"
				if presented != nil {
					attrs = append(attrs, "issuer", presented.Issuer.CommonName)
				}
			}
			log.Warn(msg, attrs...)
		}
		return nil, err
	}
}

// clockSkew tolerates a certificate issued moments ago by a CA whose clock is
// slightly ahead.
const clockSkew = 5 * time.Minute

// verifySignature checks the signature over body and returns the signing
// certificate. It does not judge the certificate's dates; the caller does. On
// failure presented is the device certificate found in the signature, if any,
// so the refusal can name it.
func verifySignature(header string, body []byte, trusted func(leaf *x509.Certificate, bundled []*x509.Certificate) error) (signer, presented *x509.Certificate, err error) {
	sig, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, nil, err
	}
	p7, err := pkcs7.Parse(sig)
	if err != nil {
		return nil, nil, err
	}
	signer = p7.GetOnlySigner()
	if signer == nil {
		// The signature carries the device certificate and often its CA chain,
		// in no fixed order. The device's is the one that is not a CA.
		for _, c := range p7.Certificates {
			if !c.IsCA {
				return nil, c, errors.New("invalid or missing signer")
			}
		}
		return nil, nil, errors.New("invalid or missing signer")
	}
	// The library compares the device's stated signing time with the
	// certificate's dates before it checks the signature, so an expired
	// certificate fails without the signature ever being tested. Verify
	// against a copy of the certificate with the end date moved out; the key
	// and everything signed are unchanged.
	open := *p7
	open.Content = body
	open.Certificates = make([]*x509.Certificate, len(p7.Certificates))
	for i, c := range p7.Certificates {
		if c == signer {
			undated := *c
			undated.NotAfter = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
			c = &undated
		}
		open.Certificates[i] = c
	}
	if err = open.Verify(); err != nil {
		return nil, signer, err
	}
	if err = trusted(signer, p7.Certificates); err != nil {
		return nil, signer, err
	}
	return signer, signer, nil
}

// OnLifecycle registers the renewal lifecycle.
func (c *Core) OnLifecycle(l Lifecycle) { c.lifecycle.Store(&l) }

// OnPushable registers a hook called whenever a device completes a TokenUpdate
// (i.e. becomes pushable). No-op if the event service is not configured.
func (c *Core) OnPushable(fn func(id string)) {
	if c.events != nil {
		c.events.OnPushable(fn)
	}
}

// Handler returns the MDM check-in/command HTTP handler to mount at the
// configured MDM path.
func (c *Core) Handler() http.Handler { return c.handler }

// Store returns the underlying storage (used by the admin/enqueue paths).
func (c *Core) Store() storage.AllStorage { return c.store }
