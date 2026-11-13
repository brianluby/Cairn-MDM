// Package mdmcore embeds NanoMDM as a library: it assembles the check-in and
// command service chain and exposes it as an HTTP handler Cairn mounts on its
// own listener. Unlike v1 — which ran NanoMDM as a separate container and
// talked to it over HTTP + its MySQL schema — the service here is composed
// in-process against a storage.AllStorage we provide.
package mdmcore

import (
	"crypto/x509"
	"encoding/base64"
	"log/slog"
	"net/http"
	"time"

	nlog "github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanomdm/cryptoutil"
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
func New(store storage.AllStorage, logger nlog.Logger, proj DeviceProjector, rec CommandRecorder, slog *slog.Logger) *Core {
	var svc service.CheckinAndCommandService = nanomdm.New(store, nanomdm.WithLogger(logger.With("service", "nanomdm")))
	// Wrap the core with the projector, then certauth on the outside. certauth
	// gates first, so the projection only runs for cert-authenticated requests
	// and records state after the core service has persisted it.
	var events *EventService
	if proj != nil || rec != nil {
		events = NewEventService(svc, proj, rec, slog)
		svc = events
	}
	svc = certauth.New(svc, store, certauth.WithLogger(logger.With("service", "certauth")))

	h := httpmdm.CheckinAndCommandHandler(svc, logger.With("handler", "mdm"))
	h = httpmdm.CertExtractMdmSignatureMiddleware(h, signatureVerifier(slog))

	return &Core{store: store, handler: h, events: events}
}

// signatureVerifier checks the Mdm-Signature on a check-in and says why when it
// refuses one. The usual reason is a device identity certificate that has
// expired: the device can no longer check in, so it cannot renew either, and
// without this line the only trace is an HTTP 400.
func signatureVerifier(log *slog.Logger) httpmdm.MdmSignatureVerifierFunc {
	return func(header string, body []byte) (*x509.Certificate, error) {
		cert, err := cryptoutil.VerifyMdmSignature(header, body)
		if err == nil || log == nil {
			return cert, err
		}
		attrs := []any{"err", err}
		if sig, e := base64.StdEncoding.DecodeString(header); e == nil {
			if p7, e := pkcs7.Parse(sig); e == nil && len(p7.Certificates) > 0 {
				c := p7.Certificates[0]
				attrs = append(attrs, "certificate", c.Subject.CommonName, "serial", c.SerialNumber.Text(16),
					"expired", time.Now().After(c.NotAfter), "not_after", c.NotAfter.UTC().Format(time.RFC3339))
			}
		}
		log.Warn("device check-in refused: signature not accepted; an expired identity certificate means the device must enroll again", attrs...)
		return cert, err
	}
}

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
