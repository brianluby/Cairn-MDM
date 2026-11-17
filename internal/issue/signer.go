package issue

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"

	"github.com/smallstep/pkcs7"
)

type signerKey struct{}

// maxSCEPBody bounds a PKIOperation body the middleware will buffer.
const maxSCEPBody = 1 << 20

// SignerExtractMiddleware makes the SCEP envelope's signing certificate available
// to the Broker through the request context. The SCEP server hands the signer
// only the decrypted CSR, so without this the Broker cannot tell an initial
// enrollment (self-signed temporary signer) from a renewal attempt (signed by a
// certificate this CA issued). The body is re-attached unread for the handler.
func SignerExtractMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("operation") != "PKIOperation" {
			next.ServeHTTP(w, r)
			return
		}
		var raw []byte
		switch r.Method {
		case http.MethodGet:
			if msg := r.URL.Query().Get("message"); msg != "" {
				raw, _ = base64.StdEncoding.DecodeString(msg)
			}
		case http.MethodPost:
			body, err := io.ReadAll(io.LimitReader(r.Body, maxSCEPBody))
			r.Body.Close()
			if err == nil {
				raw = body
				r.Body = io.NopCloser(bytes.NewReader(body))
			} else {
				r.Body = io.NopCloser(bytes.NewReader(nil))
			}
		}
		if len(raw) > 0 {
			if p7, err := pkcs7.Parse(raw); err == nil {
				if signer := p7.GetOnlySigner(); signer != nil {
					r = r.WithContext(context.WithValue(r.Context(), signerKey{}, signer))
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// SignerFromContext returns the SCEP envelope signer captured by
// SignerExtractMiddleware, or nil.
func SignerFromContext(ctx context.Context) *x509.Certificate {
	c, _ := ctx.Value(signerKey{}).(*x509.Certificate)
	return c
}

// ErrRenewalUnsupported is returned when a device signs its SCEP request with a
// certificate this CA issued. Renewal is a separate, reviewed lifecycle that this
// release does not implement; the request is refused before any grant is read so
// nothing is spent, and the attempt is recorded for the operator.
var ErrRenewalUnsupported = &renewalError{}

type renewalError struct{}

func (*renewalError) Error() string {
	return "issue: certificate renewal is not supported in this release; the device needs a new enrollment link"
}

// RenewalAttempt describes a refused renewal-style request.
type RenewalAttempt struct {
	SPKISHA256    string // public key offered in the CSR
	SignerSerial  string // lowercase hex serial of the signing certificate
	SignerSHA256  string // hex SHA-256 of the signing certificate DER
	SignerSubject string
	SignerExpires string // RFC 3339
	Reason        string
}

// RenewalObserver records refused renewal attempts. *sqlite.DB satisfies it.
type RenewalObserver interface {
	RecordRenewalAttempt(ctx context.Context, a RenewalAttempt) error
}

// WithIssuer tells the Broker which CA certificate signed the identities it
// should treat as its own, enabling renewal detection.
func (b *Broker) WithIssuer(issuer *x509.Certificate) *Broker {
	b.issuer = issuer
	return b
}

// WithRenewalObserver records refused renewal attempts.
func (b *Broker) WithRenewalObserver(o RenewalObserver) *Broker {
	b.renewals = o
	return b
}
