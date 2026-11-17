// Package enroll serves the device enrollment profile. Enrollment is gated by
// single-use, expiring grants: GET /e/{token} redeems a grant and returns the
// CA-trust + SCEP + MDM profile, with the device cert bound per-device
// (%SerialNumber%) and to the grant's owner (SubjectAltName). The bare GET
// /enroll is default-denied and only served when explicitly opened for a
// zero-friction homelab.
package enroll

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/profile"
)

// TopicProvider yields the current APNs topic (needed in the MDM payload).
type TopicProvider interface {
	GetSetting(ctx context.Context, key string) (string, error)
}

// Redemption is the grant data used to build a device's profile.
type Redemption struct {
	Platform       string
	Owner          string // rfc822/UPN → device cert SAN
	ExpectedSerial string
}

// Redeemer atomically validates and consumes a one-time enrollment grant.
type Redeemer interface {
	RedeemGrant(ctx context.Context, rawToken string) (Redemption, error)
}

// Config holds everything the handler needs to render a profile.
type Config struct {
	Organization  string   // reverse-DNS identifier root + PayloadOrganization
	CAAnchorsDER  [][]byte // CA cert(s) (DER) to install as trust anchors
	SCEPURL       string   // e.g. https://mdm.example.com/scep
	Challenge     string   // static SCEP challenge (may be empty)
	MDMServerURL  string   // e.g. https://mdm.example.com/mdm
	SubjectPrefix string   // device cert CN suffix, e.g. "devices.example.com"

	Management profile.Management // site settings of the management payload

	// PerGrantChallenge, when true, sets each profile's SCEP challenge to the
	// enrolling grant's own token instead of the static Challenge. This is the
	// enrollment-authorization Broker path: the SCEP endpoint resolves that token to
	// the grant and reconstructs the certificate from server policy.
	PerGrantChallenge bool

	// MintChallenge, when set, supplies a one-time challenge for each profile
	// in place of the static Challenge. commonName is the certificate name the
	// device will ask for when the grant fixes its serial number, and empty
	// otherwise; cnSuffix is SubjectPrefix.
	MintChallenge func(ctx context.Context, commonName, cnSuffix, owner string) (string, error)

	// AllowOpen serves the bare /enroll route unauthenticated (homelab
	// opt-in). Default false → bare /enroll is 404; use grant links.
	AllowOpen bool

	Signer *profile.Signer // optional; if set, profiles are CMS-signed
}

// Handler serves enrollment profiles.
type Handler struct {
	cfg      Config
	topics   TopicProvider
	redeemer Redeemer // may be nil (grant route disabled)
	topicKey string
	log      *slog.Logger
}

// New builds an enrollment handler. topicKey is the settings key holding the
// APNs topic (push.SettingTopic). redeemer may be nil to disable /e/{token}.
func New(cfg Config, topics TopicProvider, redeemer Redeemer, topicKey string, log *slog.Logger) *Handler {
	return &Handler{cfg: cfg, topics: topics, redeemer: redeemer, topicKey: topicKey, log: log}
}

// ServeOpen handles the bare GET /enroll. Default-denied unless AllowOpen; when
// open it issues an unbound profile (generic per-device CN, no owner SAN).
func (h *Handler) ServeOpen(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.AllowOpen {
		h.log.Info("bare /enroll denied (use a grant link)", "remote", r.RemoteAddr)
		http.NotFound(w, r)
		return
	}
	// Bare open enroll has no grant, hence no per-grant token; a Broker-backed SCEP
	// endpoint will reject the resulting empty challenge (fail-closed), which is
	// correct — open enroll cannot obtain an authority-controlled certificate.
	h.serveProfile(w, r, Redemption{}, "")
}

// ServeGrant shows instructions on GET; POST redeems the grant and serves a profile
// bound to its owner. Invalid/expired/revoked/exhausted → 410 Gone.
func (h *Handler) ServeGrant(w http.ResponseWriter, r *http.Request) {
	if h.redeemer == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "strict-origin")
	token := normalizeToken(r.PathValue("token"))
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if inspector, ok := h.redeemer.(interface {
			InspectGrant(context.Context, string) error
		}); ok {
			if err := inspector.InspectGrant(r.Context(), token); err != nil {
				http.Error(w, "This link is expired, unavailable or already used. Ask your administrator for a new link.", http.StatusGone)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = invitationPage.Execute(w, nil)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, e := url.Parse(origin)
		if e != nil || u.Host != r.Host || u.Scheme != "https" {
			http.Error(w, "Open the invitation on this server before downloading.", 403)
			return
		}
	}
	// A missing push topic must not spend a valid invitation.
	if topic, err := h.topics.GetSetting(r.Context(), h.topicKey); err != nil || topic == "" {
		http.Error(w, "Enrollment is not ready. Contact your administrator; this link has not been used.", 503)
		return
	}

	red, err := h.redeemer.RedeemGrant(r.Context(), token)
	if err != nil {
		h.log.Info("enrollment grant rejected", "remote", r.RemoteAddr, "err", err)
		http.Error(w, "This enrollment link is invalid, expired, or already used.", http.StatusGone)
		return
	}
	h.log.Info("enrollment grant redeemed", "owner", red.Owner, "platform", red.Platform, "remote", r.RemoteAddr)
	h.serveProfile(w, r, red, token)
}

// serveProfile builds, signs, and writes the .mobileconfig for a redemption. token
// is the grant's raw token, used as the per-enrollment SCEP challenge when
// PerGrantChallenge is set.
func (h *Handler) serveProfile(w http.ResponseWriter, r *http.Request, red Redemption, token string) {
	topic, err := h.topics.GetSetting(r.Context(), h.topicKey)
	if err != nil || topic == "" {
		h.log.Warn("enrollment requested but no APNs push certificate is loaded")
		http.Error(w, "server not ready: no APNs push certificate loaded", http.StatusServiceUnavailable)
		return
	}

	// Per-device subject: Apple substitutes %SerialNumber% at install, so each
	// device gets a unique, individually-revocable identity.
	subjectCN := "%SerialNumber%"
	if h.cfg.SubjectPrefix != "" {
		subjectCN += "." + h.cfg.SubjectPrefix
	}

	challenge := h.cfg.Challenge
	if h.cfg.PerGrantChallenge {
		challenge = token // the Broker resolves this token to the grant at SCEP time
	}
	if h.cfg.MintChallenge != nil {
		known := ""
		if red.ExpectedSerial != "" {
			known = strings.Replace(subjectCN, "%SerialNumber%", red.ExpectedSerial, 1)
		}
		if challenge, err = h.cfg.MintChallenge(r.Context(), known, h.cfg.SubjectPrefix, red.Owner); err != nil {
			h.log.Error("mint enrollment challenge", "err", err)
			http.Error(w, "failed to build profile", http.StatusInternalServerError)
			return
		}
	}

	prof, err := profile.BuildEnrollment(profile.EnrollmentParams{
		Management:    h.cfg.Management,
		Organization:  h.cfg.Organization,
		CAAnchorsDER:  h.cfg.CAAnchorsDER,
		SCEPURL:       h.cfg.SCEPURL,
		SubjectCN:     subjectCN,
		OwnerRFC822:   red.Owner,
		Challenge:     challenge,
		MDMServerURL:  h.cfg.MDMServerURL,
		MDMCheckInURL: h.cfg.MDMServerURL,
		Topic:         topic,
	})
	if err != nil {
		h.log.Error("build enrollment profile", "err", err)
		http.Error(w, "failed to build profile", http.StatusInternalServerError)
		return
	}

	xml, err := profile.Marshal(prof)
	if err != nil {
		h.log.Error("marshal enrollment profile", "err", err)
		http.Error(w, "failed to render profile", http.StatusInternalServerError)
		return
	}

	body := xml
	if h.cfg.Signer != nil {
		signed, serr := profile.Sign(xml, *h.cfg.Signer)
		if serr != nil {
			h.log.Error("sign enrollment profile", "err", serr)
			http.Error(w, "failed to sign profile", http.StatusInternalServerError)
			return
		}
		body = signed
	}

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="cairn-enroll.mobileconfig"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// ServeHTTP keeps the http.Handler contract pointing at the bare route.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.ServeOpen(w, r) }

// normalizeToken trims incidental whitespace from a path token.
func normalizeToken(s string) string { return strings.TrimSpace(s) }

var invitationPage = template.Must(template.New("invitation").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/assets/app.css"><title>Enroll this device · Cairn</title></head>
<body><main><h1>Enroll this device</h1><div class="card" style="padding:24px">
<p>Your administrator has authorized a device for you. Open this link in Safari on the Mac, iPhone or iPad you intend to enroll. You do not need to sign in to Cairn.</p>
<p>Use an existing internet connection, such as guest Wi-Fi, cellular or Ethernet. Read the management details before approving installation.</p>
<form method="post"><button class="btn" type="submit">Download enrollment profile</button></form>
<h2>iPhone or iPad</h2><p>Allow the download, open Settings, then Profile Downloaded (or Enroll in Your Organization). Review the profile and tap Install. Your device may ask for its passcode.</p>
<h2>Mac</h2><p>Open the downloaded profile. In System Settings, open General → Device Management, select the downloaded profile and review the installation request. Older macOS versions may place Profiles under Privacy &amp; Security.</p>
<h2>If installation was interrupted</h2><p>If you still have the downloaded profile, continue installing it. If the download was lost, the profile expired, or this link was already used, ask your administrator to revoke it and create a replacement. Do not remove existing management without their instructions.</p>
<p>Downloading does not mean enrollment or secure Wi-Fi succeeded. Your administrator can check the device's enrollment and profile acknowledgements.</p>
</div></main></body></html>`))
