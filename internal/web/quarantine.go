package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/quarantine"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// QuarantineResolver performs the evidence-gated release steps.
type QuarantineResolver interface {
	Fence(ctx context.Context, grantID int64, actor string) (*quarantine.FenceManifest, error)
	Enumerate(ctx context.Context, grantID int64, actor string) (*quarantine.EnumerationManifest, error)
	ConfirmRejected(ctx context.Context, grantID int64, actor string) (*quarantine.RejectionManifest, []string, error)
	Release(ctx context.Context, grantID int64, actor string) error
	Validate(ctx context.Context, grantID int64) ([]string, error)
	AcceptancePoints() []string
	EmbeddedBackend() bool
}

// SetQuarantineResolver installs the resolution service. Nil leaves the page
// read-only.
func (a *App) SetQuarantineResolver(r QuarantineResolver) { a.resolver = r }

// SetRadiusIngestToken enables POST /api/v1/radius/rejections with this bearer
// token. Empty disables the endpoint.
func (a *App) SetRadiusIngestToken(token string) { a.radiusToken = token }

type resolutionStore interface {
	GetQuarantineResolution(ctx context.Context, grantID int64) (sqlite.QuarantineResolution, error)
	GetIssuance(ctx context.Context, grantID int64) (sqlite.Issuance, error)
	InsertRadiusRejection(ctx context.Context, r sqlite.RadiusRejection) error
}

type quarantineRow struct {
	sqlite.Issuance
	Step  int
	Owner string
	Label string
}

// handleQuarantine lists held issuances with their resolution progress.
func (a *App) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	items, err := a.quarantine.ListQuarantined(r.Context())
	if err != nil {
		a.log.Error("list quarantined", "err", err)
	}
	rows := make([]quarantineRow, 0, len(items))
	store, _ := a.quarantine.(resolutionStore)
	for _, it := range items {
		row := quarantineRow{Issuance: it}
		if store != nil {
			if res, err := store.GetQuarantineResolution(r.Context(), it.GrantID); err == nil {
				row.Step = res.Step()
			}
		}
		if g, err := a.grants.GetGrant(r.Context(), it.GrantID); err == nil {
			row.Owner, row.Label = g.Owner, g.Label
		}
		rows = append(rows, row)
	}
	a.render(w, r, http.StatusOK, "quarantine.html", map[string]any{
		"Title":    "Quarantine",
		"Items":    rows,
		"Resolver": a.resolver != nil,
		"Embedded": a.resolver != nil && a.resolver.EmbeddedBackend(),
		"Flash":    r.URL.Query().Get("flash"),
		"Error":    r.URL.Query().Get("error"),
	})
}

// handleQuarantineDetail shows one hold's context and the four-step flow with
// the evidence gathered so far. Only the next permitted step is offered.
func (a *App) handleQuarantineDetail(w http.ResponseWriter, r *http.Request) {
	grantID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	store, ok := a.quarantine.(resolutionStore)
	if err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	iss, err := store.GetIssuance(r.Context(), grantID)
	if err != nil || iss.State != sqlite.IssuanceQuarantined {
		http.NotFound(w, r)
		return
	}
	res, err := store.GetQuarantineResolution(r.Context(), grantID)
	if err != nil {
		http.Error(w, "Cannot load resolution evidence", 503)
		return
	}
	data := map[string]any{
		"Title":      "Quarantine",
		"Issuance":   iss,
		"Resolution": res,
		"Step":       res.Step(),
		"Resolver":   a.resolver != nil,
		// Steps are offered only when this hold's signer is the embedded CA this
		// server can verify; an external-backend hold stays read-only even on an
		// embedded-mode server.
		"Embedded":   a.resolver != nil && a.resolver.EmbeddedBackend() && (iss.Backend == "" || iss.Backend == "embedded"),
		"Flash":      r.URL.Query().Get("flash"),
		"Error":      r.URL.Query().Get("error"),
		"Missing":    strings.Split(r.URL.Query().Get("missing"), "\n"),
	}
	if r.URL.Query().Get("missing") == "" {
		data["Missing"] = nil
	}
	if a.resolver != nil {
		data["AcceptancePoints"] = a.resolver.AcceptancePoints()
		if res.Step() == 3 {
			if problems, err := a.resolver.Validate(r.Context(), grantID); err == nil {
				data["Problems"] = problems
			}
		}
	}
	if g, err := a.grants.GetGrant(r.Context(), grantID); err == nil {
		data["Grant"] = g
	}
	data["Fence"] = prettyJSON(res.FenceManifest)
	data["Enumeration"] = prettyJSON(res.EnumerationManifest)
	data["Rejection"] = prettyJSON(res.RejectionManifest)
	a.render(w, r, http.StatusOK, "quarantine_detail.html", data)
}

func prettyJSON(s string) string {
	if s == "" {
		return ""
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return s
	}
	return string(b)
}

// handleQuarantineStep runs one resolution step. Admin role, CSRF and fresh MFA
// are required because release frees a lineage for re-enrollment; the storage
// layer still enforces step order, so the UI cannot skip ahead.
func (a *App) handleQuarantineStep(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	grantID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	back := "/admin/quarantine/" + strconv.FormatInt(grantID, 10)
	if a.resolver == nil {
		http.Redirect(w, r, back+"?error="+url.QueryEscape("Quarantine resolution is not configured on this server."), http.StatusSeeOther)
		return
	}
	s := sessionFrom(r)
	if s.Identity.Role != auth.RoleAdmin || a.mfa == nil || a.mfa.Fresh(r.Context(), s.Token) != nil {
		http.Error(w, "Administrator access and fresh MFA required. Open Account security to verify your code.", http.StatusForbidden)
		return
	}
	actor := s.Identity.Provider + ":" + s.Identity.Username
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	var flash string
	switch r.PathValue("step") {
	case "fence":
		_, err = a.resolver.Fence(ctx, grantID, actor)
		flash = "Fence recorded: the signer cannot complete this attempt."
	case "enumerate":
		var m *quarantine.EnumerationManifest
		m, err = a.resolver.Enumerate(ctx, grantID, actor)
		if err == nil {
			flash = "Enumeration recorded: " + strconv.Itoa(len(m.Serials)) + " certificate(s) found for this key across " + strconv.Itoa(m.Scanned) + " issued."
		}
	case "confirm":
		var missing []string
		_, missing, err = a.resolver.ConfirmRejected(ctx, grantID, actor)
		if err == nil && len(missing) > 0 {
			a.log.Info("quarantine confirm incomplete", "grant", grantID, "actor", actor, "missing", len(missing))
			http.Redirect(w, r, back+"?missing="+url.QueryEscape(strings.Join(missing, "\n")), http.StatusSeeOther)
			return
		}
		flash = "Revocation and rejection evidence recorded for every enumerated certificate."
	case "release":
		err = a.resolver.Release(ctx, grantID, actor)
		flash = "Released. Nothing was reissued; enroll the device again with a new link."
	default:
		http.NotFound(w, r)
		return
	}
	switch {
	case errors.Is(err, sqlite.ErrResolutionOrder):
		a.log.Warn("quarantine step out of order", "grant", grantID, "step", r.PathValue("step"), "actor", actor)
		http.Error(w, "The previous step's evidence is required first.", http.StatusConflict)
		return
	case errors.Is(err, quarantine.ErrBackendUnavailable):
		http.Redirect(w, r, back+"?error="+url.QueryEscape("This hold's certificate backend cannot produce verifiable evidence for that step. The hold remains; resolve it at the backend CA and keep the device off the network."), http.StatusSeeOther)
		return
	case errors.Is(err, quarantine.ErrEvidence):
		http.Redirect(w, r, back+"?error="+url.QueryEscape("Stored evidence does not satisfy the release contract: "+err.Error()), http.StatusSeeOther)
		return
	case err != nil:
		a.log.Error("quarantine step", "grant", grantID, "step", r.PathValue("step"), "actor", actor, "err", err)
		http.Redirect(w, r, back+"?error="+url.QueryEscape("The step was not recorded: "+err.Error()), http.StatusSeeOther)
		return
	}
	a.log.Info("quarantine step recorded", "grant", grantID, "step", r.PathValue("step"), "actor", actor)
	if r.PathValue("step") == "release" {
		http.Redirect(w, r, "/admin/quarantine?flash="+url.QueryEscape(flash), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"?flash="+url.QueryEscape(flash), http.StatusSeeOther)
}

// radiusRejectionBody is the JSON an acceptance point posts after it rejects a
// certificate.
type radiusRejectionBody struct {
	AcceptancePoint string `json:"acceptance_point"`
	Serial          string `json:"serial"`
	ObservedAt      string `json:"observed_at"`
	Source          string `json:"source"`
}

// handleRadiusRejection ingests an observed Access-Reject from a configured
// acceptance point. Bearer token authentication; no session, no CSRF. The
// acceptance point must be one the server knows, so a stray report cannot
// invent coverage.
func (a *App) handleRadiusRejection(w http.ResponseWriter, r *http.Request) {
	if a.radiusToken == "" || a.resolver == nil {
		http.NotFound(w, r)
		return
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(authz, prefix)), []byte(a.radiusToken)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var body radiusRejectionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	known := false
	for _, p := range a.resolver.AcceptancePoints() {
		if p == body.AcceptancePoint {
			known = true
		}
	}
	serial := strings.ToLower(strings.TrimSpace(body.Serial))
	if !known || serial == "" || len(serial) > 64 || strings.Trim(serial, "0123456789abcdef") != "" {
		http.Error(w, "unknown acceptance point or invalid serial", http.StatusBadRequest)
		return
	}
	observed, err := time.Parse(time.RFC3339, body.ObservedAt)
	if err != nil || observed.After(time.Now().Add(5*time.Minute)) {
		http.Error(w, "observed_at must be RFC 3339 and not in the future", http.StatusBadRequest)
		return
	}
	store, ok := a.quarantine.(resolutionStore)
	if !ok {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := store.InsertRadiusRejection(r.Context(), sqlite.RadiusRejection{Serial: serial, AcceptancePoint: body.AcceptancePoint, ObservedAt: observed.UTC().Format(time.RFC3339), Source: strings.TrimSpace(body.Source)}); err != nil {
		http.Error(w, "not recorded", http.StatusInternalServerError)
		return
	}
	a.log.Info("radius rejection ingested", "point", body.AcceptancePoint, "serial", serial)
	w.WriteHeader(http.StatusNoContent)
}
