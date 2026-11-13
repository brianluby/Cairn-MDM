package web

import (
	"context"
	"encoding/base64"
	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func (a *App) handleEnrollment(w http.ResponseWriter, r *http.Request) {
	a.renderEnrollment(w, r, nil)
}

// renderEnrollment lists grants; created (if non-nil) shows a just-created
// grant's one-time link + QR inline (the raw token is never redirected or
// logged — it exists only in this response).
func (a *App) renderEnrollment(w http.ResponseWriter, r *http.Request, created map[string]any) {
	grants, err := a.grants.ListGrants(r.Context())
	if err != nil {
		a.log.Error("list grants", "err", err)
	}
	groups, err := a.groups.ListGroups(r.Context())
	if err != nil {
		a.log.Error("list groups", "err", err)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "strict-origin")
	a.render(w, r, http.StatusOK, "enrollment.html", map[string]any{
		"Title":   "Enrollment",
		"Grants":  grants,
		"Groups":  groups,
		"Created": created,
		"Flash":   r.URL.Query().Get("flash"),
		"Error":   r.URL.Query().Get("error"),
	})
}

func (a *App) handleGrantCreate(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	if !a.enrollmentActor(w, r) {
		return
	}
	if !a.cfg.OwnerEnrollment {
		http.Error(w, "Enrollment is paused while certificate authorization is configured. Owner previews remain available.", 503)
		return
	}
	store, ok := a.grants.(authorizedGrantStore)
	if !ok {
		http.Error(w, "Enrollment authorization unavailable", 503)
		return
	}
	preview, err := store.GetEnrollmentPreview(r.Context(), sessionFrom(r).Token, r.PostFormValue("preview"))
	if err != nil {
		http.Error(w, "Preview expired or already used. Preview the owner again.", 409)
		return
	}
	checked, err := a.directory.EvaluateScopes(r.Context(), preview.Owner, nil)
	if err != nil || checked == nil {
		http.Error(w, "Owner verification unavailable. No link created.", 503)
		return
	}
	raw, hash := sqlite.NewGrantToken()
	id, err := store.CreateAuthorizedGrant(r.Context(), sessionFrom(r).Token, r.PostFormValue("preview"), hash, checked.Owner)
	if err != nil {
		http.Error(w, "Authorization changed or expired. Verify MFA and preview the owner again.", 409)
		return
	}
	hours := preview.Hours

	link := strings.TrimRight(a.cfg.PublicURL, "/") + "/e/" + raw
	a.log.Info("enrollment grant created", "id", id, "owner", checked.Owner.UPN, "platform", preview.Platform,
		"user", sessionFrom(r).Identity.Username) // never logs the raw token

	created := map[string]any{"Link": link, "QR": qrDataURI(link), "ExpiresHours": hours}
	a.renderEnrollment(w, r, created)
}

func (a *App) handleGrantRevoke(w http.ResponseWriter, r *http.Request) {
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := a.grants.RevokeGrant(r.Context(), id); err != nil {
		a.log.Error("revoke grant", "id", id, "err", err)
		http.Redirect(w, r, "/admin/enrollment?error="+url.QueryEscape("Revoke failed."), http.StatusSeeOther)
		return
	}
	a.log.Info("enrollment grant revoked", "id", id, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, "/admin/enrollment?flash="+url.QueryEscape("Grant revoked."), http.StatusSeeOther)
}

// qrDataURI renders a QR PNG for s as a data: URI (self-contained, no external
// requests — CSP-safe under img-src 'self' data:). Returned as template.URL
// because html/template otherwise rewrites data: URLs in src to #ZgotmplZ; the
// value is safe because we generate it here from a QR encode, not user HTML.
func qrDataURI(s string) template.URL {
	png, err := qrcode.Encode(s, qrcode.Medium, 256)
	if err != nil {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
}

type authorizedGrantStore interface {
	SaveEnrollmentPreview(context.Context, string, sqlite.EnrollmentPreview) (string, error)
	GetEnrollmentPreview(context.Context, string, string) (sqlite.EnrollmentPreview, error)
	CreateAuthorizedGrant(context.Context, string, string, string, directory.DirectoryIdentity) (int64, error)
}

func (a *App) enrollmentActor(w http.ResponseWriter, r *http.Request) bool {
	s := sessionFrom(r)
	if s == nil || s.Identity.Role != auth.RoleAdmin || a.mfa == nil || a.mfa.Fresh(r.Context(), s.Token) != nil {
		http.Error(w, "Administrator access and fresh MFA required. Open Account security to verify your code.", 403)
		return false
	}
	if a.directory == nil {
		http.Error(w, "Configure a verified LDAP directory before enrolling an owner.", 503)
		return false
	}
	if !a.directoryAdminCurrent(r) {
		http.Error(w, "Current directory administrator authorization unavailable.", 403)
		return false
	}
	return true
}
func (a *App) handleEnrollmentPreview(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	if !a.enrollmentActor(w, r) {
		return
	}
	platform := r.PostFormValue("platform")
	hours, e := strconv.Atoi(r.PostFormValue("expires_hours"))
	if e != nil || hours < 1 || hours > 24 || (platform != "macos" && platform != "ios") {
		http.Error(w, "Choose Mac or iPhone/iPad and an expiry from 1 to 24 hours.", 400)
		return
	}
	var explicitGroup sqlite.Group
	if raw := strings.TrimSpace(r.PostFormValue("group_id")); raw != "" {
		gid, e := strconv.ParseInt(raw, 10, 64)
		if e == nil {
			explicitGroup, e = a.groups.GetGroup(r.Context(), gid)
		}
		if e != nil {
			http.Error(w, "Choose an existing Cairn group or leave it blank.", 400)
			return
		}
	}
	owner, e := a.directory.ResolveOwner(r.Context(), strings.TrimSpace(r.PostFormValue("owner")))
	if e != nil || owner == nil {
		http.Error(w, "Cannot resolve an enabled, eligible AD owner.", 422)
		return
	}
	// Owner verification and rule preview share one directory round: the rule
	// results are display only, and the same evaluation runs again after enrollment.
	var rules []sqlite.DirectoryProfileRule
	if rs, ok := a.groups.(directoryRuleStore); ok {
		if rules, e = rs.ListDirectoryProfileRules(r.Context()); e != nil {
			http.Error(w, "Cannot load directory rules.", 503)
			return
		}
	}
	scopes := make([]auth.DirectoryScope, len(rules))
	for i, rule := range rules {
		scopes[i] = rule.Scope
	}
	result, e := a.directory.EvaluateScopes(r.Context(), *owner, scopes)
	if e != nil || result == nil || len(result.Matches) != len(rules) {
		http.Error(w, "Owner verification unavailable.", 503)
		return
	}
	profiles, conflicts, e := a.rulePreviewProfiles(r.Context(), rules, result, explicitGroup.ID)
	if e != nil {
		http.Error(w, "Cannot read assigned profiles.", 503)
		return
	}
	p := sqlite.EnrollmentPreview{Owner: result.Owner, Platform: platform, Hours: hours, Label: strings.TrimSpace(r.PostFormValue("label")), GroupID: explicitGroup.ID, GroupName: explicitGroup.Name}
	if len(p.Label) > 200 {
		http.Error(w, "Device label must be at most 200 bytes.", 400)
		return
	}
	store, ok := a.grants.(authorizedGrantStore)
	if !ok {
		http.Error(w, "Enrollment authorization unavailable", 503)
		return
	}
	token, e := store.SaveEnrollmentPreview(r.Context(), sessionFrom(r).Token, p)
	if e != nil {
		http.Error(w, "Cannot save preview", 503)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "strict-origin")
	a.render(w, r, 200, "enrollment_preview.html", map[string]any{
		"Title": "Confirm device owner", "Preview": p, "Token": token,
		"IssuanceReady": a.cfg.OwnerEnrollment && len(conflicts) == 0,
		"Matches":       result.Matches, "PreviewProfiles": profiles, "Conflicts": conflicts,
	})
}
