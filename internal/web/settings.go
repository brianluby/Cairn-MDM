package web

import (
	"net/http"
)

// handleSettings renders a read-only view of the running configuration: what
// the app already knows from its Config plus which auth sources are wired.
// Secrets (the SCEP challenge) are shown only as configured/none, never their
// value. There is deliberately nothing to edit here — configuration lives in
// the config file, and this page just makes the effective values visible.
func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	localUsers := -1
	if a.users != nil {
		if n, err := a.users.CountUsers(r.Context()); err == nil {
			localUsers = n
		} else {
			a.log.Error("count users", "err", err)
		}
	}
	a.render(w, r, http.StatusOK, "settings.html", map[string]any{
		"Title":            "Settings",
		"Checks":           a.setupChecks(r.Context()),
		"CAMode":           a.cfg.CAMode,
		"TLSMode":          a.cfg.TLSMode,
		"PublicURL":        a.cfg.PublicURL,
		"Organization":     a.cfg.Organization,
		"SCEPURL":          a.cfg.SCEPURL,
		"SCEPChallengeSet": a.cfg.SCEPChallenge != "",
		"CAAnchors":        len(a.cfg.CAAnchorsDER),
		"TrustedProxies":   a.cfg.TrustedProxies,
		"LocalEnabled":     a.users != nil,
		"LocalUsers":       localUsers,
		"OIDCEnabled":      a.oidc != nil,
	})
}
