package web

import (
	"net/http"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
)

func (a *App) SetMFA(m *auth.MFAStore)                          { a.mfa = m }
func (a *App) handleMFA(w http.ResponseWriter, r *http.Request) { a.renderMFA(w, r, map[string]any{}) }
func (a *App) renderMFA(w http.ResponseWriter, r *http.Request, data map[string]any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	data["Title"] = "Account security"
	data["Available"] = a.mfa != nil
	status := http.StatusOK
	if data["Error"] != nil {
		status = http.StatusBadRequest
	}
	a.render(w, r, status, "mfa.html", data)
}
func (a *App) handleMFAAction(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", 403)
		return
	}
	if a.mfa == nil {
		http.Error(w, "MFA unavailable", 503)
		return
	}
	data := map[string]any{}
	token := sessionFrom(r).Token
	var err error
	switch r.PathValue("action") {
	case "begin":
		setup, e := a.mfa.Begin(r.Context(), token, strings.TrimSpace(r.PostFormValue("invitation")))
		err = e
		if err == nil {
			data["Setup"] = setup
			data["QR"] = qrDataURI(setup.URI)
		}
	case "confirm":
		data["Codes"], err = a.mfa.Confirm(r.Context(), token, strings.TrimSpace(r.PostFormValue("code")))
	case "verify":
		err = a.mfa.Verify(r.Context(), token, strings.TrimSpace(r.PostFormValue("code")))
		if err == nil {
			data["Message"] = "Second factor verified for five minutes."
		}
	case "recover":
		data["Invitation"], err = a.mfa.Recover(r.Context(), token, strings.TrimSpace(r.PostFormValue("recovery")))
		if err == nil {
			data["Message"] = "Previous factor, recovery codes and other sessions revoked. Use this approval code to register your replacement authenticator."
		}
	case "invite":
		// Check before directory access, and recheck transactionally in Invite.
		if sessionFrom(r).Identity.Role != auth.RoleAdmin || a.mfa.Fresh(r.Context(), token) != nil {
			http.Error(w, "Administrator access and fresh MFA required", 403)
			return
		}
		var target auth.Identity
		name := strings.TrimSpace(r.PostFormValue("account"))
		switch r.PostFormValue("provider") {
		case "local":
			target, err = a.mfa.LocalIdentity(r.Context(), name)
		case "ldap":
			if a.directory == nil {
				err = auth.ErrMFA
			} else {
				var owner *auth.DirectoryIdentity
				owner, err = a.directory.ResolveOwner(r.Context(), name)
				target = auth.Identity{Provider: "ldap", Directory: owner}
			}
		default:
			err = auth.ErrMFA
		}
		if err == nil {
			data["Invitation"], err = a.mfa.Invite(r.Context(), token, target, r.PostFormValue("reset") == "yes")
		}
		if err == nil {
			data["Message"] = "Approval code created for the selected account. It expires in 15 minutes. Provide it only after verifying the person's identity. They must sign in as that account to use it."
		}
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		data["Error"] = "Request not accepted. Check the account, approval or authenticator code and its expiry. After five failed attempts, wait 15 minutes. Existing MFA requires a recovery code or administrator reset."
	}
	a.renderMFA(w, r, data)
}
