package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
)

// roleSetter changes roles and revokes sessions in the account store.
type roleSetter interface {
	SetRole(ctx context.Context, username string, role auth.Role) error
}

// usersUnavailable renders the guard page shown when no local-account backend
// has been installed via SetUsers.
func (a *App) usersUnavailable(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, http.StatusServiceUnavailable, "error.html", map[string]any{
		"Title": "Users", "Message": "User management is unavailable — no local account store is wired.",
	})
}

func (a *App) handleUsers(w http.ResponseWriter, r *http.Request) {
	if a.users == nil {
		a.usersUnavailable(w, r)
		return
	}
	a.renderUsers(w, r, nil)
}

// renderUsers lists local accounts; created (if non-nil) shows a just-created
// or just-reset account's generated password inline (the password is never
// redirected or logged — it exists only in this response, like a grant's
// one-time link).
func (a *App) renderUsers(w http.ResponseWriter, r *http.Request, created map[string]any) {
	users, err := a.users.ListUsers(r.Context())
	if err != nil {
		a.log.Error("list users", "err", err)
	}
	_, canSetRole := a.users.(roleSetter)
	a.render(w, r, http.StatusOK, "users.html", map[string]any{
		"Title":        "Users",
		"Users":        users,
		"Created":      created,
		"CanSetRole":   canSetRole,
		"RoleMappings": a.cfg.RoleMappings,
		"LDAPEnabled":  a.cfg.LDAPEnabled,
		"OIDCEnabled":  a.oidc != nil,
		"Flash":        r.URL.Query().Get("flash"),
		"Error":        r.URL.Query().Get("error"),
	})
}

func (a *App) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if a.users == nil {
		a.usersUnavailable(w, r)
		return
	}
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	f := r.PostFormValue

	username := strings.TrimSpace(f("username"))
	if username == "" {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("A username is required."), http.StatusSeeOther)
		return
	}
	role := auth.Role(f("role"))
	if !role.Valid() {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Choose a valid role."), http.StatusSeeOther)
		return
	}

	password := f("password")
	generated := false
	if password == "" {
		var err error
		if password, err = generatePassword(); err != nil {
			a.log.Error("generate password", "err", err)
			http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Generating a password failed."), http.StatusSeeOther)
			return
		}
		generated = true
	}

	if err := a.users.CreateUser(r.Context(), username, password, role, strings.TrimSpace(f("display_name"))); err != nil {
		a.log.Error("create user", "username", username, "err", err)
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	a.log.Info("local user created", "username", username, "role", role,
		"user", sessionFrom(r).Identity.Username) // never logs the password

	if generated {
		a.renderUsers(w, r, map[string]any{"Username": username, "Password": password, "Reset": false})
		return
	}
	http.Redirect(w, r, "/admin/users?flash="+url.QueryEscape("User "+username+" created."), http.StatusSeeOther)
}

func (a *App) handleUserPasswd(w http.ResponseWriter, r *http.Request) {
	if a.users == nil {
		a.usersUnavailable(w, r)
		return
	}
	limitForm(w, r)
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	username := r.PathValue("username")

	password := r.PostFormValue("password")
	generated := false
	if password == "" {
		var err error
		if password, err = generatePassword(); err != nil {
			a.log.Error("generate password", "err", err)
			http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Generating a password failed."), http.StatusSeeOther)
			return
		}
		generated = true
	}

	if err := a.users.SetPassword(r.Context(), username, password); err != nil {
		a.log.Error("set password", "username", username, "err", err)
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	a.log.Info("local user password reset", "username", username,
		"user", sessionFrom(r).Identity.Username) // never logs the password

	if generated {
		a.renderUsers(w, r, map[string]any{"Username": username, "Password": password, "Reset": true})
		return
	}
	http.Redirect(w, r, "/admin/users?flash="+url.QueryEscape("Password for "+username+" updated."), http.StatusSeeOther)
}

func (a *App) handleUserRole(w http.ResponseWriter, r *http.Request) {
	if a.users == nil {
		a.usersUnavailable(w, r)
		return
	}
	limitForm(w, r)
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	username := r.PathValue("username")
	role := auth.Role(r.PostFormValue("role"))
	if !role.Valid() {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Choose a valid role."), http.StatusSeeOther)
		return
	}
	rs, ok := a.users.(roleSetter)
	if !ok {
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("The account store does not support role changes."), http.StatusSeeOther)
		return
	}
	// Refuse to demote the last admin — that would lock the console permanently,
	// the same invariant LocalStore enforces for deletion.
	if role != auth.RoleAdmin {
		if last, err := a.isLastAdmin(r.Context(), username); err != nil {
			a.log.Error("check last admin", "username", username, "err", err)
			http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Changing the role failed."), http.StatusSeeOther)
			return
		} else if last {
			http.Redirect(w, r, "/admin/users?error="+url.QueryEscape("Refusing to demote the last admin account."), http.StatusSeeOther)
			return
		}
	}
	if err := rs.SetRole(r.Context(), username, role); err != nil {
		a.log.Error("set role", "username", username, "role", role, "err", err)
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	a.log.Info("local user role changed", "username", username, "role", role,
		"user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, "/admin/users?flash="+url.QueryEscape("Role for "+username+" set to "+string(role)+"."), http.StatusSeeOther)
}

func (a *App) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if a.users == nil {
		a.usersUnavailable(w, r)
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	username := r.PathValue("username")
	if err := a.users.DeleteUser(r.Context(), username); err != nil {
		// Surfaces LocalStore's last-admin refusal verbatim rather than a
		// generic failure — the operator needs to know why nothing happened.
		a.log.Error("delete user", "username", username, "err", err)
		http.Redirect(w, r, "/admin/users?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	a.log.Info("local user deleted", "username", username, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, "/admin/users?flash="+url.QueryEscape("User "+username+" deleted."), http.StatusSeeOther)
}

// isLastAdmin reports whether username is currently the only admin account.
func (a *App) isLastAdmin(ctx context.Context, username string) (bool, error) {
	users, err := a.users.ListUsers(ctx)
	if err != nil {
		return false, err
	}
	admins, isAdmin := 0, false
	for _, u := range users {
		if u.Role == auth.RoleAdmin {
			admins++
			if u.Username == username {
				isAdmin = true
			}
		}
	}
	return isAdmin && admins <= 1, nil
}

// generatePassword returns a fresh high-entropy password (18 random bytes,
// URL-safe base64 → 24 characters) for the generate-on-create/reset flows.
func generatePassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
