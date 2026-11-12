package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/vpn"
)

// VPNServers is the catalogue of OpenVPN server records; *vpn.Servers provides it.
type VPNServers interface {
	List(ctx context.Context) ([]vpn.Server, error)
	Get(ctx context.Context, id int64) (vpn.Server, error)
	Create(ctx context.Context, s vpn.Server, actor string) (int64, error)
	Update(ctx context.Context, s vpn.Server, actor string) error
	Delete(ctx context.Context, id int64, actor string) error
}

// SetVPN installs the VPN server catalogue. Nil leaves the VPN pages off.
func (a *App) SetVPN(s VPNServers) { a.vpn = s }

func (a *App) registerVPN(mux *http.ServeMux) {
	mux.Handle("GET /admin/vpn", a.requireRole(auth.RoleAdmin, a.handleVPN))
	mux.Handle("GET /admin/vpn/new", a.requireRole(auth.RoleAdmin, a.handleVPNServerNew))
	mux.Handle("POST /admin/vpn/new", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNServerCreate)))
	mux.Handle("POST /admin/vpn/import", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNServerImport)))
	mux.Handle("GET /admin/vpn/{id}", a.requireRole(auth.RoleAdmin, a.handleVPNServerEdit))
	mux.Handle("POST /admin/vpn/{id}", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNServerUpdate)))
	mux.Handle("POST /admin/vpn/{id}/delete", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNServerDelete)))
}

func (a *App) vpnAvailable(w http.ResponseWriter) bool {
	if a.vpn == nil {
		http.Error(w, "VPN profiles are not enabled. Set [vpn] enabled = true in cairn.toml.", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// vpnChange gates every write to a server record: a changed address, CA or
// shared key reaches every profile rendered afterwards, so it needs the same
// fresh second factor as authorizing an enrollment.
func (a *App) vpnChange(w http.ResponseWriter, r *http.Request) bool {
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return false
	}
	if !a.vpnAvailable(w) {
		return false
	}
	s := sessionFrom(r)
	if s == nil || a.mfa == nil || a.mfa.Fresh(r.Context(), s.Token) != nil {
		http.Error(w, "Fresh MFA required. Open Account security, verify your code, then submit again.", http.StatusForbidden)
		return false
	}
	return true
}

// vpnServerForm is a server record as form text, so a rejected submission can be
// shown again as typed.
type vpnServerForm struct {
	ID             int64
	Name           string
	Slug           string
	Remotes        string
	VerifyX509Name string
	CAPEM          string
	TLSKeyMode     string
	KeyDirection   string
	TLSKey         string
	HasStoredKey   bool
	Cipher         string
	Auth           string
	TunMTU         string
	UserAuth       bool
	OnDemand       bool
	Extra          string
}

func formFromServer(s vpn.Server, showKey bool) vpnServerForm {
	f := vpnServerForm{
		ID: s.ID, Name: s.Name, Slug: s.Slug, VerifyX509Name: s.VerifyX509Name, CAPEM: s.CAPEM,
		TLSKeyMode: s.TLSKeyMode, KeyDirection: strconv.Itoa(s.KeyDirection),
		HasStoredKey: s.ID != 0 && s.TLSKey != "", Cipher: s.Cipher, Auth: s.Auth,
		UserAuth: s.UserAuth, OnDemand: s.OnDemand,
	}
	if showKey {
		f.TLSKey = s.TLSKey
	}
	if s.TunMTU != 0 {
		f.TunMTU = strconv.Itoa(s.TunMTU)
	}
	var lines []string
	for _, r := range s.Remotes {
		lines = append(lines, fmt.Sprintf("%s %d %s", r.Host, r.Port, r.Proto))
	}
	f.Remotes = strings.Join(lines, "\n")
	lines = nil
	for _, d := range s.Extra {
		lines = append(lines, strings.TrimSpace(d.Name+" "+d.Value))
	}
	f.Extra = strings.Join(lines, "\n")
	return f
}

func formFromRequest(r *http.Request) vpnServerForm {
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	return vpnServerForm{
		Name: v("name"), Slug: v("slug"), Remotes: r.PostFormValue("remotes"),
		VerifyX509Name: v("verify_x509_name"), CAPEM: v("ca_pem"),
		TLSKeyMode: v("tls_key_mode"), KeyDirection: v("key_direction"), TLSKey: r.PostFormValue("tls_key"),
		Cipher: v("cipher"), Auth: v("auth"), TunMTU: v("tun_mtu"),
		UserAuth: r.PostFormValue("user_auth") == "on", OnDemand: r.PostFormValue("on_demand") == "on",
		Extra: r.PostFormValue("extra"),
	}
}

func (f vpnServerForm) server() (vpn.Server, error) {
	s := vpn.Server{
		ID: f.ID, Name: f.Name, Slug: f.Slug, VerifyX509Name: f.VerifyX509Name, CAPEM: f.CAPEM,
		TLSKeyMode: f.TLSKeyMode, TLSKey: vpn.NormalizeStaticKey(f.TLSKey),
		Cipher: f.Cipher, Auth: f.Auth, UserAuth: f.UserAuth, OnDemand: f.OnDemand,
	}
	for _, line := range strings.Split(f.Remotes, "\n") {
		p := strings.Fields(line)
		if len(p) == 0 {
			continue
		}
		if len(p) != 3 {
			return s, fmt.Errorf("server address %q must be \"host port udp\" or \"host port tcp\"", strings.TrimSpace(line))
		}
		port, err := strconv.Atoi(p[1])
		if err != nil {
			return s, fmt.Errorf("port %q is not a number", p[1])
		}
		s.Remotes = append(s.Remotes, vpn.Remote{Host: p[0], Port: port, Proto: p[2]})
	}
	if f.KeyDirection != "" {
		n, err := strconv.Atoi(f.KeyDirection)
		if err != nil {
			return s, errors.New("key direction must be 0 or 1")
		}
		s.KeyDirection = n
	}
	if f.TunMTU != "" {
		n, err := strconv.Atoi(f.TunMTU)
		if err != nil {
			return s, errors.New("tunnel MTU must be a number")
		}
		s.TunMTU = n
	}
	for _, line := range strings.Split(f.Extra, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, _ := strings.Cut(line, " ")
		s.Extra = append(s.Extra, vpn.Directive{Name: name, Value: strings.TrimSpace(value)})
	}
	return s, nil
}

func (a *App) handleVPN(w http.ResponseWriter, r *http.Request) {
	if !a.vpnAvailable(w) {
		return
	}
	servers, err := a.vpn.List(r.Context())
	if err != nil {
		a.log.Error("list vpn servers", "err", err)
		http.Error(w, "Cannot read VPN servers. Check that the VPN key file matches this database.", http.StatusServiceUnavailable)
		return
	}
	a.render(w, r, http.StatusOK, "vpn.html", map[string]any{
		"Title": "VPN", "Servers": servers, "Flash": r.URL.Query().Get("flash"),
	})
}

func (a *App) renderVPNServer(w http.ResponseWriter, r *http.Request, status int, f vpnServerForm, message string, skipped []string) {
	w.Header().Set("Cache-Control", "no-store")
	a.render(w, r, status, "vpn_server.html", map[string]any{
		"Title": "VPN", "Form": f, "Error": message, "Skipped": skipped, "New": f.ID == 0,
	})
}

func (a *App) handleVPNServerNew(w http.ResponseWriter, r *http.Request) {
	if !a.vpnAvailable(w) {
		return
	}
	a.renderVPNServer(w, r, http.StatusOK, vpnServerForm{KeyDirection: "1", TLSKeyMode: vpn.TLSKeyAuth}, "", nil)
}

// handleVPNServerImport reads a client .ovpn file into the new-server form. It
// stores nothing: the administrator reviews the fields and submits the form.
func (a *App) handleVPNServerImport(w http.ResponseWriter, r *http.Request) {
	if !a.vpnChange(w, r) {
		return
	}
	imp, err := vpn.ImportOVPN(r.PostFormValue("ovpn"))
	if err != nil {
		a.renderVPNServer(w, r, http.StatusBadRequest, vpnServerForm{KeyDirection: "1"}, "Cannot read the file: "+err.Error()+".", nil)
		return
	}
	notes := imp.Skipped
	if imp.HadIdentity {
		notes = append(notes, "client certificate and key (never stored in a server record)")
	}
	a.renderVPNServer(w, r, http.StatusOK, formFromServer(imp.Server, true), "", notes)
}

func (a *App) handleVPNServerCreate(w http.ResponseWriter, r *http.Request) {
	if !a.vpnChange(w, r) {
		return
	}
	f := formFromRequest(r)
	if f.Slug == "" {
		f.Slug = vpn.Slugify(f.Name)
	}
	s, err := f.server()
	if err == nil {
		_, err = a.vpn.Create(r.Context(), s, sessionFrom(r).Identity.Username)
	}
	if err != nil {
		a.renderVPNServer(w, r, http.StatusBadRequest, f, vpnFormError(err), nil)
		return
	}
	a.log.Info("vpn server created", "slug", s.Slug, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, "/admin/vpn?flash="+url.QueryEscape("Server saved."), http.StatusSeeOther)
}

func (a *App) vpnServerFromPath(w http.ResponseWriter, r *http.Request) (vpn.Server, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return vpn.Server{}, false
	}
	s, err := a.vpn.Get(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return vpn.Server{}, false
	}
	if err != nil {
		a.log.Error("get vpn server", "id", id, "err", err)
		http.Error(w, "Cannot read this VPN server.", http.StatusServiceUnavailable)
		return vpn.Server{}, false
	}
	return s, true
}

func (a *App) handleVPNServerEdit(w http.ResponseWriter, r *http.Request) {
	if !a.vpnAvailable(w) {
		return
	}
	s, ok := a.vpnServerFromPath(w, r)
	if !ok {
		return
	}
	// The stored key is never sent back to the browser.
	a.renderVPNServer(w, r, http.StatusOK, formFromServer(s, false), "", nil)
}

func (a *App) handleVPNServerUpdate(w http.ResponseWriter, r *http.Request) {
	if !a.vpnChange(w, r) {
		return
	}
	current, ok := a.vpnServerFromPath(w, r)
	if !ok {
		return
	}
	f := formFromRequest(r)
	f.ID, f.Slug = current.ID, current.Slug
	f.HasStoredKey = current.TLSKey != ""
	s, err := f.server()
	if err == nil {
		err = a.vpn.Update(r.Context(), s, sessionFrom(r).Identity.Username)
	}
	if err != nil {
		a.renderVPNServer(w, r, http.StatusBadRequest, f, vpnFormError(err), nil)
		return
	}
	a.log.Info("vpn server updated", "slug", current.Slug, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, "/admin/vpn?flash="+url.QueryEscape("Server saved. Profiles already on devices keep their old settings until they are issued again."), http.StatusSeeOther)
}

func (a *App) handleVPNServerDelete(w http.ResponseWriter, r *http.Request) {
	if !a.vpnChange(w, r) {
		return
	}
	s, ok := a.vpnServerFromPath(w, r)
	if !ok {
		return
	}
	if err := a.vpn.Delete(r.Context(), s.ID, sessionFrom(r).Identity.Username); err != nil {
		a.log.Error("delete vpn server", "slug", s.Slug, "err", err)
		http.Error(w, "Cannot delete this VPN server.", http.StatusConflict)
		return
	}
	a.log.Info("vpn server deleted", "slug", s.Slug, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, "/admin/vpn?flash="+url.QueryEscape("Server deleted. Profiles already on devices are not removed."), http.StatusSeeOther)
}

func vpnFormError(err error) string {
	if errors.Is(err, sqlite.ErrVPNServerExists) {
		return "Another server already uses this identifier. Choose a different one."
	}
	msg := err.Error()
	return strings.ToUpper(msg[:1]) + msg[1:] + "."
}
