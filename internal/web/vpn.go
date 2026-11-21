package web

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
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

// VPNServers is the catalogue of VPN server records; *vpn.Servers provides it.
type VPNServers interface {
	List(ctx context.Context) ([]vpn.Server, error)
	Get(ctx context.Context, id int64) (vpn.Server, error)
	Create(ctx context.Context, s vpn.Server, actor string) (int64, error)
	Update(ctx context.Context, s vpn.Server, actor string) error
	Delete(ctx context.Context, id int64, actor string) error
}

// VPNIssuer issues VPN certificates and delivers their profiles; *vpn.Service
// provides it.
type VPNIssuer interface {
	Issue(ctx context.Context, deviceID string, serverID int64, account, actor string) (sqlite.VPNIdentity, error)
	Remove(ctx context.Context, deviceID string, serverID int64, actor string) error
	Withdraw(ctx context.Context, deviceID string, serverID int64, actor string) (bool, error)
	Download(ctx context.Context, serverID int64, account, actor string) (filename string, profile []byte, err error)
	Revoke(ctx context.Context, identityID int64, actor string) error
	ConfirmRevokedAtCA(ctx context.Context, identityID int64, actor string) error
	CanRevoke() bool
	CanRevokeIdentity(v sqlite.VPNIdentity) bool
}

// VPNIdentityStore reads issued VPN certificates; *sqlite.DB provides it.
type VPNIdentityStore interface {
	GetVPNIdentity(ctx context.Context, id int64) (sqlite.VPNIdentity, error)
	DeviceVPNIdentities(ctx context.Context, deviceID string) ([]sqlite.VPNIdentity, error)
	CurrentVPNIdentities(ctx context.Context) ([]sqlite.VPNIdentity, error)
	QuarantinedVPNIdentities(ctx context.Context) ([]sqlite.VPNIdentity, error)
	VPNIdentitiesAwaitingRevocation(ctx context.Context) ([]sqlite.VPNIdentity, error)
	OpenVPNOffers(ctx context.Context, deviceID string) ([]sqlite.VPNOffer, error)
}

// SetVPN installs the VPN server catalogue. Nil leaves the VPN pages off.
func (a *App) SetVPN(s VPNServers) { a.vpn = s }

// SetVPNIssuer turns on issuing from the device page. why says, for the
// console, what is missing when issuer is nil.
func (a *App) SetVPNIssuer(issuer VPNIssuer, identities VPNIdentityStore, why string) {
	a.vpnIssuer, a.vpnIdentities, a.vpnIssuerMissing = issuer, identities, why
}

func (a *App) registerVPN(mux *http.ServeMux) {
	a.registerManual(mux)
	mux.Handle("GET /admin/vpn", a.requireRole(auth.RoleAdmin, a.handleVPN))
	// Wi-Fi networks are the same records under their own page and addresses.
	mux.Handle("GET /admin/wifi", a.requireRole(auth.RoleAdmin, a.handleWiFi))
	mux.Handle("GET /admin/wifi/new", a.requireRole(auth.RoleAdmin, a.handleWiFiNew))
	mux.Handle("POST /admin/wifi/new", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNServerCreate)))
	mux.Handle("GET /admin/wifi/{id}", a.requireRole(auth.RoleAdmin, a.handleVPNServerEdit))
	mux.Handle("POST /admin/wifi/{id}", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNServerUpdate)))
	mux.Handle("POST /admin/wifi/{id}/delete", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNServerDelete)))
	mux.Handle("GET /admin/vpn/new", a.requireRole(auth.RoleAdmin, a.handleVPNServerNew))
	mux.Handle("POST /admin/vpn/new", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNServerCreate)))
	mux.Handle("POST /admin/vpn/import", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNServerImport)))
	mux.Handle("GET /admin/vpn/{id}", a.requireRole(auth.RoleAdmin, a.handleVPNServerEdit))
	mux.Handle("POST /admin/vpn/{id}", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNServerUpdate)))
	mux.Handle("POST /admin/vpn/{id}/download", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNDownload)))
	mux.Handle("POST /admin/vpn/{id}/delete", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNServerDelete)))
	mux.Handle("POST /admin/devices/{id}/vpn/{server}/issue", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNIssue)))
	mux.Handle("POST /admin/devices/{id}/vpn/{server}/remove", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNRemove)))
	mux.Handle("POST /admin/devices/{id}/vpn/{server}/withdraw", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNWithdraw)))
	mux.Handle("POST /admin/vpn/identities/{id}/revoke", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNRevoke)))
	mux.Handle("POST /admin/vpn/identities/{id}/revoked-at-ca", a.audited(a.requireRole(auth.RoleAdmin, a.handleVPNRevokedAtCA)))
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
	// A session outlives a change in the directory. Someone removed from the
	// administrators group must not keep editing what every later profile trusts.
	if !a.directoryAdminCurrent(r) {
		http.Error(w, "Current directory administrator authorization unavailable.", http.StatusForbidden)
		return false
	}
	return true
}

// directoryAdminCurrent reports whether a directory-backed administrator still
// holds that role in the directory right now. Local administrators have no
// directory to ask and pass.
func (a *App) directoryAdminCurrent(r *http.Request) bool {
	s := sessionFrom(r)
	if s == nil {
		return false
	}
	if s.Identity.Provider != "ldap" {
		return true
	}
	validator, ok := a.directory.(interface {
		RevalidateAdministrator(context.Context, auth.DirectoryIdentity) error
	})
	return ok && s.Identity.Directory != nil && validator.RevalidateAdministrator(r.Context(), *s.Identity.Directory) == nil
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

	// IKEv2 servers.
	Kind               string
	RemoteAddress      string
	RemoteIdentifier   string
	ServerCertIssuerCN string
	ServerCertCN       string
	SignIn             string
	Encryption         string
	Integrity          string
	DHGroup            string
	PFS                bool
	TrustedSSIDs       string
	LockOnDemand       bool
	InstallCA          bool
	KeepPassword       bool
	SplitTunnel        bool

	// Wi-Fi networks.
	SSID        string
	Security    string
	ServerNames string
}

// IKEv2 reports whether the form is for a native IKEv2 server.
func (f vpnServerForm) IKEv2() bool { return f.Kind == vpn.KindIKEv2 }

// WiFi reports whether the form is for a Wi-Fi network.
func (f vpnServerForm) WiFi() bool { return f.Kind == vpn.KindWiFi }

func formFromServer(s vpn.Server, showKey bool) vpnServerForm {
	f := vpnServerForm{
		ID: s.ID, Name: s.Name, Slug: s.Slug, VerifyX509Name: s.VerifyX509Name, CAPEM: s.CAPEM,
		TLSKeyMode: s.TLSKeyMode, KeyDirection: strconv.Itoa(s.KeyDirection),
		HasStoredKey: s.ID != 0 && s.TLSKey != "", Cipher: s.Cipher, Auth: s.Auth,
		UserAuth: s.UserAuth, OnDemand: s.OnDemand,
	}
	if s.IsWiFi() {
		f.Kind, f.SSID, f.Security = vpn.KindWiFi, s.WiFi.SSID, s.WiFi.Security
		f.ServerNames = strings.Join(s.WiFi.ServerNames, "\n")
		return f
	}
	if s.IsIKEv2() {
		k := s.IKEv2
		f.Kind, f.RemoteAddress, f.RemoteIdentifier = vpn.KindIKEv2, k.RemoteAddress, k.RemoteIdentifier
		f.ServerCertIssuerCN, f.ServerCertCN, f.SignIn = k.ServerCertIssuerCN, k.ServerCertCN, k.SignIn
		f.Encryption, f.Integrity, f.DHGroup, f.PFS = k.Encryption, k.Integrity, strconv.Itoa(k.DHGroup), k.PFS
		f.TrustedSSIDs, f.LockOnDemand, f.InstallCA = strings.Join(k.TrustedSSIDs, "\n"), k.LockOnDemand, k.InstallCA
		f.KeepPassword, f.SplitTunnel = k.KeepPassword, k.SplitTunnel
		return f
	}
	if showKey {
		f.TLSKey = s.TLSKey
	}
	if s.TunMTU != 0 {
		f.TunMTU = strconv.Itoa(s.TunMTU)
	}
	var lines []string
	for _, r := range s.Remotes {
		line := fmt.Sprintf("%s %d %s", r.Host, r.Port, r.Proto)
		if r.TunMTU != 0 {
			line += " " + strconv.Itoa(r.TunMTU)
		}
		lines = append(lines, line)
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

		Kind: v("kind"), RemoteAddress: v("remote_address"), RemoteIdentifier: v("remote_identifier"),
		ServerCertIssuerCN: v("server_cert_issuer_cn"), ServerCertCN: v("server_cert_cn"), SignIn: v("sign_in"),
		Encryption: v("encryption"), Integrity: v("integrity"), DHGroup: v("dh_group"),
		PFS: r.PostFormValue("pfs") == "on", TrustedSSIDs: r.PostFormValue("trusted_ssids"),
		LockOnDemand: r.PostFormValue("lock_on_demand") == "on", InstallCA: r.PostFormValue("install_ca") == "on",
		KeepPassword: r.PostFormValue("keep_password") == "on", SplitTunnel: r.PostFormValue("split_tunnel") == "on",

		// A network name may begin or end with a space, so it is not trimmed.
		SSID: r.PostFormValue("ssid"), Security: v("security"), ServerNames: r.PostFormValue("server_names"),
	}
}

func (f vpnServerForm) ikev2Server() (vpn.Server, error) {
	s := vpn.Server{ID: f.ID, Name: f.Name, Slug: f.Slug, Kind: vpn.KindIKEv2, CAPEM: f.CAPEM, OnDemand: f.OnDemand}
	group, err := strconv.Atoi(f.DHGroup)
	if err != nil {
		return s, errors.New("Diffie-Hellman group must be a number")
	}
	s.IKEv2 = vpn.IKEv2{
		RemoteAddress: f.RemoteAddress, RemoteIdentifier: f.RemoteIdentifier,
		ServerCertIssuerCN: f.ServerCertIssuerCN, ServerCertCN: f.ServerCertCN, SignIn: f.SignIn,
		Encryption: f.Encryption, Integrity: f.Integrity, DHGroup: group, PFS: f.PFS, LockOnDemand: f.LockOnDemand, InstallCA: f.InstallCA,
		KeepPassword: f.KeepPassword && f.SignIn == vpn.IKEv2Password, SplitTunnel: f.SplitTunnel,
	}
	// A network name may begin or end with a space, so lines are not trimmed.
	for _, line := range strings.Split(strings.ReplaceAll(f.TrustedSSIDs, "\r", ""), "\n") {
		if line != "" {
			s.IKEv2.TrustedSSIDs = append(s.IKEv2.TrustedSSIDs, line)
		}
	}
	return s, nil
}

func (f vpnServerForm) server() (vpn.Server, error) {
	if f.IKEv2() {
		return f.ikev2Server()
	}
	if f.WiFi() {
		return vpn.Server{ID: f.ID, Name: f.Name, Slug: f.Slug, Kind: vpn.KindWiFi, CAPEM: f.CAPEM,
			WiFi: vpn.WiFi{SSID: f.SSID, Security: f.Security, ServerNames: strings.Fields(f.ServerNames)}}, nil
	}
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
		if len(p) != 3 && len(p) != 4 {
			return s, fmt.Errorf("server address %q must be \"host port udp\" or \"host port tcp\", with an optional tunnel MTU", strings.TrimSpace(line))
		}
		port, err := strconv.Atoi(p[1])
		if err != nil {
			return s, fmt.Errorf("port %q is not a number", p[1])
		}
		remote := vpn.Remote{Host: p[0], Port: port, Proto: p[2]}
		if len(p) == 4 {
			if remote.TunMTU, err = strconv.Atoi(p[3]); err != nil {
				return s, fmt.Errorf("tunnel MTU %q is not a number", p[3])
			}
		}
		s.Remotes = append(s.Remotes, remote)
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

func (a *App) handleVPN(w http.ResponseWriter, r *http.Request) { a.accessPage(w, r, false) }

func (a *App) handleWiFi(w http.ResponseWriter, r *http.Request) { a.accessPage(w, r, true) }

// accessHome is the list page a record belongs on.
func accessHome(s vpn.Server) string {
	if s.IsWiFi() {
		return "/admin/wifi"
	}
	return "/admin/vpn"
}

// accessPage lists VPN servers or Wi-Fi networks with their certificates. The
// two are the same kind of record and are kept on separate pages.
func (a *App) accessPage(w http.ResponseWriter, r *http.Request, wifi bool) {
	if !a.vpnAvailable(w) {
		return
	}
	all, err := a.vpn.List(r.Context())
	if err != nil {
		a.log.Error("list vpn servers", "err", err)
		http.Error(w, "Cannot read VPN servers. Check that the VPN key file matches this database.", http.StatusServiceUnavailable)
		return
	}
	servers := make([]vpn.Server, 0, len(all))
	other := map[int64]bool{} // records that belong on the other page
	for _, s := range all {
		if s.IsWiFi() == wifi {
			servers = append(servers, s)
		} else {
			other[s.ID] = true
		}
	}
	title := "VPN"
	if wifi {
		title = "Wi-Fi"
	}
	data := map[string]any{
		"Title": title, "WiFiPage": wifi, "Servers": servers, "Flash": r.URL.Query().Get("flash"),
		"IssuerMissing": a.vpnIssuerMissing, "CanRevoke": a.vpnIssuer != nil && a.vpnIssuer.CanRevoke(),
	}
	if a.vpnIdentities != nil {
		names := map[string]string{}
		if devices, err := a.devices.ListDevices(r.Context()); err == nil {
			for _, d := range devices {
				names[d.ID] = d.DisplayName()
			}
		}
		if a.manualDevices != nil {
			if devices, err := a.manualDevices.ListManualDevices(r.Context()); err == nil {
				for _, d := range devices {
					names[d.DeviceID()] = d.Name + " (not in MDM)"
				}
			}
		}
		serverNames := map[int64]string{}
		for _, s := range servers {
			serverNames[s.ID] = s.Name
		}
		rows := func(list []sqlite.VPNIdentity, err error) []vpnIdentityRow {
			if err != nil {
				a.log.Error("list vpn identities", "err", err)
			}
			out := make([]vpnIdentityRow, 0, len(list))
			for _, v := range list {
				// A certificate whose record was deleted stays on the VPN page.
				if other[v.ServerID] || (wifi && serverNames[v.ServerID] == "") {
					continue
				}
				out = append(out, vpnIdentityRow{VPNIdentity: v, DeviceName: names[v.DeviceID], ServerName: serverNames[v.ServerID],
					Manual: a.vpnIssuer == nil || !a.vpnIssuer.CanRevokeIdentity(v)})
			}
			return out
		}
		data["Current"] = rows(a.vpnIdentities.CurrentVPNIdentities(r.Context()))
		data["Held"] = rows(a.vpnIdentities.QuarantinedVPNIdentities(r.Context()))
		data["AwaitingRevocation"] = rows(a.vpnIdentities.VPNIdentitiesAwaitingRevocation(r.Context()))
	}
	a.render(w, r, http.StatusOK, "vpn.html", data)
}

// vpnIdentityRow is an identity with the names the tables show.
type vpnIdentityRow struct {
	sqlite.VPNIdentity
	DeviceName string
	ServerName string
	Manual     bool // Cairn cannot revoke this one at its CA
}

// Home is the page that shows this device's certificates.
func (v vpnIdentityRow) Home() string { return deviceHome(v.DeviceID) }

// ExpiresOn is the certificate's last day, or "" when none was issued.
func (v vpnIdentityRow) ExpiresOn() string {
	if t := v.Expires(); !t.IsZero() {
		return t.Format("2006-01-02")
	}
	return ""
}

// vpnDeviceRow is one server's state on a device page.
type vpnDeviceRow struct {
	Server vpn.Server
	Latest *vpnIdentityRow // most recent attempt, whatever its outcome
	// Offered is the account a profile was sent for when the device has not
	// yet asked for its certificate.
	Offered string
}

// accessSection is one card on a device page: its VPN servers or its Wi-Fi
// networks.
type accessSection struct {
	Title string
	WiFi  bool
	Rows  []vpnDeviceRow
}

// deviceAccess splits a device's rows into a VPN card and a Wi-Fi card,
// leaving out a card with nothing in it.
func (a *App) deviceAccess(ctx context.Context, deviceID string) []accessSection {
	sections := []accessSection{{Title: "VPN"}, {Title: "Wi-Fi", WiFi: true}}
	for _, row := range a.deviceVPNRows(ctx, deviceID) {
		i := 0
		if row.Server.IsWiFi() {
			i = 1
		}
		sections[i].Rows = append(sections[i].Rows, row)
	}
	var out []accessSection
	for _, s := range sections {
		if len(s.Rows) > 0 {
			out = append(out, s)
		}
	}
	return out
}

func (a *App) deviceVPNRows(ctx context.Context, deviceID string) []vpnDeviceRow {
	if a.vpn == nil || a.vpnIdentities == nil {
		return nil
	}
	servers, err := a.vpn.List(ctx)
	if err != nil {
		a.log.Error("list vpn servers", "err", err)
		return nil
	}
	identities, err := a.vpnIdentities.DeviceVPNIdentities(ctx, deviceID)
	if err != nil {
		a.log.Error("device vpn identities", "id", deviceID, "err", err)
	}
	offers, err := a.vpnIdentities.OpenVPNOffers(ctx, deviceID)
	if err != nil {
		a.log.Error("device vpn offers", "id", deviceID, "err", err)
	}
	rows := make([]vpnDeviceRow, 0, len(servers))
	for _, s := range servers {
		row := vpnDeviceRow{Server: s}
		for _, o := range offers {
			if o.ServerID == s.ID {
				row.Offered = o.Owner.AccountName
			}
		}
		for i := range identities { // newest first
			if identities[i].ServerID == s.ID {
				row.Latest = &vpnIdentityRow{VPNIdentity: identities[i], ServerName: s.Name}
				break
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// vpnIssueGate guards actions that create or end a credential: CSRF, an
// administrator with a fresh second factor whose directory authorization still
// holds, and a configured issuer.
func (a *App) vpnIssueGate(w http.ResponseWriter, r *http.Request) bool {
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return false
	}
	if a.vpnIssuer == nil {
		http.Error(w, "VPN certificates cannot be issued: "+a.vpnIssuerMissing, http.StatusServiceUnavailable)
		return false
	}
	return a.enrollmentActor(w, r)
}

func (a *App) handleVPNIssue(w http.ResponseWriter, r *http.Request) {
	if !a.vpnIssueGate(w, r) {
		return
	}
	deviceID := r.PathValue("id")
	back := "/admin/devices/" + url.PathEscape(deviceID)
	serverID, err := strconv.ParseInt(r.PathValue("server"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	actor := sessionFrom(r).Identity.Username
	v, err := a.vpnIssuer.Issue(r.Context(), deviceID, serverID, strings.TrimSpace(r.PostFormValue("account")), actor)
	if err != nil {
		a.log.Warn("vpn issue refused", "device", deviceID, "server", serverID, "user", actor, "err", err)
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("VPN profile not sent: "+vpnFormError(err)), http.StatusSeeOther)
		return
	}
	msg := "VPN profile for " + v.Owner.AccountName + " queued. It installs when the device next connects."
	if a.vpn != nil {
		if s, serr := a.vpn.Get(r.Context(), serverID); serr == nil && s.IsIKEv2() && s.IKEv2.UsesCertificate() {
			msg = "VPN profile for " + v.Owner.AccountName + " queued. When it installs, the device makes a key and asks Cairn for its certificate."
		} else if serr == nil && s.IsWiFi() {
			msg = "Wi-Fi profile for " + v.Owner.AccountName + " queued. When it installs, the device makes a key and asks Cairn for its certificate."
		}
	}
	http.Redirect(w, r, back+"?flash="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (a *App) handleVPNRemove(w http.ResponseWriter, r *http.Request) {
	if !a.vpnIssueGate(w, r) {
		return
	}
	deviceID := r.PathValue("id")
	back := "/admin/devices/" + url.PathEscape(deviceID)
	serverID, err := strconv.ParseInt(r.PathValue("server"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := a.vpnIssuer.Remove(r.Context(), deviceID, serverID, sessionFrom(r).Identity.Username); err != nil {
		a.log.Error("vpn profile removal", "device", deviceID, "err", err)
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("Removal not queued."), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"?flash="+url.QueryEscape("Removal queued. The certificate stays valid until it is revoked or expires."), http.StatusSeeOther)
}

// handleVPNDownload hands out a password sign-in IKEv2 profile for one
// account, to be installed by hand.
func (a *App) handleVPNDownload(w http.ResponseWriter, r *http.Request) {
	if !a.vpnIssueGate(w, r) {
		return
	}
	serverID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	actor := sessionFrom(r).Identity.Username
	name, body, err := a.vpnIssuer.Download(r.Context(), serverID, strings.TrimSpace(r.PostFormValue("account")), actor)
	if err != nil {
		a.log.Warn("vpn profile download refused", "server", serverID, "user", actor, "err", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/vpn/%d?flash=%s", serverID, url.QueryEscape("No profile: "+vpnFormError(err))), http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// handleVPNWithdraw ends an offer the device has not answered.
func (a *App) handleVPNWithdraw(w http.ResponseWriter, r *http.Request) {
	if !a.vpnIssueGate(w, r) {
		return
	}
	deviceID := r.PathValue("id")
	back := "/admin/devices/" + url.PathEscape(deviceID)
	serverID, err := strconv.ParseInt(r.PathValue("server"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	found, err := a.vpnIssuer.Withdraw(r.Context(), deviceID, serverID, sessionFrom(r).Identity.Username)
	msg := "Profile withdrawn. The device can no longer ask for a certificate with it."
	if err != nil {
		a.log.Error("vpn offer withdrawal", "device", deviceID, "err", err)
		msg = "Not withdrawn."
	} else if !found {
		msg = "Nothing to withdraw: the device has already asked for its certificate, or the profile was withdrawn."
	}
	http.Redirect(w, r, back+"?flash="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (a *App) vpnIdentityFromPath(w http.ResponseWriter, r *http.Request) (sqlite.VPNIdentity, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		var v sqlite.VPNIdentity
		if v, err = a.vpnIdentities.GetVPNIdentity(r.Context(), id); err == nil {
			return v, true
		}
	}
	http.NotFound(w, r)
	return sqlite.VPNIdentity{}, false
}

func (a *App) handleVPNRevoke(w http.ResponseWriter, r *http.Request) {
	if !a.vpnIssueGate(w, r) {
		return
	}
	v, ok := a.vpnIdentityFromPath(w, r)
	if !ok {
		return
	}
	back := deviceHome(v.DeviceID)
	if err := a.vpnIssuer.Revoke(r.Context(), v.ID, sessionFrom(r).Identity.Username); err != nil {
		a.log.Error("vpn revoke", "identity", v.ID, "err", err)
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("Not revoked: "+vpnFormError(err)), http.StatusSeeOther)
		return
	}
	msg := "Certificate " + v.CertSerial + " revoked."
	if v.CertSerial == "" {
		msg = "Hold closed."
	} else if !a.vpnIssuer.CanRevokeIdentity(v) {
		msg = "Certificate " + v.CertSerial + " marked revoked in Cairn. Revoke the same serial at the certificate authority, then confirm it on the VPN page."
	}
	http.Redirect(w, r, back+"?flash="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (a *App) handleVPNRevokedAtCA(w http.ResponseWriter, r *http.Request) {
	if !a.vpnIssueGate(w, r) {
		return
	}
	v, ok := a.vpnIdentityFromPath(w, r)
	if !ok {
		return
	}
	if err := a.vpnIssuer.ConfirmRevokedAtCA(r.Context(), v.ID, sessionFrom(r).Identity.Username); err != nil {
		a.log.Warn("vpn revoked-at-ca refused", "identity", v.ID, "err", err)
		http.Error(w, "Not recorded. Only a retired certificate that Cairn cannot revoke itself can be confirmed here.", http.StatusConflict)
		return
	}
	a.log.Info("vpn certificate confirmed revoked at the CA", "identity", v.ID, "serial", v.CertSerial, "user", sessionFrom(r).Identity.Username)
	home := "/admin/vpn"
	if s, err := a.vpn.Get(r.Context(), v.ServerID); err == nil {
		home = accessHome(s)
	}
	http.Redirect(w, r, home+"?flash="+url.QueryEscape("Recorded: "+v.CertSerial+" is revoked at the certificate authority."), http.StatusSeeOther)
}

func (a *App) renderVPNServer(w http.ResponseWriter, r *http.Request, status int, f vpnServerForm, message string, skipped []string) {
	w.Header().Set("Cache-Control", "no-store")
	a.render(w, r, status, "vpn_server.html", map[string]any{
		"Title": map[bool]string{false: "VPN", true: "Wi-Fi"}[f.WiFi()], "Form": f, "Error": message, "Skipped": skipped, "New": f.ID == 0,
		"Options": vpn.IKEv2Options(), "KnownCAs": a.knownCANames(),
		"Flash": r.URL.Query().Get("flash"), "CanIssue": a.vpnIssuer != nil,
	})
}

// knownCANames lists the common names of the CA certificates Cairn installs
// on devices at enrollment, issuing CAs before roots. They are what a server
// certificate on the same PKI was issued by, and devices already trust them.
func (a *App) knownCANames() []string {
	var issuing, roots []string
	seen := map[string]bool{}
	for _, der := range a.cfg.CAAnchorsDER {
		c, err := x509.ParseCertificate(der)
		if err != nil || c.Subject.CommonName == "" || seen[c.Subject.CommonName] {
			continue
		}
		seen[c.Subject.CommonName] = true
		if bytes.Equal(c.RawSubject, c.RawIssuer) {
			roots = append(roots, c.Subject.CommonName)
		} else {
			issuing = append(issuing, c.Subject.CommonName)
		}
	}
	return append(issuing, roots...)
}

func (a *App) handleVPNServerNew(w http.ResponseWriter, r *http.Request) {
	if !a.vpnAvailable(w) {
		return
	}
	if r.URL.Query().Get("kind") == vpn.KindIKEv2 {
		f := vpnServerForm{Kind: vpn.KindIKEv2, SignIn: vpn.IKEv2Password, Encryption: "AES-256-GCM", Integrity: "SHA2-256", DHGroup: "20", PFS: true}
		// Most servers hold a certificate from the same PKI as the devices.
		if known := a.knownCANames(); len(known) > 0 {
			f.ServerCertIssuerCN = known[0]
		}
		a.renderVPNServer(w, r, http.StatusOK, f, "", nil)
		return
	}
	a.renderVPNServer(w, r, http.StatusOK, vpnServerForm{KeyDirection: "1", TLSKeyMode: vpn.TLSKeyAuth}, "", nil)
}

func (a *App) handleWiFiNew(w http.ResponseWriter, r *http.Request) {
	if !a.vpnAvailable(w) {
		return
	}
	f := vpnServerForm{Kind: vpn.KindWiFi, Security: vpn.WiFiWPA2Enterprise}
	// RADIUS servers usually hold certificates from the same PKI as the devices.
	for _, der := range a.cfg.CAAnchorsDER {
		f.CAPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	a.renderVPNServer(w, r, http.StatusOK, f, "", nil)
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
	http.Redirect(w, r, accessHome(s)+"?flash="+url.QueryEscape("Saved."), http.StatusSeeOther)
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
	f.ID, f.Slug, f.Kind = current.ID, current.Slug, current.Kind
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
	http.Redirect(w, r, accessHome(current)+"?flash="+url.QueryEscape("Saved. Profiles already on devices keep their old settings until they are issued again."), http.StatusSeeOther)
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
	http.Redirect(w, r, accessHome(s)+"?flash="+url.QueryEscape("Deleted. Profiles already on devices are not removed."), http.StatusSeeOther)
}

func vpnFormError(err error) string {
	if errors.Is(err, sqlite.ErrVPNServerExists) {
		return "Another server already uses this identifier. Choose a different one."
	}
	msg := err.Error()
	return strings.ToUpper(msg[:1]) + msg[1:] + "."
}
