package web

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/push"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// loginThrottles associates a *LoginThrottle with an App without adding a field
// to the App struct, whose definition lives in web.go (outside this change's
// file ownership). Production runs a single long-lived App, so the map holds at
// most a handful of entries.
var loginThrottles sync.Map // key: *App, value: *auth.LoginThrottle

// SetLoginThrottle installs the brute-force limiter used by handleLogin. Passing
// nil disables throttling (the default), which keeps callers that never set one
// working unchanged.
func (a *App) SetLoginThrottle(t *auth.LoginThrottle) {
	if t == nil {
		loginThrottles.Delete(a)
		return
	}
	loginThrottles.Store(a, t)
}

// loginThrottle returns the installed throttle, or nil if none is set.
func (a *App) loginThrottle() *auth.LoginThrottle {
	if v, ok := loginThrottles.Load(a); ok {
		return v.(*auth.LoginThrottle)
	}
	return nil
}

// maxFormBytes bounds ordinary form POST bodies (login, group and builder
// forms). The profile upload has its own, larger limit (maxProfileBytes).
const maxFormBytes = 64 << 10

// limitForm caps the request body before it is parsed, so a hostile client
// can't stream an unbounded form into memory.
func limitForm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
}

// sameOrigin is a defense-in-depth companion to the CSRF token: it rejects a
// mutating request whose Origin (or, absent that, Referer) host does not match
// the configured public URL. A request with neither header is allowed — that
// covers non-browser API clients and older browsers that omit Origin on
// same-origin navigations. Only a present-but-mismatched header is a reject.
func sameOrigin(r *http.Request, publicURL string) bool {
	want, err := url.Parse(publicURL)
	if err != nil || want.Host == "" {
		return true // can't determine the expected host; don't block
	}
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return true // no Origin/Referer supplied
	}
	got, err := url.Parse(src)
	if err != nil || got.Host == "" {
		return false
	}
	return strings.EqualFold(got.Scheme, want.Scheme) && strings.EqualFold(got.Host, want.Host)
}

// render executes a template as a full page. On error it logs and writes a 500.
func (a *App) render(w http.ResponseWriter, r *http.Request, status int, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if sess := sessionFrom(r); sess != nil {
		data["User"] = sess.Identity
		data["CSRF"] = sess.CSRF
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := a.tmpl.ExecuteTemplate(w, name, data); err != nil {
		a.log.Error("template render failed", "template", name, "err", err)
	}
}

func (a *App) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	// Already signed in? Go to the console.
	if a.currentSession(r) != nil {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	a.render(w, r, http.StatusOK, "login.html", map[string]any{"SetupOpen": a.setupOpen(r.Context())})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")

	throttle := a.loginThrottle()
	throttleKey := username + "|" + a.clientIP(r)
	if throttle != nil {
		if ok, retryAfter := throttle.Allowed(throttleKey); !ok {
			a.log.Warn("login throttled", "username", username, "remote", r.RemoteAddr, "retry_after", retryAfter)
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
			a.render(w, r, http.StatusTooManyRequests, "login.html", map[string]any{
				"Error": "Too many attempts. Please try again later.", "Username": username,
			})
			return
		}
	}

	id, err := a.auth.Authenticate(r.Context(), username, password)
	if err != nil {
		if throttle != nil {
			throttle.RecordFailure(throttleKey)
		}
		a.log.Info("failed login", "username", username, "remote", r.RemoteAddr)
		a.render(w, r, http.StatusUnauthorized, "login.html", map[string]any{
			"Error": "Incorrect username or password.", "Username": username,
		})
		return
	}
	if throttle != nil {
		throttle.RecordSuccess(throttleKey)
	}

	sess, err := a.sessions.Create(r.Context(), *id)
	if err != nil {
		a.log.Error("create session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, sess.Token, sess.ExpiresAt)
	a.log.Info("login", "username", id.Username, "role", id.Role)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		if !a.checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		_ = a.sessions.Delete(r.Context(), c.Value)
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	total, active, err := a.devices.DeviceCounts(r.Context())
	if err != nil {
		a.log.Error("device counts", "err", err)
	}
	devices, err := a.devices.ListDevices(r.Context())
	if err != nil {
		a.log.Error("list devices", "err", err)
	}
	recent := devices
	if len(recent) > 5 {
		recent = recent[:5]
	}
	var alerts []sqlite.AlertState
	var heartbeat string
	if a.alerts != nil {
		states, err := a.alerts.ListAlertStates(r.Context())
		if err != nil {
			a.log.Error("list alert states", "err", err)
		}
		for _, s := range states {
			if s.Key == "heartbeat" {
				if s.NotifiedAt.Valid {
					heartbeat = s.NotifiedAt.String
				}
				continue
			}
			if s.Active {
				alerts = append(alerts, s)
			}
		}
	}
	a.render(w, r, http.StatusOK, "dashboard.html", map[string]any{
		"Title":            "Dashboard",
		"Total":            total,
		"Active":           active,
		"Recent":           recent,
		"EnrollmentURL":    strings.TrimRight(a.cfg.PublicURL, "/") + "/enroll",
		"OpenEnrollment":   a.cfg.OpenEnrollment,
		"APNs":             a.apnsStatus(r.Context()),
		"Alerts":           alerts,
		"AlertsConfigured": a.cfg.AlertsConfigured,
		"LastHeartbeat":    heartbeat,
	})
}

// apnsTopicStatus is one row of the dashboard's per-topic APNs list.
type apnsTopicStatus struct {
	Topic    string
	Subject  string
	Expires  string // YYYY-MM-DD
	Days     int    // whole days until expiry (negative once expired)
	Severity string // ok|notice|caution|warning|high|critical
	Label    string // short human status ("renew soon", "expired", …)
	Warn     bool   // true for any non-ok tier (drives the ⚠️ marker)
}

// apnsStatus summarizes every loaded APNs push certificate for the dashboard.
// Each topic carries its own expiry and renewal tier so a second fleet's expiry
// (e.g. the migrated fleet's November cliff) cannot hide behind a later date
// (MDM-APNS-001).
func (a *App) apnsStatus(ctx context.Context) map[string]any {
	topics, err := a.apnsTopics.ListAPNSTopics(ctx)
	if err != nil {
		a.log.Error("list apns topics", "err", err)
	}
	if len(topics) == 0 {
		return map[string]any{"Loaded": false}
	}
	out := make([]apnsTopicStatus, 0, len(topics))
	worst := "" // most severe tier across all topics, for the summary card
	anyWarn := false
	for _, t := range topics {
		row := apnsTopicStatus{Topic: t.Topic, Subject: t.Subject}
		if parsed, perr := time.Parse(time.RFC3339, t.NotAfter); perr == nil {
			days, sev, label := push.RenewalTier(parsed)
			row.Expires = parsed.Format("2006-01-02")
			row.Days = days
			row.Severity = sev
			row.Label = label
			row.Warn = sev != "ok"
		} else {
			row.Expires = t.NotAfter
			row.Severity = "unknown"
			row.Label = "unknown"
		}
		if row.Warn {
			anyWarn = true
		}
		worst = moreSevere(worst, row.Severity)
		out = append(out, row)
	}
	// ListAPNSTopics already orders nearest-expiry first, so out[0] is the
	// soonest to expire — the one the summary card highlights.
	return map[string]any{
		"Loaded":   true,
		"Topics":   out,
		"Count":    len(out),
		"Warn":     anyWarn,
		"Severity": worst,
		"Nearest":  out[0],
	}
}

// severityRank orders renewal tiers from benign to urgent for picking the worst.
var severityRank = map[string]int{
	"ok": 0, "notice": 1, "caution": 2, "warning": 3, "high": 4, "critical": 5, "unknown": 6,
}

func moreSevere(a, b string) string {
	if severityRank[b] > severityRank[a] {
		return b
	}
	return a
}

func (a *App) handleDeviceDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := a.devices.GetDevice(r.Context(), id)
	if err != nil {
		a.render(w, r, http.StatusNotFound, "error.html", map[string]any{
			"Title": "Not found", "Message": "No such device.",
		})
		return
	}
	commands, err := a.profiles.ListCommands(r.Context(), d.ID, 25)
	if err != nil {
		a.log.Error("list commands", "id", d.ID, "err", err)
	}
	groups, err := a.groups.DeviceGroups(r.Context(), d.ID)
	if err != nil {
		a.log.Error("device groups", "id", d.ID, "err", err)
	}
	deploys, err := a.deploys.DeviceDeploys(r.Context(), d.ID)
	if err != nil {
		a.log.Error("device deploys", "id", d.ID, "err", err)
	}
	library, err := a.profiles.ListProfiles(r.Context())
	if err != nil {
		a.log.Error("list profiles", "err", err)
	}
	// What each deployed profile takes away if removed, by identifier.
	affects := map[string]string{}
	for _, p := range library {
		if list := p.Affects(); len(list) > 0 {
			affects[p.Identifier] = strings.Join(list, "; ")
		}
	}
	// The latest DeviceInformation request, so the page can say whether a refresh
	// is still waiting on the device rather than leaving the operator to read the
	// command table.
	var refresh *sqlite.CommandEntry
	for i := range commands {
		if commands[i].RequestType == "DeviceInformation" {
			refresh = &commands[i]
			break
		}
	}
	data := map[string]any{
		"Refresh":          refresh,
		"Affects":          affects,
		"Title":            d.DisplayName(),
		"Intent":           newCommandIntent(),
		"Device":           d,
		"Commands":         commands,
		"Groups":           groups,
		"Deploys":          deploys,
		"Library":          library,
		"Flash":            r.URL.Query().Get("flash"),
		"DirectoryRefresh": a.targeting != nil,
	}
	if oc, ok := a.devices.(interface {
		ObservedDeviceCertificates(context.Context) ([]sqlite.ObservedCertificate, error)
	}); ok {
		observed, err := oc.ObservedDeviceCertificates(r.Context())
		if err != nil {
			a.log.Error("observed device certificates", "id", d.ID, "err", err)
		}
		for _, c := range observed {
			if c.DeviceID == d.ID {
				data["Presented"] = c
				data["PresentedExpired"] = !c.NotAfter.After(time.Now())
				data["PresentedDays"] = int(time.Until(c.NotAfter).Hours() / 24)
			}
		}
	}
	identity, _ := a.identityView(r.Context(), d.ID)
	data["Identity"] = identity
	if lc, ok := a.devices.(lifecycleSource); ok {
		attempts, err := lc.DeviceRenewalAttempts(r.Context(), d.ID, 10)
		if err != nil {
			a.log.Error("device renewal attempts", "id", d.ID, "err", err)
		}
		data["RenewalAttempts"] = attempts
		certs, err := lc.DeviceCertificates(r.Context())
		if err != nil {
			a.log.Error("device certificates", "id", d.ID, "err", err)
		}
		var mine []sqlite.DeviceCertificate
		for _, c := range certs {
			if c.DeviceID == d.ID {
				mine = append(mine, c)
			}
		}
		data["Certificates"] = mine
	}
	if lister, ok := a.devices.(installedProfileSource); ok {
		installed, err := lister.InstalledProfiles(r.Context(), d.ID)
		if err != nil {
			a.log.Error("installed profiles", "id", d.ID, "err", err)
		}
		data["Installed"] = installed
		data["CanListProfiles"] = true
		if len(installed) > 0 {
			data["InstalledAt"] = installed[0].SeenAt
		}
	}
	if a.vpn != nil {
		data["VPN"] = a.deviceVPNRows(r.Context(), d.ID)
		data["VPNIssuerMissing"] = a.vpnIssuerMissing
		data["VPNCanIssue"] = a.vpnIssuer != nil
	}
	if a.ownership != nil {
		if owner, err := a.ownership.GetDeviceOwner(r.Context(), d.ID); err == nil {
			data["Owner"] = owner
		} else if !errors.Is(err, sqlite.ErrNoOwner) {
			a.log.Error("device owner", "id", d.ID, "err", err)
		}
		memberships, err := a.ownership.DeviceDirectoryMemberships(r.Context(), d.ID)
		if err != nil {
			a.log.Error("device directory memberships", "id", d.ID, "err", err)
		}
		data["DirectoryMemberships"] = memberships
		if ev, err := a.ownership.DeviceDirectoryEvaluation(r.Context(), d.ID); err == nil {
			data["DirectoryEvaluation"] = ev
		} else if !errors.Is(err, sql.ErrNoRows) {
			a.log.Error("device directory evaluation", "id", d.ID, "err", err)
		}
	}
	a.render(w, r, http.StatusOK, "device.html", data)
}

// lifecycleSource is the optional store capability behind the device page's
// certificate and renewal sections.
type lifecycleSource interface {
	DeviceRenewalAttempts(ctx context.Context, deviceID string, limit int) ([]sqlite.RenewalAttempt, error)
	DeviceCertificates(ctx context.Context) ([]sqlite.DeviceCertificate, error)
}

// handleDeviceDirectoryRefresh re-binds the device's owner, re-evaluates the
// directory rules and pushes newly entitled profiles. Admin-only: it changes the
// device's desired profile set.
func (a *App) handleDeviceDirectoryRefresh(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	back := "/admin/devices/" + id
	if a.targeting == nil {
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("Directory targeting is not configured."), http.StatusSeeOther)
		return
	}
	if _, err := a.devices.GetDevice(r.Context(), id); err != nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	out, err := a.targeting.RefreshAndReconcile(ctx, id)
	user := sessionFrom(r).Identity.Username
	var flash string
	switch {
	case err != nil:
		a.log.Error("directory refresh", "id", id, "user", user, "err", err)
		flash = "Directory refresh failed; memberships were not changed."
	case !out.Owned:
		flash = "This device has no verified owner, so directory rules do not apply. " + out.Detail
	case !out.Evaluated:
		flash = "Directory unavailable; previous memberships were kept. " + out.Detail
	default:
		flash = fmt.Sprintf("Directory rules evaluated: %d matched, %d new group membership(s). Entitled profiles are being pushed.", out.Matched, len(out.Added))
	}
	a.log.Info("directory refresh", "id", id, "user", user, "owned", out.Owned, "evaluated", out.Evaluated, "matched", out.Matched)
	http.Redirect(w, r, back+"?flash="+url.QueryEscape(flash), http.StatusSeeOther)
}

// handleDeviceInstall pushes a library profile to one device as a one-off
// InstallProfile command (operator+, CSRF-checked). It records nothing in
// profile_deploys — that table tracks group-assigned pushes; ad-hoc installs
// show up in the command history.
func (a *App) handleDeviceInstall(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	ctx, ok := a.deviceCommandIntent(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	back := "/admin/devices/" + id
	pid, err := strconv.ParseInt(r.PostFormValue("profile_id"), 10, 64)
	if err != nil {
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("Choose a profile to install."), http.StatusSeeOther)
		return
	}
	prof, err := a.profiles.GetProfile(r.Context(), pid)
	if err != nil {
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("No such profile."), http.StatusSeeOther)
		return
	}
	if err := a.cmd.SendInstallProfile(ctx, prof.Data, id); err != nil {
		a.log.Error("send install profile", "id", id, "profile", pid, "err", err)
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("Failed to queue install."), http.StatusSeeOther)
		return
	}
	a.log.Info("install profile queued", "id", id, "profile", pid, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, back+"?flash="+url.QueryEscape("Install queued."), http.StatusSeeOther)
}

// handleDeviceRemove sends an explicit RemoveProfile for a profile identifier
// (operator+, CSRF-checked). Removal is always an explicit command — never
// implied by group changes.
func (a *App) handleDeviceRemove(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	ctx, ok := a.deviceCommandIntent(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	back := "/admin/devices/" + id
	identifier := strings.TrimSpace(r.PostFormValue("identifier"))
	if identifier == "" {
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("No profile identifier given."), http.StatusSeeOther)
		return
	}
	// Removing the profile that holds the management settings ends management.
	if lister, ok := a.devices.(installedProfileSource); ok {
		installed, _ := lister.InstalledProfiles(r.Context(), id)
		for _, p := range installed {
			if p.Identifier == identifier && p.HasPayload("com.apple.mdm") {
				http.Redirect(w, r, back+"?flash="+url.QueryEscape("That is the enrollment profile. Removing it would end management of this device, so it is not removed from here."), http.StatusSeeOther)
				return
			}
		}
	}
	if err := a.cmd.SendRemoveProfile(ctx, identifier, id); err != nil {
		a.log.Error("send remove profile", "id", id, "identifier", identifier, "err", err)
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("Failed to queue removal."), http.StatusSeeOther)
		return
	}
	a.log.Info("remove profile queued", "id", id, "identifier", identifier, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, back+"?flash="+url.QueryEscape("Remove queued."), http.StatusSeeOther)
}

// installedProfileSource reads the profiles a device last reported; *sqlite.DB
// provides it.
type installedProfileSource interface {
	InstalledProfiles(ctx context.Context, deviceID string) ([]sqlite.DeviceProfile, error)
}

// handleDeviceProfileList asks the device which profiles it has installed. The
// answer is stored when the device next connects.
func (a *App) handleDeviceProfileList(w http.ResponseWriter, r *http.Request) {
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	ctx, ok := a.deviceCommandIntent(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	back := "/admin/devices/" + id
	asker, ok := a.cmd.(interface {
		SendProfileList(ctx context.Context, ids ...string) error
	})
	if !ok {
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("This server cannot ask a device for its profiles."), http.StatusSeeOther)
		return
	}
	if err := asker.SendProfileList(ctx, id); err != nil {
		a.log.Error("send profile list", "id", id, "err", err)
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("Failed to queue the request."), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"?flash="+url.QueryEscape("Asked the device for its profiles. Reload this page after it next connects."), http.StatusSeeOther)
}

func (a *App) handleDeviceRefresh(w http.ResponseWriter, r *http.Request) {
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	ctx, ok := a.deviceCommandIntent(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := a.cmd.SendDeviceInformation(ctx, id); err != nil {
		a.log.Error("send device information", "id", id, "err", err)
		http.Redirect(w, r, "/admin/devices/"+id+"?flash=Failed+to+queue+refresh", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/devices/"+id+"?flash=Refresh+queued", http.StatusSeeOther)
}

// deviceFilterer is the optional filtered-list capability. The concrete store
// (*sqlite.DB) implements it; the narrow DeviceSource interface in web.go
// (outside this file's ownership) does not, so handleDevices type-asserts for it
// and falls back to an unfiltered list if it is unavailable.
type deviceFilterer interface {
	ListDevicesFiltered(ctx context.Context, query string, enrolledOnly bool) ([]sqlite.Device, error)
}

func (a *App) handleDevices(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	enrolled := r.URL.Query().Get("enrolled") == "1"

	var (
		devices []sqlite.Device
		err     error
	)
	if f, ok := a.devices.(deviceFilterer); ok {
		devices, err = f.ListDevicesFiltered(r.Context(), q, enrolled)
	} else {
		devices, err = a.devices.ListDevices(r.Context())
	}
	if err != nil {
		a.log.Error("list devices", "err", err)
	}
	var counts map[string]sqlite.DeployCounts
	var owners map[string]string
	if ls, ok := a.devices.(deviceListSource); ok {
		if counts, err = ls.DeviceDeployCounts(r.Context()); err != nil {
			a.log.Error("device deploy counts", "err", err)
		}
		if owners, err = ls.DeviceOwnerUPNs(r.Context()); err != nil {
			a.log.Error("device owners", "err", err)
		}
	}
	a.render(w, r, http.StatusOK, "devices.html", map[string]any{
		"Title":    "Devices",
		"Devices":  devices,
		"Q":        q,
		"Enrolled": enrolled,
		"Count":    len(devices),
		"Counts":   counts,
		"Owners":   owners,
	})
}

// deviceListSource is the optional capability behind the device list's owner
// and profile-outcome columns.
type deviceListSource interface {
	DeviceDeployCounts(ctx context.Context) (map[string]sqlite.DeployCounts, error)
	DeviceOwnerUPNs(ctx context.Context) (map[string]string, error)
}

// checkCSRF verifies the submitted token matches the session's for mutating
// requests.
func (a *App) checkCSRF(r *http.Request) bool {
	sess := a.currentSession(r)
	if sess == nil {
		return false
	}
	if !sameOrigin(r, a.cfg.PublicURL) {
		return false
	}
	got := r.PostFormValue("csrf")
	if got == "" {
		got = r.Header.Get("X-CSRF-Token")
	}
	return got != "" && got == sess.CSRF
}

func newCommandIntent() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func (a *App) deviceCommandIntent(w http.ResponseWriter, r *http.Request) (context.Context, bool) {
	key := r.PostFormValue("intent")
	if len(key) < 32 || len(key) > 128 || strings.ContainsAny(key, " \r\n\t") {
		http.Error(w, "Reload the device page before sending this command", 400)
		return r.Context(), false
	}
	return mdmcore.WithCommandIntent(r.Context(), sessionFrom(r).Token+"\x00"+r.URL.Path+"\x00"+key), true
}
