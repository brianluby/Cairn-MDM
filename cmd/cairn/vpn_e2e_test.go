package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	npush "github.com/micromdm/nanomdm/push"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/ca"
	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/vpn"
	"github.com/nickpdawson/cairn-mdm/internal/web"
)

type vpnE2EPush struct{}

func (vpnE2EPush) Push(_ context.Context, ids []string) (map[string]*npush.Response, error) {
	out := map[string]*npush.Response{}
	for _, id := range ids {
		out[id] = &npush.Response{}
	}
	return out, nil
}

// TestVPNProfileThroughTheConsole drives the administrator's path over HTTP: add
// a server from an .ovpn file, send a profile to an enrolled phone that has no
// verified owner, let the phone acknowledge it, and read the result back. Only
// the directory and APNs are faked; the CA, queue and console are real.
func TestVPNProfileThroughTheConsole(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := sqlite.Open(ctx, t.TempDir()+"/vpn-e2e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	authority, err := ca.Ensure(ctx, db.SQL(), ca.Options{CommonName: "Cairn VPN E2E CA", Organization: "Cairn", KeyBits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "PHONE", UDID: "PHONE", Name: "Test iPhone"}); err != nil {
		t.Fatal(err)
	}
	if err = db.DeviceTokenUpdated(ctx, "PHONE"); err != nil {
		t.Fatal(err)
	}
	owner := directory.DirectoryIdentity{DirectoryID: "dzsec", ObjectID: strings.Repeat("a", 32), UPN: "lynch.user@example.org", AccountName: "lynch.user"}
	dir := &e2eDirectory{owner: owner}

	nanoStore := db.NanoStorage(log)
	commander := mdmcore.NewCommander(nanoStore, vpnE2EPush{}).WithRecorder(db, log)
	sessions := auth.NewSessionStore(db.SQL(), time.Hour)
	local := auth.NewLocalStore(db.SQL())
	if err = local.CreateUser(ctx, "nick", "hunter2hunter2", auth.RoleAdmin, "Nick"); err != nil {
		t.Fatal(err)
	}
	console, err := web.New(sessions, local, db, commander, nil, web.Config{PublicURL: "https://mdm.example.org", Organization: "org.example"}, log)
	if err != nil {
		t.Fatal(err)
	}
	console.SetDirectory(dir)
	mfa, err := auth.NewMFAStore(db.SQL(), sessions, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	console.SetMFA(mfa)
	servers, err := vpn.NewServers(db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	console.SetVPN(servers)
	service, err := vpn.NewService(servers, db, dir, authority.EmbeddedBackend(), commander,
		vpn.Options{Organization: "org.example", Policy: issue.Policy{LeafValidity: 365 * 24 * time.Hour, Backdate: 5 * time.Minute}}, log)
	if err != nil {
		t.Fatal(err)
	}
	console.SetVPNIssuer(service, db, "")
	mux := http.NewServeMux()
	console.Register(mux)

	id, err := local.Authenticate(ctx, "nick", "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ctx, *id)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: web.SessionCookie, Value: sess.Token}
	do := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		var body io.Reader
		if form != nil {
			form.Set("csrf", sess.CSRF)
			body = strings.NewReader(form.Encode())
		}
		req := httptest.NewRequest(method, path, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	chainPEM := string(authority.RootPEM())
	serverForm := func() url.Values {
		return url.Values{
			"name": {"Office VPN"}, "remotes": {"vpn.example.org 443 udp\nvpn.example.org 443 tcp"},
			"verify_x509_name": {"vpn.example.org"}, "ca_pem": {chainPEM}, "tls_key_mode": {""}, "user_auth": {"on"},
		}
	}

	// Without a verified second factor nothing is stored or sent.
	if rr := do("POST", "/admin/vpn/new", serverForm()); rr.Code != http.StatusForbidden {
		t.Fatalf("server create without fresh MFA = %d", rr.Code)
	}
	if _, err = db.SQL().Exec(`INSERT INTO mfa_factors(principal,secret) VALUES(?,?)`, "local:"+id.SubjectID, []byte("test")); err != nil {
		t.Fatal(err)
	}
	if _, err = db.SQL().Exec(`UPDATE app_sessions SET mfa_verified_at=?`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if rr := do("POST", "/admin/vpn/new", serverForm()); rr.Code != http.StatusSeeOther {
		t.Fatalf("server create = %d: %s", rr.Code, rr.Body.String())
	}

	page := do("GET", "/admin/devices/PHONE", nil).Body.String()
	if !strings.Contains(page, "No VPN profile sent.") || !strings.Contains(page, `name="account"`) {
		t.Fatal("device page does not offer to send a profile with an account field")
	}

	// A wrong CSRF token and an unknown account are both refused.
	bad := httptest.NewRequest("POST", "/admin/devices/PHONE/vpn/1/issue", strings.NewReader("csrf=wrong&account=lynch.user"))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad.AddCookie(cookie)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, bad)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("issue with bad CSRF = %d", rr.Code)
	}
	dir.disabled = true
	if rr = do("POST", "/admin/devices/PHONE/vpn/1/issue", url.Values{"account": {"lynch.user"}}); rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "not+sent") {
		t.Fatalf("issue for a disabled owner = %d -> %s", rr.Code, rr.Header().Get("Location"))
	}
	dir.disabled = false

	if rr = do("POST", "/admin/devices/PHONE/vpn/1/issue", url.Values{"account": {"lynch.user"}}); rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "queued") {
		t.Fatalf("issue = %d -> %s", rr.Code, rr.Header().Get("Location"))
	}
	if page = do("GET", "/admin/devices/PHONE", nil).Body.String(); !strings.Contains(page, "Waiting for the device to collect it (lynch.user)") {
		t.Fatal("device page does not show the queued profile")
	}
	// A second send while one is waiting is refused rather than queueing a second key.
	if rr = do("POST", "/admin/devices/PHONE/vpn/1/issue", url.Values{"account": {"lynch.user"}}); !strings.Contains(rr.Header().Get("Location"), "already+waiting") {
		t.Fatalf("second issue while waiting -> %s", rr.Header().Get("Location"))
	}

	// The phone collects and acknowledges the profile.
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{ID: "PHONE"}
	cmd, err := nanoStore.RetrieveNextCommand(r, false)
	if err != nil || cmd == nil || cmd.Command.RequestType != "InstallProfile" {
		t.Fatalf("phone fetched %+v, %v", cmd, err)
	}
	if err = nanoStore.StoreCommandReport(r, &mdm.CommandResults{CommandUUID: cmd.CommandUUID, Status: "Acknowledged", Raw: []byte("ok")}); err != nil {
		t.Fatal(err)
	}

	identities, err := db.DeviceVPNIdentities(ctx, "PHONE")
	if err != nil || len(identities) != 1 || identities[0].DeployStatus != "installed" || identities[0].Actor != "nick" {
		t.Fatalf("identities = %+v, %v", identities, err)
	}
	serial := identities[0].CertSerial
	if page = do("GET", "/admin/devices/PHONE", nil).Body.String(); !strings.Contains(page, "Installed for lynch.user") || !strings.Contains(page, serial) {
		t.Fatal("device page does not show the installed profile and its serial")
	}
	if page = do("GET", "/admin/vpn", nil).Body.String(); !strings.Contains(page, serial) || !strings.Contains(page, "Test iPhone") {
		t.Fatal("VPN page does not list the certificate in use")
	}

	// Revoking ends the certificate at the CA and is recorded with the actor.
	if rr = do("POST", "/admin/vpn/identities/1/revoke", url.Values{}); rr.Code != http.StatusSeeOther {
		t.Fatalf("revoke = %d", rr.Code)
	}
	if _, revoked, _ := authority.IsRevoked(ctx, serial); !revoked {
		t.Fatal("certificate not revoked at the CA")
	}
	var audits int
	db.SQL().QueryRow(`SELECT count(*) FROM audit_log WHERE provider='cairn-vpn' AND username='nick' AND action IN ('vpn.identity.issue','vpn.identity.revoke')`).Scan(&audits)
	if audits != 2 {
		t.Fatalf("issue and revoke audit rows = %d, want 2", audits)
	}
	// A password sign-in IKEv2 server: the profile is downloaded for an
	// account, and cannot be pushed to a device.
	if rr := do("POST", "/admin/vpn/new", url.Values{
		"kind": {"ikev2"}, "name": {"Office IKEv2"}, "remote_address": {"vpn.example.org"}, "server_cert_issuer_cn": {"Cairn VPN E2E CA"},
		"sign_in": {"password"}, "encryption": {"AES-256-GCM"}, "integrity": {"SHA2-256"}, "dh_group": {"20"}, "on_demand": {"on"},
	}); rr.Code != http.StatusSeeOther {
		t.Fatalf("IKEv2 server create = %d: %s", rr.Code, rr.Body.String())
	}
	var ikev2ID int64
	if err = db.SQL().QueryRow(`SELECT id FROM vpn_servers WHERE slug='office-ikev2'`).Scan(&ikev2ID); err != nil {
		t.Fatal(err)
	}
	ikev2Path := fmt.Sprintf("/admin/vpn/%d", ikev2ID)
	if page := do("GET", ikev2Path, nil); page.Code != 200 || !strings.Contains(page.Body.String(), "Download a profile") {
		t.Fatalf("server page lacks the download form (%d)", page.Code)
	}
	dl := do("POST", ikev2Path+"/download", url.Values{"account": {"lynch.user"}})
	if dl.Code != 200 || dl.Header().Get("Content-Type") != "application/x-apple-aspen-config" ||
		!strings.Contains(dl.Header().Get("Content-Disposition"), "office-ikev2-lynch.user.mobileconfig") {
		t.Fatalf("download = %d %q %q", dl.Code, dl.Header().Get("Content-Type"), dl.Header().Get("Content-Disposition"))
	}
	if err = vpn.CheckIKEv2(dl.Body.Bytes()); err != nil || !strings.Contains(dl.Body.String(), "lynch.user") {
		t.Fatalf("downloaded profile: %v", err)
	}
	push := do("POST", fmt.Sprintf("/admin/devices/PHONE/vpn/%d/issue", ikev2ID), url.Values{"account": {"lynch.user"}})
	if loc, _ := url.QueryUnescape(push.Header().Get("Location")); push.Code != http.StatusSeeOther || !strings.Contains(loc, "download the profile") {
		t.Fatalf("push of a password profile = %d %q", push.Code, loc)
	}
	if page := do("GET", "/admin/devices/PHONE", nil); !strings.Contains(page.Body.String(), "installed by hand") ||
		strings.Contains(page.Body.String(), fmt.Sprintf("/vpn/%d/issue", ikev2ID)) {
		t.Fatal("device page still offers to send the password profile")
	}
}
