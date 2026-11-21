package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/plist"
	scep "github.com/smallstep/scep"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/ca"
	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/vpn"
	"github.com/nickpdawson/cairn-mdm/internal/web"
)

// A HomePod cannot enroll in MDM. An administrator records it, downloads its
// Wi-Fi profile, and the device asks for its certificate while the profile
// installs. Only the directory and APNs are faked.
func TestWiFiProfileForADeviceOutsideMDM(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := sqlite.Open(ctx, t.TempDir()+"/manual-e2e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	authority, err := ca.Ensure(ctx, db.SQL(), ca.Options{CommonName: "Cairn Manual E2E CA", Organization: "Cairn", KeyBits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	owner := directory.DirectoryIdentity{DirectoryID: "example-ad", ObjectID: strings.Repeat("a", 32), UPN: "lynch.user@example.org", AccountName: "lynch.user"}
	dir := &e2eDirectory{owner: owner}

	commander := mdmcore.NewCommander(db.NanoStorage(log), vpnE2EPush{}).WithRecorder(db, log)
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
	service, err := vpn.NewService(servers, db, dir, authority.EmbeddedBackend(), commander, vpn.Options{
		Organization: "org.example", DeviceSCEPURL: "https://mdm.example.org/scep/vpn",
		Policy: issue.Policy{LeafValidity: 365 * 24 * time.Hour, Backdate: 5 * time.Minute},
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	console.SetVPNIssuer(service, db, "")
	console.SetManualDevices(db, service, 30)
	mux := http.NewServeMux()
	console.Register(mux)
	if _, err = servers.Create(ctx, vpn.Server{
		Name: "Staff Wi-Fi", Slug: "staff-wifi", Kind: vpn.KindWiFi, CAPEM: string(authority.RootPEM()),
		WiFi: vpn.WiFi{SSID: "Example Staff", Security: vpn.WiFiWPA2Enterprise, ServerNames: []string{"radius.example.org"}},
	}, "nick"); err != nil {
		t.Fatal(err)
	}

	id, err := local.Authenticate(ctx, "nick", "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ctx, *id)
	if err != nil {
		t.Fatal(err)
	}
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
		req.AddCookie(&http.Cookie{Name: web.SessionCookie, Value: sess.Token})
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	flash := func(rr *httptest.ResponseRecorder) string {
		u, _ := url.Parse(rr.Header().Get("Location"))
		return u.Query().Get("flash")
	}
	device := url.Values{"name": {"Kitchen HomePod"}, "kind": {"homepod"}, "account": {"lynch.user"}}

	// Nothing is recorded or handed out without a fresh second factor.
	if rr := do("POST", "/admin/other-devices", device); rr.Code != http.StatusForbidden {
		t.Fatalf("add without fresh MFA = %d", rr.Code)
	}
	if _, err = db.SQL().Exec(`INSERT INTO mfa_factors(principal,secret) VALUES(?,?)`, "local:"+id.SubjectID, []byte("test")); err != nil {
		t.Fatal(err)
	}
	if _, err = db.SQL().Exec(`UPDATE app_sessions SET mfa_verified_at=?`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	dir.disabled = true
	if rr := do("POST", "/admin/other-devices", device); !strings.Contains(flash(rr), "not added") {
		t.Fatalf("add for a disabled account -> %q", flash(rr))
	}
	dir.disabled = false
	if rr := do("POST", "/admin/other-devices", device); rr.Code != http.StatusSeeOther || !strings.Contains(flash(rr), "Device added") {
		t.Fatalf("add = %d -> %q", rr.Code, flash(rr))
	}
	page := do("GET", "/admin/other-devices", nil).Body.String()
	for _, want := range []string{"Kitchen HomePod", "HomePod", "lynch.user", "Staff Wi-Fi", "No certificate.", "Download Wi-Fi profile"} {
		if !strings.Contains(page, want) {
			t.Fatalf("page lacks %q", want)
		}
	}

	rr := do("POST", "/admin/other-devices/1/wifi/1/download", url.Values{})
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/x-apple-aspen-config" || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("download = %d %q: %s", rr.Code, rr.Header().Get("Content-Type"), flash(rr))
	}
	profile := rr.Body.Bytes()
	if err = vpn.CheckWiFi(profile); err != nil {
		t.Fatalf("downloaded profile fails its checks: %v", err)
	}
	var top map[string]any
	if err = plist.Unmarshal(profile, &top); err != nil {
		t.Fatal(err)
	}
	var challenge string
	for _, raw := range top["PayloadContent"].([]any) {
		if p := raw.(map[string]any); p["PayloadType"] == "com.apple.security.scep" {
			challenge = p["PayloadContent"].(map[string]any)["Challenge"].(string)
		}
	}
	if challenge == "" {
		t.Fatal("downloaded profile has no SCEP challenge")
	}
	if page = do("GET", "/admin/other-devices", nil).Body.String(); !strings.Contains(page, "Profile downloaded, not installed yet.") {
		t.Fatal("page does not show the profile waiting to be installed")
	}

	// The HomePod installs the profile: it makes a key and asks for the certificate.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "lynch.user"}}, key)
	csr, _ := x509.ParseCertificateRequest(der)
	leaf, err := service.SignCSRContext(ctx, &scep.CSRReqMessage{CSR: csr, ChallengePassword: challenge})
	if err != nil {
		t.Fatal(err)
	}
	serial := leaf.SerialNumber.Text(16)
	page = do("GET", "/admin/other-devices", nil).Body.String()
	if !strings.Contains(strings.ToLower(page), serial) || !strings.Contains(page, "days left") || !strings.Contains(page, "Download new Wi-Fi profile") {
		t.Fatalf("page does not show certificate %s with its time left", serial)
	}
	if strings.Contains(page, "Remove Kitchen HomePod from the list") {
		t.Fatal("page offers to remove a device that holds a certificate")
	}
	if page = do("GET", "/admin/wifi", nil).Body.String(); !strings.Contains(page, "Kitchen HomePod (not in MDM)") || !strings.Contains(page, `href="/admin/other-devices"`) {
		t.Fatal("Wi-Fi page does not list the certificate under the device's name")
	}

	if rr = do("POST", "/admin/other-devices/1/remove", url.Values{}); !strings.Contains(flash(rr), "still holds a certificate") {
		t.Fatalf("remove with a live certificate -> %q", flash(rr))
	}
	rows, _ := db.DeviceVPNIdentities(ctx, sqlite.ManualDeviceID(1))
	if rr = do("POST", "/admin/vpn/identities/"+strconv.FormatInt(rows[0].ID, 10)+"/revoke", url.Values{}); rr.Code != http.StatusSeeOther || !strings.HasPrefix(rr.Header().Get("Location"), "/admin/other-devices?") {
		t.Fatalf("revoke = %d -> %s", rr.Code, rr.Header().Get("Location"))
	}
	if rr = do("POST", "/admin/other-devices/1/remove", url.Values{}); !strings.Contains(flash(rr), "Device removed") {
		t.Fatalf("remove after revoking -> %q", flash(rr))
	}
	// The name is left only as the placeholder in the add form.
	if page = do("GET", "/admin/other-devices", nil).Body.String(); strings.Count(page, "Kitchen HomePod") != 1 {
		t.Fatal("removed device is still listed")
	}
}
