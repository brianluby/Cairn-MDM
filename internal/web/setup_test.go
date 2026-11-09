package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// emptyApp is testApp without the seeded administrator, so first-run is open.
func emptyApp(t *testing.T) (*App, *auth.SessionStore, *sqlite.DB, *auth.SetupGate) {
	t.Helper()
	path := t.TempDir() + "/web.db"
	db, err := sqlite.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	sessions := auth.NewSessionStore(db.SQL(), time.Hour)
	app, err := New(sessions, auth.NewLocalStore(db.SQL()), db, stubCommander{}, nil, Config{PublicURL: "https://mdm.example.org", CAMode: "external", TLSMode: "proxy"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	app.SetUsers(auth.NewLocalStore(db.SQL()))
	mfa, err := auth.NewMFAStore(db.SQL(), sessions, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	app.SetMFA(mfa)
	gate := auth.NewSetupGate(db.SQL(), path)
	if _, err = gate.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	app.SetSetup(gate)
	return app, sessions, db, gate
}

func TestFirstRunSetupCreatesAdministratorOnce(t *testing.T) {
	app, _, db, gate := emptyApp(t)
	m := mux(app)
	get := func(path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		return rr
	}
	if rr := get("/login"); !strings.Contains(rr.Body.String(), "/setup") {
		t.Fatal("login page does not point at setup while no administrator exists")
	}
	rr := get("/setup")
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, gate.TokenPath()) || !strings.Contains(body, "Direct external SCEP") || !strings.Contains(body, "no trusted proxies") || !strings.Contains(body, "Not loaded") {
		t.Fatalf("setup page %d %s", rr.Code, body)
	}
	raw, _ := os.ReadFile(gate.TokenPath())
	token := strings.TrimSpace(string(raw))
	post := func(form string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/setup", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, req)
		return rr
	}
	if rr = post("token=" + strings.Repeat("f", 64) + "&username=root&password=correcthorsebattery&confirm=correcthorsebattery"); rr.Code != 403 {
		t.Fatalf("wrong token %d", rr.Code)
	}
	if rr = post("token=" + token + "&username=root&password=correcthorsebattery&confirm=different-password"); rr.Code != 400 {
		t.Fatalf("mismatch %d", rr.Code)
	}
	req := httptest.NewRequest("POST", "/setup", strings.NewReader("token="+token+"&username=root&password=correcthorsebattery&confirm=correcthorsebattery"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("cross-origin %d", rr.Code)
	}
	if n, _ := auth.NewLocalStore(db.SQL()).CountUsers(context.Background()); n != 0 {
		t.Fatal("rejected requests created an account")
	}

	rr = post("token=" + token + "&username=root&password=correcthorsebattery&confirm=correcthorsebattery")
	body = rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, "Administrator created") || !strings.Contains(body, "Registration approval code") {
		t.Fatalf("complete %d %s", rr.Code, body)
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == SessionCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure {
		t.Fatalf("session cookie %+v", cookie)
	}
	approval := regexp.MustCompile(`(?s)<textarea[^>]*>([^<]+)</textarea>`).FindStringSubmatch(body)
	if len(approval) != 2 || strings.TrimSpace(approval[1]) == "" {
		t.Fatal("no approval code")
	}
	if _, err := os.Stat(gate.TokenPath()); !os.IsNotExist(err) {
		t.Fatal("token file kept after setup")
	}

	// The new session reaches the console; the approval code starts MFA setup.
	authed := httptest.NewRequest("GET", "/admin", nil)
	authed.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, authed)
	if rr.Code != 200 {
		t.Fatalf("console with setup session %d", rr.Code)
	}
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(rr.Body.String())
	begin := httptest.NewRequest("POST", "/account/mfa/begin", strings.NewReader("csrf="+csrf[1]+"&invitation="+strings.TrimSpace(approval[1])))
	begin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	begin.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, begin)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Setup key") {
		t.Fatalf("mfa begin with setup approval %d %s", rr.Code, rr.Body.String())
	}

	// Setup is closed: both routes vanish and the login hint disappears.
	if rr = get("/setup"); rr.Code != 404 {
		t.Fatalf("setup after completion %d", rr.Code)
	}
	if rr = post("token=" + token + "&username=second&password=correcthorsebattery&confirm=correcthorsebattery"); rr.Code != 404 {
		t.Fatalf("second administrator %d", rr.Code)
	}
	if rr = get("/login"); strings.Contains(rr.Body.String(), "/setup") {
		t.Fatal("login still advertises setup")
	}
	if n, _ := auth.NewLocalStore(db.SQL()).CountUsers(context.Background()); n != 1 {
		t.Fatalf("accounts %d", n)
	}
}

func TestSetupRoutesAbsentWithExistingAdministrator(t *testing.T) {
	app, _, db := testApp(t)
	app.SetSetup(auth.NewSetupGate(db.SQL(), t.TempDir()+"/y.db"))
	m := mux(app)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, httptest.NewRequest("GET", "/setup", nil))
	if rr.Code != 404 {
		t.Fatalf("setup with existing admin %d", rr.Code)
	}
	req := httptest.NewRequest("POST", "/setup", strings.NewReader("token=x&username=y&password=correcthorsebattery&confirm=correcthorsebattery"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatalf("setup post with existing admin %d", rr.Code)
	}
	cookie, _ := adminSession(t, app.sessions)
	settings := httptest.NewRequest("GET", "/admin/settings", nil)
	settings.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, settings)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Setup checklist") {
		t.Fatalf("settings checklist %d", rr.Code)
	}
}

func TestDashboardShowsActiveAlertsAndWebhookState(t *testing.T) {
	app, sessions, db := testApp(t)
	if err := db.SetAlertState(context.Background(), "apns.missing", true, "No APNs push certificate is loaded.", false); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAlertState(context.Background(), "backup.stale", false, "old", true); err != nil {
		t.Fatal(err)
	}
	cookie, _ := adminSession(t, sessions)
	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	mux(app).ServeHTTP(rr, req)
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, "No APNs push certificate is loaded.") || strings.Contains(body, "backup.stale") || !strings.Contains(body, "not configured") {
		t.Fatalf("dashboard alerts %d %s", rr.Code, body)
	}
}
