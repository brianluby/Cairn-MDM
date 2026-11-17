package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
)

// usersApp builds the standard test app with the user-management backend wired
// (testApp seeds admin "nick" through a LocalStore over the same database, so a
// fresh LocalStore here sees the same accounts).
func usersApp(t *testing.T) (*App, *auth.SessionStore) {
	t.Helper()
	app, sessions, db := testApp(t)
	app.SetUsers(auth.NewLocalStore(db.SQL()))
	return app, sessions
}

func TestUsersPageListsSeededAdmin(t *testing.T) {
	app, _ := usersApp(t)
	m := mux(app)
	cookies := login(t, m)

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("users page = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "nick") {
		t.Error("users page missing the seeded admin account")
	}
	if !strings.Contains(body, "New user") {
		t.Error("users page missing the create form")
	}
}

func TestUsersPageUnavailableWithoutStore(t *testing.T) {
	app, _, _ := testApp(t) // no SetUsers
	m := mux(app)
	cookies := login(t, m)

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("users page without store = %d, want 503", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "unavailable") {
		t.Error("users page without store missing the unavailable notice")
	}
}

// TestUserCreateGeneratedPasswordShownOnce creates a user with no password so
// one is generated: the create response must show it inline, and a subsequent
// list request must not.
func TestUserCreateGeneratedPasswordShownOnce(t *testing.T) {
	app, sessions := usersApp(t)
	m := mux(app)
	cookie, csrf := adminSession(t, sessions)

	form := strings.NewReader("csrf=" + csrf + "&username=ops&role=operator&display_name=Ops")
	req := httptest.NewRequest(http.MethodPost, "/admin/users", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create with generated password = %d, want 200 (inline one-time display)", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "ops") {
		t.Error("create response missing the new username")
	}
	if !strings.Contains(body, "Shown once") {
		t.Error("create response missing the one-time password display")
	}

	// The list page after creation shows the account but not the password card.
	req = httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("users page = %d, want 200", rr.Code)
	}
	body = rr.Body.String()
	if !strings.Contains(body, "ops") {
		t.Error("users page missing the created account")
	}
	if strings.Contains(body, "Shown once") {
		t.Error("users page re-displayed the one-time password card")
	}
}

// TestUserCreateWithPasswordCanLogIn creates a user with an explicit password
// (PRG flow) and verifies the account authenticates.
func TestUserCreateWithPasswordCanLogIn(t *testing.T) {
	app, sessions := usersApp(t)
	m := mux(app)
	cookie, csrf := adminSession(t, sessions)

	form := strings.NewReader("csrf=" + csrf + "&username=viewer&role=user&password=correcthorsebattery")
	req := httptest.NewRequest(http.MethodPost, "/admin/users", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("create with explicit password = %d, want 303", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "flash=") {
		t.Fatalf("create redirect = %q, want a created flash", loc)
	}

	loginForm := strings.NewReader("username=viewer&password=correcthorsebattery")
	req = httptest.NewRequest(http.MethodPost, "/login", loginForm)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("login as created user = %d, want 302", rr.Code)
	}
}

// TestDeleteLastAdminRefused checks LocalStore's last-admin refusal surfaces as
// an error redirect (not a crash) and the account survives.
func TestDeleteLastAdminRefused(t *testing.T) {
	app, sessions := usersApp(t)
	m := mux(app)
	cookie, csrf := adminSession(t, sessions)

	form := strings.NewReader("csrf=" + csrf)
	req := httptest.NewRequest(http.MethodPost, "/admin/users/nick/delete", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("delete last admin = %d, want 303", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "error=") || !strings.Contains(loc, "last+admin") {
		t.Fatalf("delete redirect = %q, want the last-admin refusal in ?error=", loc)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "nick") {
		t.Error("the last admin was deleted despite the refusal")
	}
}

// TestSettingsPageReadOnly checks the settings page renders config values and
// never leaks the SCEP challenge.
func TestSettingsPageReadOnly(t *testing.T) {
	app, sessions := usersApp(t)
	app.cfg.Organization = "com.dzsec.mdm"
	app.cfg.SCEPURL = "https://scep.mgmt.dzsec.net/scep/mdm"
	app.cfg.SCEPChallenge = "sekrit-challenge"
	m := mux(app)
	cookie, _ := adminSession(t, sessions)

	req := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("settings page = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "https://mdm.example.org") {
		t.Error("settings page missing the public URL")
	}
	if !strings.Contains(body, "com.dzsec.mdm") {
		t.Error("settings page missing the organization")
	}
	if !strings.Contains(body, "configured") {
		t.Error("settings page missing the SCEP challenge status")
	}
	if strings.Contains(body, "sekrit-challenge") {
		t.Error("settings page leaked the SCEP challenge value")
	}
}
