package web

import (
	"context"
	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestGrantConsoleCreateShowsLinkAndQR(t *testing.T) {
	app, sessions, db := testApp(t)
	app.cfg.OwnerEnrollment = true
	app.SetDirectory(&previewDirectory{})
	mfa, err := auth.NewMFAStore(db.SQL(), sessions, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	app.SetMFA(mfa)
	id, err := auth.NewLocalStore(db.SQL()).Authenticate(context.Background(), "nick", "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(context.Background(), *id)
	if err != nil {
		t.Fatal(err)
	}
	// Seed a completed factor verification; MFA's real TOTP path is tested separately.
	if _, err = db.SQL().Exec(`INSERT INTO mfa_factors(principal,secret) VALUES(?,?)`, "local:"+id.SubjectID, []byte("test")); err != nil {
		t.Fatal(err)
	}
	if _, err = db.SQL().Exec(`UPDATE app_sessions SET mfa_verified_at=?`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: SessionCookie, Value: sess.Token}
	csrf := sess.CSRF
	m := mux(app)
	post := func(path, form string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, req)
		return rr
	}
	rr := post("/admin/enrollment/preview", "csrf="+csrf+"&label=Test+Mac&owner=nick&platform=macos&expires_hours=24")
	if rr.Code != 200 {
		t.Fatalf("preview %d %s", rr.Code, rr.Body.String())
	}
	match := regexp.MustCompile(`name="preview" value="([a-f0-9]+)"`).FindStringSubmatch(rr.Body.String())
	if len(match) != 2 {
		t.Fatal("missing owner confirmation")
	}
	form := "csrf=" + csrf + "&preview=" + match[1] + "&owner=attacker@example.org&platform=ios"
	rr = post("/admin/enrollment", form)
	if rr.Code != 200 {
		t.Fatalf("create %d %s", rr.Code, rr.Body.String())
	}
	grants, err := db.ListGrants(context.Background())
	if err != nil || len(grants) != 1 || grants[0].Owner != "nick@example.org" || grants[0].Platform != "macos" {
		t.Fatalf("unbound grant: %+v %v", grants, err)
	}
	if again := post("/admin/enrollment", form); again.Code != 409 {
		t.Fatal("preview replay accepted", again.Code)
	}

	body := rr.Body.String()
	// The one-time link is shown, contains /e/<token>, and a QR data URI.
	if !strings.Contains(body, "/e/") || !strings.Contains(body, "Enrollment link created") {
		t.Error("created link not shown on the page")
	}
	if !strings.Contains(body, "data:image/png;base64,") {
		t.Error("QR code not rendered")
	}
	// The grant now appears in the list.
	req := httptest.NewRequest(http.MethodGet, "/admin/enrollment", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "nick@example.org") {
		t.Error("grant missing from list")
	}
}

func TestGrantCreateRequiresCSRF(t *testing.T) {
	app, sessions, _ := testApp(t)
	m := mux(app)
	cookie, _ := adminSession(t, sessions)
	req := httptest.NewRequest(http.MethodPost, "/admin/enrollment", strings.NewReader("label=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-CSRF create = %d, want 403", rr.Code)
	}
}

// With a CA that issues on its own, the device gets no verified owner, so the
// preview must not promise the owner's profiles.
func TestPreviewForAnExternalCAShowsManagementOnly(t *testing.T) {
	app, sessions, db := testApp(t)
	app.cfg.OwnerEnrollment, app.cfg.OwnerUnverified = true, true
	app.SetDirectory(&previewDirectory{})
	mfa, err := auth.NewMFAStore(db.SQL(), sessions, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	app.SetMFA(mfa)
	id, err := auth.NewLocalStore(db.SQL()).Authenticate(context.Background(), "nick", "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(context.Background(), *id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.SQL().Exec(`INSERT INTO mfa_factors(principal,secret) VALUES(?,?)`, "local:"+id.SubjectID, []byte("test")); err != nil {
		t.Fatal(err)
	}
	if _, err = db.SQL().Exec(`UPDATE app_sessions SET mfa_verified_at=?`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/admin/enrollment/preview",
		strings.NewReader("csrf="+sess.CSRF+"&label=Test+iPad&owner=nick&platform=ios&expires_hours=24"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: sess.Token})
	rr := httptest.NewRecorder()
	mux(app).ServeHTTP(rr, req)
	body := rr.Body.String()
	if rr.Code != 200 {
		t.Fatalf("preview %d %s", rr.Code, body)
	}
	if !strings.Contains(body, "None. The device enrolls with management only.") {
		t.Fatal("the preview does not say the device gets no profiles")
	}
	if strings.Contains(body, "evaluated again after the device enrolls") || strings.Contains(body, "Profiles are pushed after") {
		t.Fatal("the preview still describes profiles this link cannot deploy")
	}
	if !strings.Contains(body, "Create single-use link") {
		t.Fatal("the link cannot be created")
	}
}
