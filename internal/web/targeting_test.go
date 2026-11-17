package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/targeting"
)

type fakeTargeting struct {
	outcome targeting.Outcome
	err     error
	calls   []string
}

func (f *fakeTargeting) RefreshAndReconcile(_ context.Context, id string) (targeting.Outcome, error) {
	f.calls = append(f.calls, id)
	f.outcome.DeviceID = id
	return f.outcome, f.err
}
func (f *fakeTargeting) RefreshAll(context.Context) (targeting.Summary, error) {
	f.calls = append(f.calls, "all")
	return targeting.Summary{Devices: 2, Evaluated: 1, Unavailable: 1}, f.err
}

// freshAdmin returns an admin session with a seeded, freshly verified factor.
func freshAdmin(t *testing.T, app *App, sessions *auth.SessionStore, db *sqlite.DB) (*http.Cookie, string) {
	t.Helper()
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
	return &http.Cookie{Name: SessionCookie, Value: sess.Token}, sess.CSRF
}

func postForm(m http.Handler, cookie *http.Cookie, path, form string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	return rr
}

func TestEnrollmentPreviewShowsRulesAndStoresExplicitGroup(t *testing.T) {
	app, sessions, db := testApp(t)
	app.cfg.OwnerEnrollment = true
	app.SetDirectory(&previewDirectory{})
	cookie, csrf := freshAdmin(t, app, sessions, db)
	ctx := context.Background()
	ruleGroup, _ := db.CreateGroup(ctx, "Lynchburg", "")
	siteGroup, _ := db.CreateGroup(ctx, "Lynchburg basement", "")
	wifi, _ := db.SaveProfile(ctx, sqlite.Profile{Identifier: "com.example.wifi", UUID: "w", Name: "Lynchburg Wi-Fi", Data: []byte("p")})
	printer, _ := db.SaveProfile(ctx, sqlite.Profile{Identifier: "com.example.printer", UUID: "pr", Name: "Basement printer", Data: []byte("p")})
	_ = db.AssignProfile(ctx, ruleGroup, wifi)
	_ = db.AssignProfile(ctx, siteGroup, printer)
	if err := db.SaveDirectoryProfileRule(ctx, ruleGroup, auth.DirectoryScope{DirectoryID: "example", ObjectID: "0102030405060708090a0b0c0d0e0f10", Kind: "group", Mode: "direct", Name: "Lynchburg", DN: "CN=Lynchburg,DC=example,DC=org"}, "admin", "local"); err != nil {
		t.Fatal(err)
	}
	m := mux(app)
	rr := postForm(m, cookie, "/admin/enrollment/preview", "csrf="+csrf+"&label=Mac&owner=nick&platform=macos&expires_hours=4&group_id="+itoa(siteGroup))
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, "Lynchburg Wi-Fi") || !strings.Contains(body, "Basement printer") || !strings.Contains(body, "explicit Cairn group") || !strings.Contains(body, "Lynchburg: matches") {
		t.Fatalf("preview %d %s", rr.Code, body)
	}
	match := regexp.MustCompile(`name="preview" value="([a-f0-9]+)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatal("no create button")
	}
	if rr = postForm(m, cookie, "/admin/enrollment", "csrf="+csrf+"&preview="+match[1]); rr.Code != 200 {
		t.Fatalf("create %d %s", rr.Code, rr.Body.String())
	}
	grants, err := db.ListGrants(ctx)
	if err != nil || len(grants) != 1 || grants[0].AssignGroupID != siteGroup || grants[0].AssignGroupName != "Lynchburg basement" {
		t.Fatalf("explicit group not stored: %+v %v", grants, err)
	}
	for _, table := range []string{"group_devices", "directory_memberships", "profile_deploys"} {
		var n int
		if err := db.SQL().QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("authorization wrote %s", table)
		}
	}

	// An unknown group is rejected before any directory lookup.
	if rr = postForm(m, cookie, "/admin/enrollment/preview", "csrf="+csrf+"&owner=nick&platform=macos&expires_hours=4&group_id=999"); rr.Code != 400 {
		t.Fatalf("bad group %d", rr.Code)
	}

	// The same profile reached through two sources is listed once with both sources.
	_ = db.AssignProfile(ctx, siteGroup, wifi)
	rr = postForm(m, cookie, "/admin/enrollment/preview", "csrf="+csrf+"&owner=nick&platform=macos&expires_hours=4&group_id="+itoa(siteGroup))
	body = rr.Body.String()
	if rr.Code != 200 || strings.Count(body, "<h3>Lynchburg Wi-Fi</h3>") != 1 || !strings.Contains(body, "Lynchburg basement (explicit Cairn group)") || !strings.Contains(body, `name="preview"`) {
		t.Fatalf("merged sources: %d %s", rr.Code, body)
	}
}

func TestDeviceDirectoryRefreshRouteAndGroupDirectoryMembers(t *testing.T) {
	app, sessions, db := testApp(t)
	ctx := context.Background()
	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "UDID-1", UDID: "UDID-1", Name: "Field Mac"}); err != nil {
		t.Fatal(err)
	}
	ft := &fakeTargeting{outcome: targeting.Outcome{Owned: true, Evaluated: true, Matched: 1, Added: []int64{1}}}
	m := mux(app)
	cookie, csrf := adminSession(t, sessions)

	// Not configured: redirect with an explanation, nothing called.
	rr := postForm(m, cookie, "/admin/devices/UDID-1/directory-refresh", "csrf="+csrf)
	if rr.Code != 303 || !strings.Contains(rr.Header().Get("Location"), "not+configured") {
		t.Fatalf("unconfigured %d %s", rr.Code, rr.Header().Get("Location"))
	}
	app.SetTargeting(ft)
	if rr = postForm(m, cookie, "/admin/devices/UDID-1/directory-refresh", "csrf=wrong"); rr.Code != 403 || len(ft.calls) != 0 {
		t.Fatalf("csrf %d", rr.Code)
	}
	operator, _ := sessions.Create(ctx, auth.Identity{Username: "op", Provider: "local", Role: auth.RoleOperator})
	if rr = postForm(m, &http.Cookie{Name: SessionCookie, Value: operator.Token}, "/admin/devices/UDID-1/directory-refresh", "csrf="+operator.CSRF); rr.Code != 403 || len(ft.calls) != 0 {
		t.Fatalf("operator %d", rr.Code)
	}
	if rr = postForm(m, cookie, "/admin/devices/missing/directory-refresh", "csrf="+csrf); rr.Code != 404 {
		t.Fatalf("missing device %d", rr.Code)
	}
	rr = postForm(m, cookie, "/admin/devices/UDID-1/directory-refresh", "csrf="+csrf)
	if rr.Code != 303 || len(ft.calls) != 1 || !strings.Contains(rr.Header().Get("Location"), "1+matched") {
		t.Fatalf("refresh %d %s %v", rr.Code, rr.Header().Get("Location"), ft.calls)
	}
	ft.err = errors.New("boom")
	if rr = postForm(m, cookie, "/admin/devices/UDID-1/directory-refresh", "csrf="+csrf); rr.Code != 303 || !strings.Contains(rr.Header().Get("Location"), "not+changed") {
		t.Fatalf("failed refresh %d %s", rr.Code, rr.Header().Get("Location"))
	}

	// Group and device pages show directory-derived membership separately.
	group, _ := db.CreateGroup(ctx, "Lynchburg", "")
	if err := db.SaveDirectoryProfileRule(ctx, group, auth.DirectoryScope{DirectoryID: "example", ObjectID: "0102030405060708090a0b0c0d0e0f10", Kind: "ou", Mode: "descendants", Name: "Lynchburg", DN: "OU=Lynchburg,DC=example,DC=org"}, "admin", "local"); err != nil {
		t.Fatal(err)
	}
	rules, _ := db.ListDirectoryProfileRules(ctx)
	if _, err := db.ReplaceDirectoryMemberships(ctx, "UDID-1", []int64{rules[0].ID}); err != nil {
		t.Fatal(err)
	}
	get := func(path string) string {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("%s %d", path, rr.Code)
		}
		return rr.Body.String()
	}
	if body := get("/admin/groups/" + itoa(group)); !strings.Contains(body, "Devices from directory rules") || !strings.Contains(body, "Field Mac") {
		t.Fatalf("group page lacks directory member: %s", body)
	}
	body := get("/admin/devices/UDID-1")
	if !strings.Contains(body, "via ou Lynchburg (descendants)") || !strings.Contains(body, "No verified owner") || !strings.Contains(body, "Re-evaluate directory rules") {
		t.Fatalf("device page: %s", body)
	}

	// Refresh-all from the rules page needs a directory and reports a summary.
	app.SetDirectory(&previewDirectory{})
	if rr = postForm(m, cookie, "/admin/directory/refresh", "csrf="+csrf); rr.Code != 503 {
		t.Fatalf("refresh-all with failing targeting %d", rr.Code)
	}
	ft.err = nil
	if rr = postForm(m, cookie, "/admin/directory/refresh", "csrf="+csrf); rr.Code != 200 || !strings.Contains(rr.Body.String(), "Refreshed 2 owned device(s)") {
		t.Fatalf("refresh-all %d %s", rr.Code, rr.Body.String())
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
