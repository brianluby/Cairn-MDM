package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func TestProfileDeleteIsGatedByAssignmentsAndAcknowledgement(t *testing.T) {
	app, sessions, db := testApp(t)
	ctx := context.Background()
	m := mux(app)
	cookie, csrf := adminSession(t, sessions)
	wifi, err := db.SaveProfile(ctx, sqlite.Profile{Identifier: "com.example.wifi", UUID: "w", Name: "Lynchburg Wi-Fi", PayloadTypes: "com.apple.wifi.managed,com.apple.security.scep", Data: []byte("p")})
	if err != nil {
		t.Fatal(err)
	}
	group, _ := db.CreateGroup(ctx, "Lynchburg", "")
	_ = db.AssignProfile(ctx, group, wifi)
	_ = db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "D1", UDID: "D1", Name: "Field Mac"})
	_ = db.DeviceTokenUpdated(ctx, "D1")
	_ = db.AddDeviceToGroup(ctx, group, "D1")
	_ = db.MarkDeploySent(ctx, "D1", wifi, "cmd-1", "x")

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
	body := get("/admin/profiles/" + itoa(wifi))
	if !strings.Contains(body, "Wi-Fi network access") || !strings.Contains(body, "Unassign this profile from 1 group(s)") || strings.Contains(body, `name="acknowledge"`) {
		t.Fatalf("profile page while assigned: %s", body)
	}
	// Delete while assigned is refused.
	rr := postForm(m, cookie, "/admin/profiles/"+itoa(wifi)+"/delete", "csrf="+csrf)
	if rr.Code != 303 || !strings.Contains(rr.Header().Get("Location"), "Still+assigned") {
		t.Fatalf("delete while assigned %d %s", rr.Code, rr.Header().Get("Location"))
	}
	if _, err := db.GetProfile(ctx, wifi); err != nil {
		t.Fatal("profile deleted while assigned")
	}
	_ = db.UnassignProfile(ctx, group, wifi)
	// Deployed but unacknowledged: refused with the device count.
	rr = postForm(m, cookie, "/admin/profiles/"+itoa(wifi)+"/delete", "csrf="+csrf)
	if rr.Code != 303 || !strings.Contains(rr.Header().Get("Location"), "1+device") {
		t.Fatalf("delete without acknowledgement %d %s", rr.Code, rr.Header().Get("Location"))
	}
	body = get("/admin/profiles/" + itoa(wifi))
	if !strings.Contains(body, `name="acknowledge"`) {
		t.Fatal("acknowledgement not offered once unassigned")
	}
	rr = postForm(m, cookie, "/admin/profiles/"+itoa(wifi)+"/delete", "csrf="+csrf+"&acknowledge=yes")
	if rr.Code != 303 || !strings.Contains(rr.Header().Get("Location"), "flash=") {
		t.Fatalf("acknowledged delete %d %s", rr.Code, rr.Header().Get("Location"))
	}
	if _, err := db.GetProfile(ctx, wifi); err == nil {
		t.Fatal("profile not deleted")
	}
}

func TestGroupOutcomesAndDeviceListColumns(t *testing.T) {
	app, sessions, db := testApp(t)
	ctx := context.Background()
	m := mux(app)
	cookie, _ := adminSession(t, sessions)
	group, _ := db.CreateGroup(ctx, "Lynchburg", "")
	wifi, _ := db.SaveProfile(ctx, sqlite.Profile{Identifier: "com.example.wifi", UUID: "w", Name: "Lynchburg Wi-Fi", PayloadTypes: "com.apple.wifi.managed", Data: []byte("p")})
	_ = db.AssignProfile(ctx, group, wifi)
	for _, id := range []string{"D1", "D2", "D3"} {
		_ = db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: id, UDID: id, Name: "Mac " + id})
		_ = db.DeviceTokenUpdated(ctx, id)
		_ = db.AddDeviceToGroup(ctx, group, id)
	}
	_ = db.MarkDeploySent(ctx, "D1", wifi, "c1", "x")
	if _, err := db.SQL().Exec(`UPDATE profile_deploys SET status='installed' WHERE device_id='D1'`); err != nil {
		t.Fatal(err)
	}
	_ = db.MarkDeploySent(ctx, "D2", wifi, "c2", "x")
	if _, err := db.SQL().Exec(`UPDATE profile_deploys SET status='failed' WHERE device_id='D2'`); err != nil {
		t.Fatal(err)
	}
	_, hash := sqlite.NewGrantToken()
	gid, err := db.CreateGrant(ctx, sqlite.Grant{Owner: "person@example.org", Platform: "macos", ExpiresAt: "2030-01-01 00:00:00"}, hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`INSERT INTO device_owners(device_id, grant_id, directory_id, object_id, upn) VALUES('D1', ?, 'dzsec', 'o', 'person@example.org')`, gid); err != nil {
		t.Fatal(err)
	}
	outcomes, err := db.GroupProfileOutcomes(ctx, group, wifi)
	if err != nil || len(outcomes) != 3 {
		t.Fatalf("outcomes %+v %v", outcomes, err)
	}
	status := map[string]string{}
	for _, o := range outcomes {
		status[o.DeviceID] = o.Status
		if o.Source != "manual" {
			t.Fatalf("source %+v", o)
		}
	}
	if status["D1"] != "installed" || status["D2"] != "failed" || status["D3"] != "not sent" {
		t.Fatalf("statuses %v", status)
	}
	get := func(path string) string {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("%s %d", path, rr.Code)
		}
		return rr.Body.String()
	}
	body := get("/admin/groups/" + itoa(group))
	if !strings.Contains(body, "Per-device outcomes") || !strings.Contains(body, "not sent") || !strings.Contains(body, "Mac D3") {
		t.Fatalf("group page outcomes: %s", body)
	}
	body = get("/admin/devices")
	if !strings.Contains(body, "person@example.org") || !strings.Contains(body, "1 installed") || !strings.Contains(body, "1 failed") {
		t.Fatalf("device list columns: %s", body)
	}
	body = get("/admin/devices/D1")
	if !strings.Contains(body, "Provides: Wi-Fi network access") || !strings.Contains(body, "This takes away: Wi-Fi network access") {
		t.Fatalf("device page consequence: %s", body)
	}
}

func TestDashboardAlertActionsRefreshProgressAndRoleMappings(t *testing.T) {
	app, sessions, db := testApp(t)
	ctx := context.Background()
	app.SetUsers(auth.NewLocalStore(db.SQL()))
	app.cfg.LDAPEnabled = true
	app.cfg.RoleMappings = []RoleMapping{{Provider: "ldap", Source: "CN=MDM Admins,CN=Users,DC=dzsec,DC=net", Role: "admin"}, {Provider: "ldap", Role: "user"}}
	m := mux(app)
	cookie, csrf := adminSession(t, sessions)
	get := func(path string) string {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("%s %d", path, rr.Code)
		}
		return rr.Body.String()
	}
	_ = db.SetAlertState(ctx, "apns.expiring:topic", true, "Topic expires soon.", false)
	_ = db.SetAlertState(ctx, "issuance.quarantined", true, "1 held.", false)
	body := get("/admin")
	if !strings.Contains(body, `href="/admin/apns"`) || !strings.Contains(body, `href="/admin/quarantine"`) || !strings.Contains(body, "Open quarantine") {
		t.Fatalf("dashboard alert actions: %s", body)
	}
	for key, want := range map[string]string{"backup.stale": "/admin/settings", "device-cert.expiring": "/admin/devices", "renewal.refused": "/admin/devices", "unknown.key": ""} {
		if got := alertAction(key); got != want {
			t.Fatalf("alertAction(%s)=%s", key, got)
		}
	}

	body = get("/admin/users")
	if !strings.Contains(body, "CN=MDM Admins,CN=Users,DC=dzsec,DC=net") || !strings.Contains(body, "any other signed-in user") {
		t.Fatalf("role mappings: %s", body)
	}

	// Refresh progress: queue a DeviceInformation, then resolve it.
	_ = db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "D1", UDID: "D1", Name: "Mac"})
	_ = db.DeviceTokenUpdated(ctx, "D1")
	if err := db.CommandSent(ctx, "D1", "cmd-di", "DeviceInformation"); err != nil {
		t.Fatal(err)
	}
	body = get("/admin/devices/D1")
	if !strings.Contains(body, "waiting for the device") {
		t.Fatalf("pending refresh not shown: %s", body)
	}
	if err := db.CommandResult(ctx, "D1", "cmd-di", "Acknowledged", ""); err != nil {
		t.Fatal(err)
	}
	body = get("/admin/devices/D1")
	if !strings.Contains(body, "answered") {
		t.Fatalf("answered refresh not shown: %s", body)
	}
	_ = csrf
}
