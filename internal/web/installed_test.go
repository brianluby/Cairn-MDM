package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
)

// removals records the identifiers a test asked to remove.
type removals struct {
	stubCommander
	removed *[]string
	asked   *int
}

func (c removals) SendRemoveProfile(_ context.Context, identifier string, _ ...string) error {
	*c.removed = append(*c.removed, identifier)
	return nil
}

func (c removals) SendProfileList(context.Context, ...string) error {
	*c.asked++
	return nil
}

func TestInstalledProfilesAreListedAndRemovable(t *testing.T) {
	ctx := context.Background()
	app, sessions, db := testApp(t)
	var removed []string
	var asked int
	app.cmd = removals{removed: &removed, asked: &asked}
	m := mux(app)
	cookie, csrf := freshAdmin(t, app, sessions, db)

	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "PHONE1", UDID: "PHONE1", Name: "Phone"}); err != nil {
		t.Fatal(err)
	}
	page := func() string {
		req := httptest.NewRequest("GET", "/admin/devices/PHONE1", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("device page = %d", rr.Code)
		}
		return rr.Body.String()
	}
	if body := page(); !strings.Contains(body, "has not been asked for its profiles") {
		t.Fatal("page does not say the device has not been asked")
	}
	intent := strings.Repeat("a", 32)
	rr := postForm(m, cookie, "/admin/devices/PHONE1/profile-list", url.Values{"csrf": {csrf}, "intent": {intent}}.Encode())
	if rr.Code != http.StatusSeeOther || asked != 1 {
		t.Fatalf("profile-list = %d, asked = %d", rr.Code, asked)
	}

	// The device answers: its enrollment profile, one an earlier server left,
	// and one the user installed by hand.
	err := db.SaveInstalledProfiles(ctx, "PHONE1", []mdmcore.InstalledProfile{
		{Identifier: "org.example.enroll", DisplayName: "Enrollment", PayloadTypes: []string{"com.apple.mdm", "com.apple.security.scep"}, Managed: true},
		{Identifier: "org.old.wifi", DisplayName: "Old Wi-Fi", Organization: "Old MDM", PayloadTypes: []string{"com.apple.wifi.managed"}, Managed: true},
		{Identifier: "org.user.thing", DisplayName: "By hand", PayloadTypes: []string{"com.apple.vpn.managed"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := page()
	for _, want := range []string{"org.old.wifi", "Old MDM", "com.apple.wifi.managed", "Enrollment profile", "Installed by hand"} {
		if !strings.Contains(body, want) {
			t.Errorf("device page lacks %q", want)
		}
	}
	if n := strings.Count(body, `name="identifier" value="org.`); n != 1 || !strings.Contains(body, `name="identifier" value="org.old.wifi"`) {
		t.Fatalf("remove buttons for installed profiles = %d, want one, for the old Wi-Fi profile", n)
	}

	remove := func(identifier string) {
		t.Helper()
		v := url.Values{"csrf": {csrf}, "intent": {intent + "-" + identifier}, "identifier": {identifier}}
		if rr := postForm(m, cookie, "/admin/devices/PHONE1/remove", v.Encode()); rr.Code != http.StatusSeeOther {
			t.Fatalf("remove %s = %d", identifier, rr.Code)
		}
	}
	remove("org.example.enroll")
	if len(removed) != 0 {
		t.Fatal("the enrollment profile was queued for removal")
	}
	remove("org.old.wifi")
	if len(removed) != 1 || removed[0] != "org.old.wifi" {
		t.Fatalf("removed = %v", removed)
	}

	// A later answer replaces the list.
	if err := db.SaveInstalledProfiles(ctx, "PHONE1", []mdmcore.InstalledProfile{{Identifier: "org.example.enroll", DisplayName: "Enrollment", PayloadTypes: []string{"com.apple.mdm"}, Managed: true}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page(), "org.old.wifi") {
		t.Fatal("a removed profile is still listed after the device's next answer")
	}
}
