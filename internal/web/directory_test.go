package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

type previewDirectory struct {
	fail  bool
	calls int
}

func (d *previewDirectory) ResolveOwner(context.Context, string) (*auth.DirectoryIdentity, error) {
	d.calls++
	return &auth.DirectoryIdentity{DirectoryID: "example", ObjectID: "0102030405060708090a0b0c0d0e0f10", UPN: "nick@example.org"}, nil
}
func (d *previewDirectory) ResolveScope(context.Context, string, string, string) (*auth.DirectoryScope, error) {
	d.calls++
	return &auth.DirectoryScope{DirectoryID: "example", ObjectID: "0102030405060708090a0b0c0d0e0f10", Kind: "group", Mode: "direct", Name: "Lynchburg", DN: "CN=Lynchburg,DC=example,DC=org"}, nil
}
func (d *previewDirectory) EvaluateScopes(_ context.Context, owner auth.DirectoryIdentity, scopes []auth.DirectoryScope) (*auth.DirectoryScopeEvaluation, error) {
	d.calls++
	if d.fail {
		return nil, errors.New("directory offline")
	}
	result := &auth.DirectoryScopeEvaluation{Owner: owner, CheckedAt: time.Now()}
	for _, scope := range scopes {
		result.Matches = append(result.Matches, auth.DirectoryScopeMatch{Scope: scope, Matches: true})
	}
	return result, nil
}
func TestDirectoryPreviewPermissionsAndNoDeployment(t *testing.T) {
	app, sessions, db := testApp(t)
	directory := &previewDirectory{}
	app.SetDirectory(directory)
	m := mux(app)
	ctx := context.Background()
	group, err := db.CreateGroup(ctx, "Lynchburg", "")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := db.SaveProfile(ctx, sqlite.Profile{Identifier: "com.example.lynchburg", UUID: "profile", Name: "Lynchburg Wi-Fi", Data: []byte("profile")})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AssignProfile(ctx, group, profile); err != nil {
		t.Fatal(err)
	}
	scope, _ := directory.ResolveScope(ctx, "group", "direct", "Lynchburg")
	if err = db.SaveDirectoryProfileRule(ctx, group, *scope, "admin", "local"); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := adminSession(t, sessions)
	post := func(cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/admin/directory/preview", strings.NewReader("csrf="+csrf+"&account=nick"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, req)
		return rr
	}
	if rr := post(cookie, csrf); rr.Code != 200 || !strings.Contains(rr.Body.String(), "Lynchburg Wi-Fi") || !strings.Contains(rr.Body.String(), "Preview only") {
		t.Fatalf("preview %d %s", rr.Code, rr.Body.String())
	}
	calls := directory.calls
	if rr := post(cookie, "wrong"); rr.Code != 403 {
		t.Fatalf("CSRF %d", rr.Code)
	}
	operator, err := sessions.Create(ctx, auth.Identity{Username: "operator", Provider: "local", Role: auth.RoleOperator})
	if err != nil {
		t.Fatal(err)
	}
	if rr := post(&http.Cookie{Name: SessionCookie, Value: operator.Token}, operator.CSRF); rr.Code != 403 {
		t.Fatalf("role %d", rr.Code)
	}
	if directory.calls != calls {
		t.Fatal("unauthorized request queried directory")
	}
	directory.fail = true
	if rr := post(cookie, csrf); rr.Code != 503 || strings.Contains(rr.Body.String(), "No profiles match") {
		t.Fatalf("unknown presented as empty: %d %s", rr.Code, rr.Body.String())
	}
	for _, table := range []string{"group_devices", "command_history", "profile_deploys"} {
		var count int
		if err := db.SQL().QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("preview changed %s: %d %v", table, count, err)
		}
	}
}

func TestDirectoryRuleSaveUsesResolvedIdentity(t *testing.T) {
	app, sessions, db := testApp(t)
	directory := &previewDirectory{}
	app.SetDirectory(directory)
	m := mux(app)
	group, err := db.CreateGroup(context.Background(), "Lynchburg", "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := adminSession(t, sessions)
	form := fmt.Sprintf("csrf=%s&group_id=%d&scope=group:direct&name=Lynchburg&object_id=attacker&directory_id=other", csrf, group)
	req := httptest.NewRequest("POST", "/admin/directory/rules", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != 303 {
		t.Fatalf("save %d %s", rr.Code, rr.Body.String())
	}
	rules, err := db.ListDirectoryProfileRules(context.Background())
	if err != nil || len(rules) != 1 || rules[0].Scope.DirectoryID != "example" || rules[0].Scope.ObjectID != "0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("unverified form identity saved: %+v %v", rules, err)
	}
}
