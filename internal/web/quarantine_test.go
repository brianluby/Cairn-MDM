package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/quarantine"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func TestQuarantineListsHeldIssuances(t *testing.T) {
	app, _, db := testApp(t)
	m := mux(app)
	cookies := login(t, m)

	// Seed a quarantined issuance.
	ctx := context.Background()
	_, hash := sqlite.NewGrantToken()
	gid, err := db.CreateGrant(ctx, sqlite.Grant{
		Label: "t", Platform: "macos", Owner: "u@x",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05"),
	}, hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.BeginIssuance(ctx, gid, "txnZ", "spkiZ", "reqZ"); err != nil {
		t.Fatal(err)
	}
	if err := db.QuarantineIssuance(ctx, gid, "txnZ", "spkiZ", "reqZ", "ambiguous-ca-response", "external-scep", "catx"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/quarantine", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"ambiguous-ca-response", "external-scep", "held"} {
		if !strings.Contains(body, want) {
			t.Errorf("quarantine page missing %q", want)
		}
	}
	// Detail page carries the transaction and refuses steps without a resolver.
	detail := httptest.NewRequest(http.MethodGet, "/admin/quarantine/"+itoa(gid), nil)
	for _, c := range cookies {
		detail.AddCookie(c)
	}
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, detail)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "txnZ") || !strings.Contains(rr.Body.String(), "not configured") {
		t.Fatalf("detail %d %s", rr.Code, rr.Body.String())
	}
	if rr = postForm(m, cookies[0], "/admin/quarantine/"+itoa(gid)+"/fence", "csrf="+csrfFrom(t, m, cookies[0])); rr.Code != 303 || !strings.Contains(rr.Header().Get("Location"), "not+configured") {
		t.Fatalf("step without resolver %d %s", rr.Code, rr.Header().Get("Location"))
	}
}

func csrfFrom(t *testing.T, m http.Handler, cookie *http.Cookie) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(rr.Body.String())
	if len(match) != 2 {
		t.Fatal("no csrf token")
	}
	return match[1]
}

type fakeResolver struct {
	points   []string
	embedded bool
	calls    []string
	missing  []string
}

func (f *fakeResolver) Fence(_ context.Context, id int64, actor string) (*quarantine.FenceManifest, error) {
	f.calls = append(f.calls, "fence:"+actor)
	return &quarantine.FenceManifest{GrantID: id}, nil
}
func (f *fakeResolver) Enumerate(_ context.Context, id int64, actor string) (*quarantine.EnumerationManifest, error) {
	f.calls = append(f.calls, "enumerate")
	return &quarantine.EnumerationManifest{Scanned: 3, Serials: nil}, nil
}
func (f *fakeResolver) ConfirmRejected(_ context.Context, id int64, actor string) (*quarantine.RejectionManifest, []string, error) {
	f.calls = append(f.calls, "confirm")
	return &quarantine.RejectionManifest{}, f.missing, nil
}
func (f *fakeResolver) Release(_ context.Context, id int64, actor string) error {
	f.calls = append(f.calls, "release")
	return sqlite.ErrResolutionOrder
}
func (f *fakeResolver) Validate(context.Context, int64) ([]string, error) { return nil, nil }
func (f *fakeResolver) AcceptancePoints() []string                        { return f.points }
func (f *fakeResolver) EmbeddedBackend() bool                             { return f.embedded }

func TestQuarantineStepsNeedFreshMFAAndIngestNeedsToken(t *testing.T) {
	app, sessions, db := testApp(t)
	ctx := context.Background()
	_, hash := sqlite.NewGrantToken()
	gid, _ := db.CreateGrant(ctx, sqlite.Grant{Label: "t", Platform: "macos", Owner: "u@x", ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05")}, hash)
	_, _, _ = db.BeginIssuance(ctx, gid, "txnQ", "spkiQ", "reqQ")
	_ = db.QuarantineIssuance(ctx, gid, "txnQ", "spkiQ", "reqQ", "leaf-mismatch", "embedded", "txnQ")
	fr := &fakeResolver{points: []string{"radius-a.example.org"}, embedded: true, missing: []string{"serial 1: no observed Access-Reject from radius-a.example.org after revocation"}}
	app.SetQuarantineResolver(fr)
	app.SetRadiusIngestToken("secret-token")
	m := mux(app)

	// Admin without fresh MFA is refused; no resolver call.
	cookie, csrf := adminSession(t, sessions)
	mfa, _ := auth.NewMFAStore(db.SQL(), sessions, make([]byte, 32))
	app.SetMFA(mfa)
	if rr := postForm(m, cookie, "/admin/quarantine/"+itoa(gid)+"/fence", "csrf="+csrf); rr.Code != 403 || len(fr.calls) != 0 {
		t.Fatalf("stale mfa %d %v", rr.Code, fr.calls)
	}
	fresh, csrf2 := freshAdmin(t, app, sessions, db)
	if rr := postForm(m, fresh, "/admin/quarantine/"+itoa(gid)+"/fence", "csrf="+csrf2); rr.Code != 303 || len(fr.calls) != 1 || !strings.HasPrefix(fr.calls[0], "fence:local:nick") {
		t.Fatalf("fence %d %v", rr.Code, fr.calls)
	}
	// Incomplete confirmation redirects with what is missing.
	rr := postForm(m, fresh, "/admin/quarantine/"+itoa(gid)+"/confirm", "csrf="+csrf2)
	if rr.Code != 303 || !strings.Contains(rr.Header().Get("Location"), "missing=") {
		t.Fatalf("confirm %d %s", rr.Code, rr.Header().Get("Location"))
	}
	// Out-of-order release is a 409 from storage, surfaced as such.
	if rr = postForm(m, fresh, "/admin/quarantine/"+itoa(gid)+"/release", "csrf="+csrf2); rr.Code != 409 {
		t.Fatalf("release %d", rr.Code)
	}
	if rr = postForm(m, fresh, "/admin/quarantine/"+itoa(gid)+"/bogus", "csrf="+csrf2); rr.Code != 404 {
		t.Fatalf("unknown step %d", rr.Code)
	}

	// Ingest endpoint: token, known acceptance point, valid serial and time.
	post := func(token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/radius/rejections", strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		m.ServeHTTP(rr, req)
		return rr
	}
	good := `{"acceptance_point":"radius-a.example.org","serial":"1F3A","observed_at":"` + time.Now().UTC().Format(time.RFC3339) + `","source":"test"}`
	if rr = post("", good); rr.Code != 401 {
		t.Fatalf("no token %d", rr.Code)
	}
	if rr = post("wrong", good); rr.Code != 401 {
		t.Fatalf("wrong token %d", rr.Code)
	}
	if rr = post("secret-token", strings.Replace(good, "radius-a", "radius-z", 1)); rr.Code != 400 {
		t.Fatalf("unknown point %d", rr.Code)
	}
	if rr = post("secret-token", strings.Replace(good, "1F3A", "zz", 1)); rr.Code != 400 {
		t.Fatalf("bad serial %d", rr.Code)
	}
	if rr = post("secret-token", good); rr.Code != 204 {
		t.Fatalf("ingest %d %s", rr.Code, rr.Body.String())
	}
	got, err := db.RadiusRejectionsForSerial(ctx, "1f3a")
	if err != nil || len(got) != 1 || got[0].AcceptancePoint != "radius-a.example.org" {
		t.Fatalf("stored %v %v", got, err)
	}
	app.SetRadiusIngestToken("")
	if rr = post("secret-token", good); rr.Code != 404 {
		t.Fatalf("disabled ingest %d", rr.Code)
	}
}
