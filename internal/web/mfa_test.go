package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
)

func TestMFABrowserRegistrationAndAuthorization(t *testing.T) {
	app, sessions, db := testApp(t)
	ctx := context.Background()
	m, e := auth.NewMFAStore(db.SQL(), sessions, make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	app.SetMFA(m)
	directory := &previewDirectory{}
	app.SetDirectory(directory)
	subject := strings.Repeat("a", 64)
	if _, e = db.SQL().Exec(`INSERT INTO app_users(username,password_hash,role,subject_id) VALUES('admin','unused','admin',?)`, subject); e != nil {
		t.Fatal(e)
	}
	session, e := sessions.Create(ctx, auth.Identity{Username: "admin", Role: auth.RoleAdmin, Provider: "local", SubjectID: subject})
	if e != nil {
		t.Fatal(e)
	}
	routes := mux(app)
	post := func(action string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/account/mfa/"+action, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: session.Token})
		rr := httptest.NewRecorder()
		routes.ServeHTTP(rr, req)
		return rr
	}
	invite, e := m.BootstrapLocal(ctx, "admin")
	if e != nil {
		t.Fatal(e)
	}
	if rr := post("begin", url.Values{"invitation": {invite}}); rr.Code != 403 {
		t.Fatalf("CSRF accepted %d", rr.Code)
	}
	if rr := post("invite", url.Values{"csrf": {session.CSRF}, "provider": {"ldap"}, "account": {"nick"}}); rr.Code != 403 || directory.calls != 0 {
		t.Fatal("unverified admin accessed directory")
	}
	rr := post("begin", url.Values{"csrf": {session.CSRF}, "invitation": {invite}})
	if rr.Code != 200 || rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Referrer-Policy") != "strict-origin" {
		t.Fatalf("setup headers: %d %v", rr.Code, rr.Header())
	}
	match := regexp.MustCompile(`Setup key: <code>([A-Z2-7]+)</code>`).FindStringSubmatch(rr.Body.String())
	if len(match) != 2 {
		t.Fatal("setup key not rendered", rr.Body.String())
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(match[1])
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(time.Now().Unix()/30))
	h := hmac.New(sha1.New, secret)
	h.Write(b[:])
	sum := h.Sum(nil)
	offset := sum[19] & 15
	code := fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
	rr = post("confirm", url.Values{"csrf": {session.CSRF}, "code": {code}})
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Save your recovery codes") {
		t.Fatal("confirmation failed", rr.Body.String())
	}
	rr = post("invite", url.Values{"csrf": {session.CSRF}, "provider": {"ldap"}, "account": {"nick"}, "object_id": {"forged"}})
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Approval code created") {
		t.Fatal("invitation failed", rr.Body.String())
	}
	if directory.calls != 1 {
		t.Fatalf("directory lookups %d", directory.calls)
	}
	var count int
	if e = db.SQL().QueryRow(`SELECT count(*) FROM mfa_invitations WHERE principal LIKE 'ldap:%'`).Scan(&count); e != nil || count != 1 {
		t.Fatalf("directory binding %d %v", count, e)
	}
	audits, e := db.ListAudit(ctx, 100)
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range audits {
		for _, value := range []string{a.Action, a.Target, a.Username, a.Result} {
			if strings.Contains(value, invite) || strings.Contains(value, match[1]) || strings.Contains(value, code) {
				t.Fatal("MFA credential leaked to audit")
			}
		}
	}
	// No anonymous setup route and no secret resurfacing on an ordinary page read.
	req := httptest.NewRequest("GET", "/account/mfa", nil)
	rr = httptest.NewRecorder()
	routes.ServeHTTP(rr, req)
	if rr.Code != 302 {
		t.Fatal("anonymous page", rr.Code)
	}
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: session.Token})
	rr = httptest.NewRecorder()
	routes.ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), match[1]) {
		t.Fatal("setup secret resurfaced")
	}
}

func TestOriginCheckRejectsCrossOriginAndNull(t *testing.T) {
	for _, origin := range []string{"null", "https://attacker.example", "https://localhost:9999", "http://localhost:8447"} {
		r := httptest.NewRequest("POST", "https://localhost:8447/account/mfa/verify", nil)
		r.Header.Set("Origin", origin)
		if sameOrigin(r, "https://localhost:8447") {
			t.Fatalf("accepted origin %q", origin)
		}
	}
	r := httptest.NewRequest("POST", "https://localhost:8447/account/mfa/verify", nil)
	r.Header.Set("Origin", "https://localhost:8447")
	if !sameOrigin(r, "https://localhost:8447") {
		t.Fatal("same-origin form rejected")
	}
}
