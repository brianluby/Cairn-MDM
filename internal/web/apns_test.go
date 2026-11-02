package web

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/push"
)

func TestAPNSWizardAccessAndRecovery(t *testing.T) {
	app, sessions, db := testApp(t)
	manager := push.RequestManager{Root: t.TempDir()}
	app.SetAPNS(manager, db)
	m := mux(app)
	cookie, csrf := adminSession(t, sessions)
	call := func(method, path, form string, c *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if c != nil {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/admin/apns", "", nil); w.Code != 302 {
		t.Fatalf("anonymous: %d", w.Code)
	}
	sess, err := sessions.Create(context.Background(), auth.Identity{Username: "reader", Role: auth.RoleOperator})
	if err != nil {
		t.Fatal(err)
	}
	viewer := &http.Cookie{Name: SessionCookie, Value: sess.Token}
	if w := call("GET", "/admin/apns", "", viewer); w.Code != 403 {
		t.Fatalf("viewer: %d", w.Code)
	}
	if w := call("POST", "/admin/apns/requests", "email=test@example.test", cookie); w.Code != 403 {
		t.Fatalf("csrf: %d", w.Code)
	}
	if w := call("GET", "/admin/apns", "", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), "</html>") {
		t.Fatalf("list template: %d %s", w.Code, w.Body)
	}
	values := url.Values{"csrf": {csrf}, "email": {"test@example.test"}, "apple_account": {"account reference"}}
	w := call("POST", "/admin/apns/requests", values.Encode(), cookie)
	if w.Code != 303 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	path := w.Header().Get("Location")
	id := strings.TrimPrefix(path, "/admin/apns/requests/")
	// Reconstruct the manager to exercise resumption from disk.
	app.SetAPNS(push.RequestManager{Root: manager.Root}, db)
	w = call("GET", path, "", cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "</html>") || !strings.Contains(w.Body.String(), "account reference") {
		t.Fatalf("request template: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("private key in response")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("request is cacheable")
	}
	if err := manager.SavePublicArtifact(id, "push.key", []byte("overwrite")); err == nil {
		t.Fatal("private artifact writable")
	}
	if _, err := manager.PublicArtifact(id, "push.key"); err == nil {
		t.Fatal("private artifact readable")
	}
	payload := []byte("base64-apple-request")
	if err := manager.SavePublicArtifact(id, "push_request.plist", payload); err != nil {
		t.Fatal(err)
	}
	w = call("GET", path+"/download", "", cookie)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), payload) {
		t.Fatal("download changed request")
	}
	if err := manager.SavePublicArtifact(id, "push_request.plist", []byte("replacement")); err == nil {
		t.Fatal("reviewed artifact replaced")
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("csrf", csrf)
	f, _ := mw.CreateFormFile("file", "bad.pem")
	_, _ = f.Write([]byte("not a certificate"))
	_ = mw.Close()
	r := httptest.NewRequest("POST", path+"/certificate", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	m.ServeHTTP(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "Certificate was not accepted") {
		t.Fatalf("bad certificate: %d %s", w.Code, w.Body)
	}
	if _, err := manager.PublicArtifact(id, "certificate.pem"); err == nil {
		t.Fatal("invalid certificate persisted")
	}
	values.Set("topic", "com.apple.mgmt.External.unknown")
	if w := call("POST", "/admin/apns/requests", values.Encode(), cookie); w.Code != 400 {
		t.Fatalf("unknown renewal topic: %d", w.Code)
	}
}

func TestAPNSReceiptSurvivesNewAppInstance(t *testing.T) {
	app, sessions, db := testApp(t)
	manager := push.RequestManager{Root: t.TempDir()}
	req, err := manager.Create("test@example.test", "US", "")
	if err != nil {
		t.Fatal(err)
	}
	// Seed only the public receipt to exercise the resumed page without using
	// Apple's production certificate/key or weakening the upload verifier.
	_, err = db.SQL().Exec(`INSERT INTO apns_changes(request_id,topic,fingerprint,subject,not_after,renew_topic,make_default,actor,provider) VALUES(?,?,?,?,?,'',0,'operator','local')`, req.ID, "com.apple.mgmt.External.fixture", "fixture-fingerprint", "fixture", "2027-11-02T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	app.SetAPNS(push.RequestManager{Root: manager.Root}, db)
	cookie, _ := adminSession(t, sessions)
	r := httptest.NewRequest("GET", "/admin/apns/requests/"+req.ID, nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	mux(app).ServeHTTP(w, r)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Certificate installed") || !strings.Contains(body, "</html>") {
		t.Fatalf("receipt render: %d %s", w.Code, body)
	}
	if strings.Contains(body, "Install verified certificate") || strings.Contains(body, "Send signed-request email") {
		t.Fatal("completed request still has mutation forms")
	}
	// Use the same cookie/token pair for a stale-tab submission.
	cookie, csrf := adminSession(t, sessions)
	r = httptest.NewRequest("POST", "/admin/apns/requests/"+req.ID+"/submit", strings.NewReader("csrf="+csrf))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	mux(app).ServeHTTP(w, r)
	if w.Code != 409 {
		t.Fatalf("completed request resubmitted: %d", w.Code)
	}
}
