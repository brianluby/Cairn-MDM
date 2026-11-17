package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/vpn"
)

func vpnTestCA(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func vpnTestKey() string {
	return "-----BEGIN OpenVPN Static key V1-----\n" + strings.Repeat(strings.Repeat("0123456789abcdef", 2)+"\n", 16) + "-----END OpenVPN Static key V1-----"
}

func vpnServerValues(csrf, ca string) url.Values {
	return url.Values{
		"csrf": {csrf}, "name": {"Office VPN"}, "remotes": {"vpn.example.org 443 udp\nvpn.example.org 443 tcp"},
		"verify_x509_name": {"vpn.example.org"}, "ca_pem": {ca}, "tls_key_mode": {"tls-auth"}, "key_direction": {"1"},
		"tls_key": {vpnTestKey()}, "cipher": {"AES-256-GCM"}, "auth": {"SHA256"}, "user_auth": {"on"},
	}
}

func TestVPNServerCreateEditDelete(t *testing.T) {
	app, sessions, db := testApp(t)
	servers, err := vpn.NewServers(db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	app.SetVPN(servers)
	m := mux(app)
	cookie, csrf := freshAdmin(t, app, sessions, db)
	ca := vpnTestCA(t)

	rr := postForm(m, cookie, "/admin/vpn/new", vpnServerValues(csrf, ca).Encode())
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("create = %d: %s", rr.Code, rr.Body.String())
	}
	list, err := servers.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	s := list[0]
	if s.Slug != "office-vpn" || len(s.Remotes) != 2 || s.TLSKey != vpnTestKey() || !s.UserAuth {
		t.Fatalf("stored server = %+v", s)
	}

	// The shared key is sealed in the database and never sent to the browser.
	var config, sealed []byte
	if err := db.SQL().QueryRow(`SELECT config, tls_key FROM vpn_servers`).Scan(&config, &sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("0123456789abcdef")) || bytes.Contains(config, []byte("0123456789abcdef")) {
		t.Fatal("static key stored in the clear")
	}
	req := httptest.NewRequest("GET", "/admin/vpn/1", nil)
	req.AddCookie(cookie)
	page := httptest.NewRecorder()
	m.ServeHTTP(page, req)
	if page.Code != 200 || strings.Contains(page.Body.String(), "0123456789abcdef") || !strings.Contains(page.Body.String(), "A key is stored") {
		t.Fatalf("edit page = %d, leaks key or lacks the stored-key note", page.Code)
	}

	// An edit without a pasted key keeps the stored one; the identifier cannot change.
	v := vpnServerValues(csrf, ca)
	v.Set("name", "Office VPN 2")
	v.Set("slug", "renamed")
	v.Set("tls_key", "")
	if rr = postForm(m, cookie, "/admin/vpn/1", v.Encode()); rr.Code != http.StatusSeeOther {
		t.Fatalf("update = %d: %s", rr.Code, rr.Body.String())
	}
	s, _ = servers.Get(context.Background(), 1)
	if s.Name != "Office VPN 2" || s.Slug != "office-vpn" || s.TLSKey != vpnTestKey() {
		t.Fatalf("after update = %+v", s)
	}

	// A record the renderer would refuse is not saved.
	v = vpnServerValues(csrf, ca)
	v.Set("remotes", "vpn.example.org 443 udp4")
	if rr = postForm(m, cookie, "/admin/vpn/1", v.Encode()); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid update = %d, want 400", rr.Code)
	}

	var audits int
	db.SQL().QueryRow(`SELECT count(*) FROM audit_log WHERE provider='cairn-vpn' AND username='nick'`).Scan(&audits)
	if audits != 2 {
		t.Fatalf("named audit rows = %d, want 2 (create, update)", audits)
	}

	if rr = postForm(m, cookie, "/admin/vpn/1/delete", "csrf="+csrf); rr.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d", rr.Code)
	}
	if list, _ = servers.List(context.Background()); len(list) != 0 {
		t.Fatal("server not deleted")
	}
}

func TestVPNServerWritesNeedFreshMFAAndCSRF(t *testing.T) {
	app, sessions, db := testApp(t)
	servers, _ := vpn.NewServers(db, make([]byte, 32))
	app.SetVPN(servers)
	m := mux(app)
	ca := vpnTestCA(t)

	// Admin session without a verified second factor.
	stale, staleCSRF := adminSession(t, sessions)
	if rr := postForm(m, stale, "/admin/vpn/new", vpnServerValues(staleCSRF, ca).Encode()); rr.Code != http.StatusForbidden {
		t.Fatalf("create without fresh MFA = %d, want 403", rr.Code)
	}
	cookie, _ := freshAdmin(t, app, sessions, db)
	if rr := postForm(m, cookie, "/admin/vpn/new", vpnServerValues("wrong", ca).Encode()); rr.Code != http.StatusForbidden {
		t.Fatalf("create with bad CSRF = %d, want 403", rr.Code)
	}
	if list, _ := servers.List(context.Background()); len(list) != 0 {
		t.Fatal("a refused request stored a server")
	}
}

func TestVPNImportPrefillsFormWithoutSaving(t *testing.T) {
	app, sessions, db := testApp(t)
	servers, _ := vpn.NewServers(db, make([]byte, 32))
	app.SetVPN(servers)
	m := mux(app)
	cookie, csrf := freshAdmin(t, app, sessions, db)
	ovpn := "client\ndev tun\nremote vpn.example.org 443 udp4\nverify-x509-name \"vpn.example.org\" name\nauth-user-pass\nup /bin/sh\n<ca>\n" + vpnTestCA(t) + "</ca>\n<key>\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n</key>\n"
	rr := postForm(m, cookie, "/admin/vpn/import", url.Values{"csrf": {csrf}, "ovpn": {ovpn}}.Encode())
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, "vpn.example.org 443 udp") || strings.Contains(body, "udp4") {
		t.Fatalf("import = %d; remotes not normalized", rr.Code)
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("client key echoed back")
	}
	if !strings.Contains(body, "client certificate and key") || !strings.Contains(body, ">up<") {
		t.Fatal("left-out items not listed")
	}
	if list, _ := servers.List(context.Background()); len(list) != 0 {
		t.Fatal("import saved a server")
	}
}

func TestVPNPagesOffWhenDisabled(t *testing.T) {
	app, sessions, _ := testApp(t)
	m := mux(app)
	cookie, _ := adminSession(t, sessions)
	req := httptest.NewRequest("GET", "/admin/vpn", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("/admin/vpn with VPN off = %d, want 503", rr.Code)
	}
	req = httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), `href="/admin/vpn"`) {
		t.Fatal("nav shows VPN while disabled")
	}
}

type adminCheck struct {
	DirectoryResolver
	err error
}

func (c adminCheck) RevalidateAdministrator(context.Context, auth.DirectoryIdentity) error {
	return c.err
}

// A directory administrator's session outlives removal from the admin group.
// Server-record writes and issuing both ask the directory again.
func TestDirectoryAdminIsRecheckedForVPNWrites(t *testing.T) {
	request := func(id auth.Identity) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/admin/vpn/new", nil)
		return r.WithContext(context.WithValue(r.Context(), sessionKey, &auth.Session{Identity: id}))
	}
	ldapAdmin := auth.Identity{Provider: "ldap", Role: auth.RoleAdmin, Directory: &auth.DirectoryIdentity{}}
	cases := []struct {
		name string
		app  *App
		id   auth.Identity
		want bool
	}{
		{"still an administrator", &App{directory: adminCheck{}}, ldapAdmin, true},
		{"removed from the group", &App{directory: adminCheck{err: errors.New("not a member")}}, ldapAdmin, false},
		{"directory not configured", &App{}, ldapAdmin, false},
		{"session without a directory identity", &App{directory: adminCheck{}}, auth.Identity{Provider: "ldap", Role: auth.RoleAdmin}, false},
		{"local administrator", &App{}, auth.Identity{Provider: "local", Role: auth.RoleAdmin}, true},
	}
	for _, c := range cases {
		if got := c.app.directoryAdminCurrent(request(c.id)); got != c.want {
			t.Errorf("%s: allowed = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIKEv2ServerCreateAndEdit(t *testing.T) {
	app, sessions, db := testApp(t)
	servers, err := vpn.NewServers(db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	app.SetVPN(servers)
	m := mux(app)
	cookie, csrf := freshAdmin(t, app, sessions, db)
	values := func() url.Values {
		return url.Values{
			"csrf": {csrf}, "kind": {"ikev2"}, "name": {"Office IKEv2"}, "remote_address": {"vpn.example.org"},
			"server_cert_issuer_cn": {"Test CA"}, "ca_pem": {vpnTestCA(t)}, "sign_in": {"eap-tls"},
			"encryption": {"AES-256-GCM"}, "integrity": {"SHA2-256"}, "dh_group": {"20"}, "pfs": {"on"},
			"on_demand": {"on"}, "trusted_ssids": {"Office\r\nHome Net\r\n"},
		}
	}
	req := httptest.NewRequest("GET", "/admin/vpn/new?kind=ikev2", nil)
	req.AddCookie(cookie)
	page := httptest.NewRecorder()
	m.ServeHTTP(page, req)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Add IKEv2 server") || strings.Contains(page.Body.String(), "Static key") {
		t.Fatalf("new IKEv2 form = %d", page.Code)
	}
	if strings.Contains(page.Body.String(), "known-cas") {
		t.Fatal("issuer suggestions offered although the console knows no CA")
	}
	rr := postForm(m, cookie, "/admin/vpn/new", values().Encode())
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("create = %d: %s", rr.Code, rr.Body.String())
	}
	s, err := servers.Get(context.Background(), 1)
	if err != nil || !s.IsIKEv2() || s.Slug != "office-ikev2" || !s.OnDemand || !s.IKEv2.PFS || s.IKEv2.DHGroup != 20 ||
		len(s.IKEv2.TrustedSSIDs) != 2 || s.IKEv2.TrustedSSIDs[1] != "Home Net" {
		t.Fatalf("stored server = %+v, %v", s, err)
	}

	// An edit cannot turn the record into an OpenVPN server.
	v := values()
	v.Set("kind", "openvpn")
	v.Set("name", "Office IKEv2 b")
	v.Set("sign_in", "certificate")
	if rr = postForm(m, cookie, "/admin/vpn/1", v.Encode()); rr.Code != http.StatusSeeOther {
		t.Fatalf("update = %d: %s", rr.Code, rr.Body.String())
	}
	if s, _ = servers.Get(context.Background(), 1); !s.IsIKEv2() || s.Name != "Office IKEv2 b" || s.IKEv2.SignIn != vpn.IKEv2Certificate {
		t.Fatalf("after update = %+v", s)
	}

	// A record the renderer would refuse is not saved; the form is shown again.
	v = values()
	v.Set("server_cert_issuer_cn", "Some Other CA")
	if rr = postForm(m, cookie, "/admin/vpn/1", v.Encode()); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "CA chain") {
		t.Fatalf("issuer outside the chain = %d", rr.Code)
	}

	req = httptest.NewRequest("GET", "/admin/vpn", nil)
	req.AddCookie(cookie)
	page = httptest.NewRecorder()
	m.ServeHTTP(page, req)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "IKEv2") || !strings.Contains(page.Body.String(), "vpn.example.org") {
		t.Fatalf("list page = %d", page.Code)
	}
}

// The issuer field offers the CAs devices get at enrollment, issuing CA first
// and prefilled, and still takes any other name.
func TestIKEv2FormSuggestsKnownIssuers(t *testing.T) {
	app, sessions, db := testApp(t)
	servers, err := vpn.NewServers(db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	app.SetVPN(servers)
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Root CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	issuingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuingTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Example Issuing CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuingDER, err := x509.CreateCertificate(rand.Reader, issuingTmpl, rootTmpl, &issuingKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	app.cfg.CAAnchorsDER = [][]byte{rootDER, issuingDER}
	m := mux(app)
	cookie, csrf := freshAdmin(t, app, sessions, db)

	req := httptest.NewRequest("GET", "/admin/vpn/new?kind=ikev2", nil)
	req.AddCookie(cookie)
	page := httptest.NewRecorder()
	m.ServeHTTP(page, req)
	body := page.Body.String()
	issuing, root := strings.Index(body, `<option value="Example Issuing CA">`), strings.Index(body, `<option value="Example Root CA">`)
	if issuing < 0 || root < 0 || issuing > root {
		t.Fatalf("suggestions missing or roots listed first (issuing at %d, root at %d)", issuing, root)
	}
	if !strings.Contains(body, `name="server_cert_issuer_cn" value="Example Issuing CA"`) {
		t.Fatal("the issuing CA is not prefilled")
	}
	// A name that is not suggested is still accepted.
	rr := postForm(m, cookie, "/admin/vpn/new", url.Values{
		"csrf": {csrf}, "kind": {"ikev2"}, "name": {"Partner VPN"}, "remote_address": {"vpn.partner.example"},
		"server_cert_issuer_cn": {"Partner Issuing CA G2"}, "sign_in": {"password"},
		"encryption": {"AES-256-GCM"}, "integrity": {"SHA2-256"}, "dh_group": {"20"},
	}.Encode())
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("create with a typed issuer = %d: %s", rr.Code, rr.Body.String())
	}
}
