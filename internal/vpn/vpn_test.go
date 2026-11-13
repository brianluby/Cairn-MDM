package vpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/plist"
)

func testStaticKey() string {
	line := strings.Repeat("0123456789abcdef", 2)
	return "-----BEGIN OpenVPN Static key V1-----\n" + strings.Repeat(line+"\n", 16) + "-----END OpenVPN Static key V1-----"
}

// testPKI returns a CA certificate PEM and a leaf certificate and key for cn.
func testPKI(t *testing.T, cn string) (caPEM string, certPEM, keyPEM []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caTmpl, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func testServer(caPEM string) Server {
	return Server{
		Name: "Office VPN", Slug: "office",
		Remotes:        []Remote{{Host: "vpn.example.org", Port: 443, Proto: "udp"}},
		VerifyX509Name: "vpn.example.org", CAPEM: caPEM,
		TLSKeyMode: TLSKeyAuth, KeyDirection: 1, TLSKey: testStaticKey(),
		Cipher: "AES-256-GCM", Auth: "SHA256", UserAuth: true,
	}
}

func vendorOf(t *testing.T, profile []byte) (map[string]any, map[string]any, map[string]any) {
	t.Helper()
	var top map[string]any
	if err := plist.Unmarshal(profile, &top); err != nil {
		t.Fatal(err)
	}
	payload := top["PayloadContent"].([]any)[0].(map[string]any)
	return top, payload["VPN"].(map[string]any), payload["VendorConfig"].(map[string]any)
}

func TestRenderPasswordProfile(t *testing.T) {
	caPEM, cert, key := testPKI(t, "alice")
	out, err := RenderMobileconfig("org.example", testServer(caPEM), Identity{DeviceID: "DEV1", Username: "alice", CertPEM: cert, KeyPEM: key})
	if err != nil {
		t.Fatal(err)
	}
	top, vpn, v := vendorOf(t, out)
	if top["PayloadIdentifier"] != "org.example.vpn.office" {
		t.Fatalf("identifier = %v", top["PayloadIdentifier"])
	}
	want := map[string]string{
		"client": "NOARGS", "nobind": "NOARGS", "auth-user-pass": "NOARGS", "USERNAME": "alice",
		"remote": "vpn.example.org 443 udp", "vpn-on-demand": "0", "key-direction": "1",
		"verify-x509-name": `"vpn.example.org" name`, "remote-cert-tls": "server", "cipher": "AES-256-GCM",
	}
	for k, w := range want {
		if v[k] != w {
			t.Errorf("VendorConfig[%s] = %q, want %q", k, v[k], w)
		}
	}
	for _, k := range []string{"ca", "cert", "key", "tls-auth"} {
		s, _ := v[k].(string)
		if strings.Contains(s, "\n") || !strings.Contains(s, `\n`) || !strings.HasPrefix(s, "-----BEGIN ") {
			t.Errorf("%s is not a single line with literal \\n: %.40q", k, s)
		}
	}
	if vpn["AuthenticationMethod"] != "Certificate" || vpn["AuthName"] != "DEFAULT" || vpn["RemoteAddress"] != "DEFAULT" {
		t.Errorf("VPN dictionary = %v", vpn)
	}
	if _, ok := vpn["OnDemandRules"]; ok {
		t.Error("non-on-demand profile carries OnDemandRules")
	}
}

func TestRenderIsStablePerDeviceAndDiffersAcrossDevices(t *testing.T) {
	caPEM, cert, key := testPKI(t, "alice")
	s := testServer(caPEM)
	render := func(device string) map[string]any {
		out, err := RenderMobileconfig("org.example", s, Identity{DeviceID: device, Username: "alice", CertPEM: cert, KeyPEM: key})
		if err != nil {
			t.Fatal(err)
		}
		top, _, _ := vendorOf(t, out)
		return top
	}
	a, again, b := render("DEV1"), render("DEV1"), render("DEV2")
	if a["PayloadUUID"] != again["PayloadUUID"] {
		t.Error("a re-render for the same device changed the UUID, so it would not replace in place")
	}
	if a["PayloadUUID"] == b["PayloadUUID"] {
		t.Error("two devices share a payload UUID")
	}
}

func TestRenderOnDemandCertOnlyTwoRemotes(t *testing.T) {
	caPEM, cert, key := testPKI(t, "alice")
	s := testServer(caPEM)
	s.UserAuth, s.OnDemand = false, true
	s.TLSKeyMode, s.TLSKey = TLSKeyNone, ""
	s.TunMTU = 1420
	s.Remotes = append(s.Remotes, Remote{Host: "vpn.example.org", Port: 443, Proto: "tcp", TunMTU: 1400})
	out, err := RenderMobileconfig("org.example", s, Identity{DeviceID: "DEV1", Username: "alice", CertPEM: cert, KeyPEM: key})
	if err != nil {
		t.Fatal(err)
	}
	top, vpn, v := vendorOf(t, out)
	payloads := top["PayloadContent"].([]any)
	if len(payloads) != 2 {
		t.Fatalf("payloads = %d, want one per address", len(payloads))
	}
	second := payloads[1].(map[string]any)
	v2 := second["VendorConfig"].(map[string]any)
	if v["remote"] != "vpn.example.org 443 udp" || v2["remote"] != "vpn.example.org 443 tcp" {
		t.Errorf("remotes = %v / %v", v["remote"], v2["remote"])
	}
	if v["tun-mtu"] != "1420" || v2["tun-mtu"] != "1400" {
		t.Errorf("tun-mtu = %v / %v, want the server value then the address override", v["tun-mtu"], v2["tun-mtu"])
	}
	if v["cert"] != v2["cert"] || v["key"] != v2["key"] {
		t.Error("the two connections do not share one identity")
	}
	first := payloads[0].(map[string]any)
	if first["PayloadUUID"] == second["PayloadUUID"] || first["PayloadIdentifier"] == second["PayloadIdentifier"] {
		t.Error("the two payloads share a UUID or identifier")
	}
	if first["UserDefinedName"] != "Office VPN (UDP 443)" || second["UserDefinedName"] != "Office VPN (TCP 443)" {
		t.Errorf("names = %v / %v", first["UserDefinedName"], second["UserDefinedName"])
	}
	for _, k := range []string{"vpn-on-demand", "auth-user-pass", "USERNAME", "tls-auth", "key-direction"} {
		if _, ok := v[k]; ok {
			t.Errorf("%s should be absent", k)
		}
	}
	if rules, _ := vpn["OnDemandRules"].([]any); len(rules) != 2 {
		t.Errorf("OnDemandRules = %v", vpn["OnDemandRules"])
	}
	// Only the first address connects on demand.
	if fmt.Sprint(second["VPN"].(map[string]any)["OnDemandEnabled"]) != "0" || v2["vpn-on-demand"] != "0" {
		t.Errorf("second connection is on demand: %v / %v", second["VPN"], v2["vpn-on-demand"])
	}
}

func TestRenderRefusesMismatchedIdentity(t *testing.T) {
	caPEM, cert, key := testPKI(t, "alice")
	if _, err := RenderMobileconfig("org.example", testServer(caPEM), Identity{DeviceID: "DEV1", Username: "bob", CertPEM: cert, KeyPEM: key}); err == nil {
		t.Fatal("rendered a profile whose certificate CN is not the username")
	}
	if _, err := RenderMobileconfig("org.example", testServer(caPEM), Identity{DeviceID: "DEV1", Username: "alice", CertPEM: cert, KeyPEM: cert}); err == nil {
		t.Fatal("rendered a profile without a private key")
	}
}

// Each case breaks one rule from the phase 0 device tests; Check must refuse it.
func TestCheckRejectsEachBrokenRule(t *testing.T) {
	caPEM, cert, key := testPKI(t, "alice")
	good, err := RenderMobileconfig("org.example", testServer(caPEM), Identity{DeviceID: "DEV1", Username: "alice", CertPEM: cert, KeyPEM: key})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(vpn, v map[string]any){
		"real newline in inline block": func(_, v map[string]any) { v["ca"] = strings.ReplaceAll(v["ca"].(string), `\n`, "\n") },
		"missing vpn-on-demand 0":      func(_, v map[string]any) { delete(v, "vpn-on-demand") },
		"RemoteAddress not DEFAULT":    func(vpn, _ map[string]any) { vpn["RemoteAddress"] = "vpn.example.org" },
		"Password auth method":         func(vpn, _ map[string]any) { vpn["AuthenticationMethod"] = "Password" },
		"udp4 in remote":               func(_, v map[string]any) { v["remote"] = "vpn.example.org 443 udp4" },
		"empty bare directive":         func(_, v map[string]any) { v["nobind"] = "" },
		"ignored directive":            func(_, v map[string]any) { v["persist-tun"] = "NOARGS" },
		"no username prefill":          func(_, v map[string]any) { delete(v, "USERNAME") },
		"no key":                       func(_, v map[string]any) { delete(v, "key") },
		"no server pin":                func(_, v map[string]any) { delete(v, "verify-x509-name") },
		"tls-auth without direction":   func(_, v map[string]any) { delete(v, "key-direction") },
	}
	for name, mutate := range cases {
		var top map[string]any
		if err := plist.Unmarshal(good, &top); err != nil {
			t.Fatal(err)
		}
		payload := top["PayloadContent"].([]any)[0].(map[string]any)
		mutate(payload["VPN"].(map[string]any), payload["VendorConfig"].(map[string]any))
		bad, err := plist.Marshal(top)
		if err != nil {
			t.Fatal(err)
		}
		if Check(bad) == nil {
			t.Errorf("%s: Check accepted the profile", name)
		}
	}
	if err := Check(good); err != nil {
		t.Fatalf("unmodified profile: %v", err)
	}
}

func TestServerValidate(t *testing.T) {
	caPEM, _, _ := testPKI(t, "alice")
	bad := map[string]func(*Server){
		"no remotes":       func(s *Server) { s.Remotes = nil },
		"udp4":             func(s *Server) { s.Remotes[0].Proto = "udp4" },
		"no pin":           func(s *Server) { s.VerifyX509Name = "" },
		"bad CA":           func(s *Server) { s.CAPEM = "nope" },
		"short static key": func(s *Server) { s.TLSKey = strings.Replace(s.TLSKey, "0123456789abcdef", "", 1) },
		"key without mode": func(s *Server) { s.TLSKeyMode = TLSKeyNone },
		"script option":    func(s *Server) { s.Extra = []Directive{{Name: "up", Value: "/bin/sh"}} },
		"bad slug":         func(s *Server) { s.Slug = "Office VPN" },
	}
	for name, mutate := range bad {
		s := testServer(caPEM)
		mutate(&s)
		if s.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := testServer(caPEM).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestImportOVPN(t *testing.T) {
	caPEM, cert, key := testPKI(t, "alice")
	crlf := strings.ReplaceAll(testStaticKey(), "\n", "\r\n")
	text := "dev tun\npersist-tun\npersist-key\ndata-ciphers AES-256-GCM:AES-128-GCM\ndata-ciphers-fallback AES-256-GCM\nauth SHA256\ntls-client\nclient\nresolv-retry infinite\n" +
		"remote vpn.example.org 443 udp4\nremote vpn.example.org 443 tcp4-client\nnobind\nverify-x509-name \"vpn.example.org\" name\nauth-user-pass\nremote-cert-tls server\nexplicit-exit-notify\ntun-mtu 1420\nup /etc/evil\n" +
		"<ca>\n" + caPEM + "</ca>\n<cert>\n" + string(cert) + "</cert>\n<key>\n" + string(key) + "</key>\nkey-direction 1\n<tls-auth>\n#\n# 2048 bit OpenVPN static key\n#\r\n" + crlf + "\r\n</tls-auth>\n"
	imp, err := ImportOVPN(text)
	if err != nil {
		t.Fatal(err)
	}
	s := imp.Server
	s.Name, s.Slug = "Office VPN", "office"
	if err := s.Validate(); err != nil {
		t.Fatalf("imported record does not validate: %v", err)
	}
	if len(s.Remotes) != 2 || s.Remotes[0].Proto != "udp" || s.Remotes[1].Proto != "tcp" {
		t.Errorf("remotes = %+v", s.Remotes)
	}
	if s.Cipher != "AES-256-GCM" || s.Auth != "SHA256" || s.TunMTU != 1420 || !s.UserAuth || s.VerifyX509Name != "vpn.example.org" || s.TLSKeyMode != TLSKeyAuth {
		t.Errorf("server = %+v", s)
	}
	if s.TLSKey != testStaticKey() {
		t.Error("static key was not normalized (CRLF or comments left in)")
	}
	if !imp.HadIdentity {
		t.Error("client identity in the file was not reported")
	}
	if len(imp.Skipped) != 1 || imp.Skipped[0] != "up" {
		t.Errorf("skipped = %v, want [up]", imp.Skipped)
	}
	if strings.Contains(s.CAPEM+s.TLSKey, "PRIVATE KEY") {
		t.Error("client key leaked into the server record")
	}
}

func TestSlugify(t *testing.T) {
	for in, want := range map[string]string{"Office VPN": "office-vpn", "  Universal (UDP+TCP) ": "universal-udp-tcp", "ÅÄ": ""} {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtraOptionsCannotRepeatOrEscape(t *testing.T) {
	caPEM, _, _ := testPKI(t, "alice")
	s := testServer(caPEM)
	s.Extra = []Directive{{Name: "route", Value: "10.0.0.0 255.0.0.0"}, {Name: "route", Value: "10.1.0.0 255.255.0.0"}}
	if err := s.Validate(); err == nil {
		t.Error("two route options were accepted; the profile would keep only one")
	}
	s.Extra = []Directive{{Name: "route", Value: `10.0.0.0 255.0.0.0\nup /bin/sh`}}
	if err := s.Validate(); err == nil {
		t.Error("an option value with a backslash was accepted")
	}
	imp, err := ImportOVPN("client\nremote vpn.example.org 443 udp\nverify-x509-name vpn.example.org name\ndhcp-option DNS 10.0.0.1\ndhcp-option DNS 10.0.0.2\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Server.Extra) != 1 || len(imp.Skipped) != 1 || !strings.Contains(imp.Skipped[0], "repeated") {
		t.Errorf("import kept %+v, skipped %v", imp.Server.Extra, imp.Skipped)
	}
}
