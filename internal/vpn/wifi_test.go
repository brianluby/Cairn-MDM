package vpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/plist"
)

// wifiChain returns a root and an intermediate under it, as PEM.
func wifiChain(t *testing.T) string {
	t.Helper()
	ca := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	}
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootDER, err := x509.CreateCertificate(rand.Reader, ca(1, "Test Root CA"), ca(1, "Test Root CA"), &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuingDER, err := x509.CreateCertificate(rand.Reader, ca(2, "Test Issuing CA"), ca(1, "Test Root CA"), &issuingKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuingDER}))
}

func wifiRecord(chainPEM string) Server {
	return Server{Name: "Office Wi-Fi", Slug: "office-wifi", Kind: KindWiFi, CAPEM: chainPEM,
		WiFi: WiFi{SSID: "Office Secure", Security: WiFiWPA3Enterprise, ServerNames: []string{"radius1.example.org", "radius2.example.org"}}}
}

func wifiEnrollment(cn string) *SCEPEnrollment {
	return &SCEPEnrollment{URL: "https://mdm.example.org/scep/vpn", Challenge: "one-time", CommonName: cn, Email: "alice@example.org"}
}

func payloadsOf(t *testing.T, profile []byte) (top map[string]any, byType map[string][]map[string]any) {
	t.Helper()
	if err := plist.Unmarshal(profile, &top); err != nil {
		t.Fatal(err)
	}
	byType = map[string][]map[string]any{}
	for _, c := range top["PayloadContent"].([]any) {
		p := c.(map[string]any)
		byType[p["PayloadType"].(string)] = append(byType[p["PayloadType"].(string)], p)
	}
	return top, byType
}

func TestRenderWiFiCarriesEveryRequiredKey(t *testing.T) {
	chain := wifiChain(t)
	out, err := RenderWiFi("org.example", wifiRecord(chain), WiFiIdentity{DeviceID: "PHONE1", SCEP: wifiEnrollment("Alice.Smith")})
	if err != nil {
		t.Fatal(err)
	}
	top, by := payloadsOf(t, out)
	if top["PayloadIdentifier"] != "org.example.wifi.cert.office-wifi" || top["PayloadType"] != "Configuration" {
		t.Fatalf("profile identifier=%v type=%v", top["PayloadIdentifier"], top["PayloadType"])
	}
	if len(by) != 4 || len(by["com.apple.security.root"]) != 1 || len(by["com.apple.security.pkcs1"]) != 1 ||
		len(by["com.apple.security.scep"]) != 1 || len(by["com.apple.wifi.managed"]) != 1 {
		t.Fatalf("payload types = %v", by)
	}
	if strings.Contains(string(out), "PRIVATE KEY") || strings.Contains(string(out), "pkcs12") {
		t.Fatal("profile carries a key")
	}
	root, issuing := by["com.apple.security.root"][0], by["com.apple.security.pkcs1"][0]
	if root["PayloadDisplayName"] != "Test Root CA" || issuing["PayloadDisplayName"] != "Test Issuing CA" {
		t.Fatalf("root=%v intermediate=%v", root["PayloadDisplayName"], issuing["PayloadDisplayName"])
	}

	identity := by["com.apple.security.scep"][0]
	req := identity["PayloadContent"].(map[string]any)
	subject := req["Subject"].([]any)[0].([]any)[0].([]any)
	if req["URL"] != "https://mdm.example.org/scep/vpn" || req["Challenge"] != "one-time" || req["KeyIsExtractable"] != false ||
		subject[0] != "CN" || subject[1] != "Alice.Smith" || req["SubjectAltName"].(map[string]any)["rfc822Name"] != "alice@example.org" {
		t.Fatalf("SCEP request = %v", req)
	}

	wifi := by["com.apple.wifi.managed"][0]
	want := map[string]any{"SSID_STR": "Office Secure", "HIDDEN_NETWORK": false, "AutoJoin": true, "EncryptionType": "WPA3",
		"ProxyType": "None", "PayloadCertificateUUID": identity["PayloadUUID"]}
	for k, v := range want {
		if wifi[k] != v {
			t.Errorf("%s = %v, want %v", k, wifi[k], v)
		}
	}
	for _, k := range []string{"Password", "IsHotspot", "SetupModes"} {
		if _, ok := wifi[k]; ok {
			t.Errorf("Wi-Fi payload holds %s", k)
		}
	}
	eap := wifi["EAPClientConfiguration"].(map[string]any)
	if len(eap) != 7 {
		t.Errorf("EAP settings hold %d keys, want exactly 7: %v", len(eap), eap)
	}
	// The RADIUS server compares this with the certificate's common name, which
	// is the name the device is told to ask for, capitals included.
	if eap["UserName"] != "Alice.Smith" {
		t.Errorf("UserName = %v, want the requested common name", eap["UserName"])
	}
	if types := eap["AcceptEAPTypes"].([]any); len(types) != 1 || types[0] != uint64(13) {
		t.Errorf("AcceptEAPTypes = %v", types)
	}
	if eap["TLSMinimumVersion"] != "1.2" || eap["TLSAllowTrustExceptions"] != false || eap["TLSCertificateIsRequired"] != true {
		t.Errorf("TLS settings = %v", eap)
	}
	if names := eap["TLSTrustedServerNames"].([]any); len(names) != 2 || names[0] != "radius1.example.org" || names[1] != "radius2.example.org" {
		t.Errorf("TLSTrustedServerNames = %v", names)
	}
	anchors := eap["PayloadCertificateAnchorUUID"].([]any)
	if len(anchors) != 2 || anchors[0] != root["PayloadUUID"] || anchors[1] != issuing["PayloadUUID"] {
		t.Errorf("anchors = %v, want the two CA payloads", anchors)
	}

	// WPA2 is the other mode.
	rec := wifiRecord(chain)
	rec.WiFi.Security = WiFiWPA2Enterprise
	out2, err := RenderWiFi("org.example", rec, WiFiIdentity{DeviceID: "PHONE1", SCEP: wifiEnrollment("alice")})
	if err != nil {
		t.Fatal(err)
	}
	if _, by2 := payloadsOf(t, out2); by2["com.apple.wifi.managed"][0]["EncryptionType"] != "WPA2" {
		t.Error("WPA2 Enterprise record did not render EncryptionType WPA2")
	}

	if _, err := exec.LookPath("plutil"); err == nil {
		path := t.TempDir() + "/wifi.mobileconfig"
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
		if msg, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil {
			t.Fatalf("plutil -lint: %v: %s", err, msg)
		}
	}
}

func TestRenderWiFiForAMacJoinsAsTheSystem(t *testing.T) {
	chain := wifiChain(t)
	out, err := RenderWiFi("org.example", wifiRecord(chain), WiFiIdentity{DeviceID: "MAC1", SCEP: wifiEnrollment("alice"), Mac: true})
	if err != nil {
		t.Fatal(err)
	}
	_, by := payloadsOf(t, out)
	modes, _ := by["com.apple.wifi.managed"][0]["SetupModes"].([]any)
	if len(modes) != 1 || modes[0] != "System" {
		t.Fatalf("SetupModes = %v, want System alone", modes)
	}
	// An iPhone's profile has no such key (asserted above); a login-window mode
	// would hand the machine's certificate to whoever is at the keyboard.
	var top map[string]any
	if err := plist.Unmarshal(out, &top); err != nil {
		t.Fatal(err)
	}
	for _, c := range top["PayloadContent"].([]any) {
		if p := c.(map[string]any); p["PayloadType"] == "com.apple.wifi.managed" {
			p["SetupModes"] = []any{"System", "Loginwindow"}
		}
	}
	changed, err := plist.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckWiFi(changed); err == nil {
		t.Fatal("a profile with a login-window mode was accepted")
	}
}

func TestRenderWiFiReplacesInPlaceAndDiffersByDevice(t *testing.T) {
	chain := wifiChain(t)
	uuids := func(device string) (string, string) {
		out, err := RenderWiFi("org.example", wifiRecord(chain), WiFiIdentity{DeviceID: device, SCEP: wifiEnrollment("alice")})
		if err != nil {
			t.Fatal(err)
		}
		top, _ := payloadsOf(t, out)
		var list []string
		for _, c := range top["PayloadContent"].([]any) {
			list = append(list, c.(map[string]any)["PayloadUUID"].(string))
		}
		return top["PayloadUUID"].(string), strings.Join(list, ",")
	}
	a1, list1 := uuids("PHONE1")
	a2, list2 := uuids("PHONE1")
	b, _ := uuids("PHONE2")
	if a1 != a2 || list1 != list2 {
		t.Fatal("a second render for the same device has different UUIDs; it would not replace the installed profile")
	}
	if a1 == b {
		t.Fatal("two devices share a profile UUID")
	}
}

func TestRenderWiFiRefusesAnUnusableEnrollment(t *testing.T) {
	chain := wifiChain(t)
	url := "https://mdm.example.org/scep/vpn"
	bad := map[string]WiFiIdentity{
		"no enrollment":         {DeviceID: "PHONE1"},
		"no device":             {SCEP: wifiEnrollment("alice")},
		"no challenge":          {DeviceID: "PHONE1", SCEP: &SCEPEnrollment{URL: url, CommonName: "alice"}},
		"not an account name":   {DeviceID: "PHONE1", SCEP: &SCEPEnrollment{URL: url, Challenge: "x", CommonName: "alice smith"}},
		"SCEP URL without http": {DeviceID: "PHONE1", SCEP: &SCEPEnrollment{URL: "mdm.example.org/scep", Challenge: "x", CommonName: "alice"}},
	}
	for name, id := range bad {
		if _, err := RenderWiFi("org.example", wifiRecord(chain), id); err == nil {
			t.Errorf("%s: profile rendered", name)
		}
	}
}

func TestWiFiRecordValidation(t *testing.T) {
	chain := wifiChain(t)
	bad := map[string]func(*Server){
		"no SSID":            func(s *Server) { s.WiFi.SSID = "" },
		"long SSID":          func(s *Server) { s.WiFi.SSID = strings.Repeat("x", 33) },
		"personal security":  func(s *Server) { s.WiFi.Security = "wpa2" },
		"no server names":    func(s *Server) { s.WiFi.ServerNames = nil },
		"wildcard name":      func(s *Server) { s.WiFi.ServerNames = []string{"*.example.org"} },
		"URL as name":        func(s *Server) { s.WiFi.ServerNames = []string{"https://radius.example.org"} },
		"bare host name":     func(s *Server) { s.WiFi.ServerNames = []string{"radius"} },
		"repeated name":      func(s *Server) { s.WiFi.ServerNames = []string{"r.example.org", "R.example.org"} },
		"no CA certificates": func(s *Server) { s.CAPEM = "" },
		"a TLS key":          func(s *Server) { s.TLSKeyMode, s.TLSKey = TLSKeyAuth, testStaticKey() },
	}
	for name, change := range bad {
		s := wifiRecord(chain)
		change(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: record accepted", name)
		}
	}
	if err := wifiRecord(chain).Validate(); err != nil {
		t.Fatalf("good record refused: %v", err)
	}
}

func TestCheckWiFiRefusesUnsafeProfiles(t *testing.T) {
	good, err := RenderWiFi("org.example", wifiRecord(wifiChain(t)), WiFiIdentity{DeviceID: "PHONE1", SCEP: wifiEnrollment("alice")})
	if err != nil {
		t.Fatal(err)
	}
	payload := func(top map[string]any, kind string) map[string]any {
		for _, c := range top["PayloadContent"].([]any) {
			if p := c.(map[string]any); p["PayloadType"] == kind {
				return p
			}
		}
		t.Fatalf("no %s payload", kind)
		return nil
	}
	wifiOf := func(top map[string]any) map[string]any { return payload(top, "com.apple.wifi.managed") }
	eapOf := func(top map[string]any) map[string]any { return wifiOf(top)["EAPClientConfiguration"].(map[string]any) }
	scepOf := func(top map[string]any) map[string]any {
		return payload(top, "com.apple.security.scep")["PayloadContent"].(map[string]any)
	}
	bad := map[string]func(map[string]any){
		"trust exceptions allowed": func(top map[string]any) { eapOf(top)["TLSAllowTrustExceptions"] = true },
		"no server names":          func(top map[string]any) { delete(eapOf(top), "TLSTrustedServerNames") },
		"wildcard server name":     func(top map[string]any) { eapOf(top)["TLSTrustedServerNames"] = []any{"*.example.org"} },
		"no anchors":               func(top map[string]any) { delete(eapOf(top), "PayloadCertificateAnchorUUID") },
		"anchor outside profile":   func(top map[string]any) { eapOf(top)["PayloadCertificateAnchorUUID"] = []any{"X", "Y"} },
		"PEAP offered":             func(top map[string]any) { eapOf(top)["AcceptEAPTypes"] = []any{13, 25} },
		"a password":               func(top map[string]any) { eapOf(top)["UserPassword"] = "x" },
		"an outer identity":        func(top map[string]any) { eapOf(top)["OuterIdentity"] = "anonymous" },
		"no user name":             func(top map[string]any) { delete(eapOf(top), "UserName") },
		"TLS 1.0":                  func(top map[string]any) { eapOf(top)["TLSMinimumVersion"] = "1.0" },
		"pre-shared key":           func(top map[string]any) { wifiOf(top)["Password"] = "x" },
		"identity not referenced":  func(top map[string]any) { wifiOf(top)["PayloadCertificateUUID"] = "X" },
		"hidden network":           func(top map[string]any) { wifiOf(top)["HIDDEN_NETWORK"] = true },
		"personal encryption":      func(top map[string]any) { wifiOf(top)["EncryptionType"] = "WPA" },
		"extractable key":          func(top map[string]any) { scepOf(top)["KeyIsExtractable"] = true },
		"no challenge":             func(top map[string]any) { delete(scepOf(top), "Challenge") },
		"a key in the profile": func(top map[string]any) {
			payload(top, "com.apple.security.scep")["PayloadType"] = "com.apple.security.pkcs12"
		},
	}
	for name, change := range bad {
		var top map[string]any
		if err := plist.Unmarshal(good, &top); err != nil {
			t.Fatal(err)
		}
		change(top)
		out, err := plist.Marshal(top)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckWiFi(out); err == nil {
			t.Errorf("%s: profile accepted", name)
		}
	}
	if err := CheckWiFi(good); err != nil {
		t.Fatalf("good profile refused: %v", err)
	}
}
