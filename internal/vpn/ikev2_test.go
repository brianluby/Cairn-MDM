package vpn

import (
	"strings"
	"testing"

	"github.com/micromdm/plist"
)

func testIKEv2Server(caPEM string) Server {
	return Server{
		Name: "Office IKEv2", Slug: "office-ikev2", Kind: KindIKEv2, CAPEM: caPEM,
		IKEv2: IKEv2{
			RemoteAddress: "vpn.example.org", ServerCertIssuerCN: "Test CA", SignIn: IKEv2Password,
			Encryption: "AES-256-GCM", Integrity: "SHA2-256", DHGroup: 20, PFS: true,
		},
	}
}

// ikev2Of returns the IKEv2 dictionary and the payloads by type.
func ikev2Of(t *testing.T, profile []byte) (map[string]any, map[string][]map[string]any) {
	t.Helper()
	var top map[string]any
	if err := plist.Unmarshal(profile, &top); err != nil {
		t.Fatal(err)
	}
	byType := map[string][]map[string]any{}
	for _, raw := range top["PayloadContent"].([]any) {
		p := raw.(map[string]any)
		kind := p["PayloadType"].(string)
		byType[kind] = append(byType[kind], p)
	}
	vpn := byType["com.apple.vpn.managed"]
	if len(vpn) != 1 {
		t.Fatalf("VPN payloads = %d", len(vpn))
	}
	return vpn[0]["IKEv2"].(map[string]any), byType
}

func TestIKEv2PasswordProfile(t *testing.T) {
	caPEM, _, _ := testPKI(t, "alice")
	out, err := RenderIKEv2("org.example", testIKEv2Server(caPEM), IKEv2Identity{DeviceID: "PHONE1", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	ike, byType := ikev2Of(t, out)
	for key, want := range map[string]any{
		"RemoteAddress": "vpn.example.org", "RemoteIdentifier": "vpn.example.org", "ServerCertificateCommonName": "vpn.example.org",
		"ServerCertificateIssuerCommonName": "Test CA", "LocalIdentifier": "alice", "AuthName": "alice", "AuthenticationMethod": "None",
	} {
		if ike[key] != want {
			t.Errorf("%s = %v, want %v", key, ike[key], want)
		}
	}
	if _, has := ike["AuthPassword"]; has {
		t.Error("profile carries a password key")
	}
	if _, has := ike["PayloadCertificateUUID"]; has || len(byType["com.apple.security.scep"]) != 0 {
		t.Error("password sign-in carries a certificate request")
	}
	if len(byType["com.apple.security.root"]) != 1 {
		t.Errorf("root CA payloads = %d, want 1", len(byType["com.apple.security.root"]))
	}
	child := ike["ChildSecurityAssociationParameters"].(map[string]any)
	if child["EncryptionAlgorithm"] != "AES-256-GCM" || child["IntegrityAlgorithm"] != "SHA2-256" || child["DiffieHellmanGroup"] != uint64(20) {
		t.Errorf("child proposal = %v", child)
	}

	// The same device and server render the same identifiers, so a new profile
	// replaces the installed one.
	again, _ := RenderIKEv2("org.example", testIKEv2Server(caPEM), IKEv2Identity{DeviceID: "PHONE1", Username: "alice"})
	if string(again) != string(out) {
		t.Error("rendering is not repeatable")
	}
	other, _ := RenderIKEv2("org.example", testIKEv2Server(caPEM), IKEv2Identity{DeviceID: "PHONE2", Username: "alice"})
	if string(other) == string(out) {
		t.Error("two devices share payload UUIDs")
	}
}

func TestIKEv2CertificateProfilePointsAtTheSCEPPayload(t *testing.T) {
	caPEM, _, _ := testPKI(t, "alice")
	s := testIKEv2Server(caPEM)
	s.IKEv2.SignIn = IKEv2EAPTLS
	s.OnDemand = true
	s.IKEv2.TrustedSSIDs = []string{"Office", "Home Net"}
	enrollment := &SCEPEnrollment{URL: "https://mdm.example.org/scep/vpn", Challenge: "one-time", CommonName: "alice", Email: "alice@example.org"}
	out, err := RenderIKEv2("org.example", s, IKEv2Identity{DeviceID: "PHONE1", Username: "alice", SCEP: enrollment})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "PRIVATE KEY") {
		t.Fatal("profile carries a private key")
	}
	ike, byType := ikev2Of(t, out)
	scep := byType["com.apple.security.scep"]
	if len(scep) != 1 || ike["PayloadCertificateUUID"] != scep[0]["PayloadUUID"] {
		t.Fatalf("VPN payload does not point at the SCEP payload: %v", ike["PayloadCertificateUUID"])
	}
	content := scep[0]["PayloadContent"].(map[string]any)
	if content["KeyIsExtractable"] != false || content["Challenge"] != "one-time" {
		t.Errorf("SCEP content = %v", content)
	}
	if san := content["SubjectAltName"].(map[string]any); san["rfc822Name"] != "alice@example.org" {
		t.Errorf("SAN = %v", san)
	}
	if ike["AuthenticationMethod"] != "Certificate" || ike["ExtendedAuthEnabled"] != uint64(1) {
		t.Errorf("EAP-TLS sign-in = %v / %v", ike["AuthenticationMethod"], ike["ExtendedAuthEnabled"])
	}
	rules := ike["OnDemandRules"].([]any)
	first, last := rules[0].(map[string]any), rules[len(rules)-1].(map[string]any)
	if first["Action"] != "Disconnect" || len(first["SSIDMatch"].([]any)) != 2 {
		t.Errorf("first rule = %v", first)
	}
	if len(last) != 1 || last["Action"] != "Disconnect" {
		t.Errorf("last rule = %v", last)
	}
	if ike["OnDemandUserOverrideDisabled"] != uint64(0) {
		t.Error("user cannot switch On Demand off although the record allows it")
	}

	// IKE certificate authentication is the same profile without EAP.
	s.IKEv2.SignIn = IKEv2Certificate
	out, err = RenderIKEv2("org.example", s, IKEv2Identity{DeviceID: "PHONE1", Username: "alice", SCEP: enrollment})
	if err != nil {
		t.Fatal(err)
	}
	if ike, _ = ikev2Of(t, out); ike["ExtendedAuthEnabled"] != uint64(0) {
		t.Error("certificate sign-in still asks for EAP")
	}
}

func TestIKEv2Refusals(t *testing.T) {
	caPEM, _, _ := testPKI(t, "alice")
	enrollment := &SCEPEnrollment{URL: "https://mdm.example.org/scep/vpn", Challenge: "one-time", CommonName: "alice"}
	cases := []struct {
		name   string
		change func(*Server, *IKEv2Identity)
		want   string
	}{
		{"issuer not in the chain", func(s *Server, _ *IKEv2Identity) { s.IKEv2.ServerCertIssuerCN = "Some Other CA" }, "issuer"},
		{"on demand with a password", func(s *Server, _ *IKEv2Identity) { s.OnDemand = true }, "on demand"},
		{"trusted networks without on demand", func(s *Server, _ *IKEv2Identity) { s.IKEv2.TrustedSSIDs = []string{"Office"} }, "on demand"},
		{"weak group", func(s *Server, _ *IKEv2Identity) { s.IKEv2.DHGroup = 2 }, "group"},
		{"unknown cipher", func(s *Server, _ *IKEv2Identity) { s.IKEv2.Encryption = "3DES" }, "encryption"},
		{"no sign-in", func(s *Server, _ *IKEv2Identity) { s.IKEv2.SignIn = "" }, "sign in"},
		{"certificate without a request", func(s *Server, _ *IKEv2Identity) { s.IKEv2.SignIn = IKEv2EAPTLS }, "SCEP"},
		{"certificate for another name", func(s *Server, id *IKEv2Identity) {
			s.IKEv2.SignIn = IKEv2EAPTLS
			other := *enrollment
			other.CommonName = "administrator"
			id.SCEP = &other
		}, "does not match"},
		{"request without a challenge", func(s *Server, id *IKEv2Identity) {
			s.IKEv2.SignIn = IKEv2EAPTLS
			open := *enrollment
			open.Challenge = ""
			id.SCEP = &open
		}, "challenge"},
		{"password with a request", func(_ *Server, id *IKEv2Identity) { id.SCEP = enrollment }, "no SCEP"},
		{"account name with markup", func(_ *Server, id *IKEv2Identity) { id.Username = "alice<x>" }, "username"},
	}
	for _, c := range cases {
		s := testIKEv2Server(caPEM)
		id := IKEv2Identity{DeviceID: "PHONE1", Username: "alice"}
		c.change(&s, &id)
		_, err := RenderIKEv2("org.example", s, id)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.want)) {
			t.Errorf("%s: err = %v, want mention of %q", c.name, err, c.want)
		}
	}
	if _, err := RenderIKEv2("org.example", testServer(caPEM), IKEv2Identity{DeviceID: "PHONE1", Username: "alice"}); err == nil {
		t.Error("an OpenVPN record rendered as IKEv2")
	}
}

func TestCheckIKEv2RejectsSecrets(t *testing.T) {
	caPEM, _, _ := testPKI(t, "alice")
	out, err := RenderIKEv2("org.example", testIKEv2Server(caPEM), IKEv2Identity{DeviceID: "PHONE1", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	withPassword := strings.Replace(string(out), "<key>AuthName</key>", "<key>AuthPassword</key>\n\t\t\t\t<string>hunter2</string>\n\t\t\t\t<key>AuthName</key>", 1)
	if withPassword == string(out) {
		t.Fatal("test did not change the profile")
	}
	if err := CheckIKEv2([]byte(withPassword)); err == nil || !strings.Contains(err.Error(), "password") {
		t.Errorf("profile with a password passed: %v", err)
	}
	unpinned := strings.Replace(string(out), "<string>Test CA</string>", "<string></string>", 1)
	if err := CheckIKEv2([]byte(unpinned)); err == nil {
		t.Error("profile without a pinned issuer passed")
	}
}
