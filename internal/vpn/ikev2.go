package vpn

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/micromdm/plist"
)

// Server kinds. A record with no kind is an OpenVPN server.
const (
	KindOpenVPN = "openvpn"
	KindIKEv2   = "ikev2"
)

// How a device signs in to an IKEv2 server.
const (
	// IKEv2Password is EAP with the user's name and password (MSCHAPv2). The
	// user types the password once on the device, which keeps it; Cairn does
	// not put passwords in profiles.
	IKEv2Password = "password"
	// IKEv2EAPTLS is EAP-TLS with a certificate whose key the device makes.
	IKEv2EAPTLS = "eap-tls"
	// IKEv2Certificate is IKE certificate authentication, no EAP.
	IKEv2Certificate = "certificate"
)

// IKEv2 holds the settings of a native IKEv2 server. Name, Slug, CAPEM and
// OnDemand come from the Server it belongs to. CAPEM is optional: devices
// normally trust the CA already, from the enrollment profile.
type IKEv2 struct {
	RemoteAddress    string
	RemoteIdentifier string // IKE identity of the server; empty means RemoteAddress
	// ServerCertIssuerCN and ServerCertCN pin the server certificate. When the
	// record has a CA chain, the issuer must be a certificate in it.
	ServerCertIssuerCN string
	ServerCertCN       string // empty means RemoteIdentifier
	SignIn             string
	// One proposal for the IKE and the child security association.
	Encryption string
	Integrity  string
	DHGroup    int
	PFS        bool
	// TrustedSSIDs are Wi-Fi networks where On Demand disconnects.
	TrustedSSIDs []string
	// LockOnDemand stops the user switching On Demand off in Settings.
	LockOnDemand bool
	// InstallCA puts the record's CA chain in every profile. Leave it off when
	// devices already trust the CA.
	InstallCA bool
}

var (
	ikev2Encryption = map[string]bool{"AES-128": true, "AES-256": true, "AES-128-GCM": true, "AES-256-GCM": true, "ChaCha20Poly1305": true}
	ikev2Integrity  = map[string]bool{"SHA2-256": true, "SHA2-384": true, "SHA2-512": true}
	ikev2DHGroups   = map[int]bool{14: true, 15: true, 16: true, 17: true, 18: true, 19: true, 20: true, 21: true, 31: true, 32: true}
)

// IKEv2Choices lists the values a server record accepts, in the order a form
// should offer them. DHGroups are text so a form can compare them as typed.
type IKEv2Choices struct {
	Encryption []string
	Integrity  []string
	DHGroups   []string
}

// IKEv2Options returns the accepted proposal values.
func IKEv2Options() IKEv2Choices {
	return IKEv2Choices{
		Encryption: []string{"AES-256-GCM", "AES-128-GCM", "AES-256", "AES-128", "ChaCha20Poly1305"},
		Integrity:  []string{"SHA2-256", "SHA2-384", "SHA2-512"},
		DHGroups:   []string{"14", "15", "16", "17", "18", "19", "20", "21", "31", "32"},
	}
}

// UsesCertificate reports whether the device signs in with a certificate.
func (k IKEv2) UsesCertificate() bool {
	return k.SignIn == IKEv2EAPTLS || k.SignIn == IKEv2Certificate
}

func (k IKEv2) remoteID() string {
	if k.RemoteIdentifier != "" {
		return k.RemoteIdentifier
	}
	return k.RemoteAddress
}

func (k IKEv2) serverCN() string {
	if k.ServerCertCN != "" {
		return k.ServerCertCN
	}
	return k.remoteID()
}

// IsIKEv2 reports whether the record is a native IKEv2 server.
func (s Server) IsIKEv2() bool { return s.Kind == KindIKEv2 }

func (s Server) validateIKEv2() error {
	k := s.IKEv2
	if !hostRE.MatchString(k.RemoteAddress) {
		return fmt.Errorf("server address %q is not a hostname or IP address", k.RemoteAddress)
	}
	for _, name := range []string{k.remoteID(), k.serverCN()} {
		if !nameRE.MatchString(name) {
			return fmt.Errorf("%q is not a server identifier or certificate name", name)
		}
	}
	if !issuerRE.MatchString(k.ServerCertIssuerCN) {
		return errors.New("server certificate issuer is required: the common name of the CA that issued the server certificate")
	}
	if strings.TrimSpace(s.CAPEM) == "" {
		if k.InstallCA {
			return errors.New("installing the CA chain with the profile needs the chain")
		}
	} else {
		chain, err := parseCertificates(s.CAPEM)
		if err != nil {
			return fmt.Errorf("CA chain: %w", err)
		}
		issuerKnown := false
		for _, c := range chain {
			if c.Subject.CommonName == k.ServerCertIssuerCN {
				issuerKnown = true
			}
		}
		if !issuerKnown {
			return errors.New("server certificate issuer must be the common name of a certificate in the CA chain")
		}
	}
	switch k.SignIn {
	case IKEv2Password, IKEv2EAPTLS, IKEv2Certificate:
	default:
		return errors.New("choose how devices sign in: password, EAP-TLS or certificate")
	}
	if !ikev2Encryption[k.Encryption] {
		return fmt.Errorf("encryption %q is not supported", k.Encryption)
	}
	if !ikev2Integrity[k.Integrity] {
		return fmt.Errorf("integrity %q is not supported", k.Integrity)
	}
	if !ikev2DHGroups[k.DHGroup] {
		return fmt.Errorf("Diffie-Hellman group %d is not supported", k.DHGroup)
	}
	if len(k.TrustedSSIDs) > 0 && !s.OnDemand {
		return errors.New("trusted Wi-Fi networks only apply when the server connects on demand")
	}
	if k.LockOnDemand && !s.OnDemand {
		return errors.New("On Demand can only be locked on when the server connects on demand")
	}
	if len(k.TrustedSSIDs) > 50 {
		return errors.New("50 trusted Wi-Fi networks at most")
	}
	seen := map[string]bool{}
	for _, ssid := range k.TrustedSSIDs {
		if ssid == "" || len(ssid) > 32 || strings.ContainsAny(ssid, "\r\n\x00") {
			return fmt.Errorf("Wi-Fi network name %q must be 1 to 32 bytes on one line", ssid)
		}
		if seen[ssid] {
			return fmt.Errorf("Wi-Fi network %q is listed twice", ssid)
		}
		seen[ssid] = true
	}
	return nil
}

// SCEPEnrollment tells a device where to get the certificate it signs in with.
// The device makes the key and keeps it; nothing here is a secret that outlives
// the request except the challenge, which the SCEP server must accept once.
type SCEPEnrollment struct {
	URL        string
	Name       string // CA identifier some SCEP servers want; may be empty
	Challenge  string
	CommonName string
	Email      string // rfc822 subject alternative name; may be empty
	KeySize    int    // RSA bits; 0 means 2048
}

// IKEv2Identity is the per-device part of an IKEv2 profile.
type IKEv2Identity struct {
	DeviceID string // enrollment ID; keeps payload UUIDs stable per device
	Username string // directory account name
	SCEP     *SCEPEnrollment
}

// RenderIKEv2 builds an Apple configuration profile for the native IKEv2
// client: the VPN payload, for certificate sign-in a SCEP payload the VPN
// payload points at, and the CA chain when the record asks for it. No private
// key or password is ever part of the profile. The result has passed CheckIKEv2.
func RenderIKEv2(org string, s Server, id IKEv2Identity) ([]byte, error) {
	if !s.IsIKEv2() {
		return nil, errors.New("vpn: not an IKEv2 server record")
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("vpn: server record: %w", err)
	}
	if id.DeviceID == "" || !accountRE.MatchString(id.Username) {
		return nil, errors.New("vpn: device and username are required")
	}
	k := s.IKEv2
	if k.UsesCertificate() {
		switch {
		case id.SCEP == nil:
			return nil, errors.New("vpn: certificate sign-in needs a SCEP enrollment")
		case !strings.HasPrefix(id.SCEP.URL, "https://") && !strings.HasPrefix(id.SCEP.URL, "http://"):
			return nil, errors.New("vpn: SCEP URL must be http or https")
		case id.SCEP.Challenge == "":
			return nil, errors.New("vpn: SCEP enrollment needs a challenge")
		case id.SCEP.CommonName != id.Username:
			return nil, fmt.Errorf("vpn: certificate name %q does not match username %q", id.SCEP.CommonName, id.Username)
		}
	} else if id.SCEP != nil {
		return nil, errors.New("vpn: password sign-in takes no SCEP enrollment")
	}

	identifier := PayloadIdentifier(org, s)
	ns := uuid5(nsDNS, identifier+"."+id.DeviceID)
	payloadUUID := func(tag string) string { return strings.ToUpper(uuid5(ns, tag).String()) }

	proposal := func(lifetimeMinutes int) map[string]any {
		return map[string]any{
			"EncryptionAlgorithm": k.Encryption,
			"IntegrityAlgorithm":  k.Integrity,
			"DiffieHellmanGroup":  k.DHGroup,
			"LifeTimeInMinutes":   lifetimeMinutes,
		}
	}
	ike := map[string]any{
		"RemoteAddress":                     k.RemoteAddress,
		"RemoteIdentifier":                  k.remoteID(),
		"LocalIdentifier":                   id.Username,
		"ServerCertificateIssuerCommonName": k.ServerCertIssuerCN,
		"ServerCertificateCommonName":       k.serverCN(),
		"DeadPeerDetectionRate":             "Medium",
		"DisableMOBIKE":                     0,
		"DisableRedirect":                   1,
		"EnableCertificateRevocationCheck":  0,
		"EnablePFS":                         boolInt(k.PFS),
		"UseConfigurationAttributeInternalIPSubnet": 0,
		"NATKeepAliveOffloadEnable":                 1,
		"NATKeepAliveInterval":                      110,
		"IKESecurityAssociationParameters":          proposal(480),
		"ChildSecurityAssociationParameters":        proposal(60),
	}
	switch k.SignIn {
	case IKEv2Password:
		// The server proves itself with its certificate; the client does EAP only.
		ike["AuthenticationMethod"] = "None"
		ike["ExtendedAuthEnabled"] = 1
		ike["AuthName"] = id.Username
	case IKEv2EAPTLS, IKEv2Certificate:
		ike["AuthenticationMethod"] = "Certificate"
		ike["ExtendedAuthEnabled"] = boolInt(k.SignIn == IKEv2EAPTLS)
		ike["CertificateType"] = "RSA"
		ike["PayloadCertificateUUID"] = payloadUUID("scep")
	}
	// On Demand keys sit beside the IKEv2 dictionary, at the top of the VPN
	// payload, for every VPN type.
	vpn := map[string]any{
		"PayloadType":        "com.apple.vpn.managed",
		"PayloadVersion":     1,
		"PayloadIdentifier":  identifier + ".vpn",
		"PayloadUUID":        payloadUUID("vpn"),
		"PayloadDisplayName": "VPN",
		"PayloadDescription": "IKEv2 configuration for " + s.Name,
		"UserDefinedName":    s.Name,
		"VPNType":            "IKEv2",
		"IKEv2":              ike,
		"IPv4":               map[string]any{"OverridePrimary": 1},
		"Proxies":            map[string]any{"HTTPEnable": 0, "HTTPSEnable": 0},
		"OnDemandEnabled":    boolInt(s.OnDemand),
	}
	if s.OnDemand {
		var rules []any
		if len(k.TrustedSSIDs) > 0 {
			ssids := make([]any, len(k.TrustedSSIDs))
			for i, ssid := range k.TrustedSSIDs {
				ssids[i] = ssid
			}
			rules = append(rules, map[string]any{"Action": "Disconnect", "InterfaceTypeMatch": "WiFi", "SSIDMatch": ssids})
		}
		rules = append(rules,
			map[string]any{"Action": "Connect", "InterfaceTypeMatch": "WiFi"},
			map[string]any{"Action": "Connect", "InterfaceTypeMatch": "Cellular"},
			// Anything else, a wired Mac for one, stays off the VPN.
			map[string]any{"Action": "Disconnect"},
		)
		vpn["OnDemandRules"] = rules
		vpn["OnDemandUserOverrideDisabled"] = boolInt(k.LockOnDemand)
	}

	payloads := []any{vpn}
	if k.UsesCertificate() {
		size := id.SCEP.KeySize
		if size == 0 {
			size = 2048
		}
		content := map[string]any{
			"URL":       id.SCEP.URL,
			"Subject":   []any{[]any{[]any{"CN", id.SCEP.CommonName}}},
			"Key Type":  "RSA",
			"Key Usage": 5, // digitalSignature(1) | keyEncipherment(4)
			"Keysize":   size,
			"Challenge": id.SCEP.Challenge,
			// The key never leaves the device, not even into a backup.
			"KeyIsExtractable": false,
			"Retries":          3,
			"RetryDelay":       10,
		}
		if id.SCEP.Name != "" {
			content["Name"] = id.SCEP.Name
		}
		if id.SCEP.Email != "" {
			content["SubjectAltName"] = map[string]any{"rfc822Name": id.SCEP.Email}
		}
		payloads = append(payloads, map[string]any{
			"PayloadType":        "com.apple.security.scep",
			"PayloadVersion":     1,
			"PayloadIdentifier":  identifier + ".identity",
			"PayloadUUID":        payloadUUID("scep"),
			"PayloadDisplayName": "VPN certificate for " + id.Username,
			"PayloadContent":     content,
		})
	}
	var chain []*x509.Certificate
	if k.InstallCA {
		var err error
		if chain, err = parseCertificates(s.CAPEM); err != nil {
			return nil, fmt.Errorf("vpn: CA chain: %w", err)
		}
	}
	for i, c := range chain {
		kind := "com.apple.security.pkcs1"
		if bytes.Equal(c.RawSubject, c.RawIssuer) {
			kind = "com.apple.security.root"
		}
		tag := fmt.Sprintf("ca.%d", i)
		payloads = append(payloads, map[string]any{
			"PayloadType":                kind,
			"PayloadVersion":             1,
			"PayloadIdentifier":          identifier + "." + tag,
			"PayloadUUID":                payloadUUID(tag),
			"PayloadDisplayName":         c.Subject.CommonName,
			"PayloadCertificateFileName": tag + ".cer",
			"PayloadContent":             c.Raw,
		})
	}

	description := s.Name + " for " + id.Username + "."
	if k.SignIn == IKEv2Password {
		description += " The device asks for the account password the first time it connects."
	}
	prof := map[string]any{
		"PayloadType":              "Configuration",
		"PayloadVersion":           1,
		"PayloadIdentifier":        identifier,
		"PayloadUUID":              payloadUUID("top"),
		"PayloadDisplayName":       s.Name,
		"PayloadDescription":       description,
		"PayloadOrganization":      org,
		"PayloadRemovalDisallowed": false,
		"PayloadContent":           payloads,
	}
	out, err := plist.MarshalIndent(prof, "\t")
	if err != nil {
		return nil, fmt.Errorf("vpn: marshal profile: %w", err)
	}
	if err := CheckIKEv2(out); err != nil {
		return nil, fmt.Errorf("vpn: rendered profile failed its own checks: %w", err)
	}
	return out, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CheckIKEv2 applies the rules an IKEv2 profile must meet before it is sent:
// the server certificate is pinned, the profile holds no password and no
// private key, a certificate sign-in points at a SCEP payload in the same
// profile, and On Demand rules sit at the top of the VPN payload and end in a
// rule that always matches.
func CheckIKEv2(profile []byte) error {
	if bytes.Contains(profile, []byte("PRIVATE KEY")) {
		return errors.New("an IKEv2 profile must not carry a private key")
	}
	var top map[string]any
	if err := plist.Unmarshal(profile, &top); err != nil {
		return fmt.Errorf("not a property list: %w", err)
	}
	content, _ := top["PayloadContent"].([]any)
	if str(top["PayloadIdentifier"]) == "" || str(top["PayloadUUID"]) == "" || len(content) == 0 {
		return errors.New("profile needs an identifier, a UUID and at least one payload")
	}
	var vpn, ike map[string]any
	scep := map[string]map[string]any{} // by PayloadUUID
	seen := map[string]bool{}
	for _, raw := range content {
		p, ok := raw.(map[string]any)
		if !ok {
			return errors.New("payload is not a dictionary")
		}
		id := str(p["PayloadUUID"])
		if id == "" || seen[id] {
			return errors.New("every payload needs its own UUID")
		}
		seen[id] = true
		switch str(p["PayloadType"]) {
		case "com.apple.vpn.managed":
			if ike != nil {
				return errors.New("one VPN payload per profile")
			}
			if str(p["VPNType"]) != "IKEv2" {
				return errors.New("payload is not an IKEv2 VPN payload")
			}
			if ike, ok = p["IKEv2"].(map[string]any); !ok {
				return errors.New("VPN payload has no IKEv2 dictionary")
			}
			vpn = p
		case "com.apple.security.scep":
			c, _ := p["PayloadContent"].(map[string]any)
			scep[id] = c
		case "com.apple.security.root", "com.apple.security.pkcs1":
		default:
			return fmt.Errorf("payload type %q does not belong in an IKEv2 profile", str(p["PayloadType"]))
		}
	}
	if ike == nil {
		return errors.New("profile has no VPN payload")
	}
	for _, key := range []string{"RemoteAddress", "RemoteIdentifier", "LocalIdentifier", "ServerCertificateIssuerCommonName", "ServerCertificateCommonName"} {
		if str(ike[key]) == "" {
			return fmt.Errorf("%s is missing", key)
		}
	}
	if _, has := ike["AuthPassword"]; has {
		return errors.New("an IKEv2 profile must not carry a password")
	}
	if _, has := ike["SharedSecret"]; has {
		return errors.New("an IKEv2 profile must not carry a shared secret")
	}
	for _, key := range []string{"OnDemandEnabled", "OnDemandRules", "OnDemandUserOverrideDisabled"} {
		if _, has := ike[key]; has {
			return fmt.Errorf("%s belongs at the top of the VPN payload, not inside IKEv2", key)
		}
	}
	onDemand := fmt.Sprint(vpn["OnDemandEnabled"]) == "1"
	switch str(ike["AuthenticationMethod"]) {
	case "None":
		if fmt.Sprint(ike["ExtendedAuthEnabled"]) != "1" || str(ike["AuthName"]) == "" {
			return errors.New("password sign-in needs EAP and the account name")
		}
		if len(scep) != 0 {
			return errors.New("password sign-in takes no certificate request")
		}
	case "Certificate":
		c, ok := scep[str(ike["PayloadCertificateUUID"])]
		if !ok || len(scep) != 1 {
			return errors.New("certificate sign-in must point at the one SCEP payload in the profile")
		}
		if str(c["URL"]) == "" || str(c["Challenge"]) == "" {
			return errors.New("SCEP payload needs a URL and a challenge")
		}
		if extractable, ok := c["KeyIsExtractable"].(bool); !ok || extractable {
			return errors.New("the device's key must not be extractable")
		}
	default:
		return fmt.Errorf("authentication method %q is not supported", str(ike["AuthenticationMethod"]))
	}
	rules, _ := vpn["OnDemandRules"].([]any)
	if onDemand {
		if len(rules) == 0 {
			return errors.New("On Demand needs rules")
		}
		last, _ := rules[len(rules)-1].(map[string]any)
		if len(last) != 1 || str(last["Action"]) == "" {
			return errors.New("the last On Demand rule must match every network")
		}
	} else if len(rules) != 0 {
		return errors.New("On Demand rules without On Demand")
	}
	return nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
