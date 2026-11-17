package vpn

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/micromdm/plist"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// KindWiFi is a Wi-Fi network that devices join with a certificate (EAP-TLS).
// It is kept beside the VPN servers because it uses the same certificates,
// delivery and revocation; only the profile differs.
const KindWiFi = "wifi"

// Wi-Fi security modes.
const (
	WiFiWPA2Enterprise = "wpa2-enterprise"
	WiFiWPA3Enterprise = "wpa3-enterprise"
)

// WiFi holds the settings of a Wi-Fi network record. The CA certificates the
// RADIUS servers chain to are in Server.CAPEM.
type WiFi struct {
	SSID     string
	Security string // WiFiWPA2Enterprise or WiFiWPA3Enterprise
	// ServerNames are the exact names in the RADIUS servers' certificates. A
	// device refuses a server that presents any other name.
	ServerNames []string
}

// IsWiFi reports whether the record is a Wi-Fi network.
func (s Server) IsWiFi() bool { return s.Kind == KindWiFi }

// radiusNameRE is a host name as it appears in a certificate. No wildcard: a
// device that accepts *.example.org accepts any server the CA named there.
var radiusNameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62})?)+$`)

func (s Server) validateWiFi() error {
	w := s.WiFi
	if n := len(w.SSID); n == 0 || n > 32 {
		return errors.New("network name (SSID) is required, 32 bytes at most")
	}
	for _, r := range w.SSID {
		if r < 0x20 || r == 0x7f {
			return errors.New("network name (SSID) holds a control character")
		}
	}
	if w.Security != WiFiWPA2Enterprise && w.Security != WiFiWPA3Enterprise {
		return errors.New("security must be WPA2 Enterprise or WPA3 Enterprise")
	}
	if len(w.ServerNames) == 0 || len(w.ServerNames) > 16 {
		return errors.New("one to sixteen RADIUS server certificate names are required: devices refuse any other server")
	}
	seen := map[string]bool{}
	for _, name := range w.ServerNames {
		if !radiusNameRE.MatchString(name) || len(name) > 253 {
			return fmt.Errorf("RADIUS server name %q must be a full host name as it appears in the server's certificate, with no wildcard", name)
		}
		if seen[strings.ToLower(name)] {
			return fmt.Errorf("RADIUS server name %q is listed twice", name)
		}
		seen[strings.ToLower(name)] = true
	}
	if _, err := parseCertificates(s.CAPEM); err != nil {
		return fmt.Errorf("CA certificates for the RADIUS servers: %w", err)
	}
	if s.TLSKeyMode != TLSKeyNone || strings.TrimSpace(s.TLSKey) != "" {
		return errors.New("a Wi-Fi network has no TLS key")
	}
	return nil
}

// WiFiIdentity is how one device gets the certificate its Wi-Fi profile signs
// in with. With SCEP set, the device makes the key and asks for the
// certificate, and the profile holds no key. Otherwise Leaf and Key are
// rendered into the profile, and the key must not be kept afterwards.
type WiFiIdentity struct {
	DeviceID string // enrollment ID; keeps payload UUIDs stable per device
	SCEP     *SCEPEnrollment
	Leaf     *x509.Certificate
	Key      crypto.PrivateKey
}

// RenderWiFi builds the profile that joins a device to an EAP-TLS network: the
// CA certificates, the identity (a SCEP request, or a certificate and key as
// PKCS#12), and the Wi-Fi payload that refers to both. A Wi-Fi payload can only
// use certificates from its own profile, so the CA certificates are always
// included. The result has passed CheckWiFi.
func RenderWiFi(org string, s Server, id WiFiIdentity) ([]byte, error) {
	if !s.IsWiFi() {
		return nil, errors.New("vpn: not a Wi-Fi network record")
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("vpn: Wi-Fi record: %w", err)
	}
	if id.DeviceID == "" {
		return nil, errors.New("vpn: device is required")
	}
	anchors, err := parseCertificates(s.CAPEM)
	if err != nil {
		return nil, err
	}
	identifier := PayloadIdentifier(org, s)
	ns := uuid5(nsDNS, identifier+"."+id.DeviceID)
	payloadUUID := func(tag string) string { return strings.ToUpper(uuid5(ns, tag).String()) }

	// The RADIUS server compares the name the device announces with the
	// certificate's common name, so the profile uses the name in the
	// certificate, or the one the device is told to ask for.
	var username string
	var identity map[string]any
	switch {
	case id.SCEP != nil && (id.Leaf != nil || id.Key != nil):
		return nil, errors.New("vpn: a profile takes a SCEP request or a certificate and key, not both")
	case id.SCEP != nil:
		username = id.SCEP.CommonName
		if !accountRE.MatchString(username) {
			return nil, errors.New("vpn: the certificate name must be a directory account name")
		}
		if err := id.SCEP.check(username); err != nil {
			return nil, err
		}
		identity = scepPayload(identifier+".identity", payloadUUID("identity"), "Wi-Fi certificate for "+username, id.SCEP)
	case id.Leaf != nil && id.Key != nil:
		if username = id.Leaf.Subject.CommonName; username == "" {
			return nil, errors.New("vpn: certificate has no common name to sign in with")
		}
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		password := base64.RawURLEncoding.EncodeToString(raw)
		// Triple-DES and SHA-1 are what every iOS and macOS release imports. The
		// password sits in the same profile, so this encryption protects nothing;
		// the profile itself is what has to stay private.
		p12, err := pkcs12.LegacyDES.Encode(id.Key, id.Leaf, nil, password)
		if err != nil {
			return nil, fmt.Errorf("vpn: encode identity: %w", err)
		}
		identity = map[string]any{
			"PayloadType":        "com.apple.security.pkcs12",
			"PayloadVersion":     1,
			"PayloadIdentifier":  identifier + ".identity",
			"PayloadUUID":        payloadUUID("identity"),
			"PayloadDisplayName": "Wi-Fi certificate for " + username,
			"PayloadContent":     p12,
			"Password":           password,
		}
	default:
		return nil, errors.New("vpn: a SCEP request or a certificate and key is required")
	}

	var payloads, anchorUUIDs []any
	for i, c := range anchors {
		tag := fmt.Sprintf("ca.%d", i+1)
		// Apple has one payload type for a root and another for an intermediate.
		kind := "com.apple.security.pkcs1"
		if bytes.Equal(c.RawSubject, c.RawIssuer) {
			kind = "com.apple.security.root"
		}
		payloads = append(payloads, map[string]any{
			"PayloadType":        kind,
			"PayloadVersion":     1,
			"PayloadIdentifier":  identifier + "." + tag,
			"PayloadUUID":        payloadUUID(tag),
			"PayloadDisplayName": c.Subject.CommonName,
			"PayloadContent":     c.Raw,
		})
		anchorUUIDs = append(anchorUUIDs, payloadUUID(tag))
	}
	payloads = append(payloads, identity)
	encryption := "WPA2"
	if s.WiFi.Security == WiFiWPA3Enterprise {
		encryption = "WPA3"
	}
	serverNames := make([]any, len(s.WiFi.ServerNames))
	for i, n := range s.WiFi.ServerNames {
		serverNames[i] = n
	}
	payloads = append(payloads, map[string]any{
		"PayloadType":            "com.apple.wifi.managed",
		"PayloadVersion":         1,
		"PayloadIdentifier":      identifier + ".wifi",
		"PayloadUUID":            payloadUUID("wifi"),
		"PayloadDisplayName":     "Wi-Fi (" + s.WiFi.SSID + ")",
		"SSID_STR":               s.WiFi.SSID,
		"HIDDEN_NETWORK":         false,
		"AutoJoin":               true,
		"EncryptionType":         encryption,
		"ProxyType":              "None",
		"PayloadCertificateUUID": payloadUUID("identity"),
		"EAPClientConfiguration": map[string]any{
			"AcceptEAPTypes":               []any{13},
			"UserName":                     username,
			"TLSMinimumVersion":            "1.2",
			"TLSTrustedServerNames":        serverNames,
			"PayloadCertificateAnchorUUID": anchorUUIDs,
			"TLSAllowTrustExceptions":      false,
			"TLSCertificateIsRequired":     true,
		},
	})
	prof := map[string]any{
		"PayloadType":              "Configuration",
		"PayloadVersion":           1,
		"PayloadIdentifier":        identifier,
		"PayloadUUID":              payloadUUID("top"),
		"PayloadDisplayName":       s.Name,
		"PayloadDescription":       "Joins " + s.WiFi.SSID + " with a certificate for " + username + ".",
		"PayloadOrganization":      org,
		"PayloadRemovalDisallowed": false,
		"PayloadContent":           payloads,
	}
	out, err := plist.MarshalIndent(prof, "\t")
	if err != nil {
		return nil, fmt.Errorf("vpn: marshal profile: %w", err)
	}
	if err := CheckWiFi(out); err != nil {
		return nil, fmt.Errorf("vpn: rendered profile failed its own checks: %w", err)
	}
	return out, nil
}

// CheckWiFi applies the rules an EAP-TLS Wi-Fi profile must meet. iOS refuses a
// bad payload without logging why, and a profile that trusts too much joins a
// look-alike network, so a profile that fails here is never sent.
func CheckWiFi(profile []byte) error {
	var p map[string]any
	if err := plist.Unmarshal(profile, &p); err != nil {
		return fmt.Errorf("not a property list: %w", err)
	}
	if str(p["PayloadIdentifier"]) == "" || str(p["PayloadUUID"]) == "" {
		return errors.New("profile needs an identifier and a UUID")
	}
	var wifi map[string]any
	identity := ""
	anchors := map[string]bool{}
	seen := map[string]bool{str(p["PayloadUUID"]): true}
	content, _ := p["PayloadContent"].([]any)
	for _, raw := range content {
		c, _ := raw.(map[string]any)
		id := str(c["PayloadUUID"])
		if id == "" || seen[id] {
			return errors.New("every payload needs its own UUID")
		}
		seen[id] = true
		switch kind := str(c["PayloadType"]); kind {
		case "com.apple.security.root", "com.apple.security.pkcs1":
			der, _ := c["PayloadContent"].([]byte)
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return fmt.Errorf("CA payload does not hold a certificate: %w", err)
			}
			if root := bytes.Equal(cert.RawSubject, cert.RawIssuer); root != (kind == "com.apple.security.root") {
				return fmt.Errorf("%s is in the wrong payload type for a root or an intermediate", cert.Subject.CommonName)
			}
			anchors[id] = true
		case "com.apple.security.pkcs12":
			if identity != "" {
				return errors.New("profile holds more than one identity")
			}
			if der, _ := c["PayloadContent"].([]byte); len(der) == 0 || str(c["Password"]) == "" {
				return errors.New("identity payload needs its content and password")
			}
			identity = id
		case "com.apple.security.scep":
			if identity != "" {
				return errors.New("profile holds more than one identity")
			}
			req, _ := c["PayloadContent"].(map[string]any)
			if str(req["URL"]) == "" || str(req["Challenge"]) == "" {
				return errors.New("SCEP payload needs a URL and a challenge")
			}
			if req["KeyIsExtractable"] != false {
				return errors.New("SCEP payload must keep the key on the device (KeyIsExtractable false)")
			}
			identity = id
		case "com.apple.wifi.managed":
			if wifi != nil {
				return errors.New("profile holds more than one Wi-Fi payload")
			}
			wifi = c
		default:
			return fmt.Errorf("unexpected payload type %q", kind)
		}
	}
	if wifi == nil || identity == "" || len(anchors) == 0 {
		return errors.New("profile needs a Wi-Fi payload, an identity and at least one CA certificate")
	}
	if str(wifi["SSID_STR"]) == "" || wifi["HIDDEN_NETWORK"] != false || wifi["AutoJoin"] != true || wifi["ProxyType"] != "None" {
		return errors.New("Wi-Fi payload needs a network name, HIDDEN_NETWORK false, AutoJoin true and ProxyType None")
	}
	if enc := str(wifi["EncryptionType"]); enc != "WPA2" && enc != "WPA3" {
		return fmt.Errorf("EncryptionType %q: an enterprise network is WPA2 or WPA3", enc)
	}
	if _, ok := wifi["Password"]; ok {
		return errors.New("Wi-Fi payload holds a password")
	}
	if str(wifi["PayloadCertificateUUID"]) != identity {
		return errors.New("Wi-Fi payload does not refer to the identity in this profile")
	}
	e, _ := wifi["EAPClientConfiguration"].(map[string]any)
	for _, k := range []string{"OuterIdentity", "UserPassword", "OneTimeUserPassword", "TTLSInnerAuthentication", "EAPFASTUsePAC"} {
		if _, ok := e[k]; ok {
			return fmt.Errorf("EAP settings hold %s, which EAP-TLS does not use", k)
		}
	}
	if types, ok := e["AcceptEAPTypes"].([]any); !ok || len(types) != 1 || fmt.Sprint(types[0]) != "13" {
		return errors.New("AcceptEAPTypes must be EAP-TLS (13) alone")
	}
	if str(e["UserName"]) == "" {
		return errors.New("UserName is required: the RADIUS server compares it with the certificate")
	}
	if e["TLSMinimumVersion"] != "1.2" {
		return errors.New("TLSMinimumVersion must be 1.2")
	}
	if e["TLSAllowTrustExceptions"] != false || e["TLSCertificateIsRequired"] != true {
		return errors.New("TLSAllowTrustExceptions must be false and TLSCertificateIsRequired true")
	}
	names, _ := e["TLSTrustedServerNames"].([]any)
	if len(names) == 0 {
		return errors.New("TLSTrustedServerNames is required: without it the device accepts any server the CA named")
	}
	for _, n := range names {
		if !radiusNameRE.MatchString(str(n)) {
			return fmt.Errorf("trusted server name %q is not an exact host name", n)
		}
	}
	refs, _ := e["PayloadCertificateAnchorUUID"].([]any)
	if len(refs) != len(anchors) {
		return errors.New("PayloadCertificateAnchorUUID must list every CA certificate in the profile")
	}
	for _, r := range refs {
		if !anchors[str(r)] {
			return errors.New("PayloadCertificateAnchorUUID refers to a certificate that is not in the profile")
		}
	}
	return nil
}
