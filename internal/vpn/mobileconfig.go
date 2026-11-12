package vpn

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/micromdm/plist"
)

// Identity is the per-device material a profile carries. The key is rendered into
// the profile and must not be kept by the caller afterwards.
type Identity struct {
	DeviceID string // enrollment ID; keeps payload UUIDs stable per device
	Username string // directory account name; equals the certificate CN
	CertPEM  []byte
	KeyPEM   []byte
}

const openVPNConnectSubType = "net.openvpn.connect.app"

// ignoredByConnect are options OpenVPN Connect logs as unsupported. They are
// never emitted and Check rejects them.
var ignoredByConnect = []string{"persist-tun", "persist-key", "resolv-retry", "explicit-exit-notify", "data-ciphers-fallback", "data-ciphers"}

// PayloadIdentifier is the device-side key of the profile for a server. Installing
// a profile with the same identifier replaces the earlier one.
func PayloadIdentifier(org string, s Server) string {
	if org == "" {
		org = "cairn"
	}
	return org + ".vpn." + s.Slug
}

// RenderMobileconfig builds an Apple configuration profile for OpenVPN Connect.
// OpenVPN Connect cannot read identities from the system keychain, so the
// certificate and key travel inline in VendorConfig. The result has passed Check.
func RenderMobileconfig(org string, s Server, id Identity) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("vpn: server record: %w", err)
	}
	if id.DeviceID == "" || id.Username == "" {
		return nil, errors.New("vpn: device and username are required")
	}
	if err := checkIdentity(id); err != nil {
		return nil, err
	}

	vendor := map[string]string{
		"client":           "NOARGS",
		"dev":              "tun",
		"nobind":           "NOARGS",
		"remote-cert-tls":  "server",
		"verify-x509-name": fmt.Sprintf("%q name", s.VerifyX509Name),
		"ca":               inline(s.CAPEM),
		"cert":             inline(string(id.CertPEM)),
		"key":              inline(string(id.KeyPEM)),
	}
	for i, r := range s.Remotes {
		k := "remote"
		if len(s.Remotes) > 1 {
			k = fmt.Sprintf("remote.%d", i+1)
		}
		vendor[k] = fmt.Sprintf("%s %d %s", r.Host, r.Port, r.Proto)
	}
	if s.Cipher != "" {
		vendor["cipher"] = s.Cipher
	}
	if s.Auth != "" {
		vendor["auth"] = s.Auth
	}
	if s.TunMTU != 0 {
		vendor["tun-mtu"] = fmt.Sprint(s.TunMTU)
	}
	switch s.TLSKeyMode {
	case TLSKeyAuth:
		vendor["tls-auth"] = inline(s.TLSKey)
		vendor["key-direction"] = fmt.Sprint(s.KeyDirection)
	case TLSKeyCrypt:
		vendor["tls-crypt"] = inline(s.TLSKey)
	}
	if s.UserAuth {
		vendor["auth-user-pass"] = "NOARGS"
		// Access Server meta-directive; Connect prefills the username from it.
		vendor["USERNAME"] = id.Username
	}
	if !s.OnDemand {
		vendor["vpn-on-demand"] = "0"
	}
	for _, d := range s.Extra {
		v := d.Value
		if v == "" {
			v = "NOARGS"
		}
		vendor[d.Name] = v
	}

	identifier := PayloadIdentifier(org, s)
	ns := uuid5(nsDNS, identifier+"."+id.DeviceID)
	vpnUUID := strings.ToUpper(uuid5(ns, "vpn").String())

	// AuthenticationMethod stays Certificate even when the server wants a password:
	// with Password, iOS owns the credentials and hands Connect an empty one.
	vpn := map[string]any{
		"AuthenticationMethod": "Certificate",
		"AuthName":             "DEFAULT",
		"RemoteAddress":        "DEFAULT",
		"DisconnectOnIdle":     0,
		"OnDemandEnabled":      0,
	}
	if s.OnDemand {
		vpn["OnDemandEnabled"] = 1
		vpn["OnDemandRules"] = []any{
			map[string]any{"Action": "Connect", "InterfaceTypeMatch": "WiFi"},
			map[string]any{"Action": "Connect", "InterfaceTypeMatch": "Cellular"},
		}
	}
	payload := map[string]any{
		"PayloadType":        "com.apple.vpn.managed",
		"PayloadVersion":     1,
		"PayloadIdentifier":  identifier + ".vpn",
		"PayloadUUID":        vpnUUID,
		"PayloadDisplayName": "VPN",
		"PayloadDescription": "OpenVPN Connect configuration for " + s.Name,
		"UserDefinedName":    s.Name,
		"VPNType":            "VPN",
		"VPNSubType":         openVPNConnectSubType,
		"VPN":                vpn,
		"VendorConfig":       vendor,
		"IPv4":               map[string]any{"OverridePrimary": 1},
		"Proxies":            map[string]any{"HTTPEnable": 0, "HTTPSEnable": 0},
	}
	prof := map[string]any{
		"PayloadType":              "Configuration",
		"PayloadVersion":           1,
		"PayloadIdentifier":        identifier,
		"PayloadUUID":              strings.ToUpper(uuid5(ns, "top").String()),
		"PayloadDisplayName":       s.Name,
		"PayloadDescription":       s.Name + " for " + id.Username + ". Install OpenVPN Connect first.",
		"PayloadOrganization":      org,
		"PayloadRemovalDisallowed": false,
		"PayloadContent":           []any{payload},
	}
	out, err := plist.MarshalIndent(prof, "\t")
	if err != nil {
		return nil, fmt.Errorf("vpn: marshal profile: %w", err)
	}
	if err := Check(out); err != nil {
		return nil, fmt.Errorf("vpn: rendered profile failed its own checks: %w", err)
	}
	return out, nil
}

// inline turns a PEM or static-key block into the single-line form OpenVPN
// Connect expects inside VendorConfig: literal backslash-n between lines. iOS
// refuses to install the profile when the value holds real newlines.
func inline(block string) string {
	block = strings.TrimSpace(strings.ReplaceAll(block, "\r", ""))
	return strings.ReplaceAll(block, "\n", `\n`)
}

func checkIdentity(id Identity) error {
	block, rest := pem.Decode(id.CertPEM)
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return errors.New("vpn: identity needs exactly one PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("vpn: identity certificate: %w", err)
	}
	if leaf.Subject.CommonName != id.Username {
		return fmt.Errorf("vpn: certificate CN %q does not match username %q", leaf.Subject.CommonName, id.Username)
	}
	kb, rest := pem.Decode(id.KeyPEM)
	if kb == nil || !strings.HasSuffix(kb.Type, "PRIVATE KEY") || strings.TrimSpace(string(rest)) != "" {
		return errors.New("vpn: identity needs exactly one PEM private key")
	}
	return nil
}

// profileShape is the part of a rendered profile Check reads back.
type profileShape struct {
	PayloadIdentifier string
	PayloadUUID       string
	PayloadContent    []struct {
		PayloadType  string
		PayloadUUID  string
		VPNType      string
		VPNSubType   string
		VPN          map[string]any
		VendorConfig map[string]any
	}
}

// Check applies the rules a profile must meet for iOS to install it and OpenVPN
// Connect to accept it. A device reports nothing useful when a payload breaks
// one of them, so a profile that fails here is never sent.
func Check(profile []byte) error {
	var p profileShape
	if err := plist.Unmarshal(profile, &p); err != nil {
		return fmt.Errorf("not a property list: %w", err)
	}
	if p.PayloadIdentifier == "" || p.PayloadUUID == "" || len(p.PayloadContent) != 1 {
		return errors.New("profile needs an identifier, a UUID and exactly one payload")
	}
	c := p.PayloadContent[0]
	if c.PayloadType != "com.apple.vpn.managed" || c.VPNType != "VPN" || c.VPNSubType != openVPNConnectSubType {
		return errors.New("payload is not an OpenVPN Connect VPN payload")
	}
	v := map[string]string{}
	for k, raw := range c.VendorConfig {
		val, ok := raw.(string)
		if !ok {
			return fmt.Errorf("%s is not a string", k)
		}
		v[k] = val
	}
	for k, val := range v {
		if strings.ContainsAny(val, "\r\n") {
			return fmt.Errorf("%s holds a real line break; inline blocks need literal \\n", k)
		}
		if val == "" {
			return fmt.Errorf("%s is empty; bare directives are written NOARGS", k)
		}
	}
	for _, k := range []string{"ca", "cert", "key"} {
		if !strings.HasPrefix(v[k], "-----BEGIN ") {
			return fmt.Errorf("%s must be inline", k)
		}
	}
	remotes := 0
	for k, val := range v {
		if k != "remote" && !strings.HasPrefix(k, "remote.") {
			continue
		}
		remotes++
		f := strings.Fields(val)
		if len(f) != 3 || (f[2] != "udp" && f[2] != "tcp") {
			return fmt.Errorf("%s must be \"host port udp|tcp\", got %q", k, val)
		}
	}
	if remotes == 0 {
		return errors.New("no remote")
	}
	if p, ok := v["proto"]; ok && p != "udp" && p != "tcp" {
		return fmt.Errorf("proto %q: OpenVPN Connect accepts udp or tcp only", p)
	}
	for _, k := range ignoredByConnect {
		if _, ok := v[k]; ok {
			return fmt.Errorf("%s is not supported by OpenVPN Connect", k)
		}
	}
	if v["remote-cert-tls"] != "server" || v["verify-x509-name"] == "" {
		return errors.New("server certificate pinning (remote-cert-tls, verify-x509-name) is missing")
	}
	if _, ok := v["tls-auth"]; ok && v["key-direction"] == "" {
		return errors.New("tls-auth needs key-direction")
	}
	onDemand := fmt.Sprint(c.VPN["OnDemandEnabled"]) == "1"
	if !onDemand && v["vpn-on-demand"] != "0" {
		return errors.New("a profile without VPN On Demand needs vpn-on-demand 0")
	}
	if onDemand && v["vpn-on-demand"] == "0" {
		return errors.New("vpn-on-demand 0 contradicts OnDemandEnabled")
	}
	if c.VPN["RemoteAddress"] != "DEFAULT" || c.VPN["AuthenticationMethod"] != "Certificate" || c.VPN["AuthName"] != "DEFAULT" {
		return errors.New("VPN dictionary must use RemoteAddress DEFAULT, AuthenticationMethod Certificate, AuthName DEFAULT")
	}
	if _, ok := v["auth-user-pass"]; ok && v["USERNAME"] == "" {
		return errors.New("a password-prompting profile needs USERNAME so the prompt is prefilled")
	}
	return nil
}

type uuid [16]byte

var nsDNS = uuid{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}

// uuid5 is the RFC 4122 name-based UUID. Deterministic payload UUIDs make a
// re-issued profile replace the installed one.
func uuid5(ns uuid, name string) uuid {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	var u uuid
	copy(u[:], h.Sum(nil))
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

func (u uuid) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
