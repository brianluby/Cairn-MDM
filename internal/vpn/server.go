// Package vpn models OpenVPN and native IKEv2 servers and renders per-device
// client profiles for them. It has no storage or network dependencies: callers supply the server
// record and the device's certificate and key, and get profile bytes back.
package vpn

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// TLS control-channel key modes. The static key is the server's shared secret and
// goes into every client profile.
const (
	TLSKeyNone  = ""
	TLSKeyAuth  = "tls-auth"
	TLSKeyCrypt = "tls-crypt"
)

// Remote is one address the client tries, in order.
type Remote struct {
	Host  string
	Port  int
	Proto string // "udp" or "tcp"
	// TunMTU overrides Server.TunMTU for this address. A UDP and a TCP listener
	// on one host often differ here.
	TunMTU int `json:"TunMTU,omitempty"`
}

// Server is an admin-managed VPN server definition. Kind says which protocol
// it is; the OpenVPN fields below are unused for an IKEv2 server and IKEv2 is
// unused for an OpenVPN one. Name, Slug, CAPEM and OnDemand apply to both.
type Server struct {
	ID             int64
	Name           string
	Slug           string // immutable; part of the profile's PayloadIdentifier
	Kind           string // KindOpenVPN or KindIKEv2; empty means OpenVPN
	IKEv2          IKEv2
	Remotes        []Remote
	VerifyX509Name string // exact CN of the server certificate
	CAPEM          string // chain that signs the server certificate
	TLSKeyMode     string
	KeyDirection   int    // client side of tls-auth; pfSense servers use 1
	TLSKey         string // OpenVPN static key block; held decrypted only in memory
	Cipher         string
	Auth           string
	TunMTU         int  // 0 leaves the client default
	UserAuth       bool // server also asks for a username and password
	OnDemand       bool // Apple VPN On Demand on Wi-Fi and cellular
	Extra          []Directive
}

// Directive is one extra client option from the allowlist in extraAllowed.
type Directive struct {
	Name  string
	Value string // empty for a bare directive
}

var (
	slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$`)
	nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._*-]{0,252}$`)
	algRE  = regexp.MustCompile(`^[A-Za-z0-9-]{1,40}$`)
	// issuerRE is a certificate common name as typed into a record.
	issuerRE = regexp.MustCompile(`^[^\x00-\x1f<>]{1,128}$`)
	// accountRE is a directory account name as it appears in a certificate.
	accountRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// extraAllowed lists the pass-through options a server record may carry. Anything
// that names a file, runs a program or duplicates a field of Server stays out.
var extraAllowed = map[string]bool{
	"comp-lzo": true, "compress": true, "dhcp-option": true, "float": true,
	"keepalive": true, "mssfix": true, "ping": true, "ping-restart": true,
	"rcvbuf": true, "redirect-gateway": true, "reneg-sec": true, "route": true,
	"server-poll-timeout": true, "sndbuf": true, "tls-cipher": true,
	"tls-ciphersuites": true, "tls-version-min": true,
}

// Slugify derives a slug from a display name.
func Slugify(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.TrimRight(b.String(), "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	return s
}

// Validate checks that the record can be rendered into a profile a client will
// accept. It does not contact the server.
func (s Server) Validate() error {
	if strings.TrimSpace(s.Name) == "" || len(s.Name) > 100 {
		return errors.New("name is required (100 characters at most)")
	}
	if !slugRE.MatchString(s.Slug) {
		return errors.New("identifier must be lowercase letters, digits and hyphens")
	}
	switch s.Kind {
	case "", KindOpenVPN:
	case KindIKEv2:
		return s.validateIKEv2()
	default:
		return fmt.Errorf("unknown server kind %q", s.Kind)
	}
	if len(s.Remotes) == 0 || len(s.Remotes) > 8 {
		return errors.New("one to eight server addresses are required")
	}
	for _, r := range s.Remotes {
		if !hostRE.MatchString(r.Host) {
			return fmt.Errorf("server address %q is not a hostname or IP address", r.Host)
		}
		if r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("port %d is out of range", r.Port)
		}
		if r.Proto != "udp" && r.Proto != "tcp" {
			return fmt.Errorf("protocol for %s must be udp or tcp", r.Host)
		}
		if r.TunMTU != 0 && (r.TunMTU < 576 || r.TunMTU > 9000) {
			return fmt.Errorf("tunnel MTU for %s must be between 576 and 9000", r.Host)
		}
	}
	if !nameRE.MatchString(s.VerifyX509Name) {
		return errors.New("server certificate name is required: clients refuse any other certificate")
	}
	if _, err := parseCertificates(s.CAPEM); err != nil {
		return fmt.Errorf("CA chain: %w", err)
	}
	switch s.TLSKeyMode {
	case TLSKeyNone:
		if strings.TrimSpace(s.TLSKey) != "" {
			return errors.New("choose tls-auth or tls-crypt for the TLS key")
		}
	case TLSKeyAuth, TLSKeyCrypt:
		if err := checkStaticKey(s.TLSKey); err != nil {
			return fmt.Errorf("TLS key: %w", err)
		}
		if s.TLSKeyMode == TLSKeyAuth && s.KeyDirection != 0 && s.KeyDirection != 1 {
			return errors.New("key direction must be 0 or 1")
		}
	default:
		return fmt.Errorf("unknown TLS key mode %q", s.TLSKeyMode)
	}
	for _, alg := range []string{s.Cipher, s.Auth} {
		if alg != "" && !algRE.MatchString(alg) {
			return fmt.Errorf("%q is not a cipher or digest name", alg)
		}
	}
	if s.TunMTU != 0 && (s.TunMTU < 576 || s.TunMTU > 9000) {
		return errors.New("tunnel MTU must be between 576 and 9000, or empty")
	}
	seen := map[string]bool{}
	for _, d := range s.Extra {
		if !extraAllowed[d.Name] {
			return fmt.Errorf("option %q is not supported in a server record", d.Name)
		}
		// A backslash could be read as an escaped line break by the client and
		// carry a second option past the list above.
		if strings.ContainsAny(d.Value, "\r\n<>\\") || len(d.Value) > 200 {
			return fmt.Errorf("option %q has an invalid value", d.Name)
		}
		// The profile format holds one value per option name.
		if seen[d.Name] {
			return fmt.Errorf("option %q appears more than once; a profile can carry it once. Have the server push the others", d.Name)
		}
		seen[d.Name] = true
	}
	return nil
}

func parseCertificates(pemText string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates found")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("text after the last certificate")
	}
	return out, nil
}

var staticKeyRE = regexp.MustCompile(`(?s)^-----BEGIN OpenVPN Static key V1-----\n([0-9a-fA-F\n]+)\n-----END OpenVPN Static key V1-----$`)

// NormalizeStaticKey strips comments, blank lines and CR line endings from an
// OpenVPN static key file. pfSense exports arrive with CRLF.
func NormalizeStaticKey(key string) string {
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(key, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func checkStaticKey(key string) error {
	m := staticKeyRE.FindStringSubmatch(key)
	if m == nil {
		return errors.New("expected an OpenVPN static key block")
	}
	if n := len(strings.ReplaceAll(m[1], "\n", "")); n != 512 {
		return fmt.Errorf("static key holds %d hex digits, expected 512", n)
	}
	return nil
}
