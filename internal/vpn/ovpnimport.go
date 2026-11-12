package vpn

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Imported is a server record read from a client .ovpn export, plus what the
// import left out.
type Imported struct {
	Server  Server
	Skipped []string // directives with no place in a server record
	// HadIdentity reports that the file carried a client certificate or key.
	// Both are discarded: a server record never holds a client identity.
	HadIdentity bool
}

var inlineBlockRE = regexp.MustCompile(`(?ms)^<([a-z-]+)>\s*\n(.*?)\n</([a-z-]+)>\s*$`)

// dropped are client options with no effect on the rendered profile.
var dropped = map[string]bool{
	"client": true, "dev": true, "nobind": true, "tls-client": true, "pull": true,
	"verb": true, "mute": true, "remote-cert-tls": true, "auth-nocache": true,
	"persist-tun": true, "persist-key": true, "resolv-retry": true,
	"explicit-exit-notify": true, "data-ciphers-fallback": true,
}

// ImportOVPN reads a client profile such as a pfSense Client Export file into a
// server record. The caller sets Name and Slug.
func ImportOVPN(text string) (Imported, error) {
	var imp Imported
	s := &imp.Server
	s.KeyDirection = 1
	text = strings.ReplaceAll(text, "\r", "")

	for _, m := range inlineBlockRE.FindAllStringSubmatch(text, -1) {
		if m[1] != m[3] {
			return imp, fmt.Errorf("inline block <%s> is closed by </%s>", m[1], m[3])
		}
		body := strings.TrimSpace(m[2])
		switch m[1] {
		case "ca":
			s.CAPEM = body
		case "tls-auth":
			s.TLSKeyMode, s.TLSKey = TLSKeyAuth, NormalizeStaticKey(body)
		case "tls-crypt":
			s.TLSKeyMode, s.TLSKey = TLSKeyCrypt, NormalizeStaticKey(body)
		case "cert", "key", "pkcs12":
			imp.HadIdentity = true
		default:
			imp.Skipped = append(imp.Skipped, "<"+m[1]+">")
		}
	}
	text = inlineBlockRE.ReplaceAllString(text, "")

	defaultProto := "udp"
	type rawRemote struct {
		host, port, proto string
	}
	var remotes []rawRemote
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		name, value, _ := strings.Cut(line, " ")
		value = strings.TrimSpace(value)
		f := strings.Fields(value)
		switch {
		case name == "remote":
			if len(f) < 1 {
				return imp, fmt.Errorf("remote without a host")
			}
			r := rawRemote{host: f[0], port: "1194"}
			if len(f) > 1 {
				r.port = f[1]
			}
			if len(f) > 2 {
				r.proto = f[2]
			}
			remotes = append(remotes, r)
		case name == "proto":
			defaultProto = value
		case name == "verify-x509-name":
			if len(f) > 0 {
				s.VerifyX509Name = strings.Trim(f[0], `"'`)
			}
		case name == "cipher":
			s.Cipher = value
		case name == "data-ciphers":
			if s.Cipher == "" {
				s.Cipher, _, _ = strings.Cut(value, ":")
			}
		case name == "auth":
			s.Auth = value
		case name == "tun-mtu":
			n, err := strconv.Atoi(value)
			if err != nil {
				return imp, fmt.Errorf("tun-mtu %q is not a number", value)
			}
			s.TunMTU = n
		case name == "key-direction":
			n, err := strconv.Atoi(value)
			if err != nil {
				return imp, fmt.Errorf("key-direction %q is not a number", value)
			}
			s.KeyDirection = n
		case name == "auth-user-pass":
			s.UserAuth = true
		case dropped[name]:
		case extraAllowed[name]:
			s.Extra = append(s.Extra, Directive{Name: name, Value: value})
		default:
			imp.Skipped = append(imp.Skipped, name)
		}
	}
	if len(remotes) == 0 {
		return imp, fmt.Errorf("the file has no remote line")
	}
	for _, r := range remotes {
		port, err := strconv.Atoi(r.port)
		if err != nil {
			return imp, fmt.Errorf("port %q is not a number", r.port)
		}
		proto := r.proto
		if proto == "" {
			proto = defaultProto
		}
		proto, err = clientProto(proto)
		if err != nil {
			return imp, err
		}
		s.Remotes = append(s.Remotes, Remote{Host: r.host, Port: port, Proto: proto})
	}
	return imp, nil
}

// clientProto maps OpenVPN's protocol spellings to the two OpenVPN Connect accepts.
func clientProto(p string) (string, error) {
	switch p {
	case "udp", "udp4", "udp6":
		return "udp", nil
	case "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client":
		return "tcp", nil
	}
	return "", fmt.Errorf("protocol %q is not supported", p)
}
