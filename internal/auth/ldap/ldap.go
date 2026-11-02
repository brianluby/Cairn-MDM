// Package ldap is Cairn's directory (Active Directory / LDAP) authentication
// provider. Design goals, in order:
//
//  1. No implicit privilege. Group DNs map to roles explicitly in config;
//     an authenticated user matching no mapped group gets the default role
//     ("user"). This is the structural fix for v1's bug where any
//     directory-authenticated account was treated as admin.
//  2. Verify credentials by binding AS THE USER (service account only
//     locates the entry). Empty passwords are rejected before any bind —
//     LDAP treats an empty-password bind as anonymous and reports success.
//  3. Multi-server failover: servers are tried in order per login.
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/config"
)

// Conn is the subset of the LDAP client the provider uses (injectable in
// tests).
type Conn interface {
	Bind(username, password string) error
	Search(*goldap.SearchRequest) (*goldap.SearchResult, error)
	Close() error
}

// Dialer opens a connection to one server URL.
type Dialer func(context.Context, string) (Conn, error)

// Provider authenticates console logins against a directory.
type Provider struct {
	cfg  config.LDAPCfg
	dial Dialer
	log  *slog.Logger
}

// New builds a Provider from config. The default dialer handles ldaps://
// (TLS, with optional extra CA) and ldap:// (plaintext or StartTLS).
func New(cfg config.LDAPCfg, log *slog.Logger) (*Provider, error) {
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(&(objectClass=user)(sAMAccountName=%s))"
	}
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = string(auth.RoleUser)
	}

	var tlsCfg *tls.Config
	if cfg.CAFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ldap: read ca_file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ldap: ca_file %s contains no certificates", cfg.CAFile)
		}
		tlsCfg = &tls.Config{RootCAs: pool}
	}

	p := &Provider{cfg: cfg, log: log}
	p.dial = func(ctx context.Context, serverURL string) (Conn, error) {
		u, err := url.Parse(serverURL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "ldaps" && u.Scheme != "ldap") || (u.Scheme == "ldap" && !cfg.StartTLS) {
			return nil, errors.New("LDAP requires ldaps:// or ldap:// with StartTLS")
		}
		port := u.Port()
		if port == "" {
			if u.Scheme == "ldaps" {
				port = "636"
			} else {
				port = "389"
			}
		}
		raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
		if err != nil {
			return nil, err
		}
		// A deadline covers TLS negotiation as well as every LDAP operation.
		if deadline, ok := ctx.Deadline(); ok {
			if err = raw.SetDeadline(deadline); err != nil {
				raw.Close()
				return nil, err
			}
		}
		stop := context.AfterFunc(ctx, func() { raw.Close() })
		defer stop()
		c := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if tlsCfg != nil {
			c.RootCAs = tlsCfg.RootCAs
		}
		var transport net.Conn = raw
		if u.Scheme == "ldaps" {
			secure := tls.Client(raw, c)
			if err = secure.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			transport = secure
		}
		conn := goldap.NewConn(transport, u.Scheme == "ldaps")
		conn.Start()
		conn.SetTimeout(10 * time.Second)
		if u.Scheme == "ldap" {
			if err = conn.StartTLS(c); err != nil {
				conn.Close()
				return nil, err
			}
		}
		return conn, nil
	}
	return p, nil
}

// Name identifies this provider.
func (p *Provider) Name() string { return "ldap" }

// Authenticate verifies username/password against the directory and returns
// the mapped identity.
func (p *Provider) Authenticate(ctx context.Context, username, password string) (*auth.Identity, error) {
	// An empty password would turn the user bind into an anonymous bind,
	// which succeeds. Refuse before touching the network.
	if username == "" || password == "" {
		return nil, auth.ErrInvalidCredentials
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var lastErr error
	for _, server := range p.cfg.Servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attempt, cancelAttempt := context.WithTimeout(ctx, 10*time.Second)
		id, err := p.authenticateVia(attempt, server, username, password)
		cancelAttempt()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		if err == nil {
			return id, nil
		}
		if errors.Is(err, auth.ErrInvalidCredentials) {
			// A definitive answer from a healthy server — do not fail over.
			return nil, err
		}
		p.log.Warn("ldap server failed, trying next", "server", server, "err", err)
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("ldap: no servers configured")
	}
	return nil, fmt.Errorf("ldap: all servers failed: %w", lastErr)
}

func (p *Provider) authenticateVia(ctx context.Context, server, username, password string) (*auth.Identity, error) {
	conn, err := p.dial(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	// Locate the user with the service account.
	if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("service bind: %w", err)
	}
	filter := strings.ReplaceAll(p.cfg.UserFilter, "%s", goldap.EscapeFilter(username))
	res, err := conn.Search(goldap.NewSearchRequest(
		p.cfg.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, 10, false, filter,
		[]string{"dn", "sAMAccountName", "displayName", "cn", "memberOf"}, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("user search: %w", err)
	}
	switch len(res.Entries) {
	case 0:
		return nil, auth.ErrInvalidCredentials
	case 1:
	default:
		return nil, fmt.Errorf("user search: filter matched %d entries", len(res.Entries))
	}
	entry := res.Entries[0]

	// Verify the password by binding as the located user.
	if err := conn.Bind(entry.DN, password); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return nil, auth.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("user bind: %w", err)
	}

	display := entry.GetAttributeValue("displayName")
	if display == "" {
		display = entry.GetAttributeValue("cn")
	}
	acct := entry.GetAttributeValue("sAMAccountName")
	if acct == "" {
		acct = username
	}
	return &auth.Identity{
		Username:    acct,
		DisplayName: display,
		Role:        p.mapRole(entry.GetAttributeValues("memberOf")),
		Provider:    "ldap",
	}, nil
}

// mapRole resolves the highest role granted by any matching group mapping;
// no match yields the configured default.
func (p *Provider) mapRole(memberOf []string) auth.Role {
	role := auth.Role(p.cfg.DefaultRole)
	for _, groupDN := range memberOf {
		mapped, ok := lookupDN(p.cfg.GroupRoles, groupDN)
		if !ok {
			continue
		}
		if r := auth.Role(mapped); r.Valid() && r.AtLeast(role) {
			role = r
		}
	}
	return role
}

// lookupDN finds a group mapping by case-insensitive DN comparison (AD DNs
// are not case-normalized in memberOf).
func lookupDN(m map[string]string, dn string) (string, bool) {
	for k, v := range m {
		configured, err := goldap.ParseDN(k)
		if err != nil {
			continue
		}
		actual, err := goldap.ParseDN(dn)
		if err == nil && configured.EqualFold(actual) {
			return v, true
		}
	}
	return "", false
}
