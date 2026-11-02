package ldap

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/nickpdawson/cairn-mdm/internal/auth"
)

var ErrOwnerIneligible = errors.New("directory owner is missing, ambiguous, disabled, expired or incomplete")
var identityAttributes = []string{"dn", "objectGUID", "userPrincipalName", "sAMAccountName", "userAccountControl", "accountExpires", "displayName", "cn", "memberOf"}

func directoryIdentity(entry *goldap.Entry, directory string, now time.Time) (*auth.DirectoryIdentity, error) {
	if directory == "" {
		return nil, errors.New("configure a stable auth.ldap.directory_id before resolving certificate owners")
	}
	one := func(name string) (string, bool) {
		v := entry.GetAttributeValues(name)
		if len(v) != 1 || v[0] == "" {
			return "", false
		}
		return v[0], true
	}
	guid := entry.GetRawAttributeValues("objectGUID")
	if len(guid) != 1 || len(guid[0]) != 16 {
		return nil, ErrOwnerIneligible
	}
	upn, ok := one("userPrincipalName")
	if !ok {
		return nil, ErrOwnerIneligible
	}
	addr, err := mail.ParseAddress(upn)
	if err != nil || addr.Address != upn || strings.ContainsAny(upn, "\r\n\x00") {
		return nil, ErrOwnerIneligible
	}
	account, ok := one("sAMAccountName")
	if !ok {
		return nil, ErrOwnerIneligible
	}
	uac, ok := one("userAccountControl")
	if !ok {
		return nil, ErrOwnerIneligible
	}
	flags, err := strconv.ParseUint(uac, 10, 32)
	if err != nil || flags&2 != 0 || flags&512 == 0 {
		return nil, ErrOwnerIneligible
	}
	expiry, ok := one("accountExpires")
	if !ok {
		return nil, ErrOwnerIneligible
	}
	ticks, err := strconv.ParseUint(expiry, 10, 64)
	if err != nil || ticks > 9223372036854775807 {
		return nil, ErrOwnerIneligible
	}
	// AD FILETIME counts 100 ns intervals from 1601. 0 and MaxInt64 mean never.
	if ticks != 0 && ticks != 9223372036854775807 {
		nowTicks := uint64(now.Unix()+11644473600)*10000000 + uint64(now.Nanosecond()/100)
		if ticks <= nowTicks {
			return nil, ErrOwnerIneligible
		}
	}
	return &auth.DirectoryIdentity{DirectoryID: directory, ObjectID: hex.EncodeToString(guid[0]), UPN: upn, AccountName: account}, nil
}

// ResolveOwner resolves an exact account name or UPN through the service bind.
// It proves current directory facts, not MFA, grant authority or permission to issue.
func (p *Provider) ResolveOwner(ctx context.Context, account string) (*auth.DirectoryIdentity, error) {
	if strings.TrimSpace(account) == "" {
		return nil, ErrOwnerIneligible
	}
	escaped := goldap.EscapeFilter(account)
	return p.resolveFilter(ctx, "(&(objectClass=user)(|(sAMAccountName="+escaped+")(userPrincipalName="+escaped+")))")
}

// RevalidateOwner looks up the original objectGUID, never a mutable name that
// could have been assigned to another account since the grant was created.
func (p *Provider) RevalidateOwner(ctx context.Context, owner auth.DirectoryIdentity) (*auth.DirectoryIdentity, error) {
	if owner.DirectoryID == "" || owner.DirectoryID != p.cfg.DirectoryID {
		return nil, ErrOwnerIneligible
	}
	raw, err := hex.DecodeString(owner.ObjectID)
	if err != nil || len(raw) != 16 {
		return nil, ErrOwnerIneligible
	}
	var escaped strings.Builder
	for _, b := range raw {
		fmt.Fprintf(&escaped, "\\%02x", b)
	}
	resolved, err := p.resolveFilter(ctx, "(&(objectClass=user)(objectGUID="+escaped.String()+"))")
	if err == nil && resolved.ObjectID != strings.ToLower(owner.ObjectID) {
		return nil, ErrOwnerIneligible
	}
	return resolved, err
}

func (p *Provider) resolveFilter(ctx context.Context, filter string) (*auth.DirectoryIdentity, error) {
	if p.cfg.DirectoryID == "" {
		return nil, errors.New("auth.ldap.directory_id is required for owner resolution")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var last error
	for _, server := range p.cfg.Servers {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		attempt, stop := context.WithTimeout(ctx, 10*time.Second)
		result, err := p.resolveVia(attempt, server, filter)
		stop()
		if err == nil || errors.Is(err, ErrOwnerIneligible) {
			return result, err
		}
		last = err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if last == nil {
		last = errors.New("no directory servers configured")
	}
	return nil, fmt.Errorf("owner lookup unavailable: %w", last)
}

func (p *Provider) resolveVia(ctx context.Context, server, filter string) (*auth.DirectoryIdentity, error) {
	conn, err := p.dial(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err = conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		return nil, err
	}
	result, err := conn.Search(goldap.NewSearchRequest(p.cfg.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 2, 10, false, filter, identityAttributes, nil))
	if err != nil {
		return nil, err
	}
	if len(result.Entries) != 1 {
		return nil, ErrOwnerIneligible
	}
	return directoryIdentity(result.Entries[0], p.cfg.DirectoryID, time.Now())
}
