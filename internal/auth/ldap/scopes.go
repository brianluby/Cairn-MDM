package ldap

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/nickpdawson/cairn-mdm/internal/auth"
)

var ErrScopeUnavailable = errors.New("directory scope is missing, ambiguous or incomplete")

func scopeClass(kind, mode string) (string, error) {
	switch kind {
	case "group":
		if mode == "direct" || mode == "nested" {
			return "group", nil
		}
	case "ou":
		if mode == "direct" || mode == "descendants" {
			return "organizationalUnit", nil
		}
	}
	return "", errors.New("invalid directory scope kind or membership mode")
}

func binaryFilter(raw []byte) string {
	var b strings.Builder
	for _, v := range raw {
		fmt.Fprintf(&b, "\\%02x", v)
	}
	return b.String()
}
func guidFilter(value string) (string, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 16 {
		return "", ErrScopeUnavailable
	}
	return "(objectGUID=" + binaryFilter(raw) + ")", nil
}

// withDirectory performs each complete read on one DC, with bounded failover.
// A partial attempt is discarded before another server is consulted.
func (p *Provider) withDirectory(ctx context.Context, fn func(Conn) error) error {
	if p.cfg.DirectoryID == "" {
		return errors.New("auth.ldap.directory_id is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var last error
	for _, server := range p.cfg.Servers {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		attempt, stop := context.WithTimeout(ctx, 10*time.Second)
		conn, err := p.dial(attempt, server)
		if err == nil {
			closeOnCancel := context.AfterFunc(attempt, func() { conn.Close() })
			err = conn.Bind(p.cfg.BindDN, p.cfg.BindPassword)
			if err == nil {
				err = fn(conn)
			}
			if attempt.Err() != nil {
				err = attempt.Err()
			}
			closeOnCancel()
			conn.Close()
		}
		stop()
		if err == nil || errors.Is(err, ErrScopeUnavailable) || errors.Is(err, ErrOwnerIneligible) {
			return err
		}
		last = err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if last == nil {
		last = errors.New("no directory servers configured")
	}
	return fmt.Errorf("directory evaluation unavailable: %w", last)
}

func (p *Provider) searchScope(conn Conn, filter string, attrs []string) (*goldap.Entry, error) {
	result, err := conn.Search(goldap.NewSearchRequest(p.cfg.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 2, 10, false, filter, attrs, nil))
	if err != nil {
		return nil, err
	}
	// Subordinate referrals accompany every subtree search of the domain root on
	// Samba AD; they are not missing data. Only the entry count decides.
	if result == nil || len(result.Entries) != 1 {
		return nil, ErrScopeUnavailable
	}
	entry := result.Entries[0]
	base, err := goldap.ParseDN(p.cfg.BaseDN)
	if err != nil {
		return nil, ErrScopeUnavailable
	}
	dn, err := goldap.ParseDN(entry.DN)
	if err != nil || !(base.EqualFold(dn) || base.AncestorOfFold(dn)) {
		return nil, ErrScopeUnavailable
	}
	return entry, nil
}

func scopeFromEntry(entry *goldap.Entry, directory, kind, mode string) (auth.DirectoryScope, error) {
	guid := entry.GetRawAttributeValues("objectGUID")
	if len(guid) != 1 || len(guid[0]) != 16 {
		return auth.DirectoryScope{}, ErrScopeUnavailable
	}
	return auth.DirectoryScope{DirectoryID: directory, ObjectID: hex.EncodeToString(guid[0]), Kind: kind, Mode: mode, Name: entry.GetAttributeValue("name"), DN: entry.DN}, nil
}

// ResolveScope accepts an exact name or DN and pins the result to objectGUID.
func (p *Provider) ResolveScope(ctx context.Context, kind, mode, name string) (*auth.DirectoryScope, error) {
	class, err := scopeClass(kind, mode)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(name) == "" {
		return nil, ErrScopeUnavailable
	}
	field := "name"
	if dn, e := goldap.ParseDN(name); e == nil && len(dn.RDNs) > 1 {
		field = "distinguishedName"
	}
	var result auth.DirectoryScope
	err = p.withDirectory(ctx, func(conn Conn) error {
		entry, e := p.searchScope(conn, "(&(objectClass="+class+")("+field+"="+goldap.EscapeFilter(name)+"))", []string{"objectGUID", "name"})
		if e != nil {
			return e
		}
		result, e = scopeFromEntry(entry, p.cfg.DirectoryID, kind, mode)
		return e
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// EvaluateScopes is a fresh preview, not issuance authorization or a directory
// snapshot transaction. Any unknown result rejects the entire preview.
func (p *Provider) EvaluateScopes(ctx context.Context, owner auth.DirectoryIdentity, scopes []auth.DirectoryScope) (*auth.DirectoryScopeEvaluation, error) {
	if owner.DirectoryID != p.cfg.DirectoryID || owner.DirectoryID == "" {
		return nil, ErrOwnerIneligible
	}
	ownerFilter, err := guidFilter(owner.ObjectID)
	if err != nil {
		return nil, ErrOwnerIneligible
	}
	if len(scopes) > 100 {
		return nil, errors.New("at most 100 directory scopes per preview")
	}
	for _, scope := range scopes {
		if scope.DirectoryID != owner.DirectoryID {
			return nil, ErrScopeUnavailable
		}
		if _, err = scopeClass(scope.Kind, scope.Mode); err != nil {
			return nil, err
		}
		if _, err = guidFilter(scope.ObjectID); err != nil {
			return nil, err
		}
	}
	var result *auth.DirectoryScopeEvaluation
	err = p.withDirectory(ctx, func(conn Conn) error {
		entry, e := p.searchScope(conn, "(&(objectClass=user)"+ownerFilter+")", append(append([]string{}, identityAttributes...), "objectSid", "primaryGroupID"))
		if e != nil {
			return e
		}
		current, e := directoryIdentity(entry, p.cfg.DirectoryID, time.Now())
		if e != nil {
			return e
		}
		if !strings.EqualFold(current.ObjectID, owner.ObjectID) {
			return ErrOwnerIneligible
		}
		evaluation := &auth.DirectoryScopeEvaluation{Owner: *current}
		primaryDN := ""
		for _, scope := range scopes {
			class, _ := scopeClass(scope.Kind, scope.Mode)
			filter, _ := guidFilter(scope.ObjectID)
			target, e := p.searchScope(conn, "(&(objectClass="+class+")"+filter+")", []string{"objectGUID", "name"})
			if e != nil {
				return e
			}
			fresh, e := scopeFromEntry(target, p.cfg.DirectoryID, scope.Kind, scope.Mode)
			if e != nil {
				return e
			}
			if !strings.EqualFold(fresh.ObjectID, scope.ObjectID) {
				return ErrScopeUnavailable
			}
			match := false
			if scope.Kind == "ou" {
				parent, e := goldap.ParseDN(target.DN)
				if e != nil {
					return e
				}
				child, e := goldap.ParseDN(entry.DN)
				if e != nil {
					return e
				}
				match = parent.AncestorOfFold(child) && (scope.Mode == "descendants" || len(child.RDNs) == len(parent.RDNs)+1)
			} else {
				// Primary group membership is absent from member/memberOf links.
				if primaryDN == "" {
					sid, e := primaryGroupSID(entry)
					if e != nil {
						return e
					}
					primary, e := p.searchScope(conn, "(&(objectClass=group)(objectSid="+binaryFilter(sid)+"))", []string{"objectGUID"})
					if e != nil {
						return e
					}
					primaryDN = primary.DN
				}
				targetDN, _ := goldap.ParseDN(target.DN)
				primaryParsed, _ := goldap.ParseDN(primaryDN)
				match = targetDN.EqualFold(primaryParsed)
				if !match {
					attribute := "member"
					members := "(" + attribute + "=" + goldap.EscapeFilter(entry.DN) + ")"
					if scope.Mode == "nested" {
						attribute = "member:1.2.840.113556.1.4.1941:"
						members = "(|(" + attribute + "=" + goldap.EscapeFilter(entry.DN) + ")(" + attribute + "=" + goldap.EscapeFilter(primaryDN) + "))"
					}
					found, e := conn.Search(goldap.NewSearchRequest(target.DN, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 2, 10, false, "(&"+filter+members+")", []string{"objectGUID"}, nil))
					if e != nil {
						return e
					}
					if found == nil || len(found.Entries) > 1 {
						return ErrScopeUnavailable
					}
					if len(found.Entries) == 1 {
						verified, e := scopeFromEntry(found.Entries[0], p.cfg.DirectoryID, scope.Kind, scope.Mode)
						if e != nil || verified.ObjectID != fresh.ObjectID {
							return ErrScopeUnavailable
						}
						match = true
					}
				}
			}
			evaluation.Matches = append(evaluation.Matches, auth.DirectoryScopeMatch{Scope: fresh, Matches: match})
		}
		evaluation.CheckedAt = time.Now().UTC()
		result = evaluation
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func primaryGroupSID(entry *goldap.Entry) ([]byte, error) {
	values := entry.GetRawAttributeValues("objectSid")
	rids := entry.GetAttributeValues("primaryGroupID")
	if len(values) != 1 || len(rids) != 1 {
		return nil, ErrScopeUnavailable
	}
	sid := values[0]
	if len(sid) < 12 || sid[0] != 1 || sid[1] < 1 || sid[1] > 15 || len(sid) != 8+4*int(sid[1]) {
		return nil, ErrScopeUnavailable
	}
	rid, err := strconv.ParseUint(rids[0], 10, 32)
	if err != nil {
		return nil, ErrScopeUnavailable
	}
	out := append([]byte{}, sid...)
	binary.LittleEndian.PutUint32(out[len(out)-4:], uint32(rid))
	return out, nil
}
