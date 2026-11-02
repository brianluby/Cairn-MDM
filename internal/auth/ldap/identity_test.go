package ldap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/nickpdawson/cairn-mdm/internal/auth"
)

func ownerEntry(overrides map[string][]string) *goldap.Entry {
	attrs := map[string][]string{"objectGUID": {string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})}, "userPrincipalName": {"nick@example.org"}, "sAMAccountName": {"nick"}, "userAccountControl": {"512"}, "accountExpires": {"0"}}
	for k, v := range overrides {
		attrs[k] = v
	}
	return goldap.NewEntry("CN=Nick,CN=Users,DC=example,DC=org", attrs)
}

func TestDirectoryOwnerRejectsIncompleteOrIneligible(t *testing.T) {
	now := time.Now()
	for name, overrides := range map[string]map[string][]string{
		"disabled": {"userAccountControl": {"514"}}, "computer": {"userAccountControl": {"4096"}}, "expired": {"accountExpires": {"1"}}, "missing expiry": {"accountExpires": nil}, "missing upn": {"userPrincipalName": nil}, "multiple upns": {"userPrincipalName": {"a@example.org", "b@example.org"}}, "display address": {"userPrincipalName": {"Nick <nick@example.org>"}}, "missing guid": {"objectGUID": nil}, "malformed guid": {"objectGUID": {"short"}}, "bad flags": {"userAccountControl": {"unknown"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := directoryIdentity(ownerEntry(overrides), "test-directory", now); !errors.Is(err, ErrOwnerIneligible) {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
	original, err := directoryIdentity(ownerEntry(nil), "test-directory", now)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := directoryIdentity(ownerEntry(map[string][]string{"sAMAccountName": {"newname"}, "userPrincipalName": {"newname@example.org"}}), "test-directory", now)
	if err != nil {
		t.Fatal(err)
	}
	if original.ObjectID != renamed.ObjectID || original.UPN == renamed.UPN {
		t.Fatal("rename changed immutable identity or retained stale UPN")
	}
	if _, err := directoryIdentity(ownerEntry(nil), "", now); err == nil {
		t.Fatal("unscoped identity accepted")
	}
}

type ownerConn struct {
	*fakeConn
	filter string
}

func (c *ownerConn) Search(r *goldap.SearchRequest) (*goldap.SearchResult, error) {
	c.filter = r.Filter
	return &goldap.SearchResult{Entries: []*goldap.Entry{c.entry}}, nil
}
func TestOwnerResolutionAndRevalidationUseDirectoryFacts(t *testing.T) {
	conn := &ownerConn{fakeConn: baseConn(ownerEntry(nil))}
	p := testProvider(t, conn, nil)
	p.cfg.DirectoryID = "test-directory"
	owner, err := p.ResolveOwner(context.Background(), "nick*)(objectClass=*)")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conn.filter, `nick\2a\29\28objectClass=\2a\29`) {
		t.Fatalf("unescaped lookup: %s", conn.filter)
	}
	if owner.UPN != "nick@example.org" {
		t.Fatal("owner came from requested account rather than directory")
	}
	fresh, err := p.RevalidateOwner(context.Background(), *owner)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.ObjectID != owner.ObjectID || strings.Contains(conn.filter, "sAMAccountName") {
		t.Fatalf("revalidation used mutable name: %s", conn.filter)
	}
	if !strings.Contains(conn.filter, `objectGUID=\01\02\03`) {
		t.Fatal("GUID filter not binary escaped")
	}
	owner.DirectoryID = "other-directory"
	if _, err = p.RevalidateOwner(context.Background(), *owner); !errors.Is(err, ErrOwnerIneligible) {
		t.Fatal("foreign directory owner accepted")
	}
}

func TestConfiguredDirectoryLoginCarriesVerifiedIdentity(t *testing.T) {
	p := testProvider(t, baseConn(ownerEntry(nil)), nil)
	p.cfg.DirectoryID = "test-directory"
	id, err := p.Authenticate(context.Background(), "nick", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if id.Directory == nil || id.Directory.UPN != "nick@example.org" {
		t.Fatalf("missing directory identity: %+v", id)
	}
	p = testProvider(t, baseConn(ownerEntry(map[string][]string{"userAccountControl": {"514"}})), nil)
	p.cfg.DirectoryID = "test-directory"
	if _, err = p.Authenticate(context.Background(), "nick", "hunter2"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatal("disabled directory account accepted")
	}
}
