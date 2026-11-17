package ldap

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/nickpdawson/cairn-mdm/internal/auth"
)

type scopeConn struct {
	steps []func(*goldap.SearchRequest) (*goldap.SearchResult, error)
	next  int
}

func (*scopeConn) Bind(string, string) error { return nil }
func (*scopeConn) Close() error              { return nil }
func (c *scopeConn) Search(r *goldap.SearchRequest) (*goldap.SearchResult, error) {
	if c.next >= len(c.steps) {
		return nil, errors.New("unexpected search")
	}
	step := c.steps[c.next]
	c.next++
	return step(r)
}
func scopeEntry(dn string, b byte) *goldap.Entry {
	return goldap.NewEntry(dn, map[string][]string{"objectGUID": {strings.Repeat(string(b), 16)}, "name": {"Lynchburg"}})
}
func entryStep(e *goldap.Entry) func(*goldap.SearchRequest) (*goldap.SearchResult, error) {
	return func(*goldap.SearchRequest) (*goldap.SearchResult, error) {
		return &goldap.SearchResult{Entries: []*goldap.Entry{e}}, nil
	}
}
func scopeProvider(t *testing.T, c Conn) *Provider {
	p := testProvider(t, c, nil)
	p.cfg.DirectoryID = "test-directory"
	p.cfg.Servers = p.cfg.Servers[:1]
	return p
}
func ownerRef() auth.DirectoryIdentity {
	return auth.DirectoryIdentity{DirectoryID: "test-directory", ObjectID: "0102030405060708090a0b0c0d0e0f10"}
}
func ruleRef(kind, mode string) auth.DirectoryScope {
	return auth.DirectoryScope{DirectoryID: "test-directory", ObjectID: hex.EncodeToString([]byte(strings.Repeat("g", 16))), Kind: kind, Mode: mode, DN: "stale DN ignored"}
}

func TestOUPreviewUsesCurrentObjectAndParsedAncestry(t *testing.T) {
	for _, tc := range []struct {
		name, dn, mode string
		want           bool
	}{
		{"direct", `CN=Nick,OU=Lynchburg,DC=example,DC=org`, "direct", true},
		{"nested excluded", `CN=Nick,OU=Staff,OU=Lynchburg,DC=example,DC=org`, "direct", false},
		{"nested included", `CN=Nick,OU=Staff,OU=Lynchburg,DC=example,DC=org`, "descendants", true},
		{"substring", `CN=Nick,OU=NotLynchburg,DC=example,DC=org`, "descendants", false},
		{"escaped comma", `CN=Nick\, OU=Lynchburg,OU=Elsewhere,DC=example,DC=org`, "descendants", false},
		{"case", `CN=Nick,ou=LYNCHBURG,dc=example,dc=org`, "direct", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := ownerEntry(nil)
			owner.DN = tc.dn
			target := scopeEntry("OU=Lynchburg,DC=example,DC=org", 'g')
			c := &scopeConn{steps: []func(*goldap.SearchRequest) (*goldap.SearchResult, error){entryStep(owner), entryStep(target)}}
			result, err := scopeProvider(t, c).EvaluateScopes(context.Background(), ownerRef(), []auth.DirectoryScope{ruleRef("ou", tc.mode)})
			if err != nil || result == nil || len(result.Matches) != 1 || result.Matches[0].Matches != tc.want {
				t.Fatalf("preview %+v %v", result, err)
			}
			if result.Matches[0].Scope.DN != target.DN || result.CheckedAt.IsZero() {
				t.Fatal("stale identity metadata")
			}
		})
	}
}

func TestGroupPreviewUsesPrimaryGroupAndNestedLinkQueries(t *testing.T) {
	for _, mode := range []string{"direct", "nested"} {
		t.Run(mode, func(t *testing.T) {
			owner := ownerEntry(map[string][]string{"objectSid": {string([]byte{1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 42, 0, 0, 0})}, "primaryGroupID": {"513"}})
			target := scopeEntry("CN=Lynchburg,OU=Groups,DC=example,DC=org", 'g')
			primary := scopeEntry("CN=Domain Users,CN=Users,DC=example,DC=org", 'p')
			c := &scopeConn{steps: []func(*goldap.SearchRequest) (*goldap.SearchResult, error){entryStep(owner), entryStep(target), func(r *goldap.SearchRequest) (*goldap.SearchResult, error) {
				if !strings.Contains(r.Filter, `\15\00\00\00\01\02\00\00`) {
					t.Fatalf("primary SID not reconstructed: %s", r.Filter)
				}
				return &goldap.SearchResult{Entries: []*goldap.Entry{primary}}, nil
			}, func(r *goldap.SearchRequest) (*goldap.SearchResult, error) {
				if r.Scope != goldap.ScopeBaseObject || r.BaseDN != target.DN {
					t.Fatal("membership not scoped to pinned group")
				}
				if mode == "nested" && (!strings.Contains(r.Filter, "member:1.2.840.113556.1.4.1941:=") || !strings.Contains(r.Filter, primary.DN)) {
					t.Fatalf("missing nested primary membership: %s", r.Filter)
				}
				if mode == "direct" && strings.Contains(r.Filter, "1.4.1941") {
					t.Fatal("direct membership expanded")
				}
				return &goldap.SearchResult{Entries: []*goldap.Entry{target}}, nil
			}}}
			result, err := scopeProvider(t, c).EvaluateScopes(context.Background(), ownerRef(), []auth.DirectoryScope{ruleRef("group", mode)})
			if err != nil || !result.Matches[0].Matches {
				t.Fatalf("group match %+v %v", result, err)
			}
		})
	}
}

func TestScopePreviewRejectsUnknownRatherThanPartialResult(t *testing.T) {
	owner := ownerEntry(nil)
	target := scopeEntry("OU=Lynchburg,DC=example,DC=org", 'g')
	for _, failure := range []func(*goldap.SearchRequest) (*goldap.SearchResult, error){
		func(*goldap.SearchRequest) (*goldap.SearchResult, error) { return nil, errors.New("directory offline") },
		func(*goldap.SearchRequest) (*goldap.SearchResult, error) { return &goldap.SearchResult{}, nil },
		func(*goldap.SearchRequest) (*goldap.SearchResult, error) {
			return &goldap.SearchResult{Entries: []*goldap.Entry{target, target}}, nil
		},
	} {
		c := &scopeConn{steps: []func(*goldap.SearchRequest) (*goldap.SearchResult, error){entryStep(owner), entryStep(target), failure}}
		result, err := scopeProvider(t, c).EvaluateScopes(context.Background(), ownerRef(), []auth.DirectoryScope{ruleRef("ou", "direct"), ruleRef("ou", "direct")})
		if err == nil || result != nil {
			t.Fatalf("partial result escaped: %+v %v", result, err)
		}
	}
	// Samba AD attaches subordinate referrals to every subtree search of the
	// domain root; one entry plus referrals is a complete answer, not a partial one.
	withRef := func(e *goldap.Entry) func(*goldap.SearchRequest) (*goldap.SearchResult, error) {
		return func(*goldap.SearchRequest) (*goldap.SearchResult, error) {
			return &goldap.SearchResult{Entries: []*goldap.Entry{e}, Referrals: []string{"ldaps://dzsec.net/CN=Configuration,DC=example,DC=org", "ldaps://dzsec.net/DC=DomainDnsZones,DC=example,DC=org"}}, nil
		}
	}
	ref := &scopeConn{steps: []func(*goldap.SearchRequest) (*goldap.SearchResult, error){withRef(owner), withRef(target)}}
	if result, err := scopeProvider(t, ref).EvaluateScopes(context.Background(), ownerRef(), []auth.DirectoryScope{ruleRef("ou", "direct")}); err != nil || result == nil || len(result.Matches) != 1 {
		t.Fatalf("referrals treated as partial: %+v %v", result, err)
	}
	disabled := ownerEntry(map[string][]string{"userAccountControl": {"514"}})
	c := &scopeConn{steps: []func(*goldap.SearchRequest) (*goldap.SearchResult, error){entryStep(disabled)}}
	if result, err := scopeProvider(t, c).EvaluateScopes(context.Background(), ownerRef(), nil); !errors.Is(err, ErrOwnerIneligible) || result != nil {
		t.Fatal("disabled owner accepted")
	}
}

func TestResolveScopeEscapesNamesAndPinsGUID(t *testing.T) {
	target := scopeEntry("CN=Lynchburg,OU=Groups,DC=example,DC=org", 'g')
	c := &scopeConn{steps: []func(*goldap.SearchRequest) (*goldap.SearchResult, error){func(r *goldap.SearchRequest) (*goldap.SearchResult, error) {
		if !strings.Contains(r.Filter, `name=Lynchburg\2a\29\28objectClass=\2a\29`) {
			t.Fatalf("name not escaped: %s", r.Filter)
		}
		return &goldap.SearchResult{Entries: []*goldap.Entry{target}}, nil
	}}}
	result, err := scopeProvider(t, c).ResolveScope(context.Background(), "group", "direct", "Lynchburg*)(objectClass=*)")
	if err != nil || result.ObjectID != ruleRef("group", "direct").ObjectID {
		t.Fatalf("scope %+v %v", result, err)
	}
	if _, err := scopeProvider(t, c).ResolveScope(context.Background(), "ou", "nested", "Lynchburg"); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

func TestGroupPrimaryMembershipAndOwnerMoveRefresh(t *testing.T) {
	owner := ownerEntry(map[string][]string{"objectSid": {string([]byte{1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 42, 0, 0, 0})}, "primaryGroupID": {"513"}})
	target := scopeEntry("CN=Lynchburg,CN=Users,DC=example,DC=org", 'g')
	c := &scopeConn{steps: []func(*goldap.SearchRequest) (*goldap.SearchResult, error){entryStep(owner), entryStep(target), entryStep(target)}}
	result, err := scopeProvider(t, c).EvaluateScopes(context.Background(), ownerRef(), []auth.DirectoryScope{ruleRef("group", "direct")})
	if err != nil || !result.Matches[0].Matches || c.next != 3 {
		t.Fatalf("primary membership %+v %v", result, err)
	}
	owner.DN = "CN=Nick,OU=Lynchburg,DC=example,DC=org"
	target = scopeEntry("OU=Lynchburg,DC=example,DC=org", 'g')
	c = &scopeConn{steps: []func(*goldap.SearchRequest) (*goldap.SearchResult, error){entryStep(owner), entryStep(target)}}
	p := scopeProvider(t, c)
	result, err = p.EvaluateScopes(context.Background(), ownerRef(), []auth.DirectoryScope{ruleRef("ou", "direct")})
	if err != nil || !result.Matches[0].Matches {
		t.Fatal("initial OU membership missing")
	}
	owner.DN = "CN=Nick,OU=Montana,DC=example,DC=org"
	c.next = 0
	result, err = p.EvaluateScopes(context.Background(), ownerRef(), []auth.DirectoryScope{ruleRef("ou", "direct")})
	if err != nil || result.Matches[0].Matches {
		t.Fatal("owner move retained old membership")
	}
}

func TestScopeFailoverDiscardsPartialDCResult(t *testing.T) {
	owner := ownerEntry(nil)
	target := scopeEntry("OU=Lynchburg,DC=example,DC=org", 'g')
	first := &scopeConn{steps: []func(*goldap.SearchRequest) (*goldap.SearchResult, error){entryStep(owner), func(*goldap.SearchRequest) (*goldap.SearchResult, error) { return nil, errors.New("connection lost") }}}
	moved := ownerEntry(nil)
	moved.DN = "CN=Nick,OU=Lynchburg,DC=example,DC=org"
	second := &scopeConn{steps: []func(*goldap.SearchRequest) (*goldap.SearchResult, error){entryStep(moved), entryStep(target)}}
	p := scopeProvider(t, first)
	p.cfg.Servers = []string{"first", "second"}
	p.dial = func(_ context.Context, server string) (Conn, error) {
		if server == "first" {
			return first, nil
		}
		return second, nil
	}
	result, err := p.EvaluateScopes(context.Background(), ownerRef(), []auth.DirectoryScope{ruleRef("ou", "direct")})
	if err != nil || !result.Matches[0].Matches || second.next != 2 {
		t.Fatalf("mixed DC preview %+v %v", result, err)
	}
}

func TestScopeRejectsForeignOrReplacedObjects(t *testing.T) {
	c := &scopeConn{}
	p := scopeProvider(t, c)
	foreign := ruleRef("ou", "direct")
	foreign.DirectoryID = "different-forest"
	if result, err := p.EvaluateScopes(context.Background(), ownerRef(), []auth.DirectoryScope{foreign}); err == nil || result != nil || c.next != 0 {
		t.Fatal("foreign scope evaluated")
	}
	replacement := scopeEntry("OU=Lynchburg,DC=example,DC=org", 'x')
	c.steps = []func(*goldap.SearchRequest) (*goldap.SearchResult, error){entryStep(ownerEntry(nil)), entryStep(replacement)}
	if result, err := p.EvaluateScopes(context.Background(), ownerRef(), []auth.DirectoryScope{ruleRef("ou", "direct")}); err == nil || result != nil {
		t.Fatal("replacement GUID accepted under old scope")
	}
}
