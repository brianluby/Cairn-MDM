package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"strings"
	"testing"
	"time"
)

type ownerCheck struct {
	owner directory.DirectoryIdentity
	fail  bool
	calls int
}

func (v *ownerCheck) RevalidateOwner(_ context.Context, owner directory.DirectoryIdentity) (*directory.DirectoryIdentity, error) {
	v.calls++
	if v.fail {
		return nil, errors.New("disabled or unavailable")
	}
	return &v.owner, nil
}
func TestGrantResolverRequiresPinnedCurrentOwner(t *testing.T) {
	ctx := context.Background()
	db, e := sqlite.Open(ctx, t.TempDir()+"/db")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	raw, hash := sqlite.NewGrantToken()
	id, e := db.CreateGrant(ctx, sqlite.Grant{Owner: "person@example.org", Platform: "ios", ExpiresAt: time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05")}, hash)
	if e != nil {
		t.Fatal(e)
	}
	owner := directory.DirectoryIdentity{DirectoryID: "dzsec", ObjectID: strings.Repeat("a", 32), UPN: "person@example.org"}
	check := &ownerCheck{owner: owner}
	resolver := grantResolver{db: db, directory: check}
	if _, e = resolver.LookupForIssuance(ctx, raw); e == nil {
		t.Fatal("legacy text owner inherited authorization")
	}
	encoded, _ := json.Marshal(owner)
	if _, e = db.SQL().Exec(`UPDATE enrollment_grants SET owner_identity=?,actor_subject='local:actor' WHERE id=?`, string(encoded), id); e != nil {
		t.Fatal(e)
	}
	if _, e = resolver.LookupForIssuance(ctx, raw); e != nil {
		t.Fatal(e)
	}
	check.owner.UPN = "renamed@example.org"
	if _, e = resolver.LookupForIssuance(ctx, raw); e == nil {
		t.Fatal("renamed owner silently changed grant")
	}
	check.owner = owner
	check.owner.ObjectID = strings.Repeat("b", 32)
	if _, e = resolver.LookupForIssuance(ctx, raw); e == nil {
		t.Fatal("replacement object accepted")
	}
	check.owner = owner
	check.fail = true
	redeemer := grantRedeemer{db: db, resolver: resolver}
	if _, e = redeemer.RedeemGrant(ctx, raw); e == nil {
		t.Fatal("disabled owner downloaded profile")
	}
	g, e := db.GetGrant(ctx, id)
	if e != nil || g.UseCount != 0 {
		t.Fatal("rejected validation consumed link")
	}
	check.fail = false
	if _, e = redeemer.RedeemGrant(ctx, raw); e != nil {
		t.Fatal(e)
	}
	if e = redeemer.InspectGrant(ctx, raw); e == nil {
		t.Fatal("used grant advertised as active")
	}
}
