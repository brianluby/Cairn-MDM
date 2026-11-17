package targeting

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

type fakeStore struct {
	owners      map[string]sqlite.DeviceOwner
	rules       []sqlite.DirectoryProfileRule
	replaced    [][]int64
	unavailable []string
}

func (f *fakeStore) BindDeviceOwner(_ context.Context, id string) (sqlite.DeviceOwner, error) {
	o, ok := f.owners[id]
	if !ok {
		return sqlite.DeviceOwner{}, sqlite.ErrNoOwner
	}
	return o, nil
}
func (f *fakeStore) GetDeviceOwner(ctx context.Context, id string) (sqlite.DeviceOwner, error) {
	return f.BindDeviceOwner(ctx, id)
}
func (f *fakeStore) ListDirectoryProfileRules(context.Context) ([]sqlite.DirectoryProfileRule, error) {
	return f.rules, nil
}
func (f *fakeStore) ReplaceDirectoryMemberships(_ context.Context, _ string, matched []int64) ([]int64, error) {
	f.replaced = append(f.replaced, matched)
	out := make([]int64, len(matched))
	copy(out, matched)
	return out, nil
}
func (f *fakeStore) RecordDirectoryUnavailable(_ context.Context, id, detail string) error {
	f.unavailable = append(f.unavailable, id+": "+detail)
	return nil
}
func (f *fakeStore) OwnedPushableDeviceIDs(context.Context) ([]string, error) {
	var ids []string
	for id := range f.owners {
		ids = append(ids, id)
	}
	return ids, nil
}

type fakeDirectory struct {
	err     error
	matches map[string]bool // scope object id -> matches
	calls   int
}

func (d *fakeDirectory) EvaluateScopes(_ context.Context, owner directory.DirectoryIdentity, scopes []directory.DirectoryScope) (*directory.DirectoryScopeEvaluation, error) {
	d.calls++
	if d.err != nil {
		return nil, d.err
	}
	out := &directory.DirectoryScopeEvaluation{Owner: owner}
	for _, s := range scopes {
		out.Matches = append(out.Matches, directory.DirectoryScopeMatch{Scope: s, Matches: d.matches[s.ObjectID]})
	}
	return out, nil
}

type fakeReconciler struct{ devices []string }

func (r *fakeReconciler) ReconcileDevice(_ context.Context, id string) error {
	r.devices = append(r.devices, id)
	return nil
}

func scope(id string) directory.DirectoryScope {
	return directory.DirectoryScope{DirectoryID: "dzsec", ObjectID: id, Kind: "group", Mode: "direct", Name: id}
}

func TestRefreshAppliesMatchedRulesAndKeepsMembershipsWhenDirectoryIsUnknown(t *testing.T) {
	owner := sqlite.DeviceOwner{DeviceID: "D1", GrantID: 7, Owner: directory.DirectoryIdentity{DirectoryID: "dzsec", ObjectID: "o1", UPN: "p@example.org"}}
	store := &fakeStore{owners: map[string]sqlite.DeviceOwner{"D1": owner}, rules: []sqlite.DirectoryProfileRule{
		{ID: 1, GroupID: 10, Scope: scope("s1")}, {ID: 2, GroupID: 20, Scope: scope("s2")},
	}}
	dir := &fakeDirectory{matches: map[string]bool{"s2": true}}
	rec := &fakeReconciler{}
	svc := New(store, dir, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))

	out, err := svc.RefreshAndReconcile(context.Background(), "D1")
	if err != nil || !out.Owned || !out.Evaluated || out.Matched != 1 {
		t.Fatalf("outcome %+v %v", out, err)
	}
	if len(store.replaced) != 1 || len(store.replaced[0]) != 1 || store.replaced[0][0] != 2 {
		t.Fatalf("matched rules %v", store.replaced)
	}
	if len(rec.devices) != 1 || rec.devices[0] != "D1" {
		t.Fatal("reconcile not run after refresh")
	}

	dir.err = errors.New("ldap timeout")
	out, err = svc.Refresh(context.Background(), "D1")
	if err != nil || out.Evaluated || !out.Owned {
		t.Fatalf("unavailable outcome %+v %v", out, err)
	}
	if len(store.replaced) != 1 || len(store.unavailable) != 1 {
		t.Fatalf("unknown directory answer changed memberships: %v %v", store.replaced, store.unavailable)
	}

	// Short result (fewer matches than rules) is also unknown, never partial.
	dir.err = nil
	store.rules = append(store.rules, sqlite.DirectoryProfileRule{ID: 3, GroupID: 30, Scope: scope("s3")})
	short := &shortDirectory{}
	svc = New(store, short, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if out, err = svc.Refresh(context.Background(), "D1"); err != nil || out.Evaluated || len(store.unavailable) != 2 {
		t.Fatalf("partial result accepted: %+v %v", out, err)
	}
}

type shortDirectory struct{}

func (shortDirectory) EvaluateScopes(_ context.Context, owner directory.DirectoryIdentity, scopes []directory.DirectoryScope) (*directory.DirectoryScopeEvaluation, error) {
	return &directory.DirectoryScopeEvaluation{Owner: owner, Matches: []directory.DirectoryScopeMatch{{Scope: scopes[0], Matches: true}}}, nil
}

func TestDeviceNowPushableReconcilesWithoutOwnerAndWithoutDirectory(t *testing.T) {
	store := &fakeStore{owners: map[string]sqlite.DeviceOwner{}, rules: []sqlite.DirectoryProfileRule{{ID: 1, GroupID: 10, Scope: scope("s1")}}}
	dir := &fakeDirectory{}
	rec := &fakeReconciler{}
	svc := New(store, dir, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.DeviceNowPushable("legacy")
	if len(rec.devices) != 1 || rec.devices[0] != "legacy" {
		t.Fatal("manual memberships not reconciled for an unowned device")
	}
	if dir.calls != 0 || len(store.replaced) != 0 || len(store.unavailable) != 0 {
		t.Fatal("rules evaluated for a device without a verified owner")
	}

	// Owned device, rules saved, but no directory configured: unknown, kept.
	store.owners["D1"] = sqlite.DeviceOwner{DeviceID: "D1", Owner: directory.DirectoryIdentity{DirectoryID: "dzsec", ObjectID: "o1", UPN: "p@example.org"}}
	svc = New(store, nil, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.DeviceNowPushable("D1")
	if len(store.unavailable) != 1 || len(store.replaced) != 0 || len(rec.devices) != 2 {
		t.Fatalf("no-directory handling: %v %v %v", store.unavailable, store.replaced, rec.devices)
	}

	// No rules at all: stale memberships are cleared without a directory call.
	store.rules = nil
	svc = New(store, dir, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	out, err := svc.Refresh(context.Background(), "D1")
	if err != nil || !out.Evaluated || dir.calls != 0 || len(store.replaced) != 1 || len(store.replaced[0]) != 0 {
		t.Fatalf("empty rule set: %+v %v %v", out, err, store.replaced)
	}

	sum, err := svc.RefreshAll(context.Background())
	if err != nil || sum.Devices != 1 || sum.Evaluated != 1 {
		t.Fatalf("summary %+v %v", sum, err)
	}
}
