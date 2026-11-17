package sqlite

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func newGrantDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), t.TempDir()+"/grants.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func future() string { return time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05") }
func past() string   { return time.Now().Add(-time.Hour).UTC().Format("2006-01-02 15:04:05") }

func TestGrantRedeemLifecycle(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)

	raw, hash := NewGrantToken()
	id, err := db.CreateGrant(ctx, Grant{
		Label: "Nick's Mac", Platform: "macos", Owner: "nick@dzsec.net",
		CreatedBy: "admin", ExpiresAt: future(), MaxUses: 1,
	}, hash)
	if err != nil {
		t.Fatal(err)
	}

	// First redeem wins and returns the owner.
	red, err := db.RedeemGrant(ctx, raw)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if red.Owner != "nick@dzsec.net" || red.Platform != "macos" {
		t.Errorf("redemption = %+v", red)
	}

	// Second redeem of a max_uses=1 grant fails (exhausted).
	if _, err := db.RedeemGrant(ctx, raw); !errors.Is(err, ErrGrantInvalid) {
		t.Errorf("second redeem err = %v, want ErrGrantInvalid", err)
	}

	g, _ := db.GetGrant(ctx, id)
	if g.Status() != "used" || g.UseCount != 1 {
		t.Errorf("status=%q use_count=%d, want used/1", g.Status(), g.UseCount)
	}

	// Unknown token is indistinctly invalid.
	if _, err := db.RedeemGrant(ctx, "deadbeef"); !errors.Is(err, ErrGrantInvalid) {
		t.Errorf("unknown token err = %v", err)
	}
}

func TestGrantExpiredAndRevoked(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)

	// Expired grant cannot be redeemed.
	rawExp, hashExp := NewGrantToken()
	if _, err := db.CreateGrant(ctx, Grant{ExpiresAt: past(), MaxUses: 1, CreatedBy: "a"}, hashExp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RedeemGrant(ctx, rawExp); !errors.Is(err, ErrGrantInvalid) {
		t.Errorf("expired redeem err = %v", err)
	}

	// Revoked grant cannot be redeemed.
	rawRev, hashRev := NewGrantToken()
	id, _ := db.CreateGrant(ctx, Grant{ExpiresAt: future(), MaxUses: 1, CreatedBy: "a"}, hashRev)
	if err := db.RevokeGrant(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RedeemGrant(ctx, rawRev); !errors.Is(err, ErrGrantInvalid) {
		t.Errorf("revoked redeem err = %v", err)
	}
	g, _ := db.GetGrant(ctx, id)
	if g.Status() != "revoked" {
		t.Errorf("status = %q, want revoked", g.Status())
	}
}

func TestGrantConcurrentRedeemNoDoubleSpend(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)

	raw, hash := NewGrantToken()
	if _, err := db.CreateGrant(ctx, Grant{ExpiresAt: future(), MaxUses: 1, CreatedBy: "a"}, hash); err != nil {
		t.Fatal(err)
	}

	const n = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.RedeemGrant(ctx, raw); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("concurrent redemptions succeeded %d times, want exactly 1", wins)
	}
}

// Grants are single-use: CreateGrant pins max_uses to 1 regardless of the
// requested value (the issuance model binds one certificate per grant).
func TestGrantSingleUseEnforced(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	_, hash := NewGrantToken()
	id, err := db.CreateGrant(ctx, Grant{ExpiresAt: future(), MaxUses: 25, CreatedBy: "a"}, hash)
	if err != nil {
		t.Fatal(err)
	}
	g, err := db.GetGrant(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if g.MaxUses != 1 {
		t.Errorf("MaxUses = %d, want 1 (single-use enforced)", g.MaxUses)
	}
}

// Durable single-use: the DB trigger blocks a multi-use grant even via direct SQL
// (rollback-safe — enforcement lives in the schema, not the application binary).
func TestSingleUseTriggerBlocksMultiUse(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	_, hash := NewGrantToken()
	if _, err := db.sql.ExecContext(ctx,
		`INSERT INTO enrollment_grants (token_hash, expires_at, max_uses) VALUES (?, ?, 5)`,
		hash, future()); err == nil {
		t.Fatal("trigger should reject a direct insert with max_uses <> 1")
	}
	// A single-use direct insert is allowed.
	_, hash2 := NewGrantToken()
	if _, err := db.sql.ExecContext(ctx,
		`INSERT INTO enrollment_grants (token_hash, expires_at, max_uses) VALUES (?, ?, 1)`,
		hash2, future()); err != nil {
		t.Fatalf("single-use direct insert should be allowed: %v", err)
	}
}
