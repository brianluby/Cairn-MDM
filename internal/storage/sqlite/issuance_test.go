package sqlite

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// mkGrant creates a grant and returns its id, for issuance tests.
func mkGrant(t *testing.T, db *DB) int64 {
	t.Helper()
	_, hash := NewGrantToken()
	id, err := db.CreateGrant(context.Background(), Grant{
		Label: "test", Platform: "macos", Owner: "ndawson@dzsec.net", ExpiresAt: future(),
	}, hash)
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	return id
}

func TestIssuanceFreshBinding(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	iss, idem, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1")
	if err != nil {
		t.Fatal(err)
	}
	if idem {
		t.Error("first binding should not be idempotent")
	}
	if iss.State != IssuanceIssuing {
		t.Errorf("state = %q, want ISSUING", iss.State)
	}
}

func TestIssuanceIdempotentRetry(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	if _, _, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1"); err != nil {
		t.Fatal(err)
	}
	iss, idem, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1") // identical retry
	if err != nil {
		t.Fatal(err)
	}
	if !idem {
		t.Error("identical retry should be idempotent")
	}
	if iss.State != IssuanceIssuing {
		t.Errorf("state = %q, want ISSUING (pending)", iss.State)
	}
}

func TestIssuanceConflictDifferentRequest(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	if _, _, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1"); err != nil {
		t.Fatal(err)
	}
	// Same grant, different key (e.g. attacker/replay with a different keypair).
	_, _, err := db.BeginIssuance(ctx, gid, "txn2", "spki2", "req2")
	if !errors.Is(err, ErrIssuanceConflict) {
		t.Fatalf("err = %v, want ErrIssuanceConflict", err)
	}
}

func TestIssuanceCompleteThenCachedRetry(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	if _, _, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1"); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteIssuance(ctx, gid, "txn1", "spki1", "req1", "0xSERIAL"); err != nil {
		t.Fatal(err)
	}
	iss, idem, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1") // retry after issued
	if err != nil {
		t.Fatal(err)
	}
	if !idem || iss.State != IssuanceIssued || iss.CertSerial != "0xSERIAL" {
		t.Fatalf("retry after ISSUED: idem=%v state=%q serial=%q, want cached ISSUED 0xSERIAL", idem, iss.State, iss.CertSerial)
	}
}

func TestCompleteWrongKeyRejected(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	if _, _, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1"); err != nil {
		t.Fatal(err)
	}
	// A different request must not be able to complete someone else's binding.
	if err := db.CompleteIssuance(ctx, gid, "txnX", "spkiX", "reqX", "0xEVIL"); !errors.Is(err, ErrIssuanceConflict) {
		t.Fatalf("err = %v, want ErrIssuanceConflict", err)
	}
}

func TestFailIsRecoverable(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	if _, _, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1"); err != nil {
		t.Fatal(err)
	}
	if err := db.FailIssuance(ctx, gid, "txn1", "spki1", "req1", "ca timeout"); err != nil {
		t.Fatal(err)
	}
	// A fresh request may rebind the FAILED slot (offline retry / reissue).
	iss, idem, err := db.BeginIssuance(ctx, gid, "txn2", "spki2", "req2")
	if err != nil {
		t.Fatalf("recovery BeginIssuance: %v", err)
	}
	if idem || iss.State != IssuanceIssuing {
		t.Fatalf("recovery: idem=%v state=%q, want fresh ISSUING", idem, iss.State)
	}
}

// The core invariant: N concurrent identical retries yield exactly ONE fresh
// binding; every other call is idempotent, and exactly one row exists.
func TestConcurrentSameKeyOneWinner(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	const N = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	fresh, idempotent, failed := 0, 0, 0
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, idem, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				failed++
			case idem:
				idempotent++
			default:
				fresh++
			}
		}()
	}
	wg.Wait()
	if fresh != 1 || idempotent != N-1 || failed != 0 {
		t.Fatalf("same-key race: fresh=%d idempotent=%d failed=%d, want 1/%d/0", fresh, idempotent, failed, N-1)
	}
}

// The other core invariant: N concurrent DIFFERENT requests on one grant → exactly
// one wins (ISSUING); the rest are rejected with ErrIssuanceConflict (no double
// issuance).
func TestConcurrentDifferentKeysOneWinner(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	const N = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	won, conflict, other := 0, 0, 0
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := string(rune('a' + n))
			_, idem, err := db.BeginIssuance(ctx, gid, "txn"+id, "spki"+id, "req"+id)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && !idem:
				won++
			case errors.Is(err, ErrIssuanceConflict):
				conflict++
			default:
				other++
			}
		}(i)
	}
	wg.Wait()
	if won != 1 || conflict != N-1 || other != 0 {
		t.Fatalf("different-key race: won=%d conflict=%d other=%d, want 1/%d/0", won, conflict, other, N-1)
	}
}
