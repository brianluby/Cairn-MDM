package sqlite

import (
	"bytes"
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
	if err := db.CompleteIssuance(ctx, gid, "txn1", "spki1", "req1", "0xSERIAL", nil); err != nil {
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
	if err := db.CompleteIssuance(ctx, gid, "txnX", "spkiX", "reqX", "0xEVIL", nil); !errors.Is(err, ErrIssuanceConflict) {
		t.Fatalf("err = %v, want ErrIssuanceConflict", err)
	}
}

// FAILED is terminal for a grant: a grant binds exactly once and is NOT
// auto-recovered, because FAILED can hide an ambiguous CA outcome where a cert
// was actually issued (recovering would double-issue). Retry = a new grant.
func TestFailIsTerminalNoReissue(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	if _, _, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1"); err != nil {
		t.Fatal(err)
	}
	if err := db.FailIssuance(ctx, gid, "txn1", "spki1", "req1", "ca timeout (ambiguous)"); err != nil {
		t.Fatal(err)
	}
	// A DIFFERENT request must NOT reissue on the same grant.
	if _, _, err := db.BeginIssuance(ctx, gid, "txn2", "spki2", "req2"); !errors.Is(err, ErrIssuanceConflict) {
		t.Fatalf("reissue after FAILED: err=%v, want ErrIssuanceConflict (no double-issue)", err)
	}
	// The SAME request idempotently reports FAILED (not a reissue).
	iss, idem, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1")
	if err != nil || !idem || iss.State != IssuanceFailed {
		t.Fatalf("same-key after FAILED: idem=%v state=%q err=%v, want idempotent FAILED", idem, iss.State, err)
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

// A grant revoked between validation and the claim must NOT acquire a binding
// (the TOCTOU the adversarial review found).
func TestGrantRevokedBeforeClaim(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)
	if err := db.RevokeGrant(ctx, gid); err != nil {
		t.Fatal(err)
	}
	_, _, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1")
	if !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("err = %v, want ErrGrantInvalid", err)
	}
	if _, gerr := db.GetIssuance(ctx, gid); gerr == nil {
		t.Fatal("no issuance row should exist for a revoked grant")
	}
}

// An expired grant is not claimable.
func TestGrantExpiredBeforeClaim(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	_, hash := NewGrantToken()
	gid, err := db.CreateGrant(ctx, Grant{Label: "old", Platform: "macos", Owner: "ndawson@dzsec.net", ExpiresAt: past()}, hash)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1")
	if !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("err = %v, want ErrGrantInvalid", err)
	}
}

// Revoking a grant with an in-flight ISSUING binding voids it, so the in-flight
// request can no longer complete.
func TestRevokeVoidsIssuing(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)
	if _, _, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1"); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeGrant(ctx, gid); err != nil {
		t.Fatal(err)
	}
	iss, err := db.GetIssuance(ctx, gid)
	if err != nil || iss.State != IssuanceQuarantined {
		t.Fatalf("after revoke: state=%q err=%v, want QUARANTINED", iss.State, err)
	}
	if err := db.CompleteIssuance(ctx, gid, "txn1", "spki1", "req1", "0xSERIAL", nil); !errors.Is(err, ErrIssuanceConflict) {
		t.Fatalf("complete after revoke: err=%v, want ErrIssuanceConflict", err)
	}
}

// Regression for the adversarial-review HIGH finding: after an ambiguous outcome
// recorded as FAILED (where the CA may in fact have issued), a second request must
// not produce a second certificate. The grant binds once; a different request is
// rejected and exactly one issuance row remains, bound to the first attempt.
func TestNoDoubleIssueAfterAmbiguousFailure(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	if _, _, err := db.BeginIssuance(ctx, gid, "txnA", "spkiA", "reqA"); err != nil {
		t.Fatal(err)
	}
	if err := db.FailIssuance(ctx, gid, "txnA", "spkiA", "reqA", "timeout"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.BeginIssuance(ctx, gid, "txnB", "spkiB", "reqB"); !errors.Is(err, ErrIssuanceConflict) {
		t.Fatalf("second attempt after ambiguous FAILED: err=%v, want ErrIssuanceConflict", err)
	}
	iss, err := db.GetIssuance(ctx, gid)
	if err != nil || !iss.matches("txnA", "spkiA", "reqA") {
		t.Fatalf("issuance row should still be attempt A: %+v err=%v", iss, err)
	}
}

// Cleanup preserves grants that have an issuance record (audit + no rowid reuse),
// and deletes expired grants with no issuance.
func TestDeleteExpiredPreservesGrantsWithIssuance(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)

	// Grant A: expired but valid-at-claim window is irrelevant here — create it
	// unexpired, bind an issuance, then it must survive cleanup even once expired.
	gidA := mkGrant(t, db) // unexpired
	if _, _, err := db.BeginIssuance(ctx, gidA, "txnA", "spkiA", "reqA"); err != nil {
		t.Fatal(err)
	}
	// Force A's expiry into the past so the cleanup window would otherwise delete it.
	if _, err := db.sql.ExecContext(ctx, `UPDATE enrollment_grants SET expires_at=? WHERE id=?`, past(), gidA); err != nil {
		t.Fatal(err)
	}
	// Grant B: expired, no issuance → should be deleted.
	_, hashB := NewGrantToken()
	gidB, err := db.CreateGrant(ctx, Grant{Label: "B", Platform: "macos", ExpiresAt: past()}, hashB)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.DeleteExpiredGrants(ctx, 0); err != nil {
		t.Fatalf("DeleteExpiredGrants: %v", err) // must not FK-error on A
	}
	if _, err := db.GetGrant(ctx, gidA); err != nil {
		t.Errorf("grant A (has issuance) should survive cleanup: %v", err)
	}
	if _, err := db.GetGrant(ctx, gidB); err == nil {
		t.Error("grant B (no issuance, expired) should be deleted")
	}
	// A's issuance row is intact.
	if _, err := db.GetIssuance(ctx, gidA); err != nil {
		t.Errorf("issuance row for A should be intact: %v", err)
	}
}

// Completion must carry a serial — no "issued without a serial" state.
func TestCompleteEmptySerialRejected(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)
	if _, _, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1"); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteIssuance(ctx, gid, "txn1", "spki1", "req1", "", nil); err == nil {
		t.Fatal("CompleteIssuance with empty serial must be rejected")
	}
	// State must remain ISSUING (not a half-completed ISSUED).
	iss, _ := db.GetIssuance(ctx, gid)
	if iss.State != IssuanceIssuing {
		t.Fatalf("state = %q, want ISSUING (completion rejected)", iss.State)
	}
}

// Timeout-after-signing: the CA signed but the response was lost; the client
// resends the identical SCEP request. The binding stays ISSUING (pending), the
// resend is idempotent, and once the reconciler records the serial the next
// resend returns the cached certificate.
func TestTimeoutAfterSigningThenComplete(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	if _, _, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1"); err != nil {
		t.Fatal(err)
	}
	// Resend before completion → still pending, idempotent, no second issuance.
	iss, idem, err := db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1")
	if err != nil || !idem || iss.State != IssuanceIssuing {
		t.Fatalf("resend before complete: idem=%v state=%q err=%v, want pending idempotent", idem, iss.State, err)
	}
	// Reconciler records the serial.
	if err := db.CompleteIssuance(ctx, gid, "txn1", "spki1", "req1", "0xLATE", nil); err != nil {
		t.Fatal(err)
	}
	// Resend after completion → cached cert.
	iss, idem, err = db.BeginIssuance(ctx, gid, "txn1", "spki1", "req1")
	if err != nil || !idem || iss.State != IssuanceIssued || iss.CertSerial != "0xLATE" {
		t.Fatalf("resend after complete: idem=%v state=%q serial=%q, want cached ISSUED", idem, iss.State, iss.CertSerial)
	}
}

// The DB-level CHECK constraints are the last line of defense if code is wrong:
// no unknown state, and no ISSUED row without a serial (or non-ISSUED with one).
func TestIssuanceSchemaConstraints(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	// ISSUED with an empty serial must be rejected by the CHECK.
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO cert_issuance (grant_id, txn_id, spki_sha256, request_hash, state, cert_serial)
		 VALUES (?, 't', 's', 'r', 'ISSUED', '')`, gid)
	if err == nil {
		t.Error("CHECK should reject ISSUED with empty serial")
	}
	// Unknown state must be rejected.
	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO cert_issuance (grant_id, txn_id, spki_sha256, request_hash, state)
		 VALUES (?, 't', 's', 'r', 'BOGUS')`, gid)
	if err == nil {
		t.Error("CHECK should reject an unknown state")
	}
	// ISSUING with a stray serial must be rejected.
	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO cert_issuance (grant_id, txn_id, spki_sha256, request_hash, state, cert_serial)
		 VALUES (?, 't', 's', 'r', 'ISSUING', '0xSTRAY')`, gid)
	if err == nil {
		t.Error("CHECK should reject ISSUING with a serial")
	}
}

func TestQuarantineIsTerminal(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)

	if _, _, err := db.BeginIssuance(ctx, gid, "txnQ", "spkiQ", "reqQ"); err != nil {
		t.Fatal(err)
	}
	if err := db.QuarantineIssuance(ctx, gid, "txnQ", "spkiQ", "reqQ", "ambiguous-ca-response", "external-scep", "catx"); err != nil {
		t.Fatalf("QuarantineIssuance: %v", err)
	}
	// An identical retry returns the quarantined row idempotently — never a fresh
	// binding — and it carries the recorded reason/backend.
	iss, idem, err := db.BeginIssuance(ctx, gid, "txnQ", "spkiQ", "reqQ")
	if err != nil {
		t.Fatal(err)
	}
	if !idem || iss.State != IssuanceQuarantined {
		t.Fatalf("retry after quarantine: idem=%v state=%q, want idempotent QUARANTINED", idem, iss.State)
	}
	if iss.QuarantineReason != "ambiguous-ca-response" || iss.Backend != "external-scep" || iss.BackendTxn != "catx" {
		t.Fatalf("quarantine metadata not persisted: %+v", iss)
	}
	// A quarantined attempt can never be completed (that would resurrect an
	// ambiguous outcome into a definitive issuance).
	if err := db.CompleteIssuance(ctx, gid, "txnQ", "spkiQ", "reqQ", "0xLATE", nil); !errors.Is(err, ErrIssuanceConflict) {
		t.Fatalf("completing a quarantined attempt: err=%v, want ErrIssuanceConflict", err)
	}
}

func TestListQuarantinedOnlyQuarantined(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	g1, g2 := mkGrant(t, db), mkGrant(t, db)

	if _, _, err := db.BeginIssuance(ctx, g1, "t1", "s1", "r1"); err != nil {
		t.Fatal(err)
	}
	if err := db.QuarantineIssuance(ctx, g1, "t1", "s1", "r1", "lost-after-possible-sign", "external-scep", "x1"); err != nil {
		t.Fatal(err)
	}
	// g2 issues cleanly — must not appear in the quarantine work-list.
	if _, _, err := db.BeginIssuance(ctx, g2, "t2", "s2", "r2"); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteIssuance(ctx, g2, "t2", "s2", "r2", "0xOK", nil); err != nil {
		t.Fatal(err)
	}

	list, err := db.ListQuarantined(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].GrantID != g1 {
		t.Fatalf("ListQuarantined = %+v, want exactly g1", list)
	}
}

func TestLeafDERCachedOnComplete(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	gid := mkGrant(t, db)
	leaf := []byte{0x30, 0x82, 0xDE, 0xAD} // stand-in DER

	if _, _, err := db.BeginIssuance(ctx, gid, "txnL", "spkiL", "reqL"); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteIssuance(ctx, gid, "txnL", "spkiL", "reqL", "0xSER", leaf); err != nil {
		t.Fatal(err)
	}
	// An idempotent retry returns the cached leaf without re-hitting a backend.
	iss, idem, err := db.BeginIssuance(ctx, gid, "txnL", "spkiL", "reqL")
	if err != nil {
		t.Fatal(err)
	}
	if !idem || iss.State != IssuanceIssued || !bytes.Equal(iss.LeafDER, leaf) {
		t.Fatalf("cached retry: idem=%v state=%q leaf=%x, want ISSUED with cached leaf %x", idem, iss.State, iss.LeafDER, leaf)
	}
	// GetIssuanceByTxn resolves the same row by transaction id.
	byTxn, err := db.GetIssuanceByTxn(ctx, "txnL")
	if err != nil {
		t.Fatal(err)
	}
	if byTxn.GrantID != gid || !bytes.Equal(byTxn.LeafDER, leaf) {
		t.Fatalf("GetIssuanceByTxn = %+v, want grant %d with cached leaf", byTxn, gid)
	}
}
