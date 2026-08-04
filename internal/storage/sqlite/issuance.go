package sqlite

import (
	"context"
	"errors"
)

// IssuanceState is the state of a grant's single certificate issuance.
type IssuanceState string

const (
	IssuanceIssuing IssuanceState = "ISSUING"
	IssuanceIssued  IssuanceState = "ISSUED"
	IssuanceFailed  IssuanceState = "FAILED"
)

// ErrIssuanceConflict means the grant is already bound to a *different* live
// issuance request (a different idempotency key that is ISSUING or ISSUED) — the
// grant is spent and this request must not be issued.
var ErrIssuanceConflict = errors.New("grant already bound to a different issuance request")

// Issuance is a row of the issuance state machine (schema 016).
type Issuance struct {
	GrantID     int64
	TxnID       string
	SPKISHA256  string
	RequestHash string
	State       IssuanceState
	CertSerial  string
	FailReason  string
}

// matches reports whether i is the same request as the given idempotency triple.
func (i Issuance) matches(txnID, spki, requestHash string) bool {
	return i.TxnID == txnID && i.SPKISHA256 == spki && i.RequestHash == requestHash
}

// BeginIssuance atomically binds grantID to a certificate issuance identified by
// the idempotency triple (txnID, spki, requestHash). The caller must have already
// validated the grant (unexpired, unrevoked, right platform/serial); this is the
// storage transition only.
//
//   - No prior issuance for the grant → inserts ISSUING; returns (row, false, nil).
//   - A prior ISSUING/ISSUED row with the SAME triple (a retry) → returns that row
//     and (row, true, nil). Never a second issuance; ISSUING reads as pending,
//     ISSUED returns the cached certificate serial.
//   - A prior ISSUING/ISSUED row with a DIFFERENT triple → ErrIssuanceConflict
//     (the grant is spent by another request).
//   - A prior FAILED row → the FAILED slot is rebound to this request as ISSUING
//     (recovery); returns (row, false, nil).
//
// The bool result is "idempotent": true iff this call matched an existing binding
// rather than creating a new one.
func (db *DB) BeginIssuance(ctx context.Context, grantID int64, txnID, spki, requestHash string) (Issuance, bool, error) {
	if grantID <= 0 || txnID == "" || spki == "" || requestHash == "" {
		return Issuance{}, false, errors.New("sqlite: BeginIssuance requires grantID>0 and non-empty txnID/spki/requestHash")
	}
	// Claim the grant. UNIQUE(grant_id) makes exactly one INSERT win a race.
	res, err := db.sql.ExecContext(ctx,
		`INSERT INTO cert_issuance (grant_id, txn_id, spki_sha256, request_hash, state)
		 VALUES (?, ?, ?, ?, 'ISSUING')
		 ON CONFLICT(grant_id) DO NOTHING`,
		grantID, txnID, spki, requestHash)
	if err != nil {
		return Issuance{}, false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		cur, err := db.getIssuance(ctx, grantID)
		return cur, false, err // fresh binding
	}

	// A row already existed for this grant.
	cur, err := db.getIssuance(ctx, grantID)
	if err != nil {
		return Issuance{}, false, err
	}
	if cur.State == IssuanceFailed {
		// Recover: rebind the FAILED slot to this request. Guard the race where a
		// concurrent caller rebinds first — only one UPDATE flips FAILED→ISSUING.
		rres, err := db.sql.ExecContext(ctx,
			`UPDATE cert_issuance
			    SET txn_id=?, spki_sha256=?, request_hash=?, state='ISSUING',
			        cert_serial='', fail_reason='', updated_at=datetime('now')
			  WHERE grant_id=? AND state='FAILED'`,
			txnID, spki, requestHash, grantID)
		if err != nil {
			return Issuance{}, false, err
		}
		cur, err = db.getIssuance(ctx, grantID)
		if err != nil {
			return Issuance{}, false, err
		}
		if n, _ := rres.RowsAffected(); n == 1 {
			return cur, false, nil // we recovered it
		}
		// Someone else rebound first; fall through to the key comparison below.
	}
	if cur.matches(txnID, spki, requestHash) {
		return cur, true, nil // idempotent retry (ISSUING=pending, ISSUED=cached)
	}
	return Issuance{}, false, ErrIssuanceConflict
}

// CompleteIssuance transitions the grant's ISSUING binding to ISSUED and records
// the certificate serial. Only the exact bound request (matching idempotency
// triple) in state ISSUING may complete; otherwise ErrIssuanceConflict.
func (db *DB) CompleteIssuance(ctx context.Context, grantID int64, txnID, spki, requestHash, certSerial string) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE cert_issuance
		    SET state='ISSUED', cert_serial=?, updated_at=datetime('now')
		  WHERE grant_id=? AND txn_id=? AND spki_sha256=? AND request_hash=? AND state='ISSUING'`,
		certSerial, grantID, txnID, spki, requestHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrIssuanceConflict
	}
	return nil
}

// FailIssuance transitions the grant's ISSUING binding to FAILED (recoverable —
// a later BeginIssuance may rebind the slot). Only the bound request in state
// ISSUING may fail; otherwise ErrIssuanceConflict.
func (db *DB) FailIssuance(ctx context.Context, grantID int64, txnID, spki, requestHash, reason string) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE cert_issuance
		    SET state='FAILED', fail_reason=?, updated_at=datetime('now')
		  WHERE grant_id=? AND txn_id=? AND spki_sha256=? AND request_hash=? AND state='ISSUING'`,
		reason, grantID, txnID, spki, requestHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrIssuanceConflict
	}
	return nil
}

// GetIssuance returns the issuance row for a grant, or sql.ErrNoRows if none.
func (db *DB) GetIssuance(ctx context.Context, grantID int64) (Issuance, error) {
	return db.getIssuance(ctx, grantID)
}

func (db *DB) getIssuance(ctx context.Context, grantID int64) (Issuance, error) {
	var i Issuance
	err := db.sql.QueryRowContext(ctx,
		`SELECT grant_id, txn_id, spki_sha256, request_hash, state, cert_serial, fail_reason
		   FROM cert_issuance WHERE grant_id=?`, grantID).
		Scan(&i.GrantID, &i.TxnID, &i.SPKISHA256, &i.RequestHash, &i.State, &i.CertSerial, &i.FailReason)
	if err != nil {
		return Issuance{}, err
	}
	return i, nil
}
