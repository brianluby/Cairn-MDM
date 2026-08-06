package sqlite

import (
	"context"
	"database/sql"
	"errors"
)

// IssuanceState is the state of a grant's single certificate issuance.
type IssuanceState string

const (
	IssuanceIssuing IssuanceState = "ISSUING"
	IssuanceIssued  IssuanceState = "ISSUED"
	IssuanceFailed  IssuanceState = "FAILED"
	// IssuanceQuarantined is a terminal hold for an AMBIGUOUS outcome (a response
	// lost after the CA may have signed). Distinct from FAILED (proven clean
	// failure): a quarantined attempt is never retried as a fresh issuance and never
	// relabeled FAILED — reissuing could double-issue. Resolution is out-of-band.
	IssuanceQuarantined IssuanceState = "QUARANTINED"
)

// ErrIssuanceConflict means the grant is already bound to a *different* live
// issuance request (a different idempotency key that is ISSUING or ISSUED) — the
// grant is spent and this request must not be issued.
var ErrIssuanceConflict = errors.New("grant already bound to a different issuance request")

// Issuance is a row of the issuance state machine (schema 016, extended by 019).
type Issuance struct {
	GrantID     int64
	TxnID       string
	SPKISHA256  string
	RequestHash string
	State       IssuanceState
	CertSerial  string
	FailReason  string
	// Set on QUARANTINED (schema 019).
	QuarantineReason string
	QuarantinedAt    string // empty unless QUARANTINED
	Backend          string
	BackendTxn       string
	// LeafDER caches the issued certificate (DER) on ISSUED so an idempotent SCEP
	// retry returns the identical CertRep without re-hitting the backend. nil until
	// ISSUED.
	LeafDER []byte
}

// matches reports whether i is the same request as the given idempotency triple.
func (i Issuance) matches(txnID, spki, requestHash string) bool {
	return i.TxnID == txnID && i.SPKISHA256 == spki && i.RequestHash == requestHash
}

// grantValidPredicate is the SQL that a grant must satisfy to be claimable at the
// moment of the claim: it exists, is unrevoked, and is unexpired. Grant
// platform/expected_serial are immutable once created (no TOCTOU), so device
// matching is done by the caller; revocation and expiry change over time and so
// must be checked atomically here, at the claim's linearization point.
const grantValidPredicate = `revoked_at IS NULL AND expires_at > datetime('now')`

// BeginIssuance atomically binds grantID to a certificate issuance identified by
// the idempotency triple (txnID, spki, requestHash). The grant's validity
// (unrevoked, unexpired) is re-checked **atomically with the claim**, so a grant
// revoked or expired after an earlier validation cannot acquire a binding.
//
//   - Grant valid and unbound → inserts ISSUING; returns (row, false, nil).
//   - Grant valid, prior ISSUING/ISSUED with the SAME triple (a retry) → returns
//     that row and (row, true, nil). Never a second issuance; ISSUING reads as
//     pending, ISSUED returns the cached certificate serial.
//   - Any prior binding (ISSUING/ISSUED/FAILED) with a DIFFERENT triple →
//     ErrIssuanceConflict. A grant binds EXACTLY ONCE; FAILED is terminal and is
//     NOT auto-recovered (a FAILED slot may hide an ambiguous CA outcome where a
//     cert was actually issued — reissuing would double-issue). Retry a failed
//     enrollment with a NEW grant.
//   - Grant unknown/revoked/expired and not already bound → ErrGrantInvalid.
//
// The bool result is "idempotent": true iff this call matched an existing binding.
func (db *DB) BeginIssuance(ctx context.Context, grantID int64, txnID, spki, requestHash string) (Issuance, bool, error) {
	if grantID <= 0 || txnID == "" || spki == "" || requestHash == "" {
		return Issuance{}, false, errors.New("sqlite: BeginIssuance requires grantID>0 and non-empty txnID/spki/requestHash")
	}
	// Atomic claim: insert ISSUING only if the grant is currently valid. The
	// INSERT ... SELECT evaluates the validity predicate and the write at one
	// point; UNIQUE(grant_id) makes exactly one INSERT win a race.
	res, err := db.sql.ExecContext(ctx,
		`INSERT INTO cert_issuance (grant_id, txn_id, spki_sha256, request_hash, state)
		 SELECT id, ?, ?, ?, 'ISSUING' FROM enrollment_grants
		  WHERE id = ? AND `+grantValidPredicate+`
		 ON CONFLICT(grant_id) DO NOTHING`,
		txnID, spki, requestHash, grantID)
	if err != nil {
		return Issuance{}, false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		cur, err := db.getIssuance(ctx, grantID)
		return cur, false, err // fresh binding
	}

	// Zero rows inserted: either the grant was not claimable, or a binding already
	// exists. Distinguish by whether a row exists.
	cur, err := db.getIssuance(ctx, grantID)
	if errors.Is(err, sql.ErrNoRows) {
		return Issuance{}, false, ErrGrantInvalid // grant unknown/revoked/expired, unbound
	}
	if err != nil {
		return Issuance{}, false, err
	}

	// A binding already exists for this grant. A grant binds EXACTLY ONCE: we do
	// NOT auto-recover a FAILED slot to a new request. FAILED may follow an
	// ambiguous CA outcome where a certificate WAS in fact issued; silently
	// rebinding and reissuing would double-issue. Retrying a failed enrollment
	// therefore requires a NEW grant (the self-service / offline-device model);
	// an ambiguous outcome is left ISSUING for a reconciler to resolve against the
	// CA. So the only non-error outcomes here are idempotent retries of the SAME
	// request (returning the existing ISSUING/ISSUED/FAILED row).
	if cur.matches(txnID, spki, requestHash) {
		return cur, true, nil // idempotent (ISSUING=pending, ISSUED=cached, FAILED=report)
	}
	return Issuance{}, false, ErrIssuanceConflict
}

// CompleteIssuance transitions the grant's ISSUING binding to ISSUED and records
// the certificate serial and the issued leaf (DER, for idempotent-retry caching).
// Only the exact bound request (matching idempotency triple) in state ISSUING may
// complete; otherwise ErrIssuanceConflict. A non-empty certSerial is required —
// there is no "issued without a serial" state. leafDER may be nil (retries then
// re-fetch from the backend) but SHOULD be the issued certificate.
func (db *DB) CompleteIssuance(ctx context.Context, grantID int64, txnID, spki, requestHash, certSerial string, leafDER []byte) error {
	if grantID <= 0 || txnID == "" || spki == "" || requestHash == "" || certSerial == "" {
		return errors.New("sqlite: CompleteIssuance requires grantID>0 and non-empty txnID/spki/requestHash/certSerial")
	}
	res, err := db.sql.ExecContext(ctx,
		`UPDATE cert_issuance
		    SET state='ISSUED', cert_serial=?, leaf_der=?, updated_at=datetime('now')
		  WHERE grant_id=? AND txn_id=? AND spki_sha256=? AND request_hash=? AND state='ISSUING'`,
		certSerial, leafDER, grantID, txnID, spki, requestHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrIssuanceConflict
	}
	return nil
}

// QuarantineIssuance transitions the grant's ISSUING binding to QUARANTINED — a
// terminal hold for an ambiguous outcome (see IssuanceQuarantined). Only the bound
// request in state ISSUING may be quarantined; otherwise ErrIssuanceConflict.
// reason/backend/backendTxn record why and where, for reconciliation.
func (db *DB) QuarantineIssuance(ctx context.Context, grantID int64, txnID, spki, requestHash, reason, backend, backendTxn string) error {
	if grantID <= 0 || txnID == "" || spki == "" || requestHash == "" {
		return errors.New("sqlite: QuarantineIssuance requires grantID>0 and non-empty txnID/spki/requestHash")
	}
	res, err := db.sql.ExecContext(ctx,
		`UPDATE cert_issuance
		    SET state='QUARANTINED', quarantine_reason=?, quarantined_at=datetime('now'),
		        backend=?, backend_txn=?, updated_at=datetime('now')
		  WHERE grant_id=? AND txn_id=? AND spki_sha256=? AND request_hash=? AND state='ISSUING'`,
		reason, backend, backendTxn, grantID, txnID, spki, requestHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrIssuanceConflict
	}
	return nil
}

// FailIssuance transitions the grant's ISSUING binding to FAILED. FAILED is
// TERMINAL for the grant: BeginIssuance never rebinds it (a FAILED slot can hide an
// ambiguous CA outcome where a cert was in fact issued, so rebinding would risk
// double-issuance). Retrying a failed enrollment requires a NEW grant. Only the
// bound request in state ISSUING may fail; otherwise ErrIssuanceConflict.
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

// issuanceCols is the column list scanned by scanIssuance, in order.
const issuanceCols = `grant_id, txn_id, spki_sha256, request_hash, state, cert_serial,
	fail_reason, quarantine_reason, COALESCE(quarantined_at,''), backend, backend_txn, leaf_der`

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface{ Scan(dest ...any) error }

func scanIssuance(s rowScanner) (Issuance, error) {
	var i Issuance
	err := s.Scan(&i.GrantID, &i.TxnID, &i.SPKISHA256, &i.RequestHash, &i.State,
		&i.CertSerial, &i.FailReason, &i.QuarantineReason, &i.QuarantinedAt, &i.Backend, &i.BackendTxn, &i.LeafDER)
	return i, err
}

// GetIssuance returns the issuance row for a grant, or sql.ErrNoRows if none.
func (db *DB) GetIssuance(ctx context.Context, grantID int64) (Issuance, error) {
	return db.getIssuance(ctx, grantID)
}

func (db *DB) getIssuance(ctx context.Context, grantID int64) (Issuance, error) {
	return scanIssuance(db.sql.QueryRowContext(ctx,
		`SELECT `+issuanceCols+` FROM cert_issuance WHERE grant_id=?`, grantID))
}

// GetIssuanceByTxn returns the issuance row for a SCEP transaction id, or
// sql.ErrNoRows if none. The SCEP txn id is deterministic from the public key, so it
// identifies the attempt; the idempotency triple remains the authoritative key, so a
// caller comparing an attempt should still match the full triple.
func (db *DB) GetIssuanceByTxn(ctx context.Context, txnID string) (Issuance, error) {
	return scanIssuance(db.sql.QueryRowContext(ctx,
		`SELECT `+issuanceCols+` FROM cert_issuance WHERE txn_id=? LIMIT 1`, txnID))
}

// ListQuarantined returns every issuance row in the QUARANTINED state, most recent
// first — the work-list for out-of-band (operator / reconciler) resolution.
func (db *DB) ListQuarantined(ctx context.Context) ([]Issuance, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+issuanceCols+` FROM cert_issuance WHERE state='QUARANTINED' ORDER BY quarantined_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Issuance
	for rows.Next() {
		i, err := scanIssuance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
