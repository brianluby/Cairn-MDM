package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// ErrGrantInvalid means the token is unknown, expired, revoked, or exhausted.
// It is deliberately indistinct so a caller cannot tell which (no enumeration
// oracle).
var ErrGrantInvalid = errors.New("enrollment grant invalid")

// Grant is a row of the enrollment-grant table.
type Grant struct {
	ID             int64
	Label          string
	Platform       string // any | macos | ios
	Owner          string // rfc822/UPN, flows to the device cert SAN
	CreatedBy      string
	CreatedAt      string
	ExpiresAt      string
	MaxUses        int
	UseCount       int
	RevokedAt      sql.NullString
	ExpectedSerial string
	LastUsedAt     sql.NullString
}

// Status summarizes a grant for display.
func (g Grant) Status() string {
	switch {
	case g.RevokedAt.Valid:
		return "revoked"
	case g.UseCount >= g.MaxUses:
		return "used"
	case parseTime(g.ExpiresAt).Before(time.Now()):
		return "expired"
	default:
		return "active"
	}
}

// Redemption is what a successful redeem returns — the fields needed to build
// the device's profile.
type Redemption struct {
	ID             int64
	Platform       string
	Owner          string
	ExpectedSerial string
}

// NewGrantToken returns a fresh high-entropy token (raw) and its storage hash.
// The raw token goes in the enrollment link and is shown once; only the hash
// is persisted.
func NewGrantToken() (raw, hash string) {
	var b [32]byte
	_, _ = rand.Read(b[:])
	raw = hex.EncodeToString(b[:])
	return raw, HashGrantToken(raw)
}

// HashGrantToken hashes a raw token for storage/lookup.
func HashGrantToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// CreateGrant inserts a grant and returns its ID. tokenHash must come from
// NewGrantToken/HashGrantToken.
func (db *DB) CreateGrant(ctx context.Context, g Grant, tokenHash string) (int64, error) {
	// Grants are single-use: one grant authorizes exactly one device enrollment
	// and one certificate issuance (issuance state machine, schema 016). A
	// multi-use grant could never issue past the first device (UNIQUE(grant_id)),
	// so max_uses is pinned to 1 regardless of the requested value.
	g.MaxUses = 1
	if g.Platform == "" {
		g.Platform = "any"
	}
	res, err := db.sql.ExecContext(ctx,
		`INSERT INTO enrollment_grants
		   (token_hash, label, platform, owner, created_by, expires_at, max_uses, expected_serial)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		tokenHash, g.Label, g.Platform, g.Owner, g.CreatedBy, g.ExpiresAt, g.MaxUses, g.ExpectedSerial)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// RedeemGrant atomically validates and consumes one use of the grant named by
// rawToken. The whole check-and-consume is a single UPDATE, so concurrent
// redemptions cannot double-spend. Returns ErrGrantInvalid on any failure.
func (db *DB) RedeemGrant(ctx context.Context, rawToken string) (Redemption, error) {
	var r Redemption
	err := db.sql.QueryRowContext(ctx,
		`UPDATE enrollment_grants
		    SET use_count = use_count + 1, last_used_at = datetime('now')
		  WHERE token_hash = ?
		    AND revoked_at IS NULL
		    AND use_count < max_uses
		    AND expires_at > datetime('now')
		 RETURNING id, platform, owner, expected_serial`,
		HashGrantToken(rawToken)).Scan(&r.ID, &r.Platform, &r.Owner, &r.ExpectedSerial)
	if errors.Is(err, sql.ErrNoRows) {
		return Redemption{}, ErrGrantInvalid
	}
	if err != nil {
		return Redemption{}, err
	}
	return r, nil
}

const grantCols = `id, label, platform, owner, created_by, created_at, expires_at,
	max_uses, use_count, revoked_at, expected_serial, last_used_at`

func scanGrant(row interface{ Scan(...any) error }) (Grant, error) {
	var g Grant
	err := row.Scan(&g.ID, &g.Label, &g.Platform, &g.Owner, &g.CreatedBy, &g.CreatedAt,
		&g.ExpiresAt, &g.MaxUses, &g.UseCount, &g.RevokedAt, &g.ExpectedSerial, &g.LastUsedAt)
	return g, err
}

// ListGrants returns grants newest-first.
func (db *DB) ListGrants(ctx context.Context) ([]Grant, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+grantCols+` FROM enrollment_grants ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GetGrant returns one grant by ID.
func (db *DB) GetGrant(ctx context.Context, id int64) (Grant, error) {
	return scanGrant(db.sql.QueryRowContext(ctx,
		`SELECT `+grantCols+` FROM enrollment_grants WHERE id = ?`, id))
}

// RevokeGrant marks a grant revoked (idempotent for an already-revoked grant) and
// atomically voids any in-flight issuance binding (ISSUING → FAILED), so revoking
// a grant while a certificate request is in flight cannot later complete.
func (db *DB) RevokeGrant(ctx context.Context, id int64) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE enrollment_grants SET revoked_at = datetime('now')
		 WHERE id = ? AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// No row updated: either the grant is missing, or already revoked. Treat a
		// missing grant as an error; an already-revoked grant still falls through so
		// any lingering ISSUING binding is voided.
		var one int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM enrollment_grants WHERE id = ?`, id).Scan(&one); errors.Is(err, sql.ErrNoRows) {
			return sql.ErrNoRows
		} else if err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE cert_issuance SET state='FAILED', fail_reason='grant revoked', updated_at=datetime('now')
		 WHERE grant_id = ? AND state='ISSUING'`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteExpiredGrants purges grants that expired more than the retention window
// ago (called by the cleanup job). Grants that have an issuance record are kept
// for audit (and because the FK ON DELETE RESTRICT would refuse the delete and,
// critically, keeping the row prevents its rowid from being reused by a later
// grant).
func (db *DB) DeleteExpiredGrants(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).UTC().Format("2006-01-02 15:04:05")
	res, err := db.sql.ExecContext(ctx,
		`DELETE FROM enrollment_grants
		  WHERE expires_at < ?
		    AND id NOT IN (SELECT grant_id FROM cert_issuance)`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// parseTime parses a stored datetime('now') value (UTC, "2006-01-02 15:04:05").
func parseTime(s string) time.Time {
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// GrantIssuanceInfo holds the authoritative grant facts for an issuance lookup,
// resolved from a presented challenge WITHOUT consuming the grant. Single-use at
// issuance is enforced by cert_issuance UNIQUE(grant_id), not here.
type GrantIssuanceInfo struct {
	ID       int64
	Owner    string
	Platform string
}

// LookupGrantForIssuance resolves a presented SCEP challenge (the grant's raw token)
// to the grant's issuance facts if the grant is currently valid (unrevoked and
// unexpired). It does NOT consume the grant. Returns ErrGrantInvalid if no valid
// grant matches — deliberately indistinct (no enumeration oracle).
func (db *DB) LookupGrantForIssuance(ctx context.Context, challenge string) (GrantIssuanceInfo, error) {
	var g GrantIssuanceInfo
	err := db.sql.QueryRowContext(ctx,
		`SELECT id, owner, platform FROM enrollment_grants
		  WHERE token_hash=? AND `+grantValidPredicate,
		HashGrantToken(challenge)).Scan(&g.ID, &g.Owner, &g.Platform)
	if errors.Is(err, sql.ErrNoRows) {
		return GrantIssuanceInfo{}, ErrGrantInvalid
	}
	if err != nil {
		return GrantIssuanceInfo{}, err
	}
	return g, nil
}
