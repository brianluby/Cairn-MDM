package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrResolutionOrder means a resolution step was attempted before the previous
// step's evidence exists, or after release.
var ErrResolutionOrder = errors.New("quarantine: previous step evidence required")

// QuarantineResolution is the durable evidence for one held issuance.
type QuarantineResolution struct {
	GrantID             int64
	FenceManifest       string
	FencedAt            sql.NullString
	FencedBy            string
	EnumerationManifest string
	EnumeratedAt        sql.NullString
	EnumeratedBy        string
	RejectionManifest   string
	RejectedAt          sql.NullString
	RejectedBy          string
	ReleasedAt          sql.NullString
	ReleasedBy          string
}

// Step reports how far the resolution has progressed: 0 none, 1 fenced,
// 2 enumerated, 3 confirmed rejected, 4 released.
func (q QuarantineResolution) Step() int {
	switch {
	case q.ReleasedAt.Valid:
		return 4
	case q.RejectedAt.Valid:
		return 3
	case q.EnumeratedAt.Valid:
		return 2
	case q.FencedAt.Valid:
		return 1
	default:
		return 0
	}
}

// GetQuarantineResolution returns the evidence row, or an empty one for a grant
// with no progress.
func (db *DB) GetQuarantineResolution(ctx context.Context, grantID int64) (QuarantineResolution, error) {
	q := QuarantineResolution{GrantID: grantID}
	err := db.sql.QueryRowContext(ctx, `SELECT fence_manifest, fenced_at, fenced_by, enumeration_manifest, enumerated_at, enumerated_by,
		 rejection_manifest, rejected_at, rejected_by, released_at, released_by FROM quarantine_resolutions WHERE grant_id=?`, grantID).
		Scan(&q.FenceManifest, &q.FencedAt, &q.FencedBy, &q.EnumerationManifest, &q.EnumeratedAt, &q.EnumeratedBy,
			&q.RejectionManifest, &q.RejectedAt, &q.RejectedBy, &q.ReleasedAt, &q.ReleasedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return q, nil
	}
	return q, err
}

// quarantinedGrant verifies inside tx that the grant is a QUARANTINED issuance.
func quarantinedGrant(ctx context.Context, tx *sql.Tx, grantID int64) error {
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM cert_issuance WHERE grant_id=?`, grantID).Scan(&state); err != nil {
		return fmt.Errorf("quarantine: no issuance for grant %d", grantID)
	}
	if state != string(IssuanceQuarantined) {
		return fmt.Errorf("quarantine: grant %d is %s, not QUARANTINED", grantID, state)
	}
	return nil
}

// RecordFence stores step 1. It resets later steps: a new fence invalidates any
// enumeration or rejection evidence gathered before it.
func (db *DB) RecordFence(ctx context.Context, grantID int64, manifest, actor string) error {
	if manifest == "" || actor == "" {
		return errors.New("quarantine: fence manifest and actor required")
	}
	return db.resolutionTx(ctx, grantID, actor, "quarantine.fence", func(tx *sql.Tx, cur QuarantineResolution) error {
		if cur.ReleasedAt.Valid {
			return ErrResolutionOrder
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO quarantine_resolutions(grant_id, fence_manifest, fenced_at, fenced_by) VALUES(?, ?, datetime('now'), ?)
			 ON CONFLICT(grant_id) DO UPDATE SET fence_manifest=excluded.fence_manifest, fenced_at=datetime('now'), fenced_by=excluded.fenced_by,
			   enumeration_manifest='', enumerated_at=NULL, enumerated_by='', rejection_manifest='', rejected_at=NULL, rejected_by=''`, grantID, manifest, actor)
		return err
	})
}

// RecordEnumeration stores step 2; requires a fence.
func (db *DB) RecordEnumeration(ctx context.Context, grantID int64, manifest, actor string) error {
	if manifest == "" || actor == "" {
		return errors.New("quarantine: enumeration manifest and actor required")
	}
	return db.resolutionTx(ctx, grantID, actor, "quarantine.enumerate", func(tx *sql.Tx, cur QuarantineResolution) error {
		if cur.Step() < 1 || cur.ReleasedAt.Valid {
			return ErrResolutionOrder
		}
		_, err := tx.ExecContext(ctx, `UPDATE quarantine_resolutions SET enumeration_manifest=?, enumerated_at=datetime('now'), enumerated_by=?,
			 rejection_manifest='', rejected_at=NULL, rejected_by='' WHERE grant_id=?`, manifest, actor, grantID)
		return err
	})
}

// RecordRejection stores step 3; requires an enumeration.
func (db *DB) RecordRejection(ctx context.Context, grantID int64, manifest, actor string) error {
	if manifest == "" || actor == "" {
		return errors.New("quarantine: rejection manifest and actor required")
	}
	return db.resolutionTx(ctx, grantID, actor, "quarantine.confirm-rejected", func(tx *sql.Tx, cur QuarantineResolution) error {
		if cur.Step() < 2 || cur.ReleasedAt.Valid {
			return ErrResolutionOrder
		}
		_, err := tx.ExecContext(ctx, `UPDATE quarantine_resolutions SET rejection_manifest=?, rejected_at=datetime('now'), rejected_by=? WHERE grant_id=?`, manifest, actor, grantID)
		return err
	})
}

// RecordRelease stores step 4; requires rejection evidence. The caller has
// already re-validated manifest content; this enforces order and atomicity.
func (db *DB) RecordRelease(ctx context.Context, grantID int64, actor string) error {
	if actor == "" {
		return errors.New("quarantine: actor required")
	}
	return db.resolutionTx(ctx, grantID, actor, "quarantine.release", func(tx *sql.Tx, cur QuarantineResolution) error {
		if cur.Step() != 3 {
			return ErrResolutionOrder
		}
		_, err := tx.ExecContext(ctx, `UPDATE quarantine_resolutions SET released_at=datetime('now'), released_by=? WHERE grant_id=? AND released_at IS NULL`, actor, grantID)
		return err
	})
}

func (db *DB) resolutionTx(ctx context.Context, grantID int64, actor, action string, fn func(*sql.Tx, QuarantineResolution) error) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = quarantinedGrant(ctx, tx, grantID); err != nil {
		return err
	}
	cur := QuarantineResolution{GrantID: grantID}
	err = tx.QueryRowContext(ctx, `SELECT fenced_at, enumerated_at, rejected_at, released_at FROM quarantine_resolutions WHERE grant_id=?`, grantID).
		Scan(&cur.FencedAt, &cur.EnumeratedAt, &cur.RejectedAt, &cur.ReleasedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err = fn(tx, cur); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result) VALUES(?,'console',?,?,'evidence recorded')`, actor, action, fmt.Sprintf("grant:%d", grantID)); err != nil {
		return err
	}
	return tx.Commit()
}

// RadiusRejection is one observed Access-Reject reported by an acceptance point.
type RadiusRejection struct {
	Serial          string
	AcceptancePoint string
	ObservedAt      string
	ReceivedAt      string
	Source          string
}

// InsertRadiusRejection records a server-ingested rejection.
func (db *DB) InsertRadiusRejection(ctx context.Context, r RadiusRejection) error {
	if r.Serial == "" || r.AcceptancePoint == "" || r.ObservedAt == "" {
		return errors.New("radius: serial, acceptance point and observed time required")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO radius_rejections(serial, acceptance_point, observed_at, source) VALUES(?,?,?,?)`, r.Serial, r.AcceptancePoint, r.ObservedAt, r.Source)
	return err
}

// RadiusRejectionsForSerial lists observed rejections for a serial, newest first.
func (db *DB) RadiusRejectionsForSerial(ctx context.Context, serial string) ([]RadiusRejection, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT serial, acceptance_point, observed_at, received_at, source FROM radius_rejections WHERE serial=? ORDER BY observed_at DESC`, serial)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RadiusRejection
	for rows.Next() {
		var r RadiusRejection
		if err := rows.Scan(&r.Serial, &r.AcceptancePoint, &r.ObservedAt, &r.ReceivedAt, &r.Source); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RemoveCertAuthByHash deletes every MDM certificate-authentication association
// for a certificate hash, so an enrollment can no longer authenticate with that
// certificate. Returns the number of associations removed.
func (db *DB) RemoveCertAuthByHash(ctx context.Context, sha256Hex string) (int64, error) {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM cert_auth WHERE sha256=?`, sha256Hex)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
