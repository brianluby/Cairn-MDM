package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// SCEPChallenge is a one-time challenge for a request an external CA will
// check with Cairn. The challenge itself is never stored.
type SCEPChallenge struct {
	ChallengeSHA256 string
	Purpose         string // "enroll" or "renew"
	DeviceID        string // set for a renewal
	CommonName      string // exact certificate name the request must carry, when known
	CNSuffix        string // otherwise the ending the name must have
	Note            string // who it was made for, for the record
}

// CreateSCEPChallenge records a challenge that works until expires.
func (db *DB) CreateSCEPChallenge(ctx context.Context, c SCEPChallenge, expires time.Time) error {
	if c.ChallengeSHA256 == "" || (c.Purpose != "enroll" && c.Purpose != "renew") {
		return errors.New("a SCEP challenge needs a hash and a purpose")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO scep_challenges(challenge_sha256, purpose, device_id, common_name, cn_suffix, note, expires_at)
		VALUES(?,?,?,?,?,?,?)`, c.ChallengeSHA256, c.Purpose, c.DeviceID, c.CommonName, c.CNSuffix, c.Note, expires.UTC().Format(time.RFC3339))
	return err
}

// UseSCEPChallenge answers the CA's question: may a request for commonName,
// made with the key keyID, use this challenge? The first request that fits
// spends the challenge for that name and key. The same name and key may ask
// again, because a CA can evaluate one request more than once. why says what
// was wrong when the answer is no.
func (db *DB) UseSCEPChallenge(ctx context.Context, challengeSHA256, commonName, keyID string, now time.Time) (ok bool, why string, err error) {
	if commonName == "" || keyID == "" {
		return false, "the CA sent no certificate name or key identifier", nil
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, "", err
	}
	defer tx.Rollback()
	var id int64
	var state, wantCN, suffix, usedCN, usedKey, expires string
	err = tx.QueryRowContext(ctx, `SELECT id, state, common_name, cn_suffix, used_cn, used_key_id, expires_at FROM scep_challenges WHERE challenge_sha256=?`,
		challengeSHA256).Scan(&id, &state, &wantCN, &suffix, &usedCN, &usedKey, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "unknown challenge", nil
	}
	if err != nil {
		return false, "", err
	}
	switch state {
	case "USED":
		if usedCN == commonName && usedKey == keyID {
			return true, "", nil
		}
		return false, "challenge already used for another name or key", nil
	case "OPEN":
	default:
		return false, "challenge is closed", nil
	}
	if expires <= now.UTC().Format(time.RFC3339) {
		return false, "challenge expired", nil
	}
	switch {
	case wantCN != "" && commonName != wantCN:
		return false, "request is for another certificate name", nil
	case wantCN == "" && suffix != "" && (!strings.HasSuffix(commonName, "."+suffix) || len(commonName) == len(suffix)+1):
		return false, "certificate name does not end as this server's names do", nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE scep_challenges SET state='USED', used_cn=?, used_key_id=?, used_at=datetime('now') WHERE id=? AND state='OPEN'`,
		commonName, keyID, id); err != nil {
		return false, "", err
	}
	return true, "", tx.Commit()
}

// RenewalKeyIssued reports whether a renewal challenge made for the device
// since the given time was used by the key keyID.
func (db *DB) RenewalKeyIssued(ctx context.Context, deviceID, keyID string, since time.Time) (bool, error) {
	var n int
	err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM scep_challenges WHERE purpose='renew' AND device_id=? AND state='USED' AND used_key_id=? AND created_at >= ?`,
		deviceID, keyID, since.UTC().Format("2006-01-02 15:04:05")).Scan(&n)
	return n > 0, err
}

// CloseSCEPChallenges closes a device's unused renewal challenges, for a
// renewal that ended or a device that left.
func (db *DB) CloseSCEPChallenges(ctx context.Context, deviceID string) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE scep_challenges SET state='CLOSED' WHERE device_id=? AND state='OPEN'`, deviceID)
	return err
}

// PruneSCEPChallenges closes challenges past their expiry and deletes rows
// older than keep, which no renewal can still refer to.
func (db *DB) PruneSCEPChallenges(ctx context.Context, now time.Time, keep time.Duration) error {
	if _, err := db.sql.ExecContext(ctx, `UPDATE scep_challenges SET state='CLOSED' WHERE state='OPEN' AND expires_at <= ?`, now.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	_, err := db.sql.ExecContext(ctx, `DELETE FROM scep_challenges WHERE created_at < ?`, now.Add(-keep).UTC().Format("2006-01-02 15:04:05"))
	return err
}
