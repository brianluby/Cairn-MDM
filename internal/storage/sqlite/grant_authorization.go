package sqlite

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/directory"
)

// EnrollmentPreview is a server-owned confirmation, not trusted form fields.
// Profile assignment remains a separate operation until device ownership exists.
type EnrollmentPreview struct {
	Owner    directory.DirectoryIdentity
	Label    string
	Platform string
	Hours    int
	// GroupID is an optional explicit Cairn device group the device should join
	// after it is bound to this owner (0 = none). Validated again at creation.
	GroupID   int64
	GroupName string
}

func (db *DB) SaveEnrollmentPreview(ctx context.Context, rawSession string, p EnrollmentPreview) (string, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	raw, hash := NewGrantToken()
	_, err = db.sql.ExecContext(ctx, `INSERT INTO enrollment_previews(token_hash,session_hash,payload,expires_at) VALUES(?,?,?,?)`, hash, HashGrantToken(rawSession), string(body), time.Now().Add(5*time.Minute).Unix())
	return raw, err
}
func (db *DB) GetEnrollmentPreview(ctx context.Context, rawSession, token string) (EnrollmentPreview, error) {
	var body string
	var p EnrollmentPreview
	err := db.sql.QueryRowContext(ctx, `SELECT payload FROM enrollment_previews WHERE token_hash=? AND session_hash=? AND expires_at>?`, HashGrantToken(token), HashGrantToken(rawSession), time.Now().Unix()).Scan(&body)
	if err != nil {
		return p, ErrGrantInvalid
	}
	err = json.Unmarshal([]byte(body), &p)
	return p, err
}

// CreateAuthorizedGrant checks the actor's session, role, current factor and fresh
// MFA inside the same write transaction as preview consumption, grant and audit.
// Directory reads are deliberately external: the caller revalidates the pinned
// owner first, and issuance must revalidate again. This is not an AD transaction.
func (db *DB) CreateAuthorizedGrant(ctx context.Context, rawSession, previewToken, grantHash string, owner directory.DirectoryIdentity) (id int64, err error) {
	rawGUID, e := hex.DecodeString(owner.ObjectID)
	if e != nil || len(rawGUID) != 16 || owner.DirectoryID == "" || owner.UPN == "" {
		return 0, ErrGrantInvalid
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	var payload string
	err = tx.QueryRowContext(ctx, `DELETE FROM enrollment_previews WHERE token_hash=? AND session_hash=? AND expires_at>? RETURNING payload`, HashGrantToken(previewToken), HashGrantToken(rawSession), time.Now().Unix()).Scan(&payload)
	if err != nil {
		return 0, ErrGrantInvalid
	}
	var p EnrollmentPreview
	if err = json.Unmarshal([]byte(payload), &p); err != nil {
		return
	}
	if p.Owner.DirectoryID != owner.DirectoryID || p.Owner.ObjectID != owner.ObjectID || p.Owner.UPN != owner.UPN || p.Hours < 1 || p.Hours > 24 || (p.Platform != "macos" && p.Platform != "ios") {
		return 0, ErrGrantInvalid
	}
	var actor, provider, username string
	var verified int64
	now := time.Now().Unix()
	err = tx.QueryRowContext(ctx, `SELECT s.auth_subject,s.provider,s.username,s.mfa_verified_at FROM app_sessions s JOIN mfa_factors f ON f.principal=s.auth_subject
 WHERE s.token=? AND s.role='admin' AND unixepoch(s.expires_at)>? AND s.mfa_verified_at>? AND s.mfa_verified_at<=?
 AND (s.provider='ldap' OR (s.provider='local' AND EXISTS(SELECT 1 FROM app_users u WHERE u.username=s.username AND u.role='admin' AND 'local:'||u.subject_id=s.auth_subject)))`, HashGrantToken(rawSession), now, now-300, now).Scan(&actor, &provider, &username, &verified)
	if err != nil {
		return 0, ErrGrantInvalid
	}
	encoded, err := json.Marshal(owner)
	if err != nil {
		return 0, err
	}
	var assignGroup any // NULL unless the preview named an existing group
	if p.GroupID != 0 {
		var one int
		if err = tx.QueryRowContext(ctx, `SELECT 1 FROM groups WHERE id=?`, p.GroupID).Scan(&one); err != nil {
			return 0, ErrGrantInvalid
		}
		assignGroup = p.GroupID
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO enrollment_grants(token_hash,label,platform,owner,created_by,expires_at,max_uses,expected_serial,owner_identity,actor_subject,actor_provider,mfa_verified_at,assign_group_id) VALUES(?,?,?,?,?,?,1,'',?,?,?,?,?)`, grantHash, p.Label, p.Platform, owner.UPN, username, time.Now().Add(time.Duration(p.Hours)*time.Hour).UTC().Format("2006-01-02 15:04:05"), string(encoded), actor, provider, verified, assignGroup)
	if err != nil {
		return 0, err
	}
	id, err = res.LastInsertId()
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result) VALUES(?,?,'enrollment.authorize',?,?)`, username, provider, fmt.Sprintf("grant:%d", id), fmt.Sprintf("admin-assisted; actor=%s; owner=%s/%s; group=%d", actor, owner.DirectoryID, owner.ObjectID, p.GroupID))
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}
