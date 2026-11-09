package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/directory"
)

// DeviceOwner is the verified directory owner bound to an enrolled device. It is
// derived from the certificate the device authenticates with, which Cairn issued
// for exactly one administrator-authorized grant. It is not asserted by a form.
type DeviceOwner struct {
	DeviceID     string
	GrantID      int64
	Owner        directory.DirectoryIdentity
	ActorSubject string
	BoundAt      string
	UpdatedAt    string
}

// DirectoryMembership is one device group membership produced by a directory
// rule, with the rule facts needed to explain it on the console.
type DirectoryMembership struct {
	GroupID     int64
	GroupName   string
	RuleID      int64
	Scope       directory.DirectoryScope
	EvaluatedAt string
}

// DirectoryEvaluation records the last attempt to apply directory rules to a
// device. Status "unavailable" means the directory answer was unknown and the
// previous memberships were kept.
type DirectoryEvaluation struct {
	DeviceID    string
	AttemptedAt string
	EvaluatedAt sql.NullString
	Status      string
	Detail      string
}

// ErrNoOwner means the device has not authenticated with a certificate that
// Cairn issued for an owner-authorized grant (legacy, open or external-SCEP
// enrollments have no verified owner).
var ErrNoOwner = errors.New("device has no verified owner")

// BindDeviceOwner derives the device's owner from the certificate it authenticated
// with and records it. The newest issued certificate the device has presented wins,
// so a device re-enrolled under a later grant follows that grant's owner. When the
// grant named an explicit Cairn group, the device joins it as manual membership.
// Binding, group join and audit commit together. Returns ErrNoOwner when the chain
// does not resolve; nothing is written in that case.
func (db *DB) BindDeviceOwner(ctx context.Context, deviceID string) (DeviceOwner, error) {
	if deviceID == "" {
		return DeviceOwner{}, ErrNoOwner
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return DeviceOwner{}, err
	}
	defer tx.Rollback()
	var (
		grantID    int64
		ownerJSON  string
		actor      string
		assignToID sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `SELECT g.id, g.owner_identity, g.actor_subject, g.assign_group_id
		 FROM cert_auth ca
		 JOIN cert_issuance i ON i.leaf_sha256 = ca.sha256 AND i.state = 'ISSUED'
		 JOIN enrollment_grants g ON g.id = i.grant_id
		 WHERE ca.enrollment_id = ? AND g.owner_identity <> '' AND g.actor_subject <> ''
		 ORDER BY ca.created_at DESC, i.updated_at DESC, i.id DESC LIMIT 1`, deviceID).Scan(&grantID, &ownerJSON, &actor, &assignToID)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceOwner{}, ErrNoOwner
	}
	if err != nil {
		return DeviceOwner{}, err
	}
	var owner directory.DirectoryIdentity
	if err = json.Unmarshal([]byte(ownerJSON), &owner); err != nil || owner.DirectoryID == "" || owner.ObjectID == "" || owner.UPN == "" {
		return DeviceOwner{}, ErrNoOwner
	}
	var previousGrant int64
	err = tx.QueryRowContext(ctx, `SELECT grant_id FROM device_owners WHERE device_id=?`, deviceID).Scan(&previousGrant)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err = tx.ExecContext(ctx, `INSERT INTO device_owners(device_id,grant_id,directory_id,object_id,upn,account_name,actor_subject) VALUES(?,?,?,?,?,?,?)`,
			deviceID, grantID, owner.DirectoryID, owner.ObjectID, owner.UPN, owner.AccountName, actor); err != nil {
			return DeviceOwner{}, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result) VALUES('','system','device.owner-bind',?,?)`,
			"device:"+deviceID, fmt.Sprintf("grant:%d owner=%s/%s", grantID, owner.DirectoryID, owner.ObjectID)); err != nil {
			return DeviceOwner{}, err
		}
	case err != nil:
		return DeviceOwner{}, err
	case previousGrant != grantID:
		if _, err = tx.ExecContext(ctx, `UPDATE device_owners SET grant_id=?,directory_id=?,object_id=?,upn=?,account_name=?,actor_subject=?,updated_at=datetime('now') WHERE device_id=?`,
			grantID, owner.DirectoryID, owner.ObjectID, owner.UPN, owner.AccountName, actor, deviceID); err != nil {
			return DeviceOwner{}, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result) VALUES('','system','device.owner-change',?,?)`,
			"device:"+deviceID, fmt.Sprintf("grant:%d->%d owner=%s/%s", previousGrant, grantID, owner.DirectoryID, owner.ObjectID)); err != nil {
			return DeviceOwner{}, err
		}
	}
	if assignToID.Valid {
		res, e := tx.ExecContext(ctx, `INSERT INTO group_devices(group_id,device_id) SELECT id, ? FROM groups WHERE id=? ON CONFLICT DO NOTHING`, deviceID, assignToID.Int64)
		if e != nil {
			return DeviceOwner{}, e
		}
		if n, _ := res.RowsAffected(); n == 1 {
			if _, e = tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result) VALUES('','system','group.device-add',?,?)`,
				fmt.Sprintf("group:%d", assignToID.Int64), fmt.Sprintf("device:%s from grant:%d", deviceID, grantID)); e != nil {
				return DeviceOwner{}, e
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return DeviceOwner{}, err
	}
	return db.GetDeviceOwner(ctx, deviceID)
}

// GetDeviceOwner returns the recorded owner, or ErrNoOwner.
func (db *DB) GetDeviceOwner(ctx context.Context, deviceID string) (DeviceOwner, error) {
	var o DeviceOwner
	err := db.sql.QueryRowContext(ctx, `SELECT device_id,grant_id,directory_id,object_id,upn,account_name,actor_subject,bound_at,updated_at FROM device_owners WHERE device_id=?`, deviceID).
		Scan(&o.DeviceID, &o.GrantID, &o.Owner.DirectoryID, &o.Owner.ObjectID, &o.Owner.UPN, &o.Owner.AccountName, &o.ActorSubject, &o.BoundAt, &o.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceOwner{}, ErrNoOwner
	}
	return o, err
}

// OwnedPushableDeviceIDs lists enrolled devices with a recorded owner and a push
// token: the set a directory refresh re-evaluates.
func (db *DB) OwnedPushableDeviceIDs(ctx context.Context) ([]string, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT d.id FROM devices d JOIN device_owners o ON o.device_id = d.id
		 WHERE d.checked_out_at IS NULL AND d.token_updated_at IS NOT NULL ORDER BY d.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ReplaceDirectoryMemberships makes the device's directory-derived memberships
// exactly the groups of the matched rules, records a successful evaluation and
// returns the group IDs that were added. Rules that no longer exist are ignored.
// Manual group_devices rows are untouched. Installed profiles are never removed
// here; a membership that disappears only narrows the desired set.
func (db *DB) ReplaceDirectoryMemberships(ctx context.Context, deviceID string, matchedRuleIDs []int64) (added []int64, err error) {
	if deviceID == "" {
		return nil, errors.New("device id required")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Build the matched-rule predicate once; an empty match set removes every
	// directory membership of the device.
	predicate := "0"
	var args []any
	if len(matchedRuleIDs) > 0 {
		predicate = "r.id IN (?" + strings.Repeat(",?", len(matchedRuleIDs)-1) + ")"
		for _, id := range matchedRuleIDs {
			args = append(args, id)
		}
	}
	deleteArgs := append([]any{deviceID}, args...)
	if _, err = tx.ExecContext(ctx, `DELETE FROM directory_memberships WHERE device_id=? AND rule_id NOT IN (SELECT r.id FROM directory_profile_rules r WHERE `+predicate+`)`, deleteArgs...); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.id, r.group_id FROM directory_profile_rules r WHERE `+predicate+`
		 AND NOT EXISTS (SELECT 1 FROM directory_memberships dm WHERE dm.device_id=? AND dm.rule_id=r.id)`, append(args, deviceID)...)
	if err != nil {
		return nil, err
	}
	type pair struct{ rule, group int64 }
	var fresh []pair
	for rows.Next() {
		var p pair
		if err = rows.Scan(&p.rule, &p.group); err != nil {
			rows.Close()
			return nil, err
		}
		fresh = append(fresh, p)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for _, p := range fresh {
		if _, err = tx.ExecContext(ctx, `INSERT INTO directory_memberships(device_id,group_id,rule_id) VALUES(?,?,?) ON CONFLICT DO NOTHING`, deviceID, p.group, p.rule); err != nil {
			return nil, err
		}
		added = append(added, p.group)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE directory_memberships SET evaluated_at=datetime('now') WHERE device_id=?`, deviceID); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO directory_evaluations(device_id,attempted_at,evaluated_at,status,detail) VALUES(?,datetime('now'),datetime('now'),'ok','')
		 ON CONFLICT(device_id) DO UPDATE SET attempted_at=datetime('now'), evaluated_at=datetime('now'), status='ok', detail=''`, deviceID); err != nil {
		return nil, err
	}
	return added, tx.Commit()
}

// RecordDirectoryUnavailable notes a failed evaluation without changing any
// membership: an unknown directory answer is not an empty one.
func (db *DB) RecordDirectoryUnavailable(ctx context.Context, deviceID, detail string) error {
	if len(detail) > 500 {
		detail = detail[:500]
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO directory_evaluations(device_id,attempted_at,evaluated_at,status,detail) VALUES(?,datetime('now'),NULL,'unavailable',?)
		 ON CONFLICT(device_id) DO UPDATE SET attempted_at=datetime('now'), status='unavailable', detail=excluded.detail`, deviceID, detail)
	return err
}

// DeviceDirectoryMemberships lists the directory-derived memberships of a device
// with the rule that produced each.
func (db *DB) DeviceDirectoryMemberships(ctx context.Context, deviceID string) ([]DirectoryMembership, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT dm.group_id, g.name, r.id, r.directory_id, r.object_id, r.kind, r.mode, r.name, r.dn, dm.evaluated_at
		 FROM directory_memberships dm JOIN groups g ON g.id = dm.group_id JOIN directory_profile_rules r ON r.id = dm.rule_id
		 WHERE dm.device_id=? ORDER BY g.name COLLATE NOCASE, r.id`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryMembership
	for rows.Next() {
		var m DirectoryMembership
		if err := rows.Scan(&m.GroupID, &m.GroupName, &m.RuleID, &m.Scope.DirectoryID, &m.Scope.ObjectID, &m.Scope.Kind, &m.Scope.Mode, &m.Scope.Name, &m.Scope.DN, &m.EvaluatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeviceDirectoryEvaluation returns the last evaluation record, or sql.ErrNoRows
// when rules have never been evaluated for the device.
func (db *DB) DeviceDirectoryEvaluation(ctx context.Context, deviceID string) (DirectoryEvaluation, error) {
	var e DirectoryEvaluation
	err := db.sql.QueryRowContext(ctx, `SELECT device_id, attempted_at, evaluated_at, status, detail FROM directory_evaluations WHERE device_id=?`, deviceID).
		Scan(&e.DeviceID, &e.AttemptedAt, &e.EvaluatedAt, &e.Status, &e.Detail)
	return e, err
}

// GroupDirectoryDevices lists devices that belong to a group through directory
// rules (distinct from manual members).
func (db *DB) GroupDirectoryDevices(ctx context.Context, groupID int64) ([]Device, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT d.id, d.udid, d.serial, d.name, d.model, d.product, d.os_version, d.build_version,
		        d.enrolled_at, d.last_seen, d.token_updated_at, d.checked_out_at
		 FROM devices d WHERE d.id IN (SELECT device_id FROM directory_memberships WHERE group_id = ?)
		 ORDER BY d.name COLLATE NOCASE`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UDID, &d.Serial, &d.Name, &d.Model, &d.Product,
			&d.OSVersion, &d.BuildVersion, &d.EnrolledAt, &d.LastSeen, &d.TokenUpdatedAt, &d.CheckedOutAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
