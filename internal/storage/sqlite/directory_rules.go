package sqlite

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/directory"
)

type DirectoryProfileRule struct {
	ID        int64
	GroupID   int64
	GroupName string
	Scope     directory.DirectoryScope
}

func (db *DB) ListDirectoryProfileRules(ctx context.Context) ([]DirectoryProfileRule, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT r.id,r.group_id,g.name,r.directory_id,r.object_id,r.kind,r.mode,r.name,r.dn FROM directory_profile_rules r JOIN groups g ON g.id=r.group_id ORDER BY r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirectoryProfileRule
	for rows.Next() {
		var r DirectoryProfileRule
		if err = rows.Scan(&r.ID, &r.GroupID, &r.GroupName, &r.Scope.DirectoryID, &r.Scope.ObjectID, &r.Scope.Kind, &r.Scope.Mode, &r.Scope.Name, &r.Scope.DN); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) SaveDirectoryProfileRule(ctx context.Context, groupID int64, scope directory.DirectoryScope, actor, provider string) error {
	raw, err := hex.DecodeString(scope.ObjectID)
	if err != nil || len(raw) != 16 || scope.DirectoryID == "" || scope.DN == "" || actor == "" {
		return errors.New("resolved scope and actor are required")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO directory_profile_rules(group_id,directory_id,object_id,kind,mode,name,dn) VALUES(?,?,?,?,?,?,?) ON CONFLICT(group_id,directory_id,object_id,kind,mode) DO UPDATE SET name=excluded.name,dn=excluded.dn`, groupID, scope.DirectoryID, strings.ToLower(scope.ObjectID), scope.Kind, scope.Mode, scope.Name, scope.DN)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result) VALUES(?,?,'directory-rule.save',?,'preview only')`, actor, provider, fmt.Sprintf("group:%d/%s/%s/%s/%s", groupID, scope.DirectoryID, scope.ObjectID, scope.Kind, scope.Mode)); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) DeleteDirectoryProfileRule(ctx context.Context, id int64, actor, provider string) error {
	if actor == "" {
		return errors.New("actor required")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM directory_profile_rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result) VALUES(?,?,'directory-rule.delete',?,'preview only')`, actor, provider, fmt.Sprint(id)); err != nil {
		return err
	}
	return tx.Commit()
}
