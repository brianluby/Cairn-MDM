package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// VPNServerRow is a stored OpenVPN server definition. Config is opaque JSON and
// SealedKey is ciphertext; internal/vpn owns both encodings.
type VPNServerRow struct {
	ID        int64
	Name      string
	Slug      string
	Config    []byte
	SealedKey []byte
	CreatedAt string
	UpdatedAt string
}

// ErrVPNServerExists means another server already uses the slug.
var ErrVPNServerExists = errors.New("a VPN server with this identifier already exists")

const vpnServerCols = `id, name, slug, config, tls_key, created_at, updated_at`

func scanVPNServer(row interface{ Scan(...any) error }) (VPNServerRow, error) {
	var r VPNServerRow
	err := row.Scan(&r.ID, &r.Name, &r.Slug, &r.Config, &r.SealedKey, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

// ListVPNServers returns every server, by name.
func (db *DB) ListVPNServers(ctx context.Context) ([]VPNServerRow, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+vpnServerCols+` FROM vpn_servers ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VPNServerRow
	for rows.Next() {
		r, err := scanVPNServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetVPNServer returns one server or sql.ErrNoRows.
func (db *DB) GetVPNServer(ctx context.Context, id int64) (VPNServerRow, error) {
	return scanVPNServer(db.sql.QueryRowContext(ctx, `SELECT `+vpnServerCols+` FROM vpn_servers WHERE id=?`, id))
}

// CreateVPNServer inserts a server and its audit entry together.
func (db *DB) CreateVPNServer(ctx context.Context, r VPNServerRow, actor string) (int64, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO vpn_servers(name, slug, config, tls_key) VALUES(?,?,?,?)`, r.Name, r.Slug, r.Config, r.SealedKey)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrVPNServerExists
		}
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err = vpnServerAudit(ctx, tx, actor, "vpn.server.create", r.Slug); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// UpdateVPNServer replaces a server's name and settings. The slug never changes.
// A nil SealedKey keeps the stored key; an empty non-nil one clears it.
func (db *DB) UpdateVPNServer(ctx context.Context, r VPNServerRow, actor string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var res sql.Result
	if r.SealedKey == nil {
		res, err = tx.ExecContext(ctx, `UPDATE vpn_servers SET name=?, config=?, updated_at=datetime('now') WHERE id=?`, r.Name, r.Config, r.ID)
	} else {
		var key any = r.SealedKey
		if len(r.SealedKey) == 0 {
			key = nil
		}
		res, err = tx.ExecContext(ctx, `UPDATE vpn_servers SET name=?, config=?, tls_key=?, updated_at=datetime('now') WHERE id=?`, r.Name, r.Config, key, r.ID)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	var slug string
	if err = tx.QueryRowContext(ctx, `SELECT slug FROM vpn_servers WHERE id=?`, r.ID).Scan(&slug); err != nil {
		return err
	}
	if err = vpnServerAudit(ctx, tx, actor, "vpn.server.update", slug); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteVPNServer removes a server and records who did it.
func (db *DB) DeleteVPNServer(ctx context.Context, id int64, actor string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var slug string
	if err = tx.QueryRowContext(ctx, `SELECT slug FROM vpn_servers WHERE id=?`, id).Scan(&slug); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM vpn_servers WHERE id=?`, id); err != nil {
		return err
	}
	if err = vpnServerAudit(ctx, tx, actor, "vpn.server.delete", slug); err != nil {
		return err
	}
	return tx.Commit()
}

// vpnServerAudit records a server change in the same transaction as the change,
// so a server definition never changes without a named actor on record.
func vpnServerAudit(ctx context.Context, tx *sql.Tx, actor, action, slug string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result,remote) VALUES(?,'cairn-vpn',?,?,'ok','')`, actor, action, slug)
	return err
}

// CountSealedVPNKeys reports how many servers hold a sealed key, so a missing
// key file is never silently replaced.
func (db *DB) CountSealedVPNKeys(ctx context.Context) (int, error) {
	var n int
	err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM vpn_servers WHERE tls_key IS NOT NULL`).Scan(&n)
	return n, err
}
