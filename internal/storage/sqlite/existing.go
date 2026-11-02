package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// OpenExisting is for operational CLI writes, which must never create a fleet
// database or migrate a running server's schema as a side effect.
func OpenExisting(ctx context.Context, path string) (*DB, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("existing database required: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("database must be a regular file")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: absolute}
	q := url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(5000)", "foreign_keys(ON)"}}
	u.RawQuery = q.Encode()
	handle, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	handle.SetMaxOpenConns(1)
	db := &DB{sql: handle}
	if err = db.checkSchema(ctx); err != nil {
		handle.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) checkSchema(ctx context.Context) error {
	entries, err := schemaFS.ReadDir("schema")
	if err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			expected[strings.TrimSuffix(e.Name(), ".sql")] = true
		}
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("database schema unavailable; use the matching server release: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var version string
		if err = rows.Scan(&version); err != nil {
			return err
		}
		if !expected[version] {
			return fmt.Errorf("database has unsupported migration %s; use the matching server release", version)
		}
		delete(expected, version)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(expected) != 0 {
		return fmt.Errorf("database needs %d migrations; upgrade and back up the server explicitly before using this command", len(expected))
	}
	return nil
}
