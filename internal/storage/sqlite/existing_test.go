package sqlite

import (
	"context"
	"database/sql"
	"os"
	"testing"
)

func TestOpenExistingNeverCreatesOrMigrates(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/fleet.db"
	if db, err := OpenExisting(ctx, path); err == nil {
		db.Close()
		t.Fatal("created missing database")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing database was created")
	}
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.sql.Exec(`DELETE FROM schema_migrations WHERE version='022_apns_changes'`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if handle, err := OpenExisting(ctx, path); err == nil {
		handle.Close()
		t.Fatal("accepted missing migration")
	}
	// Open directly to prove the rejected operational command did not migrate.
	handle, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = handle.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version='022_apns_changes'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("operational open migrated schema")
	}
	_, err = handle.Exec(`INSERT INTO schema_migrations(version) VALUES('022_apns_changes')`)
	if err != nil {
		t.Fatal(err)
	}
	handle.Close()
	db, err = OpenExisting(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.sql.Exec(`INSERT INTO schema_migrations(version) VALUES('999_future')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if handle, err := OpenExisting(ctx, path); err == nil {
		handle.Close()
		t.Fatal("accepted newer schema")
	}
}
