package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// OpenMFAKey keeps the encryption key outside SQLite, in a private directory.
// A missing key with encrypted state is an error, never a request to replace it.
func OpenMFAKey(ctx context.Context, db *sql.DB, dbPath string) ([]byte, error) {
	dir := dbPath + ".mfa"
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("MFA key directory must be a real private directory (0700): %s", dir)
	}
	path := filepath.Join(dir, "key")
	read := func() ([]byte, error) {
		info, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("MFA key must be a regular private file (0600)")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		if len(b) != 32 {
			return nil, errors.New("invalid MFA encryption key length")
		}
		return b, nil
	}
	if b, e := read(); !errors.Is(e, os.ErrNotExist) {
		return b, e
	}
	var n int
	if err = db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM mfa_factors)+(SELECT count(*) FROM mfa_setups)`).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, errors.New("MFA key missing: restore the matching key backup; refusing to replace it")
	}
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "key-pending-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	// Link is atomic and refuses to overwrite a concurrently published key.
	if err = os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return nil, err
	}
	return read()
}
