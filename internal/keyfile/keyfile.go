// Package keyfile keeps 32-byte data-encryption keys in private files next to
// the database, outside SQLite, so a copy of the database alone cannot decrypt
// what it holds.
package keyfile

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Open returns the key stored at dir/key, creating directory and key on first
// use. label names the key in errors ("MFA", "VPN"). inUse reports whether data
// sealed under the key already exists: a missing key is then an error, never a
// reason to mint a new one.
func Open(dir, label string, inUse func() (bool, error)) ([]byte, error) {
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s key directory must be a real private directory (0700): %s", label, dir)
	}
	path := filepath.Join(dir, "key")
	read := func() ([]byte, error) {
		info, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("%s key must be a regular private file (0600)", label)
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("invalid %s encryption key length", label)
		}
		return b, nil
	}
	if b, e := read(); !errors.Is(e, os.ErrNotExist) {
		return b, e
	}
	used, err := inUse()
	if err != nil {
		return nil, err
	}
	if used {
		return nil, fmt.Errorf("%s key missing: restore the matching key backup; refusing to replace it", label)
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
