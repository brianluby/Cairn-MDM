package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/alexedwards/argon2id"
)

// ErrSetupClosed means a local account already exists; first-run setup is over.
var ErrSetupClosed = errors.New("setup: closed")

// ErrSetupToken means the presented setup token did not match the host file.
var ErrSetupToken = errors.New("setup: token mismatch")

// ErrSetupPassword means the chosen administrator password is too short.
var ErrSetupPassword = errors.New("setup: password must be at least 12 characters")

// SetupGate controls browser first-run setup. Setup is open only while the
// database has no local account. Completing it requires a token that lives in a
// 0600 file beside the database, so only someone with host access can claim the
// first administrator; nothing is accepted from an anonymous browser alone.
type SetupGate struct {
	db   *sql.DB
	path string
}

// NewSetupGate returns a gate whose token file is <storagePath>.setup-token.
func NewSetupGate(db *sql.DB, storagePath string) *SetupGate {
	return &SetupGate{db: db, path: storagePath + ".setup-token"}
}

// TokenPath is where the operator reads the setup token on the host.
func (g *SetupGate) TokenPath() string { return g.path }

// Open reports whether first-run setup is still available.
func (g *SetupGate) Open(ctx context.Context) (bool, error) {
	var n int
	if err := g.db.QueryRowContext(ctx, `SELECT count(*) FROM app_users`).Scan(&n); err != nil {
		return false, err
	}
	return n == 0, nil
}

// Prepare is called at service start. While setup is open it makes sure a token
// file exists (keeping an existing one so a restart does not invalidate the
// token the operator already copied); once setup is closed it removes any stale
// file. Returns whether setup is open.
func (g *SetupGate) Prepare(ctx context.Context) (bool, error) {
	open, err := g.Open(ctx)
	if err != nil {
		return false, err
	}
	if !open {
		if err := os.Remove(g.path); err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("setup: remove stale token file: %w", err)
		}
		return false, nil
	}
	if existing, err := os.ReadFile(g.path); err == nil && len(strings.TrimSpace(string(existing))) == 64 {
		return true, nil
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false, err
	}
	f, err := os.OpenFile(g.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return false, fmt.Errorf("setup: write token file: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(hex.EncodeToString(b[:]) + "\n"); err != nil {
		return false, err
	}
	return true, f.Chmod(0o600)
}

// Complete verifies the token and creates the first local administrator in one
// transaction that re-checks that no account exists. The token file is removed on
// success; a mismatch leaves it in place. Callers should throttle attempts.
func (g *SetupGate) Complete(ctx context.Context, token, username, password string) error {
	open, err := g.Open(ctx)
	if err != nil {
		return err
	}
	if !open {
		return ErrSetupClosed
	}
	stored, err := os.ReadFile(g.path)
	if err != nil {
		return ErrSetupToken
	}
	want := strings.TrimSpace(string(stored))
	got := strings.TrimSpace(token)
	if len(want) != 64 || len(got) != len(want) || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return ErrSetupToken
	}
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 64 || strings.ContainsAny(username, " \t\r\n") {
		return errors.New("setup: choose a username without spaces (at most 64 characters)")
	}
	if len(password) < 12 {
		return ErrSetupPassword
	}
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return err
	}
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM app_users`).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return ErrSetupClosed
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO app_users (username, password_hash, role, display_name, subject_id) VALUES (?, ?, 'admin', '', ?)`, username, hash, randomToken()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result) VALUES(?,'local','setup.complete','first administrator','host setup token')`, username); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if err := os.Remove(g.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("setup: administrator created but the token file could not be removed: %w", err)
	}
	return nil
}
