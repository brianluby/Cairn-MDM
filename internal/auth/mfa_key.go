package auth

import (
	"context"
	"database/sql"

	"github.com/nickpdawson/cairn-mdm/internal/keyfile"
)

// OpenMFAKey keeps the encryption key outside SQLite, in a private directory.
// A missing key with encrypted state is an error, never a request to replace it.
func OpenMFAKey(ctx context.Context, db *sql.DB, dbPath string) ([]byte, error) {
	return keyfile.Open(dbPath+".mfa", "MFA", func() (bool, error) {
		var n int
		err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM mfa_factors)+(SELECT count(*) FROM mfa_setups)`).Scan(&n)
		return n > 0, err
	})
}
