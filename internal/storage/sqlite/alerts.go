package sqlite

import (
	"context"
	"database/sql"
)

// AlertState is one remembered alert condition.
type AlertState struct {
	Key        string
	Active     bool
	Message    string
	ChangedAt  string
	NotifiedAt sql.NullString
}

// ListAlertStates returns every remembered condition, active first.
func (db *DB) ListAlertStates(ctx context.Context) ([]AlertState, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT key, active, message, changed_at, notified_at FROM alert_state ORDER BY active DESC, key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertState
	for rows.Next() {
		var s AlertState
		var active int
		if err := rows.Scan(&s.Key, &active, &s.Message, &s.ChangedAt, &s.NotifiedAt); err != nil {
			return nil, err
		}
		s.Active = active == 1
		out = append(out, s)
	}
	return out, rows.Err()
}

// SetAlertState records a condition's current activity and message. When
// notified is true the notification time is stamped now; otherwise it is kept,
// so a failed delivery is retried on the next check.
func (db *DB) SetAlertState(ctx context.Context, key string, active bool, message string, notified bool) error {
	a := 0
	if active {
		a = 1
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO alert_state(key, active, message, changed_at, notified_at)
		 VALUES(?, ?, ?, datetime('now'), CASE WHEN ? THEN datetime('now') ELSE NULL END)
		 ON CONFLICT(key) DO UPDATE SET
		   changed_at = CASE WHEN alert_state.active <> excluded.active THEN datetime('now') ELSE alert_state.changed_at END,
		   active = excluded.active,
		   message = excluded.message,
		   notified_at = CASE WHEN ? THEN datetime('now') ELSE alert_state.notified_at END`,
		key, a, message, notified, notified)
	return err
}
