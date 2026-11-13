package sqlite

import (
	"context"
	"database/sql"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
)

// CommandEntry is a row of a device's command history.
type CommandEntry struct {
	CommandUUID          string
	DeviceID             string
	RequestType          string
	Status               string
	Error                string
	SentAt               string
	ResultAt             sql.NullString
	NotificationStatus   string
	NotificationAttempts int
	NotificationError    string
}

// Pending reports whether the device has not yet answered.
func (c CommandEntry) Pending() bool {
	return c.Status == "Queued" || c.Status == "Sent" || c.Status == "NotNow"
}

// compile-time check that DB records command history.
var _ mdmcore.CommandRecorder = (*DB)(nil)

// CommandSent records a command at enqueue time (one row per target device).
func (db *DB) CommandSent(ctx context.Context, deviceID, commandUUID, requestType string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO command_history (command_uuid, device_id, request_type)
		 VALUES (?, ?, ?)
		 ON CONFLICT (command_uuid, device_id) DO NOTHING`,
		commandUUID, deviceID, requestType)
	return err
}

// CommandResult resolves a history row when the device reports at check-in.
// Results for commands not sent through Cairn (unknown UUIDs) are ignored.
// InstallProfile results also resolve the matching profile_deploys row, which
// is how the reconciler learns a deploy landed (or failed) without polling.
func (db *DB) CommandResult(ctx context.Context, deviceID, commandUUID, status, errDesc string) error {
	return recordCommandResult(ctx, db.sql, deviceID, commandUUID, status, errDesc)
}

func recordCommandResult(ctx context.Context, executor sqlExecutor, deviceID, commandUUID, status, errDesc string) error {
	_, err := executor.ExecContext(ctx,
		`UPDATE command_history
		 SET status = ?, error = ?, result_at = datetime('now')
		 WHERE command_uuid = ? AND device_id = ? AND status IN ('Sent','Queued','NotNow')`,
		status, errDesc, commandUUID, deviceID)
	if err != nil {
		return err
	}
	var deployStatus string
	switch status {
	case "Acknowledged":
		deployStatus = "installed"
	case "Error", "CommandFormatError":
		deployStatus = "failed"
	default: // NotNow etc. — still in flight
		return nil
	}
	// profile_deploys is keyed (device_id, profile_id) with command_uuid stored;
	// an InstallProfile UUID is per-device, so command_uuid alone resolves the
	// right row. Scope by device_id too as a belt-and-suspenders guard.
	if _, err = executor.ExecContext(ctx,
		`UPDATE profile_deploys SET status = ?, updated_at = datetime('now')
		 WHERE command_uuid = ? AND device_id = ? AND status = 'sent'`, deployStatus, commandUUID, deviceID); err != nil {
		return err
	}
	if err = renewalCommandResult(ctx, executor, deviceID, commandUUID, deployStatus, errDesc); err != nil {
		return err
	}
	return vpnCommandResult(ctx, executor, deviceID, commandUUID, deployStatus)
}

// ListCommands returns the most recent history for a device.
func (db *DB) ListCommands(ctx context.Context, deviceID string, limit int) ([]CommandEntry, error) {
	if limit <= 0 {
		limit = 25
	}
	rows, err := db.sql.QueryContext(ctx,
		`SELECT h.command_uuid,h.device_id,h.request_type,h.status,h.error,h.sent_at,h.result_at,COALESCE(o.state,''),COALESCE(o.attempts,0),COALESCE(o.last_error,'')
 FROM command_history h LEFT JOIN push_outbox o ON o.command_uuid=h.command_uuid AND o.device_id=h.device_id WHERE h.device_id=? ORDER BY h.sent_at DESC,h.command_uuid LIMIT ?`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CommandEntry
	for rows.Next() {
		var c CommandEntry
		if err := rows.Scan(&c.CommandUUID, &c.DeviceID, &c.RequestType, &c.Status,
			&c.Error, &c.SentAt, &c.ResultAt, &c.NotificationStatus, &c.NotificationAttempts, &c.NotificationError); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
