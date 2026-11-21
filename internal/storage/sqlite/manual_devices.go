package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/directory"
)

// ManualDevice is a device outside MDM that an administrator installs a
// certificate profile on by hand.
type ManualDevice struct {
	ID        int64
	Name      string
	Kind      string
	Owner     directory.DirectoryIdentity // the account its certificate names
	CreatedBy string
	CreatedAt string
	RemovedAt sql.NullString
}

// Kinds of manual device, for display. Anything else is stored as "other".
var manualDeviceKinds = map[string]bool{"appletv": true, "homepod": true, "visionpro": true, "watch": true, "other": true}

const manualDevicePrefix = "manual:"

// ManualDeviceID is the device_id a manual device's certificates are kept
// under. No enrollment ID contains a colon, so the two never collide.
func ManualDeviceID(id int64) string { return manualDevicePrefix + strconv.FormatInt(id, 10) }

// ParseManualDeviceID reverses ManualDeviceID.
func ParseManualDeviceID(deviceID string) (int64, bool) {
	rest, ok := strings.CutPrefix(deviceID, manualDevicePrefix)
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(rest, 10, 64)
	return id, err == nil && id > 0
}

// DeviceID is the device_id this device's certificates are kept under.
func (d ManualDevice) DeviceID() string { return ManualDeviceID(d.ID) }

// ErrManualDeviceInUse refuses to remove a device that still holds a certificate.
var ErrManualDeviceInUse = errors.New("this device still holds a certificate; revoke it first")

const manualDeviceCols = `id, name, kind, directory_id, object_id, upn, account_name, created_by, created_at, removed_at`

func scanManualDevice(s rowScanner) (ManualDevice, error) {
	var d ManualDevice
	err := s.Scan(&d.ID, &d.Name, &d.Kind, &d.Owner.DirectoryID, &d.Owner.ObjectID, &d.Owner.UPN, &d.Owner.AccountName, &d.CreatedBy, &d.CreatedAt, &d.RemovedAt)
	return d, err
}

// CreateManualDevice records a device and the account its certificate will name.
func (db *DB) CreateManualDevice(ctx context.Context, d ManualDevice) (int64, error) {
	d.Name = strings.TrimSpace(d.Name)
	if d.Name == "" || len(d.Name) > 80 {
		return 0, errors.New("a device needs a name of 80 characters at most")
	}
	if !manualDeviceKinds[d.Kind] {
		d.Kind = "other"
	}
	if d.Owner.DirectoryID == "" || d.Owner.ObjectID == "" || d.Owner.UPN == "" || d.Owner.AccountName == "" {
		return 0, errors.New("a device needs a verified directory account")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO manual_devices(name, kind, directory_id, object_id, upn, account_name, created_by) VALUES(?,?,?,?,?,?,?)`,
		d.Name, d.Kind, d.Owner.DirectoryID, d.Owner.ObjectID, d.Owner.UPN, d.Owner.AccountName, d.CreatedBy)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err = vpnIdentityAudit(ctx, tx, d.CreatedBy, "manual-device.create", fmt.Sprintf("device=%s owner=%s", ManualDeviceID(id), d.Owner.UPN)); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// GetManualDevice returns one device, removed or not, or sql.ErrNoRows.
func (db *DB) GetManualDevice(ctx context.Context, id int64) (ManualDevice, error) {
	return scanManualDevice(db.sql.QueryRowContext(ctx, `SELECT `+manualDeviceCols+` FROM manual_devices WHERE id=?`, id))
}

// ListManualDevices returns the devices that have not been removed, by name.
func (db *DB) ListManualDevices(ctx context.Context) ([]ManualDevice, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+manualDeviceCols+` FROM manual_devices WHERE removed_at IS NULL ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ManualDevice
	for rows.Next() {
		d, err := scanManualDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RemoveManualDevice takes a device off the list and closes any profile that
// was downloaded for it and not yet installed. It is refused while the device
// holds a certificate that has not been revoked.
func (db *DB) RemoveManualDevice(ctx context.Context, id int64, actor string) error {
	deviceID := ManualDeviceID(id)
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var held int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM vpn_identities WHERE device_id=? AND state IN ('ISSUING','ISSUED')`, deviceID).Scan(&held); err != nil {
		return err
	}
	if held > 0 {
		return ErrManualDeviceInUse
	}
	res, err := tx.ExecContext(ctx, `UPDATE manual_devices SET removed_at=datetime('now') WHERE id=? AND removed_at IS NULL`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	if _, err = closeVPNOffers(ctx, tx, "Device removed by "+actor, `device_id=?`, deviceID); err != nil {
		return err
	}
	if err = vpnIdentityAudit(ctx, tx, actor, "manual-device.remove", "device="+deviceID); err != nil {
		return err
	}
	return tx.Commit()
}

// HandOverVPNIdentity records that a certificate was given to the device that
// asked for it, where no MDM command will ever report the profile installed.
// Earlier certificates for the same device and network are superseded, as they
// are when an enrolled device acknowledges a new profile.
func (db *DB) HandOverVPNIdentity(ctx context.Context, id int64) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var deviceID string
	var serverID int64
	err = tx.QueryRowContext(ctx, `SELECT device_id, server_id FROM vpn_identities WHERE id=? AND state='ISSUED' AND deploy_status='sent'`, id).Scan(&deviceID, &serverID)
	if err != nil {
		return fmt.Errorf("vpn identity %d is not an issued certificate waiting to be handed over: %w", id, err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE vpn_identities SET deploy_status='installed', updated_at=datetime('now') WHERE id=?`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE vpn_identities SET state='SUPERSEDED', updated_at=datetime('now')
		WHERE device_id=? AND server_id=? AND id<>? AND state='ISSUED'`, deviceID, serverID, id); err != nil {
		return err
	}
	return tx.Commit()
}
