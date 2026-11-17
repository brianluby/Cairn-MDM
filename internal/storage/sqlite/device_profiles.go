package sqlite

import (
	"context"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
)

// DeviceProfile is one profile a device reported as installed.
type DeviceProfile struct {
	Identifier   string
	Name         string
	Organization string
	PayloadTypes []string
	Managed      bool // installed by MDM, so MDM can remove it
	SeenAt       string
}

// HasPayload reports whether the profile carries a payload of the given type.
func (p DeviceProfile) HasPayload(payloadType string) bool {
	for _, t := range p.PayloadTypes {
		if t == payloadType {
			return true
		}
	}
	return false
}

// SaveInstalledProfiles replaces what is on record for the device with its
// latest ProfileList answer.
func (db *DB) SaveInstalledProfiles(ctx context.Context, deviceID string, profiles []mdmcore.InstalledProfile) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM device_profiles WHERE device_id=?`, deviceID); err != nil {
		return err
	}
	for _, p := range profiles {
		if p.Identifier == "" {
			continue
		}
		if _, err = tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO device_profiles (device_id, identifier, name, organization, payload_types, managed) VALUES (?,?,?,?,?,?)`,
			deviceID, p.Identifier, p.DisplayName, p.Organization, strings.Join(p.PayloadTypes, ","), p.Managed); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InstalledProfiles returns the profiles the device last reported, by name.
func (db *DB) InstalledProfiles(ctx context.Context, deviceID string) ([]DeviceProfile, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT identifier, name, organization, payload_types, managed, seen_at FROM device_profiles
		 WHERE device_id=? ORDER BY name COLLATE NOCASE, identifier`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceProfile
	for rows.Next() {
		var p DeviceProfile
		var types string
		if err := rows.Scan(&p.Identifier, &p.Name, &p.Organization, &types, &p.Managed, &p.SeenAt); err != nil {
			return nil, err
		}
		if types != "" {
			p.PayloadTypes = strings.Split(types, ",")
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
