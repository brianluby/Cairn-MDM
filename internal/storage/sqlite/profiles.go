package sqlite

import (
	"context"
	"database/sql"
	"strings"
)

// Profile is a row of the configuration-profile library.
type Profile struct {
	ID           int64
	Identifier   string
	UUID         string
	Name         string
	Organization string
	PayloadTypes string // comma-joined for display
	Source       string
	Data         []byte
	CreatedAt    string
	UpdatedAt    string
}

// Types splits PayloadTypes for display.
func (p Profile) Types() []string {
	if p.PayloadTypes == "" {
		return nil
	}
	return strings.Split(p.PayloadTypes, ",")
}

// SaveProfile upserts a profile keyed by its PayloadIdentifier (matching device
// semantics: same identifier = in-place replacement) and returns its row ID.
func (db *DB) SaveProfile(ctx context.Context, p Profile) (int64, error) {
	var id int64
	// updated_at uses millisecond resolution: the deploy reconciler re-arms on
	// any updated_at change, and second-resolution would miss a rapid re-upload.
	err := db.sql.QueryRowContext(ctx,
		`INSERT INTO profiles (identifier, uuid, name, organization, payload_types, source, data, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%f','now'))
		 ON CONFLICT (identifier) DO UPDATE SET
		   uuid          = excluded.uuid,
		   name          = excluded.name,
		   organization  = excluded.organization,
		   payload_types = excluded.payload_types,
		   source        = excluded.source,
		   data          = excluded.data,
		   updated_at    = strftime('%Y-%m-%d %H:%M:%f','now')
		 RETURNING id`,
		p.Identifier, p.UUID, p.Name, p.Organization, p.PayloadTypes, p.Source, p.Data).Scan(&id)
	return id, err
}

const profileCols = `id, identifier, uuid, name, organization, payload_types, source, data, created_at, updated_at`

func scanProfile(row interface{ Scan(...any) error }) (Profile, error) {
	var p Profile
	err := row.Scan(&p.ID, &p.Identifier, &p.UUID, &p.Name, &p.Organization,
		&p.PayloadTypes, &p.Source, &p.Data, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// ListProfiles returns the library ordered by name.
func (db *DB) ListProfiles(ctx context.Context) ([]Profile, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+profileCols+` FROM profiles ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Profile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProfile returns one profile by row ID, or sql.ErrNoRows.
func (db *DB) GetProfile(ctx context.Context, id int64) (Profile, error) {
	return scanProfile(db.sql.QueryRowContext(ctx,
		`SELECT `+profileCols+` FROM profiles WHERE id = ?`, id))
}

// DeleteProfile removes a profile from the library. Devices that already have
// it installed keep it — removal from devices is a RemoveProfile command.
func (db *DB) DeleteProfile(ctx context.Context, id int64) error {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM profiles WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Affects names what removing this profile takes away, derived from its payload
// types, so confirmations can say "this device may lose Wi-Fi" instead of a
// generic warning. Empty when nothing connectivity- or trust-related is inside.
func (p Profile) Affects() []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, t := range p.Types() {
		switch {
		case t == "com.apple.wifi.managed":
			add("Wi-Fi network access")
		case t == "com.apple.vpn.managed" || t == "com.apple.ikev2" || strings.HasPrefix(t, "com.apple.vpn"):
			add("VPN access")
		case t == "com.apple.security.scep" || t == "com.apple.security.pkcs12" || t == "com.apple.security.pkcs1" || t == "com.apple.security.root":
			add("certificates and trust (other profiles may depend on them)")
		case t == "com.apple.mdm":
			add("MDM management itself")
		case t == "com.apple.extensiblesso" || t == "com.apple.sso":
			add("single sign-on")
		}
	}
	return out
}

// ProfileGroups lists the groups a profile is assigned to.
func (db *DB) ProfileGroups(ctx context.Context, profileID int64) ([]Group, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+groupCols+` FROM groups g JOIN group_profiles gp ON gp.group_id = g.id WHERE gp.profile_id = ? ORDER BY g.name COLLATE NOCASE`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.DeviceCount, &g.ProfileCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeployCounts summarizes a device's group-assigned profile deployments.
type DeployCounts struct {
	Installed int
	Pending   int
	Failed    int
}

// DeviceDeployCounts returns per-device deployment counts for the device list.
func (db *DB) DeviceDeployCounts(ctx context.Context) (map[string]DeployCounts, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT device_id,
		 SUM(CASE WHEN status='installed' THEN 1 ELSE 0 END), SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END), SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)
		 FROM profile_deploys GROUP BY device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]DeployCounts{}
	for rows.Next() {
		var id string
		var c DeployCounts
		if err := rows.Scan(&id, &c.Installed, &c.Pending, &c.Failed); err != nil {
			return nil, err
		}
		out[id] = c
	}
	return out, rows.Err()
}

// GroupProfileOutcome is one member device's status for one assigned profile.
// Status is installed | sent | failed | not sent (member without a deploy row,
// usually not yet pushable).
type GroupProfileOutcome struct {
	DeviceID   string
	DeviceName string
	Status     string
	UpdatedAt  string
	Source     string // manual | directory | both
}

// GroupProfileOutcomes lists every member (manual or directory-derived) of a group
// with its deployment status for one assigned profile, so a group action shows
// per-device results instead of a bare count.
func (db *DB) GroupProfileOutcomes(ctx context.Context, groupID, profileID int64) ([]GroupProfileOutcome, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT m.device_id, COALESCE(NULLIF(d.name,''), NULLIF(d.serial,''), m.device_id),
		 COALESCE(dep.status, 'not sent'), COALESCE(dep.updated_at, ''),
		 CASE WHEN gd.device_id IS NOT NULL AND dm.device_id IS NOT NULL THEN 'both' WHEN gd.device_id IS NOT NULL THEN 'manual' ELSE 'directory' END
		 FROM `+membershipUnion+` m
		 LEFT JOIN devices d ON d.id = m.device_id
		 LEFT JOIN group_devices gd ON gd.group_id = m.group_id AND gd.device_id = m.device_id
		 LEFT JOIN (SELECT DISTINCT device_id, group_id FROM directory_memberships) dm ON dm.group_id = m.group_id AND dm.device_id = m.device_id
		 LEFT JOIN profile_deploys dep ON dep.device_id = m.device_id AND dep.profile_id = ?
		 WHERE m.group_id = ? ORDER BY d.name COLLATE NOCASE, m.device_id`, profileID, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupProfileOutcome
	for rows.Next() {
		var o GroupProfileOutcome
		if err := rows.Scan(&o.DeviceID, &o.DeviceName, &o.Status, &o.UpdatedAt, &o.Source); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// DeviceOwnerUPNs maps enrolled device IDs to their verified owner UPN.
func (db *DB) DeviceOwnerUPNs(ctx context.Context) (map[string]string, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT device_id, upn FROM device_owners`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, upn string
		if err := rows.Scan(&id, &upn); err != nil {
			return nil, err
		}
		out[id] = upn
	}
	return out, rows.Err()
}
