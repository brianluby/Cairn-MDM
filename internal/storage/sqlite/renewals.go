package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrRenewalOpen means the device already has a renewal in flight.
var ErrRenewalOpen = errors.New("a renewal is already in progress for this device")

// Renewal is one attempt to replace a device's identity certificate.
type Renewal struct {
	ID                int64
	DeviceID          string
	State             string
	CommandUUID       string
	OldSHA256         string
	NewSHA256         string
	ProfileIdentifier string
	Actor             string
	Error             string
	StartedAt         string
	UpdatedAt         string
}

// Open reports whether the attempt is still waiting on the device.
func (r Renewal) Open() bool {
	return r.State == "lookup" || r.State == "sent" || r.State == "installed"
}

// RenewalCandidate is an enrolled device, the identity certificate it last
// presented and its most recent renewal attempt.
type RenewalCandidate struct {
	DeviceID    string
	DeviceName  string
	CheckInHost string
	SHA256      string
	CommonName  string
	SANEmail    string
	Topic       string // APNs topic the device enrolled under
	NotAfter    time.Time
	Last        Renewal // zero when the device has never been renewed
}

const renewalColumns = `id, device_id, state, command_uuid, old_sha256, new_sha256, profile_identifier, actor, error, started_at, updated_at`

func scanRenewal(s rowScanner) (Renewal, error) {
	var r Renewal
	err := s.Scan(&r.ID, &r.DeviceID, &r.State, &r.CommandUUID, &r.OldSHA256, &r.NewSHA256, &r.ProfileIdentifier, &r.Actor, &r.Error, &r.StartedAt, &r.UpdatedAt)
	return r, err
}

// RenewalCandidates lists every enrolled device that has presented an identity
// certificate, with the one it presented most recently.
func (db *DB) RenewalCandidates(ctx context.Context) ([]RenewalCandidate, error) {
	return db.renewalCandidates(ctx, "")
}

// RenewalCandidate returns one device's entry. ok is false when the device is
// not enrolled or has never presented a certificate.
func (db *DB) RenewalCandidate(ctx context.Context, deviceID string) (c RenewalCandidate, ok bool, err error) {
	list, err := db.renewalCandidates(ctx, deviceID)
	if err != nil || len(list) == 0 {
		return RenewalCandidate{}, false, err
	}
	return list[0], true, nil
}

func (db *DB) renewalCandidates(ctx context.Context, deviceID string) ([]RenewalCandidate, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT d.id, COALESCE(NULLIF(d.name,''), NULLIF(d.serial,''), d.id), d.checkin_host,
			c.sha256, c.common_name, c.san_email, c.not_after,
			COALESCE((SELECT CAST(v AS TEXT) FROM nano_kv WHERE bucket='enrollments' AND k = d.id || '.topic'), '')
		FROM device_identity_certs c
		JOIN cert_auth ca ON ca.sha256 = c.sha256
		JOIN devices d ON d.id = ca.enrollment_id
		WHERE d.checked_out_at IS NULL AND (? = '' OR d.id = ?)
		ORDER BY d.id, MAX(COALESCE(c.last_accepted,''), COALESCE(c.last_refused,'')) DESC, c.not_after DESC`, deviceID, deviceID)
	if err != nil {
		return nil, err
	}
	var out []RenewalCandidate
	seen := map[string]bool{}
	for rows.Next() {
		var c RenewalCandidate
		var notAfter string
		if err := rows.Scan(&c.DeviceID, &c.DeviceName, &c.CheckInHost, &c.SHA256, &c.CommonName, &c.SANEmail, &notAfter, &c.Topic); err != nil {
			rows.Close()
			return nil, err
		}
		if seen[c.DeviceID] {
			continue
		}
		seen[c.DeviceID] = true
		c.NotAfter, _ = time.Parse(time.RFC3339, notAfter)
		out = append(out, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	// One statement at a time: the pool is a single connection.
	for i := range out {
		last, found, err := db.LastRenewal(ctx, out[i].DeviceID)
		if err != nil {
			return nil, err
		}
		if found {
			out[i].Last = last
		}
	}
	return out, nil
}

// LastRenewal returns a device's most recent renewal attempt.
func (db *DB) LastRenewal(ctx context.Context, deviceID string) (Renewal, bool, error) {
	r, err := scanRenewal(db.sql.QueryRowContext(ctx, `SELECT `+renewalColumns+` FROM device_renewals WHERE device_id=? ORDER BY id DESC LIMIT 1`, deviceID))
	if errors.Is(err, sql.ErrNoRows) {
		return Renewal{}, false, nil
	}
	return r, err == nil, err
}

// DeviceRenewals returns a device's renewal attempts, newest first.
func (db *DB) DeviceRenewals(ctx context.Context, deviceID string, limit int) ([]Renewal, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT `+renewalColumns+` FROM device_renewals WHERE device_id=? ORDER BY id DESC LIMIT ?`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Renewal
	for rows.Next() {
		r, err := scanRenewal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// BeginRenewal records a new attempt in the lookup state under the CommandUUID
// of the ProfileList command about to be queued.
func (db *DB) BeginRenewal(ctx context.Context, deviceID, commandUUID, oldSHA256, actor string) error {
	if deviceID == "" || commandUUID == "" || oldSHA256 == "" {
		return errors.New("renewal needs a device, a command and the certificate being replaced")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO device_renewals(device_id, state, command_uuid, old_sha256, actor) VALUES(?, 'lookup', ?, ?, ?)`,
		deviceID, commandUUID, oldSHA256, actor)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrRenewalOpen
	}
	if err != nil {
		return err
	}
	return db.auditRenewal(ctx, actor, "identity.renew.start", deviceID, "started")
}

// RenewalProfileQueued moves an attempt from lookup to sent, under the
// CommandUUID of the InstallProfile command about to be queued. It reports
// false when the attempt is no longer waiting on that lookup.
func (db *DB) RenewalProfileQueued(ctx context.Context, deviceID, lookupUUID, installUUID, profileIdentifier string) (bool, error) {
	res, err := db.sql.ExecContext(ctx, `UPDATE device_renewals SET state='sent', command_uuid=?, profile_identifier=?, updated_at=datetime('now')
		WHERE device_id=? AND state='lookup' AND command_uuid=?`, installUUID, profileIdentifier, deviceID, lookupUUID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// FailRenewal closes a device's open attempt with the reason.
func (db *DB) FailRenewal(ctx context.Context, deviceID, reason string) error {
	res, err := db.sql.ExecContext(ctx, `UPDATE device_renewals SET state='failed', error=?, updated_at=datetime('now')
		WHERE device_id=? AND state IN ('lookup','sent','installed')`, reason, deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return db.auditRenewal(ctx, "", "identity.renew.fail", deviceID, reason)
	}
	return nil
}

// NoteRenewalProblem records why a certificate the device presented during a
// renewal was not accepted, without closing the attempt.
func (db *DB) NoteRenewalProblem(ctx context.Context, renewalID int64, reason string) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE device_renewals SET error=? WHERE id=? AND state<>'renewed' AND error<>?`, reason, renewalID, reason)
	return err
}

// FailStaleRenewals closes attempts the device has not moved forward since
// the cutoff, and attempts whose command never reached the queue (Cairn
// stopped between recording the attempt and queueing the command).
func (db *DB) FailStaleRenewals(ctx context.Context, cutoff time.Time, reason string) (int64, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	const open = `state IN ('lookup','sent','installed')`
	stale := open + ` AND updated_at < ?1`
	orphan := open + ` AND state <> 'installed' AND updated_at < datetime('now','-10 minutes')
		AND NOT EXISTS (SELECT 1 FROM command_history h WHERE h.command_uuid = device_renewals.command_uuid)`
	stamp := cutoff.UTC().Format("2006-01-02 15:04:05")
	var total int64
	for _, step := range []struct{ where, why string }{{stale, reason}, {orphan, "The command was never queued."}} {
		if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log (username, provider, action, target, result, remote)
			SELECT '', 'system', 'identity.renew.fail', 'device ' || device_id, ?2, '' FROM device_renewals WHERE `+step.where, stamp, step.why); err != nil {
			return 0, err
		}
		res, err := tx.ExecContext(ctx, `UPDATE device_renewals SET state='failed', error=?2, updated_at=datetime('now') WHERE `+step.where, stamp, step.why)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, tx.Commit()
}

// AwaitedRenewal returns the attempt whose certificate the device may still
// turn up with: the newest one, started since the cutoff, that got as far as
// queueing the enrollment profile, provided no attempt has completed after
// it. A later attempt still at its lookup does not hide it. A closed attempt
// counts too: the device can install the profile and switch certificates
// without its answer ever arriving, and refusing the new certificate then
// would strand it.
func (db *DB) AwaitedRenewal(ctx context.Context, deviceID string, since time.Time) (Renewal, bool, error) {
	r, err := scanRenewal(db.sql.QueryRowContext(ctx, `SELECT `+renewalColumns+` FROM device_renewals r
		WHERE device_id=?1 AND profile_identifier<>'' AND state IN ('sent','installed','failed') AND started_at >= ?2
		  AND NOT EXISTS (SELECT 1 FROM device_renewals n WHERE n.device_id=r.device_id AND n.id>r.id AND n.state='renewed')
		ORDER BY id DESC LIMIT 1`, deviceID, since.UTC().Format("2006-01-02 15:04:05")))
	if errors.Is(err, sql.ErrNoRows) {
		return Renewal{}, false, nil
	}
	return r, err == nil, err
}

// CompleteRenewal associates the new certificate with the device and marks
// the attempt renewed, in one transaction. It refuses a certificate already
// known for any enrollment. Any later attempt still open is closed. The
// replaced certificate stays associated until RetireRenewedCertificates
// removes it.
func (db *DB) CompleteRenewal(ctx context.Context, renewalID int64, deviceID, newSHA256 string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var known int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM cert_auth WHERE sha256=?`, newSHA256).Scan(&known); err != nil {
		return err
	}
	if known != 0 {
		return errors.New("certificate is already associated with an enrollment")
	}
	if err = markRenewed(ctx, tx, renewalID, deviceID, newSHA256); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO cert_auth (enrollment_id, sha256) VALUES (?, ?)`, deviceID, newSHA256); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log (username, provider, action, target, result, remote) VALUES ('', 'system', 'identity.renew.complete', ?, ?, '')`,
		"device "+deviceID, "certificate "+newSHA256); err != nil {
		return err
	}
	return tx.Commit()
}

func markRenewed(ctx context.Context, tx *sql.Tx, renewalID int64, deviceID, newSHA256 string) error {
	res, err := tx.ExecContext(ctx, `UPDATE device_renewals SET state='renewed', new_sha256=?, error='', updated_at=datetime('now')
		WHERE id=? AND device_id=? AND state IN ('sent','installed','failed') AND profile_identifier<>''`, newSHA256, renewalID, deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("no renewal is waiting for this device")
	}
	_, err = tx.ExecContext(ctx, `UPDATE device_renewals SET state='failed', error='Closed: an earlier renewal completed.', updated_at=datetime('now')
		WHERE device_id=? AND id>? AND state IN ('lookup','sent','installed')`, deviceID, renewalID)
	return err
}

// MarkRenewedByEnrollment closes an attempt when the device enrolled again by
// itself and NanoMDM associated the new certificate.
func (db *DB) MarkRenewedByEnrollment(ctx context.Context, renewalID int64, deviceID, newSHA256 string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = markRenewed(ctx, tx, renewalID, deviceID, newSHA256); err != nil {
		return err
	}
	return tx.Commit()
}

// RetireRenewedCertificates stops accepting certificates that were replaced
// before the cutoff. The delay covers requests the device already had in
// flight with the old certificate when it switched.
func (db *DB) RetireRenewedCertificates(ctx context.Context, cutoff time.Time) (int64, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stamp := cutoff.UTC().Format("2006-01-02 15:04:05")
	res, err := tx.ExecContext(ctx, `DELETE FROM cert_auth WHERE EXISTS (SELECT 1 FROM device_renewals r
		WHERE r.state='renewed' AND r.old_retired_at IS NULL AND r.updated_at < ? AND r.new_sha256 <> ''
		  AND r.device_id = cert_auth.enrollment_id AND r.old_sha256 = cert_auth.sha256)`, stamp)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err = tx.ExecContext(ctx, `UPDATE device_renewals SET old_retired_at=datetime('now') WHERE state='renewed' AND old_retired_at IS NULL AND updated_at < ?`, stamp); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// IdentityCommonName returns the common name recorded for a certificate a
// device has presented, or "" when none is on record.
func (db *DB) IdentityCommonName(ctx context.Context, sha256Hex string) (string, error) {
	var cn string
	err := db.sql.QueryRowContext(ctx, `SELECT common_name FROM device_identity_certs WHERE sha256=?`, sha256Hex).Scan(&cn)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return cn, err
}

// SetCheckInHost remembers the host name a device checks in through.
func (db *DB) SetCheckInHost(ctx context.Context, deviceID, host string) error {
	if host == "" {
		return nil
	}
	_, err := db.sql.ExecContext(ctx, `UPDATE devices SET checkin_host=? WHERE id=? AND checkin_host<>?`, host, deviceID, host)
	return err
}

// CertificateAssociated reports whether the certificate is associated with the
// device.
func (db *DB) CertificateAssociated(ctx context.Context, deviceID, sha256Hex string) (bool, error) {
	var n int
	err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM cert_auth WHERE enrollment_id=? AND sha256=?`, deviceID, sha256Hex).Scan(&n)
	return n > 0, err
}

func (db *DB) auditRenewal(ctx context.Context, actor, action, deviceID, result string) error {
	provider := "system"
	if actor != "" && actor != "schedule" {
		provider = "console"
	}
	return db.AppendAudit(ctx, AuditEntry{Username: actor, Provider: provider, Action: action, Target: "device " + deviceID, Result: result})
}

// renewalCommandResult moves a renewal forward when the device answers the
// command it is waiting on. status is "installed" or "failed".
func renewalCommandResult(ctx context.Context, executor sqlExecutor, deviceID, commandUUID, status, errDesc string) error {
	if status == "installed" {
		_, err := executor.ExecContext(ctx, `UPDATE device_renewals SET state='installed', updated_at=datetime('now')
			WHERE device_id=? AND command_uuid=? AND state='sent'`, deviceID, commandUUID)
		return err
	}
	if errDesc == "" {
		errDesc = "the device reported an error"
	}
	_, err := executor.ExecContext(ctx, `UPDATE device_renewals SET state='failed', error=?, updated_at=datetime('now')
		WHERE device_id=? AND command_uuid=? AND state IN ('lookup','sent')`, errDesc, deviceID, commandUUID)
	return err
}

// DevicesWithUnknownCertificate lists enrolled devices that can be sent
// commands, have never presented an identity certificate that was recorded,
// and have no command waiting for an answer.
func (db *DB) DevicesWithUnknownCertificate(ctx context.Context) ([]string, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT d.id FROM devices d
		WHERE d.checked_out_at IS NULL AND d.token_updated_at IS NOT NULL
		AND NOT EXISTS (SELECT 1 FROM nano_kv WHERE bucket='enrollments' AND k = d.id || '.disabled')
		AND NOT EXISTS (SELECT 1 FROM cert_auth a JOIN device_identity_certs c ON c.sha256 = a.sha256 WHERE a.enrollment_id = d.id)
		AND NOT EXISTS (SELECT 1 FROM command_history h WHERE h.device_id = d.id AND h.status IN ('Queued','Sent','NotNow'))
		ORDER BY d.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
