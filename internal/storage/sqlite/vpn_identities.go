package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/directory"
)

// VPN identity states.
const (
	VPNIssuing     = "ISSUING"
	VPNIssued      = "ISSUED"
	VPNFailed      = "FAILED"
	VPNQuarantined = "QUARANTINED"
	VPNSuperseded  = "SUPERSEDED"
	VPNRevoked     = "REVOKED"
)

// VPNIdentity is one VPN certificate requested for a device and the delivery of
// its profile. It never holds a private key.
type VPNIdentity struct {
	ID           int64
	ServerID     int64
	DeviceID     string
	Owner        directory.DirectoryIdentity
	Actor        string
	State        string
	SPKISHA256   string
	CertSerial   string
	LeafDER      []byte
	NotAfter     string // RFC 3339; empty until issued
	Backend      string
	FailReason   string
	CommandUUID  string
	DeployStatus string
	RevokedAt    sql.NullString
	CreatedAt    string
	UpdatedAt    string
}

// Expires parses NotAfter; the zero time means no certificate was issued.
func (v VPNIdentity) Expires() time.Time {
	t, _ := time.Parse(time.RFC3339, v.NotAfter)
	return t
}

// Current reports whether this is a certificate a device may be using.
func (v VPNIdentity) Current() bool { return v.State == VPNIssued }

// ErrVPNIssuanceInFlight means an earlier request for the same device and
// server has not finished.
var ErrVPNIssuanceInFlight = errors.New("a VPN certificate request for this device and server is already in progress")

const vpnIdentityCols = `id, server_id, device_id, directory_id, object_id, upn, account_name, actor, state, spki_sha256,
	cert_serial, leaf_der, not_after, backend, fail_reason, command_uuid, deploy_status, revoked_at, created_at, updated_at`

func scanVPNIdentity(s rowScanner) (VPNIdentity, error) {
	var v VPNIdentity
	err := s.Scan(&v.ID, &v.ServerID, &v.DeviceID, &v.Owner.DirectoryID, &v.Owner.ObjectID, &v.Owner.UPN, &v.Owner.AccountName,
		&v.Actor, &v.State, &v.SPKISHA256, &v.CertSerial, &v.LeafDER, &v.NotAfter, &v.Backend, &v.FailReason,
		&v.CommandUUID, &v.DeployStatus, &v.RevokedAt, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

func (db *DB) queryVPNIdentities(ctx context.Context, where string, args ...any) ([]VPNIdentity, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+vpnIdentityCols+` FROM vpn_identities `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VPNIdentity
	for rows.Next() {
		v, err := scanVPNIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// BeginVPNIdentity records the intent to issue before any CA is contacted, with
// the audit entry naming the administrator and the owner.
func (db *DB) BeginVPNIdentity(ctx context.Context, v VPNIdentity) (int64, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO vpn_identities(server_id, device_id, directory_id, object_id, upn, account_name, actor, spki_sha256, backend)
		VALUES(?,?,?,?,?,?,?,?,?)`, v.ServerID, v.DeviceID, v.Owner.DirectoryID, v.Owner.ObjectID, v.Owner.UPN, v.Owner.AccountName, v.Actor, v.SPKISHA256, v.Backend)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrVPNIssuanceInFlight
		}
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err = vpnIdentityAudit(ctx, tx, v.Actor, "vpn.identity.issue", fmt.Sprintf("device=%s owner=%s server=%d", v.DeviceID, v.Owner.UPN, v.ServerID)); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func vpnIdentityAudit(ctx context.Context, ex sqlExecutor, actor, action, target string) error {
	_, err := ex.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result,remote) VALUES(?,'cairn-vpn',?,?,'ok','')`, actor, action, target)
	return err
}

// vpnTransition moves an ISSUING row to its outcome. Only ISSUING rows move, so
// a late or repeated call cannot overwrite a recorded outcome.
func (db *DB) vpnTransition(ctx context.Context, id int64, set string, args ...any) error {
	res, err := db.sql.ExecContext(ctx, `UPDATE vpn_identities SET `+set+`, updated_at=datetime('now') WHERE id=? AND state='ISSUING'`, append(args, id)...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("vpn identity %d is not awaiting a CA outcome", id)
	}
	return nil
}

// CompleteVPNIdentity records the issued certificate.
func (db *DB) CompleteVPNIdentity(ctx context.Context, id int64, serial string, leafDER []byte, notAfter time.Time) error {
	if serial == "" || len(leafDER) == 0 {
		return errors.New("an issued VPN identity needs a serial and a certificate")
	}
	return db.vpnTransition(ctx, id, `state='ISSUED', cert_serial=?, leaf_der=?, not_after=?`, serial, leafDER, notAfter.UTC().Format(time.RFC3339))
}

// FailVPNIdentity records that the CA definitely issued nothing.
func (db *DB) FailVPNIdentity(ctx context.Context, id int64, reason string) error {
	return db.vpnTransition(ctx, id, `state='FAILED', fail_reason=?`, reason)
}

// QuarantineVPNIdentity records an outcome that cannot be trusted: the CA may
// have issued a certificate Cairn did not receive or did not ask for. serial is
// the certificate's when one was seen.
func (db *DB) QuarantineVPNIdentity(ctx context.Context, id int64, reason, serial string, leafDER []byte) error {
	return db.vpnTransition(ctx, id, `state='QUARANTINED', fail_reason=?, cert_serial=?, leaf_der=?`, reason, serial, leafDER)
}

// MarkVPNDeploySent ties an issued identity to the InstallProfile command that
// carries its key.
func (db *DB) MarkVPNDeploySent(ctx context.Context, id int64, commandUUID string) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE vpn_identities SET command_uuid=?, deploy_status='sent', updated_at=datetime('now') WHERE id=? AND state='ISSUED'`, commandUUID, id)
	return err
}

// MarkVPNDeployFailed records that the profile never reached the queue. The
// certificate exists but no device holds its key.
func (db *DB) MarkVPNDeployFailed(ctx context.Context, id int64, reason string) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE vpn_identities SET deploy_status='failed', fail_reason=?, updated_at=datetime('now') WHERE id=? AND state='ISSUED'`, reason, id)
	return err
}

// GetVPNIdentity returns one identity or sql.ErrNoRows.
func (db *DB) GetVPNIdentity(ctx context.Context, id int64) (VPNIdentity, error) {
	return scanVPNIdentity(db.sql.QueryRowContext(ctx, `SELECT `+vpnIdentityCols+` FROM vpn_identities WHERE id=?`, id))
}

// DeviceVPNIdentities lists a device's identities, newest first.
func (db *DB) DeviceVPNIdentities(ctx context.Context, deviceID string) ([]VPNIdentity, error) {
	return db.queryVPNIdentities(ctx, `WHERE device_id=? ORDER BY id DESC`, deviceID)
}

// ServerVPNIdentities lists a server's identities, newest first.
func (db *DB) ServerVPNIdentities(ctx context.Context, serverID int64) ([]VPNIdentity, error) {
	return db.queryVPNIdentities(ctx, `WHERE server_id=? ORDER BY id DESC`, serverID)
}

// CurrentVPNIdentities lists every certificate a device may be using.
func (db *DB) CurrentVPNIdentities(ctx context.Context) ([]VPNIdentity, error) {
	return db.queryVPNIdentities(ctx, `WHERE state='ISSUED' ORDER BY not_after`)
}

// QuarantinedVPNIdentities lists attempts whose CA outcome is unresolved.
func (db *DB) QuarantinedVPNIdentities(ctx context.Context) ([]VPNIdentity, error) {
	return db.queryVPNIdentities(ctx, `WHERE state='QUARANTINED' ORDER BY id`)
}

// VPNIdentitiesAwaitingRevocation lists certificates no device should use any
// more that the CA has not been told to revoke: replaced ones, ones whose
// profile never installed, and ones an administrator revoked.
func (db *DB) VPNIdentitiesAwaitingRevocation(ctx context.Context) ([]VPNIdentity, error) {
	return db.queryVPNIdentities(ctx, `WHERE revoked_at IS NULL AND cert_serial <> '' AND (
		state IN ('SUPERSEDED','REVOKED') OR (state='ISSUED' AND deploy_status IN ('failed','expired'))) ORDER BY id`)
}

// MarkVPNIdentityRevoked records an administrator's decision to revoke. The CA
// side is tracked separately by MarkVPNCertificateRevoked.
func (db *DB) MarkVPNIdentityRevoked(ctx context.Context, id int64, actor string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE vpn_identities SET state='REVOKED', updated_at=datetime('now') WHERE id=? AND state IN ('ISSUED','SUPERSEDED','QUARANTINED')`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("vpn identity %d has no certificate to revoke", id)
	}
	// A profile still waiting in the queue carries this certificate's key.
	if _, err = withdrawVPNPayloads(ctx, tx, "failed", "Certificate revoked before the device collected the profile", `id=?`, id); err != nil {
		return err
	}
	if err = vpnIdentityAudit(ctx, tx, actor, "vpn.identity.revoke", fmt.Sprintf("identity=%d", id)); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkVPNCertificateRevoked records that the CA accepted the revocation.
func (db *DB) MarkVPNCertificateRevoked(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE vpn_identities SET revoked_at=datetime('now'), updated_at=datetime('now') WHERE id=? AND revoked_at IS NULL`, id)
	return err
}

// vpnCommandResult resolves the delivery of a VPN profile when its
// InstallProfile command reaches a final status, in the transaction that stores
// the device's report. The queued command body, which holds the private key, is
// replaced in the same transaction. Once the new profile is installed, earlier
// certificates for the same device and server are superseded.
func vpnCommandResult(ctx context.Context, ex sqlExecutor, deviceID, commandUUID, deployStatus string) error {
	var id, serverID int64
	err := ex.QueryRowContext(ctx, `SELECT id, server_id FROM vpn_identities WHERE command_uuid=? AND device_id=? AND deploy_status='sent'`, commandUUID, deviceID).Scan(&id, &serverID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = ex.ExecContext(ctx, `UPDATE vpn_identities SET deploy_status=?, updated_at=datetime('now') WHERE id=?`, deployStatus, id); err != nil {
		return err
	}
	if deployStatus == "installed" {
		if _, err = ex.ExecContext(ctx, `UPDATE vpn_identities SET state='SUPERSEDED', updated_at=datetime('now')
			WHERE device_id=? AND server_id=? AND id<>? AND state='ISSUED'`, deviceID, serverID, id); err != nil {
			return err
		}
	}
	return scrubVPNPayload(ctx, ex, commandUUID)
}

// scrubVPNPayload replaces a queued InstallProfile body with a harmless
// ProfileList command under the same UUID. NanoMDM keeps command bodies after
// they are answered, and this one holds a private key. A replacement rather
// than a delete keeps the queue consistent if the device has not fetched the
// command yet: it receives the placeholder instead of the profile.
func scrubVPNPayload(ctx context.Context, ex sqlExecutor, commandUUID string) error {
	stub := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Command</key><dict><key>RequestType</key><string>ProfileList</string></dict><key>CommandUUID</key><string>` + commandUUID + `</string></dict></plist>`
	if _, err := ex.ExecContext(ctx, `UPDATE nano_kv SET v=? WHERE bucket='queue' AND k=?`, []byte(stub), commandUUID+".raw"); err != nil {
		return err
	}
	_, err := ex.ExecContext(ctx, `UPDATE nano_kv SET v=? WHERE bucket='queue' AND k=?`, []byte("ProfileList"), commandUUID+".req_type")
	return err
}

// withdrawVPNPayloads cancels undelivered VPN profiles matching where: the
// identity is marked with status, the queued body is scrubbed and the command
// history says why. It returns how many were withdrawn.
func withdrawVPNPayloads(ctx context.Context, ex sqlExecutor, status, why, where string, args ...any) (int, error) {
	rows, err := ex.QueryContext(ctx, `SELECT id, device_id, command_uuid FROM vpn_identities WHERE deploy_status='sent' AND `+where, args...)
	if err != nil {
		return 0, err
	}
	type pending struct {
		id           int64
		device, uuid string
	}
	var list []pending
	for rows.Next() {
		var p pending
		if err = rows.Scan(&p.id, &p.device, &p.uuid); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, p := range list {
		if _, err = ex.ExecContext(ctx, `UPDATE vpn_identities SET deploy_status=?, fail_reason=?, updated_at=datetime('now') WHERE id=?`, status, why, p.id); err != nil {
			return 0, err
		}
		if _, err = ex.ExecContext(ctx, `UPDATE command_history SET status='Cancelled', error=?, result_at=datetime('now')
			WHERE command_uuid=? AND device_id=? AND status IN ('Queued','Sent','NotNow')`, why, p.uuid, p.device); err != nil {
			return 0, err
		}
		if err = scrubVPNPayload(ctx, ex, p.uuid); err != nil {
			return 0, err
		}
	}
	return len(list), nil
}

// WithdrawStaleVPNPayloads cancels VPN profiles a device has not collected since
// before, so a private key does not wait in the queue indefinitely for a device
// that may never return. The identity then needs issuing again.
func (db *DB) WithdrawStaleVPNPayloads(ctx context.Context, before time.Time) (int, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n, err := withdrawVPNPayloads(ctx, tx, "expired", "VPN profile withdrawn: the device did not collect it in time",
		`updated_at < ?`, before.UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}
