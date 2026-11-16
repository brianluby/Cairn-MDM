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

// VPN offer states.
const (
	VPNOfferOpen    = "OFFERED"
	VPNOfferClaimed = "CLAIMED"
	VPNOfferClosed  = "CLOSED"
)

// VPNOffer is an invitation for one device to request a VPN certificate for a
// key it makes itself. The challenge is never stored, only its hash.
type VPNOffer struct {
	ID              int64
	ServerID        int64
	DeviceID        string
	Owner           directory.DirectoryIdentity
	Actor           string
	ChallengeSHA256 string
	CommandUUID     string
	State           string
	SPKISHA256      string
	IdentityID      sql.NullInt64
	CloseReason     string
	ExpiresAt       string // RFC 3339
	CreatedAt       string
}

// ErrVPNOfferOpen means the device already has an unanswered offer for the server.
var ErrVPNOfferOpen = errors.New("a certificate request for this device and server is already waiting for the device")

// ErrVPNOfferSpent means the offer was claimed by another key, closed or expired.
var ErrVPNOfferSpent = errors.New("this certificate request is no longer open")

const vpnOfferCols = `id, server_id, device_id, directory_id, object_id, upn, account_name, actor, challenge_sha256,
	command_uuid, state, spki_sha256, identity_id, close_reason, expires_at, created_at`

func scanVPNOffer(s rowScanner) (VPNOffer, error) {
	var o VPNOffer
	err := s.Scan(&o.ID, &o.ServerID, &o.DeviceID, &o.Owner.DirectoryID, &o.Owner.ObjectID, &o.Owner.UPN, &o.Owner.AccountName,
		&o.Actor, &o.ChallengeSHA256, &o.CommandUUID, &o.State, &o.SPKISHA256, &o.IdentityID, &o.CloseReason, &o.ExpiresAt, &o.CreatedAt)
	return o, err
}

// CreateVPNOffer records an offer before its profile is queued. It is refused
// while the device has an open offer, an unanswered CA request or an
// uncollected profile for the same server.
func (db *DB) CreateVPNOffer(ctx context.Context, o VPNOffer, expires time.Time) (int64, error) {
	if o.ChallengeSHA256 == "" || o.CommandUUID == "" {
		return 0, errors.New("a VPN offer needs a challenge hash and the CommandUUID of its profile")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO vpn_offers(server_id, device_id, directory_id, object_id, upn, account_name, actor, challenge_sha256, command_uuid, expires_at)
		SELECT ?,?,?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM vpn_identities WHERE device_id=? AND server_id=?
			AND (state='ISSUING' OR (state='ISSUED' AND deploy_status='sent')))`,
		o.ServerID, o.DeviceID, o.Owner.DirectoryID, o.Owner.ObjectID, o.Owner.UPN, o.Owner.AccountName, o.Actor, o.ChallengeSHA256, o.CommandUUID,
		expires.UTC().Format(time.RFC3339), o.DeviceID, o.ServerID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrVPNOfferOpen
		}
		return 0, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, ErrVPNOfferOpen
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err = vpnIdentityAudit(ctx, tx, o.Actor, "vpn.offer.create", fmt.Sprintf("device=%s owner=%s server=%d", o.DeviceID, o.Owner.UPN, o.ServerID)); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// VPNOfferByChallenge finds the offer a challenge hash belongs to, or sql.ErrNoRows.
func (db *DB) VPNOfferByChallenge(ctx context.Context, challengeSHA256 string) (VPNOffer, error) {
	return scanVPNOffer(db.sql.QueryRowContext(ctx, `SELECT `+vpnOfferCols+` FROM vpn_offers WHERE challenge_sha256=?`, challengeSHA256))
}

// ClaimVPNOffer binds an open, unexpired offer to the public key that presented
// its challenge and starts the certificate request for it, in one transaction.
// It returns the new vpn_identities row. ErrVPNOfferSpent means the offer was
// no longer open; the caller looks it up again to tell a retry from a stranger.
func (db *DB) ClaimVPNOffer(ctx context.Context, offerID int64, spkiSHA256, backend string, now time.Time) (int64, error) {
	if spkiSHA256 == "" {
		return 0, errors.New("claiming a VPN offer needs the public key hash")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	o, err := scanVPNOffer(tx.QueryRowContext(ctx, `SELECT `+vpnOfferCols+` FROM vpn_offers WHERE id=?`, offerID))
	if err != nil {
		return 0, err
	}
	if o.State != VPNOfferOpen || o.ExpiresAt <= now.UTC().Format(time.RFC3339) {
		return 0, ErrVPNOfferSpent
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO vpn_identities(server_id, device_id, directory_id, object_id, upn, account_name, actor, spki_sha256, backend, command_uuid)
		SELECT ?,?,?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM vpn_identities WHERE device_id=? AND server_id=?
			AND (state='ISSUING' OR (state='ISSUED' AND deploy_status='sent')))`,
		o.ServerID, o.DeviceID, o.Owner.DirectoryID, o.Owner.ObjectID, o.Owner.UPN, o.Owner.AccountName, o.Actor, spkiSHA256, backend, o.CommandUUID,
		o.DeviceID, o.ServerID)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, ErrVPNIssuanceInFlight
	}
	identityID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE vpn_offers SET state='CLAIMED', spki_sha256=?, identity_id=?, updated_at=datetime('now') WHERE id=? AND state='OFFERED'`,
		spkiSHA256, identityID, offerID); err != nil {
		return 0, err
	}
	if err = vpnIdentityAudit(ctx, tx, o.Actor, "vpn.identity.issue", fmt.Sprintf("device=%s owner=%s server=%d device-key", o.DeviceID, o.Owner.UPN, o.ServerID)); err != nil {
		return 0, err
	}
	return identityID, tx.Commit()
}

// closeVPNOffers closes open offers matching where, replaces their queued
// profiles (each holds a live challenge) and says why in the command history.
func closeVPNOffers(ctx context.Context, ex sqlExecutor, why, where string, args ...any) (int, error) {
	rows, err := ex.QueryContext(ctx, `SELECT id, device_id, command_uuid FROM vpn_offers WHERE state='OFFERED' AND `+where, args...)
	if err != nil {
		return 0, err
	}
	type open struct {
		id           int64
		device, uuid string
	}
	var list []open
	for rows.Next() {
		var o open
		if err = rows.Scan(&o.id, &o.device, &o.uuid); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, o := range list {
		if _, err = ex.ExecContext(ctx, `UPDATE vpn_offers SET state='CLOSED', close_reason=?, updated_at=datetime('now') WHERE id=?`, why, o.id); err != nil {
			return 0, err
		}
		if _, err = ex.ExecContext(ctx, `UPDATE command_history SET status='Cancelled', error=?, result_at=datetime('now')
			WHERE command_uuid=? AND device_id=? AND status IN ('Queued','Sent','NotNow')`, why, o.uuid, o.device); err != nil {
			return 0, err
		}
		if err = scrubVPNPayload(ctx, ex, o.uuid); err != nil {
			return 0, err
		}
	}
	return len(list), nil
}

// CloseVPNOffer closes one open offer, for a profile that could not be queued.
func (db *DB) CloseVPNOffer(ctx context.Context, id int64, why string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = closeVPNOffers(ctx, tx, why, `id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ExpireVPNOffers closes offers no device answered in time.
func (db *DB) ExpireVPNOffers(ctx context.Context, now time.Time) (int, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n, err := closeVPNOffers(ctx, tx, "VPN profile withdrawn: the device did not request its certificate in time", `expires_at <= ?`, now.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// OpenVPNOffers lists a device's unanswered offers.
func (db *DB) OpenVPNOffers(ctx context.Context, deviceID string) ([]VPNOffer, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+vpnOfferCols+` FROM vpn_offers WHERE device_id=? AND state='OFFERED' ORDER BY id DESC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VPNOffer
	for rows.Next() {
		o, err := scanVPNOffer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// vpnOfferCommandResult closes an offer the device never answered when its
// InstallProfile command reaches a final status: the device will not ask for
// the certificate any more, so the challenge must stop working at once.
func vpnOfferCommandResult(ctx context.Context, ex sqlExecutor, deviceID, commandUUID, deployStatus string) error {
	why := "The device reported the profile installed without asking for its certificate"
	if deployStatus != "installed" {
		why = "The device could not install the profile"
	}
	_, err := closeVPNOffers(ctx, ex, why, `command_uuid=? AND device_id=?`, commandUUID, deviceID)
	return err
}

// WithdrawVPNOffer closes a device's open offer for a server on an
// administrator's word, for a profile sent to the wrong device or account. It
// reports whether there was one.
func (db *DB) WithdrawVPNOffer(ctx context.Context, deviceID string, serverID int64, actor string) (bool, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	n, err := closeVPNOffers(ctx, tx, "Withdrawn by "+actor, `device_id=? AND server_id=?`, deviceID, serverID)
	if err != nil || n == 0 {
		return false, err
	}
	if err = vpnIdentityAudit(ctx, tx, actor, "vpn.offer.withdraw", fmt.Sprintf("device=%s server=%d", deviceID, serverID)); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// VPNCommandOpen reports whether the device has yet to give a final answer to
// the command.
func (db *DB) VPNCommandOpen(ctx context.Context, deviceID, commandUUID string) (bool, error) {
	var n int
	err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM command_history WHERE command_uuid=? AND device_id=? AND status IN ('Queued','Sent','NotNow')`,
		commandUUID, deviceID).Scan(&n)
	return n > 0, err
}

// WithdrawVPNCommand replaces a queued VPN profile whose certificate request
// ended without a certificate, and says why in the command history.
func (db *DB) WithdrawVPNCommand(ctx context.Context, deviceID, commandUUID, why string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE command_history SET status='Cancelled', error=?, result_at=datetime('now')
		WHERE command_uuid=? AND device_id=? AND status IN ('Queued','Sent','NotNow')`, why, commandUUID, deviceID); err != nil {
		return err
	}
	if err = scrubVPNPayload(ctx, tx, commandUUID); err != nil {
		return err
	}
	return tx.Commit()
}
