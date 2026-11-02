package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
)

func (s *nanoStore) ClaimPush(ctx context.Context, uuid string, now time.Time) (*mdmcore.PushAttempt, error) {
	tx, err := s.db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// A crash after the sixth claim still reaches a visible terminal retry state.
	_, err = tx.ExecContext(ctx, `UPDATE push_outbox SET state='exhausted',last_error='Notification retry limit reached' WHERE state='pending' AND attempts>=6 AND lease_until<=?`, now.Unix())
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE push_outbox SET state='resolved' WHERE state='pending' AND EXISTS(SELECT 1 FROM command_history h WHERE h.command_uuid=push_outbox.command_uuid AND h.device_id=push_outbox.device_id AND h.status NOT IN ('Queued','Sent','NotNow'))`)
	if err != nil {
		return nil, err
	}
	var a mdmcore.PushAttempt
	err = tx.QueryRowContext(ctx, `SELECT command_uuid,device_id FROM push_outbox WHERE state='pending' AND attempts<6 AND next_attempt<=? AND lease_until<=? AND (?='' OR command_uuid=?) ORDER BY next_attempt,command_uuid,device_id LIMIT 1`, now.Unix(), now.Unix(), uuid, uuid).Scan(&a.CommandUUID, &a.DeviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	a.LeaseToken = hex.EncodeToString(nonce[:])
	_, err = tx.ExecContext(ctx, `UPDATE push_outbox SET attempts=attempts+1,lease_until=?,lease_token=? WHERE command_uuid=? AND device_id=?`, now.Add(30*time.Second).Unix(), a.LeaseToken, a.CommandUUID, a.DeviceID)
	if err != nil {
		return nil, err
	}
	return &a, tx.Commit()
}

func (s *nanoStore) FinishPush(ctx context.Context, a mdmcore.PushAttempt, result mdmcore.PushResult, now time.Time) error {
	// Lease fencing prevents a late worker overwriting a newer attempt's result.
	if result.Failure == "" {
		_, err := s.db.sql.ExecContext(ctx, `UPDATE push_outbox SET state='accepted',lease_until=0,last_error='' WHERE command_uuid=? AND device_id=? AND lease_token=? AND state='pending'`, a.CommandUUID, a.DeviceID, a.LeaseToken)
		return err
	}
	_, err := s.db.sql.ExecContext(ctx, `UPDATE push_outbox SET state=CASE WHEN ? OR attempts>=6 THEN 'exhausted' ELSE 'pending' END,lease_until=0,next_attempt=?+MIN(300,30*(1 << (attempts-1))),last_error=? WHERE command_uuid=? AND device_id=? AND lease_token=? AND state='pending'`, result.StopRetry, now.Unix(), result.Failure, a.CommandUUID, a.DeviceID, a.LeaseToken)
	return err
}

// RetryNotification starts one new bounded notification cycle for an existing
// pending command. It never creates or requeues a command.
func (db *DB) RetryNotification(ctx context.Context, device, uuid, intent, actor, provider string) error {
	if intent == "" || actor == "" {
		return errors.New("retry requires an operation key and actor")
	}
	sum := sha256.Sum256([]byte(intent))
	key := hex.EncodeToString(sum[:])
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existingDevice, existingUUID string
	err = tx.QueryRowContext(ctx, `SELECT device_id,command_uuid FROM push_retry_actions WHERE action_hash=?`, key).Scan(&existingDevice, &existingUUID)
	if err == nil {
		if existingDevice != device || existingUUID != uuid {
			return errors.New("retry key already used for a different command")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE push_outbox SET state='pending',attempts=0,next_attempt=0,lease_until=0,lease_token='',last_error='' WHERE device_id=? AND command_uuid=? AND state='exhausted' AND EXISTS(SELECT 1 FROM command_history h WHERE h.device_id=push_outbox.device_id AND h.command_uuid=push_outbox.command_uuid AND h.status IN ('Queued','Sent','NotNow')) AND NOT EXISTS(SELECT 1 FROM nano_kv WHERE bucket='enrollments' AND k=?||'.disabled')`, device, uuid, device)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("notification is not exhausted or the command is no longer pending")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO push_retry_actions(action_hash,command_uuid,device_id) VALUES(?,?,?)`, key, uuid, device); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(username,provider,action,target,result) VALUES(?,?,'command.retry-notification',?,'scheduled')`, actor, provider, device+"/"+uuid); err != nil {
		return err
	}
	return tx.Commit()
}
