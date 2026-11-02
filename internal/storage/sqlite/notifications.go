package sqlite

import (
	"context"
	"crypto/rand"
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

func (s *nanoStore) FinishPush(ctx context.Context, a mdmcore.PushAttempt, failure string, now time.Time) error {
	// Lease fencing prevents a late worker overwriting a newer attempt's result.
	if failure == "" {
		_, err := s.db.sql.ExecContext(ctx, `UPDATE push_outbox SET state='accepted',lease_until=0,last_error='' WHERE command_uuid=? AND device_id=? AND lease_token=? AND state='pending'`, a.CommandUUID, a.DeviceID, a.LeaseToken)
		return err
	}
	_, err := s.db.sql.ExecContext(ctx, `UPDATE push_outbox SET state=CASE WHEN attempts>=6 THEN 'exhausted' ELSE 'pending' END,lease_until=0,next_attempt=?+MIN(300,30*(1 << (attempts-1))),last_error=? WHERE command_uuid=? AND device_id=? AND lease_token=? AND state='pending'`, now.Unix(), failure, a.CommandUUID, a.DeviceID, a.LeaseToken)
	return err
}
