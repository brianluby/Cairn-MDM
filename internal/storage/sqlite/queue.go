package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"

	"github.com/micromdm/nanomdm/mdm"
)

// EnqueueCommand commits the upstream queue representation and Cairn history
// together. No notification is attempted until this transaction commits.
func (s *nanoStore) EnqueueCommand(ctx context.Context, ids []string, cmd *mdm.Command) (map[string]error, error) {
	return s.EnqueueNotifiedCommand(ctx, ids, cmd, false)
}
func (s *nanoStore) EnqueueNotifiedCommand(ctx context.Context, ids []string, cmd *mdm.Command, notify bool) (map[string]error, error) {
	if cmd == nil || len(ids) == 0 {
		return nil, errors.New("command and target devices are required")
	}
	unique := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" {
			return nil, errors.New("empty device ID")
		}
		if !seen[id] {
			unique = append(unique, id)
			seen[id] = true
		}
	}
	tx, err := s.db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if mdmcore.CommandIntent(ctx) != "" {
		var previous []byte
		err := tx.QueryRowContext(ctx, `SELECT v FROM nano_kv WHERE bucket='queue' AND k=?`, cmd.CommandUUID+".raw").Scan(&previous)
		if err == nil {
			if !bytes.Equal(previous, cmd.Raw) {
				return nil, errors.New("operation key already used for different command content")
			}
			rows, err := tx.QueryContext(ctx, `SELECT device_id FROM command_history WHERE command_uuid=?`, cmd.CommandUUID)
			if err != nil {
				return nil, err
			}
			count := 0
			matches := true
			for rows.Next() {
				var id string
				if err = rows.Scan(&id); err != nil {
					rows.Close()
					return nil, err
				}
				count++
				if !seen[id] {
					matches = false
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, err
			}
			if !matches || count != len(unique) {
				return nil, errors.New("operation key already used for different targets")
			}
			var notifications int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM push_outbox WHERE command_uuid=?`, cmd.CommandUUID).Scan(&notifications); err != nil {
				return nil, err
			}
			if (notify && notifications != count) || (!notify && notifications != 0) {
				return nil, errors.New("operation key already used with different notification intent")
			}
			return nil, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	for _, id := range unique {
		var disabled int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM nano_kv WHERE bucket='enrollments' AND k=?`, id+".disabled").Scan(&disabled); err != nil {
			return nil, err
		}
		if disabled != 0 {
			return nil, fmt.Errorf("enrollment %s is disabled", id)
		}
	}
	perTarget, err := newNanoKV(tx, s.log).EnqueueCommand(ctx, unique, cmd)
	if err != nil {
		return perTarget, err
	}
	for _, failure := range perTarget {
		if failure != nil {
			return perTarget, fmt.Errorf("queue rolled back: %w", failure)
		}
	}
	for _, id := range unique {
		_, err = tx.ExecContext(ctx, `INSERT INTO command_history(command_uuid,device_id,request_type,status) VALUES(?,?,?,'Queued')`, cmd.CommandUUID, id, cmd.Command.RequestType)
		if err != nil {
			return nil, fmt.Errorf("queue history: %w", err)
		}
	}
	if notify {
		for _, id := range unique {
			if _, err = tx.ExecContext(ctx, `INSERT INTO push_outbox(command_uuid,device_id) VALUES(?,?)`, cmd.CommandUUID, id); err != nil {
				return nil, err
			}
		}
	}
	return nil, tx.Commit()
}

// All linked-list reads and writes use one SQL snapshot/transaction. This also
// serializes reports with enqueues from another console/CLI connection.
func (s *nanoStore) RetrieveNextCommand(r *mdm.Request, skipNotNow bool) (*mdm.Command, error) {
	tx, err := s.db.sql.BeginTx(r.Context(), nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	cmd, err := newNanoKV(tx, s.log).RetrieveNextCommand(r, skipNotNow)
	if err != nil {
		return nil, err
	}
	return cmd, tx.Commit()
}
func (s *nanoStore) StoreCommandReport(r *mdm.Request, report *mdm.CommandResults) error {
	tx, err := s.db.sql.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = newNanoKV(tx, s.log).StoreCommandReport(r, report); err != nil {
		return err
	}
	if report.Status != "Idle" {
		description := ""
		if len(report.ErrorChain) > 0 {
			e := report.ErrorChain[0]
			description = e.LocalizedDescription
			if description == "" {
				description = e.USEnglishDescription
			}
			if description == "" {
				description = fmt.Sprintf("%s error %d", e.ErrorDomain, e.ErrorCode)
			}
		}
		if err = recordCommandResult(r.Context(), tx, r.ID, report.CommandUUID, report.Status, description); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *nanoStore) ClearQueue(r *mdm.Request) error {
	tx, err := s.db.sql.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = newNanoKV(tx, s.log).ClearQueue(r); err != nil {
		return err
	}
	// Clearing the queue leaves command bodies behind; a VPN profile's holds a key.
	if _, err = withdrawVPNPayloads(r.Context(), tx, "failed", "Command queue cleared", `device_id=?`, r.ID); err != nil {
		return err
	}
	return tx.Commit()
}

// Disable cancels pending work for this enrollment and its user channels in
// the same transaction as NanoMDM's disable flag. Re-enrollment cannot inherit it.
func (s *nanoStore) Disable(r *mdm.Request) error {
	tx, err := s.db.sql.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ids := []string{r.ID}
	if r.ParentID == "" {
		prefix := r.ID + ".user_ch."
		rows, err := tx.QueryContext(r.Context(), `SELECT substr(k,length(?)+1) FROM nano_kv WHERE bucket='enrollments' AND substr(k,1,length(?))=?`, prefix, prefix, prefix)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	store := newNanoKV(tx, s.log)
	for _, id := range ids {
		request := mdm.NewRequestWithContext(r.Context(), r.Certificate)
		// Enumerate children ourselves: NanoMDM v0.9.0 returns the mapping
		// prefix instead of its child ID. Nonempty ParentID disables its traversal.
		request.EnrollID = &mdm.EnrollID{ID: id, ParentID: r.ID}
		if err = store.Disable(request); err != nil {
			return err
		}
		if err = store.ClearQueue(request); err != nil {
			return err
		}
		if _, err = tx.ExecContext(r.Context(), `UPDATE command_history SET status='Cancelled',error='Enrollment disabled',result_at=datetime('now') WHERE device_id=? AND status IN ('Queued','Sent','NotNow')`, id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(r.Context(), `UPDATE push_outbox SET state='resolved',lease_until=0,last_error='Enrollment disabled' WHERE device_id=? AND state IN ('pending','exhausted')`, id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(r.Context(), `UPDATE profile_deploys SET status='failed',updated_at=datetime('now') WHERE device_id=? AND status='sent'`, id); err != nil {
			return err
		}
		if _, err = withdrawVPNPayloads(r.Context(), tx, "failed", "Enrollment disabled", `device_id=?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
