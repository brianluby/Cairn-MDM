package sqlite

import (
	"context"
	"errors"
	"fmt"

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
	return tx.Commit()
}
