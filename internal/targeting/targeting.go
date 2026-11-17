// Package targeting applies directory profile rules to enrolled devices. It binds
// a device to the verified owner behind its issued certificate, evaluates the
// saved group/OU rules against that owner's current directory facts, records the
// resulting group memberships, then hands the device to the assignment
// reconciler so the groups' profiles are pushed.
//
// A directory failure is an unknown answer: memberships are left as they were and
// the failure is recorded for the console. Nothing here removes an installed
// profile; a vanished membership only narrows what the reconciler will push.
package targeting

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// Store is what the service needs from storage. *sqlite.DB satisfies it.
type Store interface {
	BindDeviceOwner(ctx context.Context, deviceID string) (sqlite.DeviceOwner, error)
	GetDeviceOwner(ctx context.Context, deviceID string) (sqlite.DeviceOwner, error)
	ListDirectoryProfileRules(ctx context.Context) ([]sqlite.DirectoryProfileRule, error)
	ReplaceDirectoryMemberships(ctx context.Context, deviceID string, matchedRuleIDs []int64) ([]int64, error)
	RecordDirectoryUnavailable(ctx context.Context, deviceID, detail string) error
	OwnedPushableDeviceIDs(ctx context.Context) ([]string, error)
}

// Directory evaluates saved scopes against an owner's current directory object.
type Directory interface {
	EvaluateScopes(ctx context.Context, owner directory.DirectoryIdentity, scopes []directory.DirectoryScope) (*directory.DirectoryScopeEvaluation, error)
}

// Reconciler pushes the profiles a device is now entitled to.
type Reconciler interface {
	ReconcileDevice(ctx context.Context, deviceID string) error
}

// Outcome summarizes one device evaluation for logs and the console.
type Outcome struct {
	DeviceID string
	// Owned is false when the device has no verified owner; rules do not apply.
	Owned bool
	// Evaluated is true when the directory answered and memberships were replaced.
	Evaluated bool
	Matched   int
	Added     []int64
	// Detail explains a skipped or failed evaluation.
	Detail string
}

// Service is the directory-targeting coordinator.
type Service struct {
	store Store
	dir   Directory // nil when no verified directory is configured
	rec   Reconciler
	log   *slog.Logger
}

// New builds a Service. dir may be nil; rec may be nil in tests.
func New(store Store, dir Directory, rec Reconciler, log *slog.Logger) *Service {
	return &Service{store: store, dir: dir, rec: rec, log: log}
}

// DeviceNowPushable is the mdmcore.OnPushable hook: bind the owner, apply the
// rules, then reconcile. The reconcile runs even when rules cannot be applied so
// manual memberships still deliver.
func (s *Service) DeviceNowPushable(deviceID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := s.Refresh(ctx, deviceID)
	if err != nil {
		s.log.Warn("directory targeting on enroll failed", "device", deviceID, "err", err)
	} else if out.Owned {
		s.log.Info("directory targeting on enroll", "device", deviceID, "evaluated", out.Evaluated, "matched", out.Matched, "added", len(out.Added), "detail", out.Detail)
	}
	if s.rec != nil {
		if err := s.rec.ReconcileDevice(ctx, deviceID); err != nil {
			s.log.Warn("reconcile on enroll failed", "device", deviceID, "err", err)
		}
	}
}

// Refresh binds (or re-binds) the device's owner and re-evaluates the rules. It
// does not push profiles; callers reconcile afterwards. A device without a
// verified owner returns Owned=false and nil error.
func (s *Service) Refresh(ctx context.Context, deviceID string) (Outcome, error) {
	out := Outcome{DeviceID: deviceID}
	owner, err := s.store.BindDeviceOwner(ctx, deviceID)
	if errors.Is(err, sqlite.ErrNoOwner) {
		out.Detail = "no verified owner: the device did not enroll through an owner-authorized link"
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Owned = true
	rules, err := s.store.ListDirectoryProfileRules(ctx)
	if err != nil {
		return out, err
	}
	if len(rules) == 0 {
		// Nothing to evaluate; clear stale memberships from deleted rules and
		// record a successful (empty) evaluation.
		if _, err = s.store.ReplaceDirectoryMemberships(ctx, deviceID, nil); err != nil {
			return out, err
		}
		out.Evaluated = true
		return out, nil
	}
	if s.dir == nil {
		out.Detail = "directory not configured; previous memberships kept"
		return out, s.store.RecordDirectoryUnavailable(ctx, deviceID, out.Detail)
	}
	scopes := make([]directory.DirectoryScope, len(rules))
	for i, r := range rules {
		scopes[i] = r.Scope
	}
	result, err := s.dir.EvaluateScopes(ctx, owner.Owner, scopes)
	if err != nil || result == nil || len(result.Matches) != len(rules) {
		detail := "directory evaluation unavailable"
		if err != nil {
			detail += ": " + err.Error()
		}
		out.Detail = detail
		return out, s.store.RecordDirectoryUnavailable(ctx, deviceID, detail)
	}
	var matched []int64
	for i, m := range result.Matches {
		if m.Matches && m.Scope.ObjectID == rules[i].Scope.ObjectID {
			matched = append(matched, rules[i].ID)
		}
	}
	added, err := s.store.ReplaceDirectoryMemberships(ctx, deviceID, matched)
	if err != nil {
		return out, err
	}
	out.Evaluated = true
	out.Matched = len(matched)
	out.Added = added
	return out, nil
}

// RefreshAndReconcile is the console action: re-evaluate one device, then push
// whatever its memberships now entitle it to.
func (s *Service) RefreshAndReconcile(ctx context.Context, deviceID string) (Outcome, error) {
	out, err := s.Refresh(ctx, deviceID)
	if err != nil {
		return out, err
	}
	if s.rec != nil {
		if rerr := s.rec.ReconcileDevice(ctx, deviceID); rerr != nil {
			s.log.Warn("reconcile after refresh failed", "device", deviceID, "err", rerr)
		}
	}
	return out, nil
}

// Summary totals a fleet-wide refresh.
type Summary struct {
	Devices     int
	Evaluated   int
	Unavailable int
	Errors      int
}

// RefreshAll re-evaluates every owned, pushable device, one directory round per
// device, and reconciles each. It stops early when ctx ends.
func (s *Service) RefreshAll(ctx context.Context) (Summary, error) {
	var sum Summary
	ids, err := s.store.OwnedPushableDeviceIDs(ctx)
	if err != nil {
		return sum, err
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return sum, ctx.Err()
		}
		sum.Devices++
		out, err := s.RefreshAndReconcile(ctx, id)
		switch {
		case err != nil:
			sum.Errors++
			s.log.Warn("directory refresh failed", "device", id, "err", err)
		case out.Evaluated:
			sum.Evaluated++
		default:
			sum.Unavailable++
		}
	}
	return sum, nil
}
