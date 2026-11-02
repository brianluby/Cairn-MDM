package mdmcore

import (
	"context"
	"log/slog"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/push"
)

type PushAttempt struct{ CommandUUID, DeviceID, LeaseToken string }

// NotificationStore durably couples queue acceptance to a notification intent.
// Retries send APNs wakeups only; they never enqueue another MDM command.
type NotificationStore interface {
	EnqueueNotifiedCommand(context.Context, []string, *mdm.Command, bool) (map[string]error, error)
	ClaimPush(context.Context, string, time.Time) (*PushAttempt, error)
	FinishPush(context.Context, PushAttempt, string, time.Time) error
}

// DispatchNotifications performs bounded work. An empty UUID selects any due
// command; a CLI/console action limits immediate attempts to its own UUID.
func DispatchNotifications(ctx context.Context, store NotificationStore, pusher push.Pusher, uuid string) error {
	for i := 0; i < 16; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		attempt, err := store.ClaimPush(ctx, uuid, time.Now())
		if err != nil {
			return err
		}
		if attempt == nil {
			return nil
		}
		pushCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		responses, pushErr := pusher.Push(pushCtx, []string{attempt.DeviceID})
		cancel()
		failure := ""
		response := responses[attempt.DeviceID]
		if pushErr != nil {
			failure = "APNs request failed"
		} else if response == nil {
			failure = "APNs returned no result"
		} else if response.Err != nil {
			failure = "APNs rejected the notification"
		}
		if err = store.FinishPush(ctx, *attempt, failure, time.Now()); err != nil {
			return err
		}
	}
	return nil
}

func RunNotifications(ctx context.Context, store NotificationStore, pusher push.Pusher, log *slog.Logger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if err := DispatchNotifications(ctx, store, pusher, ""); err != nil && ctx.Err() == nil {
			log.Warn("APNs notification retry failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
