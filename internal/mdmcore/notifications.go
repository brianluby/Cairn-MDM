package mdmcore

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/push"
	"github.com/micromdm/nanomdm/push/nanopush"
)

type PushAttempt struct{ CommandUUID, DeviceID, LeaseToken string }

// PushResult stores a sanitized outcome, never raw provider text or tokens.
type PushResult struct {
	Failure   string
	StopRetry bool
}

func classifyPushError(err error) PushResult {
	result := PushResult{Failure: "APNs rejected the notification"}
	var response *nanopush.JSONPushError
	if !errors.As(err, &response) || response == nil {
		return result
	}
	switch response.Reason {
	case "BadDeviceToken", "DeviceTokenNotForTopic", "Forbidden", "ExpiredToken", "Unregistered", "PayloadTooLarge", "BadCertificate", "BadCertificateEnvironment", "TopicDisallowed", "MissingTopic", "BadTopic", "BadPayload", "PayloadEmpty":
		result.Failure = "APNs: " + response.Reason + "; correct the cause before retrying"
		result.StopRetry = true
	case "TooManyRequests", "InternalServerError", "ServiceUnavailable", "Shutdown":
		result.Failure = "APNs: " + response.Reason
	}
	return result
}

// NotificationStore durably couples queue acceptance to a notification intent.
// Retries send APNs wakeups only; they never enqueue another MDM command.
type NotificationStore interface {
	EnqueueNotifiedCommand(context.Context, []string, *mdm.Command, bool) (map[string]error, error)
	ClaimPush(context.Context, string, time.Time) (*PushAttempt, error)
	FinishPush(context.Context, PushAttempt, PushResult, time.Time) error
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
		result := PushResult{}
		response := responses[attempt.DeviceID]
		if pushErr != nil {
			result.Failure = "APNs request failed"
		} else if response == nil {
			result.Failure = "APNs returned no result"
		} else if response.Err != nil {
			result = classifyPushError(response.Err)
		}
		if err = store.FinishPush(ctx, *attempt, result, time.Now()); err != nil {
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
