// Package push wraps NanoMDM's APNs push stack and the APNs push-certificate
// lifecycle. The push certificate (from mdmcert.download or Apple Business
// Manager) is stored in the same storage backend as everything else; its topic
// is what ties enrolled devices to this server.
package push

import (
	"time"

	nanolog "github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanomdm/push"
	"github.com/micromdm/nanomdm/push/nanopush"
	pushsvc "github.com/micromdm/nanomdm/push/service"
	"github.com/micromdm/nanomdm/storage"
)

// SettingTopic is the settings key under which the active APNs topic is cached
// so enrollment-profile generation can read it without knowing it in advance.
const SettingTopic = "apns_topic"

// SettingNotAfter caches the push certificate expiry (RFC3339) for renewal UX.
const SettingNotAfter = "apns_not_after"

// NewPusher builds a NanoMDM push service over the given storage. The returned
// Pusher looks up each enrollment's topic + push token and the stored push
// certificate to deliver APNs notifications.
func NewPusher(store storage.AllStorage, logger nanolog.Logger) push.Pusher {
	return pushsvc.New(store, store, nanopush.NewFactory(), logger.With("service", "push"))
}

// RenewalTier maps a push certificate's expiry to a renewal alert tier. It
// returns the whole days remaining (negative once expired), a severity token
// used for UI styling (critical|high|warning|caution|notice|ok), and a short
// human label. Thresholds escalate at 90/60/30/14/7 days so a second fleet's
// nearer expiry can never hide behind a later one.
func RenewalTier(notAfter time.Time) (days int, severity, label string) {
	days = int(time.Until(notAfter).Hours() / 24)
	switch {
	case days < 0:
		return days, "critical", "expired"
	case days <= 7:
		return days, "critical", "renew now"
	case days <= 14:
		return days, "high", "renew now"
	case days <= 30:
		return days, "warning", "renew soon"
	case days <= 60:
		return days, "caution", "plan renewal"
	case days <= 90:
		return days, "notice", "upcoming"
	default:
		return days, "ok", "ok"
	}
}
