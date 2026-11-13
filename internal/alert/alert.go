// Package alert is Cairn's out-of-band notification path. A Checker derives
// alert conditions from stored state (certificate expiry, quarantined issuances,
// backup freshness), remembers which ones it has already announced, and posts
// transitions, daily reminders and a heartbeat to a webhook. The webhook is
// independent of the MDM host's mail, so a dead host or a stuck certificate is
// noticed even when nothing else reports.
package alert

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// Notifier posts a message to the configured webhook. ntfy understands the
// Title/Priority/Tags headers; other receivers see a plain text body.
type Notifier struct {
	url    string
	client *http.Client
}

// NewNotifier returns a Notifier for url, or nil when url is empty.
func NewNotifier(url string) *Notifier {
	if url == "" {
		return nil
	}
	return &Notifier{url: url, client: &http.Client{Timeout: 10 * time.Second}}
}

// Send posts one message. priority is an ntfy level: min, low, default, high, urgent.
func (n *Notifier) Send(ctx context.Context, title, body, priority string) error {
	if n == nil {
		return errors.New("alerts: no webhook configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Title", title)
	if priority != "" {
		req.Header.Set("Priority", priority)
	}
	req.Header.Set("User-Agent", "cairn-alerts")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("alerts: webhook returned %s", resp.Status)
	}
	return nil
}

// Store is what the Checker reads and remembers. *sqlite.DB satisfies it.
type Store interface {
	ListAPNSTopics(ctx context.Context) ([]sqlite.APNSTopic, error)
	ListQuarantined(ctx context.Context) ([]sqlite.Issuance, error)
	ListAlertStates(ctx context.Context) ([]sqlite.AlertState, error)
	SetAlertState(ctx context.Context, key string, active bool, message string, notified bool) error
}

// lifecycleSource is the optional store capability behind renewal and device
// certificate expiry conditions. *sqlite.DB satisfies it.
type lifecycleSource interface {
	ListRenewalAttempts(ctx context.Context, since time.Time, limit int) ([]sqlite.RenewalAttempt, error)
	DeviceCertificates(ctx context.Context) ([]sqlite.DeviceCertificate, error)
}

// observedSource is the optional store capability behind the conditions for
// certificates devices present at check-in. *sqlite.DB satisfies it.
type observedSource interface {
	ObservedDeviceCertificates(ctx context.Context) ([]sqlite.ObservedCertificate, error)
}

// identityConditions reports devices whose check-in certificate has expired or
// expires within 30 days. An expired one locks the device out of management:
// it can be told nothing, so it has to enroll again by hand. Thirty days leaves
// time to reach a remote device while it still listens.
func identityConditions(ctx context.Context, src observedSource, now time.Time) ([]Condition, error) {
	certs, err := src.ObservedDeviceCertificates(ctx)
	if err != nil {
		return nil, err
	}
	var expiring, expired []string
	for _, c := range certs {
		switch {
		case !c.NotAfter.After(now):
			expired = append(expired, c.DeviceName)
		case c.NotAfter.Sub(now) < 30*24*time.Hour:
			expiring = append(expiring, fmt.Sprintf("%s (%s)", c.DeviceName, c.NotAfter.Format("2006-01-02")))
		}
	}
	var out []Condition
	if len(expired) > 0 {
		sort.Strings(expired)
		out = append(out, Condition{Key: "identity.expired", Title: "Cairn: devices locked out by an expired certificate", Message: "These devices can no longer check in because their identity certificate expired: " + strings.Join(expired, ", ") + ". Each has to remove the management profile and enroll again with a new link.", Priority: "urgent"})
	}
	if len(expiring) > 0 {
		sort.Strings(expiring)
		out = append(out, Condition{Key: "identity.expiring", Title: "Cairn: device certificates expire within 30 days", Message: "Enroll these devices again before the date shown, or they lose management and cannot be reached: " + strings.Join(expiring, ", ") + ".", Priority: "high"})
	}
	return out, nil
}

// vpnSource is the optional store capability behind the VPN certificate
// conditions. *sqlite.DB satisfies it.
type vpnSource interface {
	CurrentVPNIdentities(ctx context.Context) ([]sqlite.VPNIdentity, error)
	QuarantinedVPNIdentities(ctx context.Context) ([]sqlite.VPNIdentity, error)
	VPNIdentitiesAwaitingRevocation(ctx context.Context) ([]sqlite.VPNIdentity, error)
}

// vpnConditions reports VPN certificates near or past expiry, requests held
// after an untrusted CA answer, and retired certificates the CA has not revoked.
func vpnConditions(ctx context.Context, src vpnSource, now time.Time) ([]Condition, error) {
	var out []Condition
	current, err := src.CurrentVPNIdentities(ctx)
	if err != nil {
		return nil, err
	}
	var expiring, expired []string
	for _, v := range current {
		if v.DeployStatus != "installed" {
			continue
		}
		exp := v.Expires()
		who := fmt.Sprintf("%s on %s", v.Owner.AccountName, v.DeviceID)
		switch {
		case !exp.After(now):
			expired = append(expired, who)
		case exp.Sub(now) < 30*24*time.Hour:
			expiring = append(expiring, fmt.Sprintf("%s (%s)", who, exp.Format("2006-01-02")))
		}
	}
	if len(expired) > 0 {
		out = append(out, Condition{Key: "vpn-cert.expired", Title: "Cairn: VPN certificate EXPIRED", Message: "VPN certificates have expired for: " + strings.Join(expired, ", ") + ". Send a new VPN profile from each device's page while the device can still reach Cairn.", Priority: "urgent"})
	}
	if len(expiring) > 0 {
		out = append(out, Condition{Key: "vpn-cert.expiring", Title: "Cairn: VPN certificates expire within 30 days", Message: "Send a new VPN profile before expiry: " + strings.Join(expiring, ", ") + ".", Priority: "high"})
	}
	held, err := src.QuarantinedVPNIdentities(ctx)
	if err != nil {
		return nil, err
	}
	if len(held) > 0 {
		out = append(out, Condition{Key: "vpn.held", Title: "Cairn: VPN certificate requests held", Message: fmt.Sprintf("%d VPN certificate request(s) are held after a certificate authority answer that could not be trusted. Review the VPN page.", len(held)), Priority: "high"})
	}
	waiting, err := src.VPNIdentitiesAwaitingRevocation(ctx)
	if err != nil {
		return nil, err
	}
	var serials []string
	for _, v := range waiting {
		// The hourly sweep revokes where the CA allows it; only what outlasts
		// two sweeps needs a person.
		if t, perr := time.Parse("2006-01-02 15:04:05", v.UpdatedAt); perr == nil && now.Sub(t) > 2*time.Hour {
			serials = append(serials, v.CertSerial)
		}
	}
	if len(serials) > 0 {
		out = append(out, Condition{Key: "vpn.revocation-pending", Title: "Cairn: VPN certificates to revoke at the CA", Message: "Retired in Cairn but not revoked at the certificate authority: " + strings.Join(serials, ", ") + ". Revoke them there and confirm on the VPN page.", Priority: "high"})
	}
	return out, nil
}

// Condition is one active alert.
type Condition struct {
	Key      string
	Title    string
	Message  string
	Priority string
}

// Checker evaluates conditions and drives the Notifier.
type Checker struct {
	store    Store
	notifier *Notifier
	cfg      config.Alerts
	log      *slog.Logger
	now      func() time.Time
	// remindAfter is how long an unresolved condition waits before a reminder.
	remindAfter time.Duration
}

// HeartbeatKey is the alert_state row that records the last heartbeat.
const HeartbeatKey = "heartbeat"

// New builds a Checker. notifier may be nil (conditions are still recorded for
// the console, nothing is sent).
func New(store Store, notifier *Notifier, cfg config.Alerts, log *slog.Logger) *Checker {
	return &Checker{store: store, notifier: notifier, cfg: cfg.WithDefaults(), log: log, now: time.Now, remindAfter: 24 * time.Hour}
}

// Evaluate derives the currently active conditions without sending anything.
func (c *Checker) Evaluate(ctx context.Context) ([]Condition, error) {
	var out []Condition
	topics, err := c.store.ListAPNSTopics(ctx)
	if err != nil {
		return nil, err
	}
	now := c.now()
	if len(topics) == 0 {
		out = append(out, Condition{Key: "apns.missing", Title: "Cairn: no APNs push certificate", Message: "No APNs push certificate is loaded. Devices cannot enroll or receive commands.", Priority: "high"})
	}
	for _, t := range topics {
		exp, perr := time.Parse(time.RFC3339, t.NotAfter)
		if perr != nil {
			out = append(out, Condition{Key: "apns.unreadable:" + t.Topic, Title: "Cairn: APNs expiry unreadable", Message: "Topic " + t.Topic + " has an unreadable expiry (" + t.NotAfter + ").", Priority: "high"})
			continue
		}
		days := int(exp.Sub(now).Hours() / 24)
		switch {
		case !exp.After(now):
			out = append(out, Condition{Key: "apns.expired:" + t.Topic, Title: "Cairn: APNs certificate EXPIRED", Message: fmt.Sprintf("Topic %s expired %s. Devices on this topic cannot be reached until it is renewed.", t.Topic, exp.Format("2006-01-02")), Priority: "urgent"})
		case days < c.cfg.APNSWarnDays:
			out = append(out, Condition{Key: "apns.expiring:" + t.Topic, Title: "Cairn: APNs certificate expires soon", Message: fmt.Sprintf("Topic %s expires %s (%d days). Renew it from the APNs page.", t.Topic, exp.Format("2006-01-02"), days), Priority: "high"})
		}
	}
	held, err := c.store.ListQuarantined(ctx)
	if err != nil {
		return nil, err
	}
	if len(held) > 0 {
		out = append(out, Condition{Key: "issuance.quarantined", Title: "Cairn: certificate issuances quarantined", Message: fmt.Sprintf("%d certificate issuance(s) are held after an ambiguous CA outcome. Review the Quarantine page.", len(held)), Priority: "high"})
	}
	if os, ok := c.store.(observedSource); ok {
		conds, err := identityConditions(ctx, os, now)
		if err != nil {
			return nil, err
		}
		out = append(out, conds...)
	}
	if vs, ok := c.store.(vpnSource); ok {
		conds, err := vpnConditions(ctx, vs, now)
		if err != nil {
			return nil, err
		}
		out = append(out, conds...)
	}
	if lc, ok := c.store.(lifecycleSource); ok {
		attempts, err := lc.ListRenewalAttempts(ctx, now.Add(-7*24*time.Hour), 50)
		if err != nil {
			return nil, err
		}
		if len(attempts) > 0 {
			names := map[string]bool{}
			var list []string
			for _, a := range attempts {
				n := a.DeviceName
				if n == "" {
					n = "unknown device (signer " + a.SignerSerial + ")"
				}
				if !names[n] {
					names[n] = true
					list = append(list, n)
				}
			}
			sort.Strings(list)
			out = append(out, Condition{Key: "renewal.refused", Title: "Cairn: device tried to renew its certificate", Message: fmt.Sprintf("%d renewal attempt(s) in the last 7 days were refused; renewal is not available in this release. Issue a new enrollment link for: %s.", len(attempts), strings.Join(list, ", ")), Priority: "high"})
		}
		certs, err := lc.DeviceCertificates(ctx)
		if err != nil {
			return nil, err
		}
		var expiring, expired []string
		for _, dc := range certs {
			if dc.Revoked {
				continue
			}
			switch {
			case !dc.NotAfter.After(now):
				expired = append(expired, dc.DeviceName)
			case dc.NotAfter.Sub(now) < 14*24*time.Hour:
				expiring = append(expiring, fmt.Sprintf("%s (%s)", dc.DeviceName, dc.NotAfter.Format("2006-01-02")))
			}
		}
		if len(expired) > 0 {
			sort.Strings(expired)
			out = append(out, Condition{Key: "device-cert.expired", Title: "Cairn: device certificate EXPIRED", Message: "Expired device identity certificate(s) still associated with: " + strings.Join(expired, ", ") + ". Re-enroll these devices; network access with the old certificate will fail.", Priority: "urgent"})
		}
		if len(expiring) > 0 {
			sort.Strings(expiring)
			out = append(out, Condition{Key: "device-cert.expiring", Title: "Cairn: device certificates expire within 14 days", Message: "Re-enroll before expiry (no renewal path in this release): " + strings.Join(expiring, ", ") + ".", Priority: "high"})
		}
	}
	if c.cfg.BackupDir != "" {
		newest, berr := newestBackup(c.cfg.BackupDir)
		maxAge := time.Duration(c.cfg.BackupMaxAgeHours) * time.Hour
		switch {
		case berr != nil:
			out = append(out, Condition{Key: "backup.unreadable", Title: "Cairn: backup directory unreadable", Message: "Cannot read " + c.cfg.BackupDir + ": " + berr.Error(), Priority: "high"})
		case newest.IsZero():
			out = append(out, Condition{Key: "backup.missing", Title: "Cairn: no backup found", Message: "No backup bundle exists in " + c.cfg.BackupDir + ".", Priority: "high"})
		case now.Sub(newest) > maxAge:
			out = append(out, Condition{Key: "backup.stale", Title: "Cairn: backup is stale", Message: fmt.Sprintf("Newest backup in %s is from %s, older than %d hours.", c.cfg.BackupDir, newest.Format("2006-01-02 15:04"), c.cfg.BackupMaxAgeHours), Priority: "high"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// newestBackup returns the modification time of the newest bundle in dir
// (zero when none).
func newestBackup(dir string) (time.Time, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return time.Time{}, err
	}
	var newest time.Time
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".tar.gz") && !strings.HasSuffix(name, ".db") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	_ = filepath.Base
	return newest, nil
}

// Run evaluates once and reconciles against remembered state: new conditions
// are announced, persisting ones reminded daily, cleared ones reported as
// resolved, and a heartbeat sent on its schedule. Delivery failures leave the
// state unnotified so the next run retries.
func (c *Checker) Run(ctx context.Context) error {
	conditions, err := c.Evaluate(ctx)
	if err != nil {
		return err
	}
	states, err := c.store.ListAlertStates(ctx)
	if err != nil {
		return err
	}
	remembered := map[string]sqlite.AlertState{}
	for _, s := range states {
		remembered[s.Key] = s
	}
	now := c.now()
	active := map[string]bool{}
	for _, cond := range conditions {
		active[cond.Key] = true
		prev, known := remembered[cond.Key]
		switch {
		case !known || !prev.Active || !prev.NotifiedAt.Valid:
			sent := c.send(ctx, cond.Title, cond.Message, cond.Priority)
			if err := c.store.SetAlertState(ctx, cond.Key, true, cond.Message, sent); err != nil {
				return err
			}
		case c.older(prev.NotifiedAt.String, now, c.remindAfter):
			sent := c.send(ctx, cond.Title+" (still active)", cond.Message, cond.Priority)
			if err := c.store.SetAlertState(ctx, cond.Key, true, cond.Message, sent); err != nil {
				return err
			}
		}
	}
	for key, prev := range remembered {
		if key == HeartbeatKey || !prev.Active || active[key] {
			continue
		}
		sent := c.send(ctx, "Cairn: resolved", key+" cleared. Previous message: "+prev.Message, "default")
		if err := c.store.SetAlertState(ctx, key, false, prev.Message, sent); err != nil {
			return err
		}
	}
	hb, known := remembered[HeartbeatKey]
	if !known || !hb.NotifiedAt.Valid || c.older(hb.NotifiedAt.String, now, time.Duration(c.cfg.HeartbeatHours)*time.Hour) {
		summary := fmt.Sprintf("Cairn is running. %d alert(s) active.", len(conditions))
		sent := c.send(ctx, "Cairn heartbeat", summary, "min")
		if err := c.store.SetAlertState(ctx, HeartbeatKey, len(conditions) > 0, summary, sent); err != nil {
			return err
		}
	}
	return nil
}

// older reports whether a stored datetime('now') value is more than d before now.
func (c *Checker) older(stamp string, now time.Time, d time.Duration) bool {
	t, err := time.Parse("2006-01-02 15:04:05", stamp)
	if err != nil {
		return true
	}
	return now.Sub(t) > d
}

func (c *Checker) send(ctx context.Context, title, body, priority string) bool {
	if c.notifier == nil {
		return false
	}
	if err := c.notifier.Send(ctx, title, body, priority); err != nil {
		c.log.Warn("alert delivery failed", "title", title, "err", err)
		return false
	}
	c.log.Info("alert sent", "title", title)
	return true
}

// Loop runs Run every interval until ctx ends. The first run happens after a
// short delay so a restarting server finishes coming up first.
func (c *Checker) Loop(ctx context.Context, interval time.Duration) {
	first := time.NewTimer(time.Minute)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
	}
	for {
		if err := c.Run(ctx); err != nil {
			c.log.Warn("alert check failed", "err", err)
		}
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
