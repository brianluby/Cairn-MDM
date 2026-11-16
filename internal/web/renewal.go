package web

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/renew"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// Renewals starts identity certificate renewals and says where a device
// stands. *renew.Service satisfies it.
type Renewals interface {
	Renew(ctx context.Context, deviceID, actor string) error
	Status(sqlite.RenewalCandidate) renew.Status
}

// renewalStore is the store capability behind the device page's renewal rows.
type renewalStore interface {
	RenewalCandidate(ctx context.Context, deviceID string) (sqlite.RenewalCandidate, bool, error)
	DeviceRenewals(ctx context.Context, deviceID string, limit int) ([]sqlite.Renewal, error)
}

// SetIdentityPolicy tells the console how expired identity certificates are
// treated. renewals is nil when Cairn does not renew them; automatic is false
// when renewals start only from the device page.
func (a *App) SetIdentityPolicy(expiredGrace time.Duration, renewals Renewals, automatic bool) {
	a.identityGrace, a.renewals, a.renewalsAutomatic = expiredGrace, renewals, automatic
}

// identityView is what the device page shows about the certificate the device
// checks in with.
type identityView struct {
	State      string // valid | grace | refused
	GraceUntil time.Time
	Renewing   bool   // Cairn renews this device on its own schedule
	CanRenew   bool   // show the button
	InProgress bool   // an attempt is waiting on the device
	Off        bool   // this server does not renew certificates
	Blocked    string // why renewal cannot run
	Attempts   []sqlite.Renewal
}

func (a *App) identityView(ctx context.Context, deviceID string) (identityView, bool) {
	rs, ok := a.devices.(renewalStore)
	if !ok {
		return identityView{}, false
	}
	c, found, err := rs.RenewalCandidate(ctx, deviceID)
	if err != nil || !found {
		if err != nil {
			a.log.Error("device identity certificate", "id", deviceID, "err", err)
		}
		return identityView{}, false
	}
	now := time.Now()
	v := identityView{State: "valid", GraceUntil: c.NotAfter.Add(a.identityGrace), Renewing: a.renewals != nil && a.renewalsAutomatic}
	switch {
	case now.Before(c.NotAfter):
	case a.identityGrace > 0 && now.Before(v.GraceUntil):
		v.State = "grace"
	default:
		v.State = "refused"
	}
	v.Off = a.renewals == nil
	if a.renewals != nil {
		v.Blocked = a.renewals.Status(c).Blocked
		v.InProgress = c.Last.Open()
		v.CanRenew = v.State != "refused" && v.Blocked == "" && !c.Last.Open()
	}
	if v.Attempts, err = rs.DeviceRenewals(ctx, deviceID, 5); err != nil {
		a.log.Error("device renewals", "id", deviceID, "err", err)
	}
	return v, true
}

// handleDeviceRenew starts a renewal of the device's identity certificate.
// Admin-only: it replaces the device's enrollment profile.
func (a *App) handleDeviceRenew(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	back := "/admin/devices/" + id
	if _, err := a.devices.GetDevice(r.Context(), id); err != nil {
		http.NotFound(w, r)
		return
	}
	flash := "Renewal started. The device is asked for its profile list, then sent its enrollment profile again. This page shows each step."
	if a.renewals == nil {
		flash = "Certificate renewal is not turned on for this server."
	} else if err := a.renewals.Renew(r.Context(), id, sessionFrom(r).Identity.Username); err != nil {
		a.log.Warn("device renewal", "id", id, "user", sessionFrom(r).Identity.Username, "err", err)
		flash = "Renewal did not start: " + err.Error()
	}
	http.Redirect(w, r, back+"?flash="+url.QueryEscape(flash), http.StatusSeeOther)
}
