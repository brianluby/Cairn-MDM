package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/vpn"
)

// ManualDeviceStore keeps the devices outside MDM; *sqlite.DB provides it.
type ManualDeviceStore interface {
	CreateManualDevice(ctx context.Context, d sqlite.ManualDevice) (int64, error)
	GetManualDevice(ctx context.Context, id int64) (sqlite.ManualDevice, error)
	ListManualDevices(ctx context.Context) ([]sqlite.ManualDevice, error)
	RemoveManualDevice(ctx context.Context, id int64, actor string) error
}

// ManualIssuer hands out profiles for devices outside MDM; *vpn.Service
// provides it.
type ManualIssuer interface {
	DownloadManual(ctx context.Context, manualID, serverID int64, actor string) (filename string, profile []byte, err error)
}

// SetManualDevices turns on the page for devices outside MDM. warnDays is how
// long before a certificate expires the page marks it.
func (a *App) SetManualDevices(store ManualDeviceStore, issuer ManualIssuer, warnDays int) {
	a.manualDevices, a.manualIssuer, a.manualWarnDays = store, issuer, warnDays
}

const otherDevicesPath = "/admin/other-devices"

func (a *App) registerManual(mux *http.ServeMux) {
	mux.Handle("GET "+otherDevicesPath, a.requireRole(auth.RoleAdmin, a.handleOtherDevices))
	mux.Handle("POST "+otherDevicesPath, a.audited(a.requireRole(auth.RoleAdmin, a.handleOtherDeviceCreate)))
	mux.Handle("POST "+otherDevicesPath+"/{id}/wifi/{server}/download", a.audited(a.requireRole(auth.RoleAdmin, a.handleOtherDeviceDownload)))
	mux.Handle("POST "+otherDevicesPath+"/{id}/remove", a.audited(a.requireRole(auth.RoleAdmin, a.handleOtherDeviceRemove)))
}

// manualKinds are the device types offered on the form, in order.
var manualKinds = []struct{ Value, Label string }{
	{"homepod", "HomePod"}, {"visionpro", "Apple Vision Pro"}, {"watch", "Apple Watch"}, {"appletv", "Apple TV"}, {"other", "Other"},
}

func manualKindLabel(kind string) string {
	for _, k := range manualKinds {
		if k.Value == kind {
			return k.Label
		}
	}
	return "Other"
}

// manualNetworkRow is one Wi-Fi network's state on one device outside MDM.
type manualNetworkRow struct {
	Server   vpn.Server
	Current  *sqlite.VPNIdentity // the certificate the device holds, if any
	IssuedOn string
	Expires  string
	DaysLeft int
	Expiring bool // inside the warning window, or already expired
	Pending  bool // a profile was downloaded and has not been installed yet
}

type manualDeviceRow struct {
	sqlite.ManualDevice
	KindLabel string
	Networks  []manualNetworkRow
	Held      bool // holds a certificate, so it cannot be removed yet
}

func (a *App) manualAvailable(w http.ResponseWriter) bool {
	if !a.vpnAvailable(w) {
		return false
	}
	if a.manualDevices == nil {
		http.Error(w, "Profiles for devices outside MDM are not available on this server.", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (a *App) handleOtherDevices(w http.ResponseWriter, r *http.Request) {
	if !a.manualAvailable(w) {
		return
	}
	ctx := r.Context()
	devices, err := a.manualDevices.ListManualDevices(ctx)
	if err != nil {
		a.log.Error("list manual devices", "err", err)
		http.Error(w, "Cannot read the device list.", http.StatusInternalServerError)
		return
	}
	var networks []vpn.Server
	if all, err := a.vpn.List(ctx); err == nil {
		for _, s := range all {
			if s.IsWiFi() {
				networks = append(networks, s)
			}
		}
	} else {
		a.log.Error("list vpn servers", "err", err)
	}
	now := time.Now()
	rows := make([]manualDeviceRow, 0, len(devices))
	for _, d := range devices {
		row := manualDeviceRow{ManualDevice: d, KindLabel: manualKindLabel(d.Kind)}
		current := map[int64]*sqlite.VPNIdentity{}
		pending := map[int64]bool{}
		if a.vpnIdentities != nil {
			if list, err := a.vpnIdentities.DeviceVPNIdentities(ctx, d.DeviceID()); err == nil {
				for i := range list {
					if v := &list[i]; v.Current() && current[v.ServerID] == nil {
						current[v.ServerID] = v
						row.Held = true
					}
				}
			}
			if offers, err := a.vpnIdentities.OpenVPNOffers(ctx, d.DeviceID()); err == nil {
				for _, o := range offers {
					pending[o.ServerID] = o.ExpiresAt > now.UTC().Format(time.RFC3339)
				}
			}
		}
		for _, s := range networks {
			n := manualNetworkRow{Server: s, Current: current[s.ID], Pending: pending[s.ID]}
			if v := n.Current; v != nil {
				if len(v.CreatedAt) >= 10 {
					n.IssuedOn = v.CreatedAt[:10]
				}
				if exp := v.Expires(); !exp.IsZero() {
					n.Expires = exp.Format("2006-01-02")
					n.DaysLeft = int(exp.Sub(now).Hours() / 24)
					n.Expiring = exp.Sub(now) < time.Duration(a.manualWarnDays)*24*time.Hour
				}
			}
			row.Networks = append(row.Networks, n)
		}
		rows = append(rows, row)
	}
	a.render(w, r, http.StatusOK, "other_devices.html", map[string]any{
		"Title": "Other devices", "Devices": rows, "Networks": networks, "Kinds": manualKinds,
		"Flash": r.URL.Query().Get("flash"), "IssuerMissing": a.vpnIssuerMissing, "WarnDays": a.manualWarnDays,
	})
}

func otherDevicesFlash(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, otherDevicesPath+"?flash="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (a *App) handleOtherDeviceCreate(w http.ResponseWriter, r *http.Request) {
	if !a.vpnIssueGate(w, r) || !a.manualAvailable(w) {
		return
	}
	actor := sessionFrom(r).Identity.Username
	owner, err := a.directory.ResolveOwner(r.Context(), strings.TrimSpace(r.PostFormValue("account")))
	if err != nil || owner == nil {
		otherDevicesFlash(w, r, "Device not added: the account is disabled, missing or cannot be verified in the directory.")
		return
	}
	id, err := a.manualDevices.CreateManualDevice(r.Context(), sqlite.ManualDevice{
		Name: r.PostFormValue("name"), Kind: r.PostFormValue("kind"), Owner: *owner, CreatedBy: actor,
	})
	if err != nil {
		otherDevicesFlash(w, r, "Device not added: "+err.Error()+".")
		return
	}
	a.log.Info("manual device added", "device", sqlite.ManualDeviceID(id), "owner", owner.UPN, "user", actor)
	otherDevicesFlash(w, r, "Device added. Download its Wi-Fi profile when you are ready to install it.")
}

func (a *App) handleOtherDeviceDownload(w http.ResponseWriter, r *http.Request) {
	if !a.vpnIssueGate(w, r) || !a.manualAvailable(w) {
		return
	}
	id, err1 := strconv.ParseInt(r.PathValue("id"), 10, 64)
	serverID, err2 := strconv.ParseInt(r.PathValue("server"), 10, 64)
	if err1 != nil || err2 != nil || a.manualIssuer == nil {
		http.NotFound(w, r)
		return
	}
	actor := sessionFrom(r).Identity.Username
	name, body, err := a.manualIssuer.DownloadManual(r.Context(), id, serverID, actor)
	if err != nil {
		a.log.Warn("manual profile download refused", "device", sqlite.ManualDeviceID(id), "server", serverID, "user", actor, "err", err)
		otherDevicesFlash(w, r, "No profile: "+vpnFormError(err))
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (a *App) handleOtherDeviceRemove(w http.ResponseWriter, r *http.Request) {
	if !a.vpnIssueGate(w, r) || !a.manualAvailable(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	err = a.manualDevices.RemoveManualDevice(r.Context(), id, sessionFrom(r).Identity.Username)
	switch {
	case errors.Is(err, sqlite.ErrManualDeviceInUse):
		otherDevicesFlash(w, r, "Not removed: this device still holds a certificate. Revoke it first.")
	case err != nil:
		otherDevicesFlash(w, r, "Not removed: the device is not on the list.")
	default:
		otherDevicesFlash(w, r, "Device removed from the list. Nothing was changed on the device itself.")
	}
}

// deviceHome is the page that shows a device's certificates: its own page for
// an enrolled device, the list for one outside MDM.
func deviceHome(deviceID string) string {
	if _, manual := sqlite.ParseManualDeviceID(deviceID); manual {
		return otherDevicesPath
	}
	return "/admin/devices/" + url.PathEscape(deviceID)
}
