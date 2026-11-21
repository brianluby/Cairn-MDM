package vpn_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/micromdm/plist"

	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/vpn"
)

// profileChallenge reads the SCEP challenge out of a downloaded profile.
func profileChallenge(t *testing.T, profile []byte) string {
	t.Helper()
	if err := vpn.CheckWiFi(profile); err != nil {
		t.Fatalf("downloaded profile fails its checks: %v", err)
	}
	var top map[string]any
	if err := plist.Unmarshal(profile, &top); err != nil {
		t.Fatal(err)
	}
	for _, raw := range top["PayloadContent"].([]any) {
		if p := raw.(map[string]any); p["PayloadType"] == "com.apple.security.scep" {
			return p["PayloadContent"].(map[string]any)["Challenge"].(string)
		}
	}
	t.Fatal("profile has no SCEP payload")
	return ""
}

// manualFixture is a Wi-Fi network, one device outside MDM owned by alice, and
// a service with a two-year lifetime for such devices and a movable clock.
func manualFixture(t *testing.T) (f *fixture, svc *vpn.Service, wifi, device int64, clock *time.Time) {
	t.Helper()
	f = setup(t)
	ctx := context.Background()
	wifi = f.wifiNetwork(t)
	now := time.Now()
	clock = &now
	day := 24 * time.Hour
	svc, err := vpn.NewService(f.servers, f.db, f.dir, f.backend, f.cmd, vpn.Options{
		Organization: "org.example", DeviceSCEPURL: "https://mdm.example.org/scep/vpn",
		Policy:       issue.Policy{LeafValidity: 365 * day, Backdate: 5 * time.Minute},
		ManualPolicy: issue.Policy{LeafValidity: 730 * day, Backdate: 5 * time.Minute},
		RenewBefore:  800 * day, // every certificate is inside the renewal window
		Now:          func() time.Time { return *clock },
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	device, err = f.db.CreateManualDevice(ctx, sqlite.ManualDevice{Name: "Kitchen HomePod", Kind: "homepod", Owner: f.dir.owner, CreatedBy: "nick"})
	if err != nil {
		t.Fatal(err)
	}
	return f, svc, wifi, device, clock
}

func TestManualDeviceGetsACertificateFromADownloadedProfile(t *testing.T) {
	ctx := context.Background()
	f, svc, wifi, device, clock := manualFixture(t)
	deviceID := sqlite.ManualDeviceID(device)

	name, profile, err := svc.DownloadManual(ctx, device, wifi, "nick")
	if err != nil {
		t.Fatal(err)
	}
	if name != "office-wifi-kitchen-homepod.mobileconfig" {
		t.Errorf("file name = %q", name)
	}
	challenge := profileChallenge(t, profile)
	if list, _ := f.db.DeviceVPNIdentities(ctx, deviceID); len(list) != 0 {
		t.Fatal("a certificate was requested before the device asked")
	}
	if cmd := f.device(t, "PHONE1", ""); cmd != nil {
		t.Fatal("a command was queued for an enrolled device")
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf, err := svc.SignCSRContext(ctx, requestWithKey(t, key, "alice", challenge))
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "alice" || !key.PublicKey.Equal(leaf.PublicKey) {
		t.Fatalf("leaf subject = %q", leaf.Subject.CommonName)
	}
	if life := leaf.NotAfter.Sub(leaf.NotBefore); life < 729*24*time.Hour || life > 731*24*time.Hour {
		t.Errorf("certificate lifetime = %s, want the two years set for devices outside MDM", life)
	}
	rows, _ := f.db.DeviceVPNIdentities(ctx, deviceID)
	if len(rows) != 1 || rows[0].State != sqlite.VPNIssued || rows[0].DeployStatus != "installed" || rows[0].Actor != "nick" {
		t.Fatalf("identity rows = %+v", rows)
	}

	// The same key may ask again while the profile is still good; no other key may.
	if again, err := svc.SignCSRContext(ctx, requestWithKey(t, key, "alice", challenge)); err != nil || !again.Equal(leaf) {
		t.Fatalf("repeat request: %v", err)
	}
	if _, err = svc.SignCSRContext(ctx, deviceRequest(t, "alice", challenge)); err == nil {
		t.Fatal("a second key was certified with a used challenge")
	}
	*clock = clock.Add(11 * time.Minute)
	if _, err = svc.SignCSRContext(ctx, requestWithKey(t, key, "alice", challenge)); err == nil {
		t.Fatal("the challenge still works after its ten minutes")
	}

	// The sweep cannot renew a device outside MDM and must not try.
	svc.Sweep(ctx)
	if rows, _ = f.db.DeviceVPNIdentities(ctx, deviceID); len(rows) != 1 || rows[0].State != sqlite.VPNIssued {
		t.Fatalf("identity rows after the sweep = %+v", rows)
	}

	// A new download and install replaces the certificate.
	_, profile, err = svc.DownloadManual(ctx, device, wifi, "nick")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SignCSRContext(ctx, deviceRequest(t, "alice", profileChallenge(t, profile))); err != nil {
		t.Fatal(err)
	}
	rows, _ = f.db.DeviceVPNIdentities(ctx, deviceID)
	var current, superseded int
	for _, r := range rows {
		switch r.State {
		case sqlite.VPNIssued:
			current++
		case sqlite.VPNSuperseded:
			superseded++
		}
	}
	if current != 1 || superseded != 1 {
		t.Fatalf("after a second install: %d current, %d superseded", current, superseded)
	}
}

func TestManualDownloadRefusals(t *testing.T) {
	ctx := context.Background()
	f, svc, wifi, device, clock := manualFixture(t)

	// Only the newest download works.
	_, first, err := svc.DownloadManual(ctx, device, wifi, "nick")
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := svc.DownloadManual(ctx, device, wifi, "nick")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SignCSRContext(ctx, deviceRequest(t, "alice", profileChallenge(t, first))); err == nil {
		t.Fatal("an earlier download still worked after a newer one")
	}

	// A profile nobody installed in time is worthless.
	*clock = clock.Add(11 * time.Minute)
	if _, err = svc.SignCSRContext(ctx, deviceRequest(t, "alice", profileChallenge(t, second))); err == nil {
		t.Fatal("a profile worked after its ten minutes")
	}
	if rows, _ := f.db.DeviceVPNIdentities(ctx, sqlite.ManualDeviceID(device)); len(rows) != 0 {
		t.Fatalf("identities after refused requests = %d", len(rows))
	}

	// A VPN server's profile is not handed out this way.
	if _, _, err = svc.DownloadManual(ctx, device, f.server, "nick"); !errors.Is(err, vpn.ErrManualWiFiOnly) {
		t.Fatalf("VPN server: err = %v, want ErrManualWiFiOnly", err)
	}

	// A disabled owner gets no profile, and a profile already downloaded gets no certificate.
	_, live, err := svc.DownloadManual(ctx, device, wifi, "nick")
	if err != nil {
		t.Fatal(err)
	}
	f.dir.disabled = true
	if _, _, err = svc.DownloadManual(ctx, device, wifi, "nick"); !errors.Is(err, vpn.ErrOwnerIneligible) {
		t.Fatalf("disabled owner: err = %v, want ErrOwnerIneligible", err)
	}
	f.dir.disabled = false
	_, live, err = svc.DownloadManual(ctx, device, wifi, "nick")
	if err != nil {
		t.Fatal(err)
	}
	f.dir.disabled = true
	if _, err = svc.SignCSRContext(ctx, deviceRequest(t, "alice", profileChallenge(t, live))); err == nil {
		t.Fatal("a certificate was issued for a disabled owner")
	}
	f.dir.disabled = false

	// A removed device gets nothing, and its open profile stops working.
	_, live, err = svc.DownloadManual(ctx, device, wifi, "nick")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.RemoveManualDevice(ctx, device, "nick"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SignCSRContext(ctx, deviceRequest(t, "alice", profileChallenge(t, live))); err == nil {
		t.Fatal("a removed device got a certificate")
	}
	if _, _, err = svc.DownloadManual(ctx, device, wifi, "nick"); !errors.Is(err, vpn.ErrManualDeviceGone) {
		t.Fatalf("removed device: err = %v, want ErrManualDeviceGone", err)
	}
}

func TestManualDeviceHoldingACertificateIsNotRemoved(t *testing.T) {
	ctx := context.Background()
	f, svc, wifi, device, _ := manualFixture(t)
	_, profile, err := svc.DownloadManual(ctx, device, wifi, "nick")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SignCSRContext(ctx, deviceRequest(t, "alice", profileChallenge(t, profile))); err != nil {
		t.Fatal(err)
	}
	if err = f.db.RemoveManualDevice(ctx, device, "nick"); !errors.Is(err, sqlite.ErrManualDeviceInUse) {
		t.Fatalf("remove with a live certificate: err = %v, want ErrManualDeviceInUse", err)
	}
	rows, _ := f.db.DeviceVPNIdentities(ctx, sqlite.ManualDeviceID(device))
	if err = svc.Revoke(ctx, rows[0].ID, "nick"); err != nil {
		t.Fatal(err)
	}
	if err = f.db.RemoveManualDevice(ctx, device, "nick"); err != nil {
		t.Fatalf("remove after revoking: %v", err)
	}
}
