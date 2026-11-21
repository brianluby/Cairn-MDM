package vpn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// A manual device is one that cannot enroll in MDM. Its Wi-Fi profile is
// downloaded by an administrator and installed by hand. The profile works the
// way a pushed one does: it carries a challenge good for one key, and the
// device makes that key and asks Cairn for the certificate while the profile
// installs. What differs is everything after: no command ever reports the
// profile installed, and Cairn can neither replace the certificate before it
// expires nor remove the profile.

// manualOfferFor is how long a downloaded profile's challenge works when
// Options.ManualOfferFor is unset. Apple devices discard a downloaded profile
// that is not installed within eight minutes.
const manualOfferFor = 10 * time.Minute

// Errors an administrator can act on.
var (
	ErrManualDeviceGone = errors.New("this device is not on the list any more")
	ErrManualWiFiOnly   = errors.New("only a Wi-Fi network's profile can be downloaded for a device outside MDM")
)

// DownloadManual renders the Wi-Fi profile for a device outside MDM and opens
// the offer its challenge belongs to. A profile downloaded earlier for the same
// device and network stops working. The file name is suggested for the download.
func (s *Service) DownloadManual(ctx context.Context, manualID, serverID int64, actor string) (filename string, profile []byte, err error) {
	if s.opts.DeviceSCEPURL == "" {
		return "", nil, ErrDeviceKeyed
	}
	dev, err := s.store.GetManualDevice(ctx, manualID)
	if err != nil || dev.RemovedAt.Valid {
		return "", nil, ErrManualDeviceGone
	}
	server, err := s.servers.Get(ctx, serverID)
	if err != nil {
		return "", nil, fmt.Errorf("vpn: server: %w", err)
	}
	if !server.IsWiFi() {
		return "", nil, ErrManualWiFiOnly
	}
	owner := dev.Owner
	if fresh, rerr := s.dir.RevalidateOwner(ctx, owner); rerr != nil || fresh == nil || *fresh != owner {
		return "", nil, ErrOwnerIneligible
	}
	deviceID := dev.DeviceID()
	if _, err = s.store.WithdrawVPNOffer(ctx, deviceID, serverID, actor); err != nil {
		return "", nil, err
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", nil, err
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	window := s.opts.ManualOfferFor
	if window <= 0 {
		window = manualOfferFor
	}
	// No command is queued. The UUID only fills the column and keeps the row
	// distinct from any real command.
	offerID, err := s.store.CreateVPNOffer(ctx, sqlite.VPNOffer{
		ServerID: serverID, DeviceID: deviceID, Owner: owner, Actor: actor,
		ChallengeSHA256: challengeHash(challenge), CommandUUID: mdmcore.NewCommandUUID(),
	}, s.now().Add(window))
	if errors.Is(err, sqlite.ErrVPNOfferOpen) {
		return "", nil, ErrAwaitingDevice
	}
	if err != nil {
		return "", nil, err
	}
	profile, err = RenderWiFi(s.opts.Organization, server, WiFiIdentity{DeviceID: deviceID,
		SCEP: &SCEPEnrollment{URL: s.opts.DeviceSCEPURL, Challenge: challenge, CommonName: owner.AccountName, Email: owner.UPN}})
	if err == nil && s.opts.Sign != nil {
		if profile, err = s.opts.Sign(profile); err != nil {
			err = fmt.Errorf("vpn: sign profile: %w", err)
		}
	}
	if err != nil {
		if cerr := s.store.CloseVPNOffer(context.WithoutCancel(ctx), offerID, "Profile not made: "+err.Error()); cerr != nil {
			s.log.Error("vpn: offer not closed", "offer", offerID, "err", cerr)
		}
		return "", nil, err
	}
	s.log.Info("vpn: Wi-Fi profile downloaded for a device outside MDM", "offer", offerID, "device", deviceID, "name", dev.Name,
		"server", server.Slug, "owner", owner.UPN, "actor", actor, "valid_for", window.String())
	return server.Slug + "-" + Slugify(dev.Name) + ".mobileconfig", profile, nil
}
