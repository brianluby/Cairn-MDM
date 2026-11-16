package vpn

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// IdentityStore is the state the service keeps per issued certificate;
// *sqlite.DB provides it.
type IdentityStore interface {
	BeginVPNIdentity(ctx context.Context, v sqlite.VPNIdentity) (int64, error)
	CompleteVPNIdentity(ctx context.Context, id int64, serial string, leafDER []byte, notAfter time.Time) error
	FailVPNIdentity(ctx context.Context, id int64, reason string) error
	QuarantineVPNIdentity(ctx context.Context, id int64, reason, serial string, leafDER []byte) error
	MarkVPNDeployFailed(ctx context.Context, id int64, reason string) error
	GetVPNIdentity(ctx context.Context, id int64) (sqlite.VPNIdentity, error)
	DeviceVPNIdentities(ctx context.Context, deviceID string) ([]sqlite.VPNIdentity, error)
	MarkVPNIdentityRevoked(ctx context.Context, id int64, actor string) error
	MarkVPNCertificateRevoked(ctx context.Context, id int64, actor string) error
	QuarantineStaleVPNIssuing(ctx context.Context, before time.Time) (int, error)
	VPNIdentitiesAwaitingRevocation(ctx context.Context) ([]sqlite.VPNIdentity, error)
	WithdrawStaleVPNPayloads(ctx context.Context, before time.Time) (int, error)
	CreateVPNOffer(ctx context.Context, o sqlite.VPNOffer, expires time.Time) (int64, error)
	VPNOfferByChallenge(ctx context.Context, challengeSHA256 string) (sqlite.VPNOffer, error)
	ClaimVPNOffer(ctx context.Context, offerID int64, spkiSHA256, backend string, now time.Time) (int64, error)
	CloseVPNOffer(ctx context.Context, id int64, why string) error
	ExpireVPNOffers(ctx context.Context, now time.Time) (int, error)
	WithdrawVPNOffer(ctx context.Context, deviceID string, serverID int64, actor string) (bool, error)
	VPNCommandOpen(ctx context.Context, deviceID, commandUUID string) (bool, error)
	WithdrawVPNCommand(ctx context.Context, deviceID, commandUUID, why string) error
	GetDeviceOwner(ctx context.Context, deviceID string) (sqlite.DeviceOwner, error)
	GetDevice(ctx context.Context, id string) (sqlite.Device, error)
}

// Directory resolves and rechecks the account a certificate names.
type Directory interface {
	ResolveOwner(ctx context.Context, account string) (*directory.DirectoryIdentity, error)
	RevalidateOwner(ctx context.Context, owner directory.DirectoryIdentity) (*directory.DirectoryIdentity, error)
}

// Commander queues MDM commands for a device.
type Commander interface {
	SendInstallProfileAs(ctx context.Context, uuid string, profile []byte, id string) error
	SendRemoveProfile(ctx context.Context, identifier string, ids ...string) error
}

// Options configure a Service.
type Options struct {
	Organization string       // reverse-DNS root of payload identifiers
	Policy       issue.Policy // lifetime and the ceiling accepted from an external CA
	KeyType      string       // issue.KeyRSA2048 or issue.KeyP256
	// UncollectedAfter is how long a queued profile, and the key in it, waits for
	// a device before it is withdrawn. Zero means seven days.
	UncollectedAfter time.Duration
	// DeviceSCEPURL is where devices reach Cairn's SCEP endpoint for VPN
	// certificates on keys they make. Empty leaves certificate sign-in off.
	DeviceSCEPURL string
	// IssuedHere reports whether the configured CA issued a certificate. Set it
	// when the CA's identity is known locally (Cairn's own CA), so a certificate
	// from an earlier issuer is never sent to this one for revocation.
	IssuedHere func(*x509.Certificate) bool
}

// Service issues VPN certificates and delivers the profiles that carry them.
type Service struct {
	servers *Servers
	store   IdentityStore
	dir     Directory
	backend issue.CABackend
	cmd     Commander
	opts    Options
	log     *slog.Logger
	now     func() time.Time
}

// NewService wires the VPN service.
func NewService(servers *Servers, store IdentityStore, dir Directory, backend issue.CABackend, cmd Commander, opts Options, log *slog.Logger) (*Service, error) {
	if servers == nil || store == nil || backend == nil || cmd == nil {
		return nil, errors.New("vpn: servers, store, CA backend and commander are required")
	}
	if dir == nil {
		return nil, errors.New("vpn: a verified directory is required to name certificate owners")
	}
	if opts.UncollectedAfter == 0 {
		opts.UncollectedAfter = 7 * 24 * time.Hour
	}
	return &Service{servers: servers, store: store, dir: dir, backend: backend, cmd: cmd, opts: opts, log: log, now: time.Now}, nil
}

// Errors an administrator can act on.
var (
	ErrOwnerRequired   = errors.New("this device has no verified owner; name the account the certificate is for")
	ErrOwnerMismatch   = errors.New("this device belongs to a different verified owner")
	ErrOwnerIneligible = errors.New("the account is disabled, missing or cannot be verified in the directory")
	ErrDeviceGone      = errors.New("the device is not enrolled or cannot receive commands")
	ErrAwaitingDevice  = errors.New("a profile is already waiting for this device and installs when it next connects; revoke that certificate first to send a new one")
	ErrPlatform        = errors.New("OpenVPN profiles are built for iPhone and iPad; this device is a Mac")
	ErrDeviceKeyed     = errors.New("this server signs devices in with a certificate, and Cairn's SCEP endpoint for VPN certificates is not set up")
	ErrHeld            = errors.New("the certificate authority's answer could not be trusted; the request is held for review and no profile was sent")
)

// Owner decides whose name a device's certificate carries. A device bound to a
// verified owner at enrollment always uses that owner. Otherwise the acting
// administrator names the account, which is resolved in the directory.
func (s *Service) Owner(ctx context.Context, deviceID, account string) (directory.DirectoryIdentity, error) {
	bound, err := s.store.GetDeviceOwner(ctx, deviceID)
	switch {
	case err == nil:
		fresh, rerr := s.dir.RevalidateOwner(ctx, bound.Owner)
		if rerr != nil || fresh == nil {
			return directory.DirectoryIdentity{}, ErrOwnerIneligible
		}
		if account != "" && !sameAccount(account, *fresh) {
			return directory.DirectoryIdentity{}, ErrOwnerMismatch
		}
		return *fresh, nil
	case !errors.Is(err, sqlite.ErrNoOwner):
		return directory.DirectoryIdentity{}, err
	}
	if account == "" {
		return directory.DirectoryIdentity{}, ErrOwnerRequired
	}
	owner, err := s.dir.ResolveOwner(ctx, account)
	if err != nil || owner == nil {
		return directory.DirectoryIdentity{}, ErrOwnerIneligible
	}
	return *owner, nil
}

func sameAccount(account string, id directory.DirectoryIdentity) bool {
	return strings.EqualFold(account, id.AccountName) || strings.EqualFold(account, id.UPN)
}

// Issue gets a certificate for the device's owner from the CA and queues the
// profile that carries it. actor is the administrator, already checked for role
// and a fresh second factor by the caller.
//
// The private key lives in this call and in the queued command only. If the
// profile cannot be queued the certificate is left without a holder and is
// listed for revocation.
func (s *Service) Issue(ctx context.Context, deviceID string, serverID int64, account, actor string) (sqlite.VPNIdentity, error) {
	var none sqlite.VPNIdentity
	dev, err := s.store.GetDevice(ctx, deviceID)
	if err != nil || dev.CheckedOutAt.Valid || !dev.TokenUpdatedAt.Valid {
		return none, ErrDeviceGone
	}
	server, err := s.servers.Get(ctx, serverID)
	if err != nil {
		return none, fmt.Errorf("vpn: server: %w", err)
	}
	if !server.IsIKEv2() && (strings.HasPrefix(dev.Model, "Mac") || strings.HasPrefix(dev.Product, "Mac")) {
		return none, ErrPlatform
	}
	owner, err := s.Owner(ctx, deviceID, account)
	if err != nil {
		return none, err
	}
	if owner.AccountName == "" || owner.UPN == "" {
		return none, ErrOwnerIneligible
	}
	if server.IsIKEv2() {
		return s.sendIKEv2(ctx, deviceID, server, owner, actor)
	}

	// One undelivered key per device and server at a time.
	earlier, err := s.store.DeviceVPNIdentities(ctx, deviceID)
	if err != nil {
		return none, err
	}
	for _, e := range earlier {
		if e.ServerID == serverID && e.State == sqlite.VPNIssued && e.DeployStatus == "sent" {
			return none, ErrAwaitingDevice
		}
	}

	key, err := issue.NewServerKey(s.opts.KeyType)
	if err != nil {
		return none, err
	}
	// CN is the account name: the VPN server matches it against the login name.
	facts := issue.GrantFacts{CommonName: owner.AccountName, Owner: owner.UPN}
	req, err := issue.ServerKeyedRequest(s.opts.Policy, facts, key, s.now())
	if err != nil {
		return none, err
	}
	backendName := s.backend.Capabilities().Name
	// The profile's CommandUUID is fixed and recorded before anything is queued,
	// so the device's answer finds this row however fast it comes.
	commandUUID := mdmcore.NewCommandUUID()
	id, err := s.store.BeginVPNIdentity(ctx, sqlite.VPNIdentity{
		ServerID: serverID, DeviceID: deviceID, Owner: owner, Actor: actor, SPKISHA256: req.SPKISHA256, Backend: backendName,
		CommandUUID: commandUUID,
	})
	if errors.Is(err, sqlite.ErrVPNIssuanceInFlight) {
		return none, ErrAwaitingDevice
	}
	if err != nil {
		return none, err
	}
	// From here the outcome has to be recorded even if the administrator's
	// browser goes away: an unrecorded CA answer or queued key cannot be cleaned up.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
	defer cancel()

	// Recheck the owner immediately before signing; nothing has been asked of the
	// CA yet, so a change here is a clean refusal.
	if fresh, rerr := s.dir.RevalidateOwner(ctx, owner); rerr != nil || fresh == nil || *fresh != owner {
		s.record(id, s.store.FailVPNIdentity(ctx, id, "owner authorization changed before signing"))
		return none, ErrOwnerIneligible
	}

	res, err := s.backend.Issue(ctx, req)
	// A local signer either signed or did not; only a remote CA can leave doubt.
	clean := res.Status == issue.StatusFailedClean || s.backend.Capabilities().AtomicIssue
	switch {
	case err != nil && clean:
		s.record(id, s.store.FailVPNIdentity(ctx, id, "CA refused: "+err.Error()))
		return none, fmt.Errorf("vpn: the certificate authority refused the request: %w", err)
	case err != nil || res.Status != issue.StatusIssued:
		// Unknown or pending: the CA may have signed. Never retried with this key.
		reason := "CA outcome unknown"
		if err != nil {
			reason += ": " + err.Error()
		}
		s.record(id, s.store.QuarantineVPNIdentity(ctx, id, reason, res.Serial, nil))
		return none, ErrHeld
	case res.Leaf == nil || res.Serial == "":
		s.record(id, s.store.QuarantineVPNIdentity(ctx, id, "CA reported success without a certificate", res.Serial, nil))
		return none, ErrHeld
	}
	if verr := issue.VerifyLeaf(res.Leaf, req, s.opts.Policy, s.now()); verr != nil {
		s.record(id, s.store.QuarantineVPNIdentity(ctx, id, "certificate differs from the request: "+verr.Error(), res.Serial, res.Leaf.Raw))
		return none, ErrHeld
	}
	if err = s.store.CompleteVPNIdentity(ctx, id, res.Serial, res.Leaf.Raw, res.Leaf.NotAfter); err != nil {
		return none, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err == nil {
		var profile []byte
		profile, err = RenderMobileconfig(s.opts.Organization, server, Identity{
			DeviceID: deviceID, Username: owner.AccountName,
			CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: res.Leaf.Raw}),
			KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		})
		if err == nil {
			err = s.cmd.SendInstallProfileAs(ctx, commandUUID, profile, deviceID)
		}
	}
	if err != nil {
		s.record(id, s.store.MarkVPNDeployFailed(ctx, id, "Profile not queued: "+err.Error()))
		s.log.Error("vpn: profile not queued; certificate has no holder", "identity", id, "device", deviceID, "serial", res.Serial, "err", err)
		return none, fmt.Errorf("vpn: certificate %s was issued but the profile could not be queued: %w", res.Serial, err)
	}
	s.log.Info("vpn: profile queued", "identity", id, "device", deviceID, "server", server.Slug, "owner", owner.UPN, "serial", res.Serial, "actor", actor)
	return s.store.GetVPNIdentity(ctx, id)
}

// sendIKEv2 queues an IKEv2 profile. With password sign-in there is no
// certificate and nothing to record beyond the command: the profile holds the
// account name and the server settings. With certificate sign-in the profile
// carries an offer the device answers with its own key.
func (s *Service) sendIKEv2(ctx context.Context, deviceID string, server Server, owner directory.DirectoryIdentity, actor string) (sqlite.VPNIdentity, error) {
	var none sqlite.VPNIdentity
	if server.IKEv2.UsesCertificate() {
		return s.offerDeviceKey(ctx, deviceID, server, owner, actor)
	}
	profile, err := RenderIKEv2(s.opts.Organization, server, IKEv2Identity{DeviceID: deviceID, Username: owner.AccountName})
	if err != nil {
		return none, err
	}
	if err = s.cmd.SendInstallProfileAs(ctx, mdmcore.NewCommandUUID(), profile, deviceID); err != nil {
		return none, fmt.Errorf("vpn: the profile could not be queued: %w", err)
	}
	s.log.Info("vpn: IKEv2 profile queued", "device", deviceID, "server", server.Slug, "owner", owner.UPN, "sign_in", server.IKEv2.SignIn, "actor", actor)
	return sqlite.VPNIdentity{ServerID: server.ID, DeviceID: deviceID, Owner: owner, Actor: actor}, nil
}

// Remove queues removal of the server's profile from the device. The
// certificate stays valid until it is revoked or expires.
func (s *Service) Remove(ctx context.Context, deviceID string, serverID int64, actor string) error {
	if _, err := s.store.GetDevice(ctx, deviceID); err != nil {
		return ErrDeviceGone
	}
	server, err := s.servers.Get(ctx, serverID)
	if err != nil {
		return err
	}
	if err = s.cmd.SendRemoveProfile(ctx, PayloadIdentifier(s.opts.Organization, server), deviceID); err != nil {
		return err
	}
	s.log.Info("vpn: profile removal queued", "device", deviceID, "server", server.Slug, "actor", actor)
	return nil
}

// Withdraw closes the device's unanswered offer for a server, so the challenge
// in a profile sent to the wrong device or for the wrong account stops working.
func (s *Service) Withdraw(ctx context.Context, deviceID string, serverID int64, actor string) (bool, error) {
	found, err := s.store.WithdrawVPNOffer(ctx, deviceID, serverID, actor)
	if err == nil && found {
		s.log.Info("vpn: offer withdrawn", "device", deviceID, "server", serverID, "actor", actor)
	}
	return found, err
}

// record logs a failure to store an outcome. The row then stays as it was and
// the hourly sweep holds it for review.
func (s *Service) record(id int64, err error) {
	if err != nil {
		s.log.Error("vpn: outcome not recorded", "identity", id, "err", err)
	}
}

// Revoke marks a certificate revoked and, when the CA backend can revoke,
// revokes it there. With a backend that cannot (an external SCEP CA), the
// identity stays listed by AwaitingRevocation until an administrator revokes
// the serial at the CA and confirms it.
func (s *Service) Revoke(ctx context.Context, identityID int64, actor string) error {
	if err := s.store.MarkVPNIdentityRevoked(ctx, identityID, actor); err != nil {
		return err
	}
	v, err := s.store.GetVPNIdentity(ctx, identityID)
	if err != nil {
		return err
	}
	return s.revokeAtCA(ctx, v)
}

func (s *Service) revokeAtCA(ctx context.Context, v sqlite.VPNIdentity) error {
	if !s.CanRevokeIdentity(v) || v.CertSerial == "" || v.RevokedAt.Valid {
		return nil
	}
	reason := issue.RevokeSuperseded
	if v.State == sqlite.VPNRevoked {
		reason = issue.RevokeUnspecified
	}
	if err := s.backend.Revoke(ctx, v.CertSerial, reason); err != nil {
		return fmt.Errorf("vpn: revoke %s at the CA: %w", v.CertSerial, err)
	}
	return s.store.MarkVPNCertificateRevoked(ctx, v.ID, "cairn")
}

// ConfirmRevokedAtCA records that an administrator revoked the serial at a CA
// Cairn cannot revoke at itself. It is refused for a certificate Cairn revokes
// by itself and for one that is still in use.
func (s *Service) ConfirmRevokedAtCA(ctx context.Context, identityID int64, actor string) error {
	v, err := s.store.GetVPNIdentity(ctx, identityID)
	if err != nil {
		return err
	}
	if s.CanRevokeIdentity(v) {
		return errors.New("vpn: Cairn revokes this certificate itself")
	}
	return s.store.MarkVPNCertificateRevoked(ctx, identityID, actor)
}

// CanRevoke reports whether the configured CA revokes on Cairn's request.
func (s *Service) CanRevoke() bool { return s.backend.Capabilities().CanRevoke }

// CanRevokeIdentity reports whether Cairn can revoke this certificate: the
// configured CA must be the one that issued it. After a change of issuer, the
// earlier CA's certificates have to be revoked there by hand; sending their
// serials to the new CA would revoke nothing, or the wrong certificate.
func (s *Service) CanRevokeIdentity(v sqlite.VPNIdentity) bool {
	caps := s.backend.Capabilities()
	if !caps.CanRevoke || v.Backend != caps.Name {
		return false
	}
	if s.opts.IssuedHere == nil {
		return true
	}
	leaf, err := x509.ParseCertificate(v.LeafDER)
	return err == nil && s.opts.IssuedHere(leaf)
}

// Sweep withdraws profiles no device collected and revokes certificates that
// were replaced or never delivered. It is safe to run repeatedly.
func (s *Service) Sweep(ctx context.Context) {
	if n, err := s.store.QuarantineStaleVPNIssuing(ctx, s.now().Add(-15*time.Minute)); err != nil {
		s.log.Error("vpn: hold abandoned requests", "err", err)
	} else if n > 0 {
		s.log.Warn("vpn: held requests whose CA outcome was never recorded", "count", n)
	}
	if n, err := s.store.WithdrawStaleVPNPayloads(ctx, s.now().Add(-s.opts.UncollectedAfter)); err != nil {
		s.log.Error("vpn: withdraw stale profiles", "err", err)
	} else if n > 0 {
		s.log.Warn("vpn: withdrew profiles no device collected", "count", n)
	}
	if n, err := s.store.ExpireVPNOffers(ctx, s.now()); err != nil {
		s.log.Error("vpn: close unanswered offers", "err", err)
	} else if n > 0 {
		s.log.Warn("vpn: withdrew profiles whose device never requested a certificate", "count", n)
	}
	retired, err := s.store.VPNIdentitiesAwaitingRevocation(ctx)
	if err != nil {
		s.log.Error("vpn: list certificates awaiting revocation", "err", err)
		return
	}
	for _, v := range retired {
		if err := s.revokeAtCA(ctx, v); err != nil {
			s.log.Error("vpn: revoke retired certificate", "identity", v.ID, "err", err)
		}
	}
}
