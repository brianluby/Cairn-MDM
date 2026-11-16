package vpn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	scep "github.com/smallstep/scep"

	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// Device-keyed issuance is for clients that can use an identity from the
// system keychain (the native IKEv2 client). The device makes the key and asks
// Cairn's SCEP endpoint for a certificate, presenting a challenge that Cairn
// put in that device's profile and that works once, for one key. The
// certificate content comes from the offer and the directory; from the request
// Cairn takes the public key and its proof of possession only.

var errOfferRefused = errors.New("vpn: certificate request refused")

func challengeHash(challenge string) string {
	sum := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(sum[:])
}

// offerDeviceKey records an offer and queues the profile that carries its
// challenge. Nothing is asked of the CA until the device answers.
func (s *Service) offerDeviceKey(ctx context.Context, deviceID string, server Server, owner directory.DirectoryIdentity, actor string) (sqlite.VPNIdentity, error) {
	var none sqlite.VPNIdentity
	if s.opts.DeviceSCEPURL == "" {
		return none, ErrDeviceKeyed
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return none, err
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	commandUUID := mdmcore.NewCommandUUID()
	offerID, err := s.store.CreateVPNOffer(ctx, sqlite.VPNOffer{
		ServerID: server.ID, DeviceID: deviceID, Owner: owner, Actor: actor,
		ChallengeSHA256: challengeHash(challenge), CommandUUID: commandUUID,
	}, s.now().Add(s.opts.UncollectedAfter))
	if errors.Is(err, sqlite.ErrVPNOfferOpen) {
		return none, ErrAwaitingDevice
	}
	if err != nil {
		return none, err
	}
	profile, err := RenderIKEv2(s.opts.Organization, server, IKEv2Identity{
		DeviceID: deviceID, Username: owner.AccountName,
		SCEP: &SCEPEnrollment{URL: s.opts.DeviceSCEPURL, Challenge: challenge, CommonName: owner.AccountName, Email: owner.UPN},
	})
	if err == nil {
		err = s.cmd.SendInstallProfileAs(ctx, commandUUID, profile, deviceID)
	}
	if err != nil {
		if cerr := s.store.CloseVPNOffer(context.WithoutCancel(ctx), offerID, "Profile not queued: "+err.Error()); cerr != nil {
			s.log.Error("vpn: offer not closed", "offer", offerID, "err", cerr)
		}
		return none, fmt.Errorf("vpn: the profile could not be queued: %w", err)
	}
	s.log.Info("vpn: IKEv2 profile queued; the device will request its certificate", "offer", offerID, "device", deviceID, "server", server.Slug, "owner", owner.UPN, "actor", actor)
	return sqlite.VPNIdentity{ServerID: server.ID, DeviceID: deviceID, Owner: owner, Actor: actor}, nil
}

// SignCSRContext answers a device's SCEP request; it implements the SCEP
// server's signer. Every refusal returns the same error to the device and logs
// the reason, so the endpoint tells a stranger nothing about which challenges
// exist.
func (s *Service) SignCSRContext(ctx context.Context, m *scep.CSRReqMessage) (*x509.Certificate, error) {
	leaf, reason, err := s.signDeviceKey(ctx, m)
	if err != nil {
		s.log.Warn("vpn: device certificate request refused", "reason", reason, "err", err)
		return nil, errOfferRefused
	}
	return leaf, nil
}

func (s *Service) signDeviceKey(ctx context.Context, m *scep.CSRReqMessage) (leaf *x509.Certificate, reason string, err error) {
	if m == nil || m.CSR == nil || m.CSR.PublicKey == nil || m.ChallengePassword == "" {
		return nil, "request has no key or no challenge", errOfferRefused
	}
	if err = m.CSR.CheckSignature(); err != nil {
		return nil, "request is not signed by its own key", err
	}
	offer, err := s.store.VPNOfferByChallenge(ctx, challengeHash(m.ChallengePassword))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "unknown challenge", errOfferRefused
	}
	if err != nil {
		return nil, "offer lookup", err
	}
	txnID, spki, err := issue.Identity(m.CSR.PublicKey)
	if err != nil {
		return nil, "unusable public key", err
	}
	switch offer.State {
	case sqlite.VPNOfferClaimed:
		// A device repeats its request when the reply was lost. Only the key
		// that claimed the offer gets the certificate again.
		if offer.SPKISHA256 != spki || !offer.IdentityID.Valid {
			return nil, "challenge already used by another key", errOfferRefused
		}
		v, err := s.store.GetVPNIdentity(ctx, offer.IdentityID.Int64)
		if err != nil {
			return nil, "identity lookup", err
		}
		if v.State != sqlite.VPNIssued || v.DeployStatus != "sent" {
			return nil, fmt.Sprintf("repeat request for an identity that is %s/%s", v.State, v.DeployStatus), errOfferRefused
		}
		leaf, err = x509.ParseCertificate(v.LeafDER)
		return leaf, "stored certificate unreadable", err
	case sqlite.VPNOfferOpen:
	default:
		return nil, "offer is closed", errOfferRefused
	}

	dev, err := s.store.GetDevice(ctx, offer.DeviceID)
	if err != nil || dev.CheckedOutAt.Valid || !dev.TokenUpdatedAt.Valid {
		return nil, "device is no longer enrolled", errOfferRefused
	}
	server, err := s.servers.Get(ctx, offer.ServerID)
	if err != nil || !server.IsIKEv2() || !server.IKEv2.UsesCertificate() {
		return nil, "server record no longer takes certificates", errOfferRefused
	}
	owner := offer.Owner
	// The profile told the device which name to ask for. A request for another
	// name is refused before a CA that reads the request could act on it.
	if m.CSR.Subject.CommonName != owner.AccountName {
		return nil, fmt.Sprintf("request names %q, offer is for %q", m.CSR.Subject.CommonName, owner.AccountName), errOfferRefused
	}
	if len(m.CSR.DNSNames)+len(m.CSR.IPAddresses)+len(m.CSR.URIs) != 0 {
		return nil, "request asks for names the offer does not cover", errOfferRefused
	}
	for _, email := range m.CSR.EmailAddresses {
		if email != owner.UPN {
			return nil, fmt.Sprintf("request asks for address %q, offer is for %q", email, owner.UPN), errOfferRefused
		}
	}
	if fresh, rerr := s.dir.RevalidateOwner(ctx, owner); rerr != nil || fresh == nil || *fresh != owner {
		return nil, "owner is disabled, missing or changed in the directory", errOfferRefused
	}

	tmpl, err := issue.Reconstruct(s.opts.Policy, issue.GrantFacts{CommonName: owner.AccountName, Owner: owner.UPN}, m.CSR.PublicKey, s.now())
	if err != nil {
		return nil, "certificate template", err
	}
	req := issue.IssueRequest{
		TxnID: txnID, SPKISHA256: spki, PublicKey: m.CSR.PublicKey, DeviceCSR: m.CSR,
		Template: tmpl, RequestHash: issue.RequestHash(tmpl, 0),
	}
	id, err := s.store.ClaimVPNOffer(ctx, offer.ID, spki, s.backend.Capabilities().Name, s.now())
	if err != nil {
		return nil, "offer could not be claimed", err
	}
	// From here the outcome has to be recorded even if the device hangs up.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
	defer cancel()

	res, err := s.backend.Issue(ctx, req)
	clean := res.Status == issue.StatusFailedClean || s.backend.Capabilities().AtomicIssue
	switch {
	case err != nil && clean:
		s.record(id, s.store.FailVPNIdentity(ctx, id, "CA refused: "+err.Error()))
		return nil, "CA refused", err
	case err != nil || res.Status != issue.StatusIssued:
		why := "CA outcome unknown"
		if err != nil {
			why += ": " + err.Error()
		}
		s.record(id, s.store.QuarantineVPNIdentity(ctx, id, why, res.Serial, nil))
		return nil, why, ErrHeld
	case res.Leaf == nil || res.Serial == "":
		s.record(id, s.store.QuarantineVPNIdentity(ctx, id, "CA reported success without a certificate", res.Serial, nil))
		return nil, "CA reported success without a certificate", ErrHeld
	}
	if verr := issue.VerifyLeaf(res.Leaf, req, s.opts.Policy, s.now()); verr != nil {
		s.record(id, s.store.QuarantineVPNIdentity(ctx, id, "certificate differs from the request: "+verr.Error(), res.Serial, res.Leaf.Raw))
		return nil, "certificate differs from the request", ErrHeld
	}
	if err = s.store.CompleteVPNIdentity(ctx, id, res.Serial, res.Leaf.Raw, res.Leaf.NotAfter); err != nil {
		return nil, "outcome not recorded", err
	}
	s.log.Info("vpn: certificate issued for a device-made key", "identity", id, "device", offer.DeviceID, "server", server.Slug, "owner", owner.UPN, "serial", res.Serial)
	return res.Leaf, "", nil
}
