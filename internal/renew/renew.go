// Package renew replaces a device's identity certificate before it expires.
//
// Apple devices never renew the certificate they check in with. When it
// expires the device is cut off and has to be enrolled again by hand. Cairn
// instead pushes the device's own enrollment profile again while it can still
// be reached: the device asks the CA for a new certificate, switches to it,
// and Cairn associates the new certificate with the same enrollment.
//
// The steps for one device:
//
//  1. Ask which installed profile holds the enrollment (ProfileList). The new
//     profile has to carry the same identifier or the device adds a second
//     enrollment profile instead of replacing the first, and refuses it.
//  2. Queue the enrollment profile under that identifier, asking for the same
//     certificate name and pointing at the same server name the device uses.
//  3. When the device checks in with a certificate Cairn has not seen, accept
//     it if it comes from the pinned CA and carries the same name.
//  4. A day later, stop accepting the certificate it replaced.
package renew

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

const (
	// retryAfter is how long a failed attempt rests before the next one.
	retryAfter = 24 * time.Hour
	// staleAfter closes an attempt the device has not moved forward.
	staleAfter = 7 * 24 * time.Hour
	// retireAfter is how long the replaced certificate stays accepted.
	retireAfter = 24 * time.Hour

	// acceptFor is how long after an attempt starts the device may still
	// present the certificate that attempt produced.
	acceptFor = 30 * 24 * time.Hour

	mdmPayloadType = "com.apple.mdm"
)

// Store is the persistence the service needs. *sqlite.DB satisfies it.
type Store interface {
	RenewalCandidates(ctx context.Context) ([]sqlite.RenewalCandidate, error)
	RenewalCandidate(ctx context.Context, deviceID string) (sqlite.RenewalCandidate, bool, error)
	LastRenewal(ctx context.Context, deviceID string) (sqlite.Renewal, bool, error)
	BeginRenewal(ctx context.Context, deviceID, commandUUID, oldSHA256, actor string) error
	RenewalProfileQueued(ctx context.Context, deviceID, lookupUUID, installUUID, profileIdentifier string) (bool, error)
	FailRenewal(ctx context.Context, deviceID, reason string) error
	NoteRenewalProblem(ctx context.Context, renewalID int64, reason string) error
	AwaitedRenewal(ctx context.Context, deviceID string, since time.Time) (sqlite.Renewal, bool, error)
	FailStaleRenewals(ctx context.Context, cutoff time.Time, reason string) (int64, error)
	CompleteRenewal(ctx context.Context, renewalID int64, deviceID, newSHA256 string) error
	MarkRenewedByEnrollment(ctx context.Context, renewalID int64, deviceID, newSHA256 string) error
	RetireRenewedCertificates(ctx context.Context, cutoff time.Time) (int64, error)
	SetCheckInHost(ctx context.Context, deviceID, host string) error
	CertificateAssociated(ctx context.Context, deviceID, sha256Hex string) (bool, error)
	IdentityCommonName(ctx context.Context, sha256Hex string) (string, error)
}

// Commander queues the two commands a renewal uses.
type Commander interface {
	SendProfileListAs(ctx context.Context, uuid, id string) error
	SendInstallProfileAs(ctx context.Context, uuid string, profile []byte, id string) error
}

// Target describes the enrollment profile to build for one device.
type Target struct {
	Identifier   string // PayloadIdentifier of the profile being replaced
	DisplayName  string
	Organization string
	ServerURL    string // check-in URL the device already uses
	CommonName   string // certificate name to ask the CA for
	OwnerEmail   string // rfc822 name to carry over, if the current certificate has one
	Topic        string // APNs topic the device enrolled under; a device refuses a profile that changes it
}

// Options configure the service.
type Options struct {
	// RenewBefore is how long before expiry a renewal starts.
	RenewBefore time.Duration
	// ExpiredGrace is how long after expiry a device may still be renewed. It
	// has to match the grace the check-in service applies.
	ExpiredGrace time.Duration
	// ServerURL is the check-in URL new enrollments use.
	ServerURL string
	// Hosts are further host names devices may check in through, as they
	// appear in the request (host or host:port). A device seen on any other
	// name is not renewed, because the name could be a proxy's internal one
	// and a profile pointing there would strand the device.
	Hosts []string
	// Anchors is the CA chain a renewed certificate has to come from.
	Anchors []*x509.Certificate
	// Profile builds the enrollment profile.
	Profile func(Target) ([]byte, error)
	// ManualOnly keeps the schedule from starting renewals; an administrator
	// starts each one.
	ManualOnly bool
	Now        func() time.Time
}

// Service runs renewals. It implements mdmcore.Lifecycle.
type Service struct {
	store Store
	cmd   Commander
	opts  Options
	log   *slog.Logger
	roots *x509.CertPool
	inter *x509.CertPool
	// starting keeps check-ins from the same device from racing to start.
	starting sync.Map
}

var _ mdmcore.Lifecycle = (*Service)(nil)

// New builds the service.
func New(store Store, cmd Commander, opts Options, log *slog.Logger) (*Service, error) {
	if opts.Profile == nil {
		return nil, errors.New("renew: no enrollment profile builder")
	}
	if len(opts.Anchors) == 0 {
		return nil, errors.New("renew: no CA chain to check renewed certificates against")
	}
	u, err := url.Parse(opts.ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("renew: server URL %q is not an https URL", opts.ServerURL)
	}
	if opts.RenewBefore <= 0 {
		return nil, errors.New("renew: renew-before period must be positive")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Service{store: store, cmd: cmd, opts: opts, log: log, roots: x509.NewCertPool(), inter: x509.NewCertPool()}
	for _, c := range opts.Anchors {
		if c.CheckSignatureFrom(c) == nil {
			s.roots.AddCert(c)
		} else {
			s.inter.AddCert(c)
		}
	}
	return s, nil
}

// Status says where a device stands.
type Status struct {
	Due      bool   // inside the renew-before window
	Expired  bool   // past expiry
	Stranded bool   // past expiry and grace: cannot check in, has to enroll again
	Blocked  string // why a renewal cannot run, if it cannot
}

// Status reports a candidate's standing at the current time.
func (s *Service) Status(c sqlite.RenewalCandidate) Status {
	now := s.opts.Now()
	st := Status{
		Due:     !c.NotAfter.IsZero() && c.NotAfter.Sub(now) <= s.opts.RenewBefore,
		Expired: !c.NotAfter.IsZero() && now.After(c.NotAfter),
	}
	st.Stranded = st.Expired && (s.opts.ExpiredGrace <= 0 || now.After(c.NotAfter.Add(s.opts.ExpiredGrace)))
	if _, err := s.serverURL(c.CheckInHost); err != nil {
		st.Blocked = err.Error()
	}
	return st
}

// Sweep starts renewals that are due and tidies finished ones. Run it hourly.
func (s *Service) Sweep(ctx context.Context) {
	now := s.opts.Now()
	if n, err := s.store.FailStaleRenewals(ctx, now.Add(-staleAfter), "The device did not answer within 7 days."); err != nil {
		s.log.Warn("renewal: close stale attempts", "err", err)
	} else if n > 0 {
		s.log.Warn("renewal: attempts closed without an answer from the device", "count", n)
	}
	if n, err := s.store.RetireRenewedCertificates(ctx, now.Add(-retireAfter)); err != nil {
		s.log.Warn("renewal: retire replaced certificates", "err", err)
	} else if n > 0 {
		s.log.Info("renewal: replaced certificates are no longer accepted", "count", n)
	}
	if s.opts.ManualOnly {
		return
	}
	candidates, err := s.store.RenewalCandidates(ctx)
	if err != nil {
		s.log.Warn("renewal: list devices", "err", err)
		return
	}
	for _, c := range candidates {
		if !s.shouldStart(c) {
			continue
		}
		if err := s.start(ctx, c, "schedule"); err != nil && !errors.Is(err, sqlite.ErrRenewalOpen) {
			s.log.Warn("renewal: start", "device", c.DeviceName, "err", err)
		}
	}
}

// shouldStart reports whether the schedule should begin an attempt now.
func (s *Service) shouldStart(c sqlite.RenewalCandidate) bool {
	st := s.Status(c)
	if !st.Due || st.Stranded || st.Blocked != "" || c.Last.Open() {
		return false
	}
	if c.Last.State == "renewed" && c.Last.NewSHA256 != c.SHA256 && s.since(c.Last.UpdatedAt) < 2*retireAfter {
		// Just renewed, and the new certificate has not been recorded at a
		// check-in yet. Its next check-in settles which one it is using.
		return false
	}
	if c.Last.State == "failed" && s.since(c.Last.UpdatedAt) < retryAfter {
		return false
	}
	return true
}

// since is the time elapsed since a database timestamp; a stamp that does not
// parse counts as long ago.
func (s *Service) since(stamp string) time.Duration {
	at, err := time.Parse("2006-01-02 15:04:05", stamp)
	if err != nil {
		return 1 << 62
	}
	return s.opts.Now().Sub(at)
}

// Renew starts a renewal for one device now, whatever its expiry date. actor
// is the administrator who asked.
func (s *Service) Renew(ctx context.Context, deviceID, actor string) error {
	c, ok, err := s.store.RenewalCandidate(ctx, deviceID)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("This device has not checked in with a certificate Cairn recognizes, so there is nothing to renew.")
	}
	if st := s.Status(c); st.Stranded {
		return errors.New("This device's certificate expired too long ago for it to check in. Enroll it again with a new link.")
	} else if st.Blocked != "" {
		return errors.New(st.Blocked)
	}
	return s.start(ctx, c, actor)
}

func (s *Service) start(ctx context.Context, c sqlite.RenewalCandidate, actor string) error {
	if _, busy := s.starting.LoadOrStore(c.DeviceID, true); busy {
		return sqlite.ErrRenewalOpen
	}
	defer s.starting.Delete(c.DeviceID)
	// The row goes in first: the device can answer the moment the command is
	// queued, and the answer has to find it.
	uuid := mdmcore.NewCommandUUID()
	if err := s.store.BeginRenewal(ctx, c.DeviceID, uuid, c.SHA256, actor); err != nil {
		return err
	}
	if err := s.cmd.SendProfileListAs(ctx, uuid, c.DeviceID); err != nil {
		_ = s.store.FailRenewal(ctx, c.DeviceID, "Could not queue the profile lookup: "+err.Error())
		return err
	}
	s.log.Info("renewal: started", "device", c.DeviceName, "expires", c.NotAfter.Format("2006-01-02"), "by", actor)
	return nil
}

// ProfileList handles the device's list of installed profiles: it finds the
// enrollment profile and queues its replacement.
func (s *Service) ProfileList(ctx context.Context, deviceID, commandUUID string, profiles []mdmcore.InstalledProfile) {
	last, ok, err := s.store.LastRenewal(ctx, deviceID)
	if err != nil || !ok || last.State != "lookup" || last.CommandUUID != commandUUID {
		return
	}
	fail := func(reason string) {
		s.log.Warn("renewal: cannot continue", "device", deviceID, "reason", reason)
		if err := s.store.FailRenewal(ctx, deviceID, reason); err != nil {
			s.log.Warn("renewal: record failure", "device", deviceID, "err", err)
		}
	}
	var enrollment []mdmcore.InstalledProfile
	for _, p := range profiles {
		if p.HasPayload(mdmPayloadType) {
			enrollment = append(enrollment, p)
		}
	}
	if len(enrollment) != 1 || enrollment[0].Identifier == "" {
		fail(fmt.Sprintf("The device lists %d profiles with a management payload; expected exactly one.", len(enrollment)))
		return
	}
	c, ok, err := s.store.RenewalCandidate(ctx, deviceID)
	if err != nil || !ok {
		fail("The device's current certificate is no longer on record.")
		return
	}
	if c.SHA256 != last.OldSHA256 {
		fail("The device changed certificates while the renewal was starting.")
		return
	}
	if c.CommonName == "" {
		fail("The current certificate has no common name to repeat.")
		return
	}
	server, err := s.serverURL(c.CheckInHost)
	if err != nil {
		fail(err.Error())
		return
	}
	if c.Topic == "" {
		fail("The device has no push topic on record.")
		return
	}
	installed := enrollment[0]
	body, err := s.opts.Profile(Target{
		Identifier:   installed.Identifier,
		DisplayName:  installed.DisplayName,
		Organization: installed.Organization,
		ServerURL:    server,
		CommonName:   c.CommonName,
		OwnerEmail:   c.SANEmail,
		Topic:        c.Topic,
	})
	if err != nil {
		fail("Could not build the enrollment profile: " + err.Error())
		return
	}
	uuid := mdmcore.NewCommandUUID()
	moved, err := s.store.RenewalProfileQueued(ctx, deviceID, commandUUID, uuid, installed.Identifier)
	if err != nil || !moved {
		if err != nil {
			s.log.Warn("renewal: record profile", "device", deviceID, "err", err)
		}
		return
	}
	if err := s.cmd.SendInstallProfileAs(ctx, uuid, body, deviceID); err != nil {
		fail("Could not queue the enrollment profile: " + err.Error())
		return
	}
	s.log.Info("renewal: enrollment profile queued", "device", c.DeviceName, "profile", installed.Identifier, "server", server)
}

// serverURL returns the check-in URL to put in a device's renewed profile,
// given the host name it was last seen on.
func (s *Service) serverURL(host string) (string, error) {
	base, _ := url.Parse(s.opts.ServerURL)
	if host == "" || sameHost(host, base.Host) {
		return s.opts.ServerURL, nil
	}
	for _, h := range s.opts.Hosts {
		if sameHost(host, h) {
			u := *base
			u.Host = h
			return u.String(), nil
		}
	}
	return "", fmt.Errorf("The device checks in through %q, which is not this server's public name. List it under [renewal] server_hosts if devices are meant to use it.", host)
}

func sameHost(a, b string) bool {
	norm := func(h string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ":443") }
	return norm(a) == norm(b)
}

// CheckedIn records the host name an authorized request came in on.
func (s *Service) CheckedIn(ctx context.Context, deviceID, host string) {
	if err := s.store.SetCheckInHost(ctx, deviceID, host); err != nil {
		s.log.Warn("renewal: record check-in host", "device", deviceID, "err", err)
	}
}

// Presented sees every signed request before the certificate is checked
// against the enrollment. During a renewal it associates the new certificate.
func (s *Service) Presented(ctx context.Context, deviceID string, cert *x509.Certificate) {
	awaited, ok, err := s.store.AwaitedRenewal(ctx, deviceID, s.opts.Now().Add(-acceptFor))
	if err != nil || !ok {
		return
	}
	sum := sha256.Sum256(cert.Raw)
	hash := hex.EncodeToString(sum[:])
	if hash == awaited.OldSHA256 {
		return
	}
	if known, err := s.store.CertificateAssociated(ctx, deviceID, hash); err != nil {
		s.log.Warn("renewal: look up certificate", "device", deviceID, "err", err)
		return
	} else if known {
		// A certificate the device already had. If it was issued after this
		// attempt began, the device enrolled again by itself and the attempt
		// is done. An older one is only a late request.
		started := s.opts.Now().Add(-s.since(awaited.StartedAt))
		if s.opts.Now().Before(cert.NotAfter) && cert.NotBefore.After(started.Add(-retireAfter)) {
			_ = s.store.MarkRenewedByEnrollment(ctx, awaited.ID, deviceID, hash)
		}
		return
	}
	if !s.fromCA(cert) {
		// Anyone can send a request signed with a certificate of their own
		// making. It is refused further on; nothing is recorded here.
		return
	}
	if err := s.acceptable(ctx, awaited, cert); err != nil {
		// The device now holds a certificate Cairn will not accept, and may
		// have dropped the old one. Someone has to look.
		reason := "The device presented a new certificate that was not accepted: " + err.Error()
		s.log.Error("renewal: new certificate refused", "device", deviceID, "serial", cert.SerialNumber.Text(16), "subject", cert.Subject.String(), "err", err)
		_ = s.store.NoteRenewalProblem(ctx, awaited.ID, reason)
		return
	}
	if err := s.store.CompleteRenewal(ctx, awaited.ID, deviceID, hash); err != nil {
		s.log.Error("renewal: associate new certificate", "device", deviceID, "err", err)
		return
	}
	s.log.Info("renewal: complete", "device", deviceID, "serial", cert.SerialNumber.Text(16), "expires", cert.NotAfter.UTC().Format("2006-01-02"))
}

// fromCA reports whether cert chains to the configured CA and is in date.
func (s *Service) fromCA(cert *x509.Certificate) bool {
	_, err := cert.Verify(x509.VerifyOptions{Roots: s.roots, Intermediates: s.inter, CurrentTime: s.opts.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

// acceptable decides whether cert, already known to come from the
// configured CA, may replace the certificate under renewal. The request's
// signature proved its sender holds the key.
func (s *Service) acceptable(ctx context.Context, r sqlite.Renewal, cert *x509.Certificate) error {
	want, err := s.store.IdentityCommonName(ctx, r.OldSHA256)
	if err != nil {
		return err
	}
	if want == "" || cert.Subject.CommonName != want {
		return fmt.Errorf("its name %q differs from the current certificate's %q", cert.Subject.CommonName, want)
	}
	return nil
}

// RenewalCommand names the command a device with an expired certificate may
// be given. With none waiting it starts a renewal, so the device is asked to
// come back for it.
func (s *Service) RenewalCommand(ctx context.Context, deviceID string) string {
	last, ok, err := s.store.LastRenewal(ctx, deviceID)
	if err != nil {
		s.log.Warn("renewal: look up attempt", "device", deviceID, "err", err)
		return ""
	}
	if ok && (last.State == "lookup" || last.State == "sent") {
		return last.CommandUUID
	}
	if ok && last.Open() {
		return ""
	}
	if s.opts.ManualOnly {
		return ""
	}
	c, found, err := s.store.RenewalCandidate(ctx, deviceID)
	if err != nil || !found || !s.shouldStart(c) {
		return ""
	}
	// Off the request path: queueing also sends the push that brings the
	// device back for the command.
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if err := s.start(ctx, c, "schedule"); err != nil && !errors.Is(err, sqlite.ErrRenewalOpen) {
			s.log.Warn("renewal: start at check-in", "device", c.DeviceName, "err", err)
		}
	}()
	return ""
}
