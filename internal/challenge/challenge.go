// Package challenge gives devices one-time SCEP challenges and answers an
// external CA that asks whether a request may use one.
//
// It is for a CA that devices talk to directly (ca.mode external). Without it
// every enrollment profile carries the same static challenge, and anyone who
// has one profile can ask the CA for a certificate in any name. With it the CA
// calls Cairn for each request, passing the certificate name, the request's
// key identifier and the challenge the device presented; Cairn says yes once,
// for the name and key the challenge was made for.
package challenge

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// Store is the persistence the service needs; *sqlite.DB provides it.
type Store interface {
	CreateSCEPChallenge(ctx context.Context, c sqlite.SCEPChallenge, expires time.Time) error
	UseSCEPChallenge(ctx context.Context, challengeSHA256, commonName, keyID string, now time.Time) (bool, string, error)
	RenewalKeyIssued(ctx context.Context, deviceID, keyID string, since time.Time) (bool, error)
	PruneSCEPChallenges(ctx context.Context, now time.Time, keep time.Duration) error
}

// Options configure the service.
type Options struct {
	// Secret is what the CA presents as a bearer token on every lookup.
	Secret string
	// AllowedSources, when set, limits lookups to these addresses or networks,
	// judged by the connection's own address. Use it when the CA reaches Cairn
	// directly, not through a proxy.
	AllowedSources []netip.Prefix
	// EnrollTTL and RenewTTL are how long a challenge works. Zero means one
	// day and seven days.
	EnrollTTL time.Duration
	RenewTTL  time.Duration
	Now       func() time.Time
}

// Service mints challenges and answers lookups.
type Service struct {
	store Store
	opts  Options
	log   *slog.Logger
}

// New builds the service.
func New(store Store, opts Options, log *slog.Logger) (*Service, error) {
	if len(opts.Secret) < 32 {
		return nil, errors.New("challenge: the lookup secret must be at least 32 characters")
	}
	if opts.EnrollTTL == 0 {
		opts.EnrollTTL = 24 * time.Hour
	}
	if opts.RenewTTL == 0 {
		opts.RenewTTL = 7 * 24 * time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Service{store: store, opts: opts, log: log}, nil
}

func hashOf(challenge string) string {
	sum := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(sum[:])
}

func (s *Service) mint(ctx context.Context, c sqlite.SCEPChallenge, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	// URL-safe: the CA puts it in a request path.
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	c.ChallengeSHA256 = hashOf(challenge)
	if err := s.store.CreateSCEPChallenge(ctx, c, s.opts.Now().Add(ttl)); err != nil {
		return "", err
	}
	return challenge, nil
}

// ForEnrollment mints the challenge for a new enrollment profile. commonName
// is the certificate name the device will ask for when Cairn knows it;
// otherwise the name must end in "." + cnSuffix.
func (s *Service) ForEnrollment(ctx context.Context, commonName, cnSuffix, note string) (string, error) {
	if commonName == "" && cnSuffix == "" {
		return "", errors.New("challenge: an enrollment challenge needs a name or a name ending")
	}
	return s.mint(ctx, sqlite.SCEPChallenge{Purpose: "enroll", CommonName: commonName, CNSuffix: cnSuffix, Note: note}, s.opts.EnrollTTL)
}

// ForRenewal mints the challenge for the profile that renews a device's
// certificate under the same name.
func (s *Service) ForRenewal(ctx context.Context, deviceID, commonName string) (string, error) {
	if deviceID == "" || commonName == "" {
		return "", errors.New("challenge: a renewal challenge needs the device and its certificate name")
	}
	return s.mint(ctx, sqlite.SCEPChallenge{Purpose: "renew", DeviceID: deviceID, CommonName: commonName}, s.opts.RenewTTL)
}

// KeyID is the subject key identifier a CA derives from a request's public
// key: the SHA-1 of the key bits, as lowercase hex.
func KeyID(cert *x509.Certificate) (string, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return "", err
	}
	sum := sha1.Sum(spki.Key.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeKeyID(id string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(id))
}

// RenewedKey reports an error unless cert's key is the one that used a
// renewal challenge made for the device since the given time. It is how a
// renewal tells the device's new certificate from one somebody else obtained
// in the same name.
func (s *Service) RenewedKey(ctx context.Context, deviceID string, cert *x509.Certificate, since time.Time) error {
	id, err := KeyID(cert)
	if err != nil {
		return err
	}
	ok, err := s.store.RenewalKeyIssued(ctx, deviceID, id, since)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("its key did not use this device's renewal challenge")
	}
	return nil
}

// Prune closes expired challenges and drops old rows.
func (s *Service) Prune(ctx context.Context) {
	if err := s.store.PruneSCEPChallenges(ctx, s.opts.Now(), 90*24*time.Hour); err != nil {
		s.log.Error("challenge: prune", "err", err)
	}
}

// Handler answers GET {name}/{keyid}/{challenge}, the three path values the CA
// fills in. A request that may proceed gets 200 with the challenge as the body,
// which is what a CA that compares the returned value with the presented one
// expects. Everything else, a wrong bearer token included, gets the same 404.
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		name, keyID, presented := r.PathValue("name"), normalizeKeyID(r.PathValue("keyid")), r.PathValue("challenge")
		deny := func(why string) {
			s.log.Warn("challenge: lookup refused", "reason", why, "name", name, "remote", r.RemoteAddr)
			http.NotFound(w, r)
		}
		if !s.sourceAllowed(r.RemoteAddr) {
			deny("source address not allowed")
			return
		}
		token, isBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		got, want := sha256.Sum256([]byte(token)), sha256.Sum256([]byte(s.opts.Secret))
		if !isBearer || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			deny("wrong or missing bearer token")
			return
		}
		if presented == "" {
			deny("no challenge in the request")
			return
		}
		ok, why, err := s.store.UseSCEPChallenge(r.Context(), hashOf(presented), name, keyID, s.opts.Now())
		if err != nil {
			s.log.Error("challenge: lookup", "err", err)
			http.Error(w, "lookup failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			deny(why)
			return
		}
		s.log.Info("challenge: accepted", "name", name, "key_id", keyID)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(presented))
	})
}

func (s *Service) sourceAllowed(remote string) bool {
	if len(s.opts.AllowedSources) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range s.opts.AllowedSources {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
