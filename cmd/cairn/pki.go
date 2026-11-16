package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"time"

	kitlog "github.com/go-kit/kit/log"
	scepserver "github.com/micromdm/scep/v2/server"

	"github.com/nickpdawson/cairn-mdm/internal/broker"
	"github.com/nickpdawson/cairn-mdm/internal/ca"
	"github.com/nickpdawson/cairn-mdm/internal/challenge"
	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/enroll"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/profile"
	"github.com/nickpdawson/cairn-mdm/internal/push"
	"github.com/nickpdawson/cairn-mdm/internal/renew"
	"github.com/nickpdawson/cairn-mdm/internal/server"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// brokerDefaultMaxLeafValidityDays is the default accepted ceiling on the validity
// span of certificates the backend CA returns in broker mode. It comfortably covers a
// 1-year backend profile plus margin; operators tighten it via
// [ca.broker] max_leaf_validity_days. All other verify checks are unaffected.
const brokerDefaultMaxLeafValidityDays = 400

// grantResolver adapts the sqlite grant lookup to issue.GrantResolver: it maps a
// presented SCEP challenge (the grant's raw token) to the grant's issuance facts,
// without consuming the grant.
type ownerValidator interface {
	RevalidateOwner(context.Context, directory.DirectoryIdentity) (*directory.DirectoryIdentity, error)
}
type grantResolver struct {
	db        *sqlite.DB
	directory ownerValidator
}

func (r grantResolver) validate(ctx context.Context, challenge string) (sqlite.GrantIssuanceInfo, error) {
	info, err := r.db.LookupGrantForIssuance(ctx, challenge)
	if err != nil {
		return info, err
	}
	if r.directory == nil || info.OwnerIdentity == nil || info.ActorSubject == "" {
		return info, sqlite.ErrGrantInvalid
	}
	fresh, err := r.directory.RevalidateOwner(ctx, *info.OwnerIdentity)
	if err != nil || fresh == nil || fresh.DirectoryID != info.OwnerIdentity.DirectoryID || fresh.ObjectID != info.OwnerIdentity.ObjectID || fresh.UPN != info.Owner {
		return info, sqlite.ErrGrantInvalid
	}
	return info, nil
}

func (r grantResolver) LookupForIssuance(ctx context.Context, challenge string) (issue.GrantFacts, error) {
	info, err := r.validate(ctx, challenge)
	if err != nil {
		return issue.GrantFacts{}, err
	}
	cn := info.Owner
	if cn == "" {
		cn = fmt.Sprintf("cairn-device-%d", info.ID)
	}
	return issue.GrantFacts{GrantID: info.ID, Owner: info.Owner, CommonName: cn, Platform: info.Platform}, nil
}

// wirePKI configures the SCEP and enrollment handlers according to ca.mode:
//
//	generate/import — Cairn runs the embedded SCEP CA and mounts /scep; the
//	                  enrollment profile installs Cairn's CA and points SCEP at
//	                  <public_url>/scep.
//	external        — no /scep; the enrollment profile installs the configured
//	                  trust chain and points SCEP at ca.external.scep_url.
//
// It mutates deps and returns a summary of the wired PKI so other parts of the
// binary (the console's profile builders, future profile signing) can reuse the
// SCEP endpoint, challenge, and trust anchors without re-deriving them.
type pkiResult struct {
	Authority *ca.CA // nil in external mode
	Org       string // reverse-DNS identifier root, e.g. "cairn.mdm.example.org"
	SCEPURL   string
	Challenge string
	Anchors   [][]byte // trust-anchor certs (DER)
	// Challenges issues one-time SCEP challenges when the external CA looks
	// them up with Cairn. Nil otherwise.
	Challenges *challenge.Service
	// RenewalProfile builds the enrollment profile that renews a device's
	// identity certificate. Nil in the modes where renewal is not built.
	RenewalProfile func(renew.Target) ([]byte, error)
}

// resolver carries the verified-owner boundary shared by profile redemption and
// certificate issuance: without a directory validator every grant fails closed.
func wirePKI(ctx context.Context, cfg config.Config, store *sqlite.DB, topics enroll.TopicProvider, resolver grantResolver, log *slog.Logger, deps *server.Deps) (*pkiResult, error) {
	// Redeem and issue use the same verified owner boundary. Legacy grants do not
	// inherit authorization merely because their free-text owner happens to match.
	redeemer := grantRedeemer{db: store, resolver: resolver}
	host := publicHost(cfg.Server.PublicURL)
	org := "cairn." + host

	// Optional profile-signing identity (validated at startup — a bad/expired
	// signing cert fails the boot rather than silently serving unsigned).
	var signer *profile.Signer
	if s := cfg.Profile.Signing; s.Enabled() {
		var err error
		signer, err = profile.LoadSigner(s.CertFile, s.KeyFile)
		if err != nil {
			return nil, err
		}
		log.Info("enrollment profile signing enabled", "signer", signer.Fingerprint(),
			"days_to_expiry", signer.DaysUntilExpiry())
	} else {
		log.Warn("enrollment profiles are UNSIGNED (set [profile.signing] cert_file/key_file)")
	}

	// mountEnroll builds the enroll handler and mounts both the grant route
	// (GET /e/{token}) and the bare /enroll route (default-denied unless
	// enrollment.allow_open).
	mountEnroll := func(c enroll.Config) {
		c.AllowOpen = cfg.Enrollment.AllowOpen
		c.Signer = signer
		h := enroll.New(c, topics, redeemer, push.SettingTopic, log)
		deps.Enroll = h
		deps.EnrollGrant = http.HandlerFunc(h.ServeGrant)
	}

	if cfg.CA.Mode.Embedded() {
		opts := ca.Options{
			CommonName:   "Cairn CA (" + host + ")",
			Organization: "Cairn",
			Challenge:    cfg.CA.External.Challenge, // static challenge if configured
		}
		if cfg.CA.Mode == config.CAImport {
			certPEM, err := os.ReadFile(cfg.CA.Import.CertFile)
			if err != nil {
				return nil, fmt.Errorf("read ca.import.cert_file: %w", err)
			}
			keyPEM, err := os.ReadFile(cfg.CA.Import.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("read ca.import.key_file: %w", err)
			}
			if cfg.CA.Import.RootCertFile != "" {
				// Two-tier: cert/key are the online issuer, root_cert_file is the offline root.
				rootPEM, err := os.ReadFile(cfg.CA.Import.RootCertFile)
				if err != nil {
					return nil, fmt.Errorf("read ca.import.root_cert_file: %w", err)
				}
				opts.ImportRootCertPEM = rootPEM
				opts.ImportIssuerCertPEM = certPEM
				opts.ImportIssuerKeyPEM = keyPEM
			} else {
				opts.ImportCertPEM = certPEM
				opts.ImportKeyPEM = keyPEM
			}
		}

		authority, err := ca.Ensure(ctx, store.SQL(), opts)
		if err != nil {
			return nil, err
		}
		// Route SCEP through the enrollment-authorization Broker: it reconstructs the
		// certificate from policy+grant (never the CSR), drives the issuance state
		// machine, and fails closed to quarantine. The per-enrollment SCEP challenge
		// is the grant's token, which the Broker resolves via grantResolver.
		policy := issue.DefaultPolicy()
		policy.LeafValidity = time.Duration(cfg.Issuance.WithDefaults().LeafValidityDays) * 24 * time.Hour
		policy.CRLDistributionPoint = cfg.Server.PublicURL + "/crl" // embedded CA serves its own CRL
		brk := issue.NewBroker(authority.EmbeddedBackend(), store, resolver, policy).
			WithIssuer(authority.Certificate()).WithRenewalObserver(renewalRecorder{db: store})
		scepHandler, err := authority.SCEPHandlerWith(brk)
		if err != nil {
			return nil, err
		}
		// The envelope signer lets the Broker refuse renewal-style requests
		// explicitly and record them, instead of failing on a spent grant.
		deps.SCEP = issue.SignerExtractMiddleware(scepHandler)
		log.Info("device certificate policy", "leaf_validity_days", cfg.Issuance.WithDefaults().LeafValidityDays, "renewal", "not implemented; re-enroll before expiry")
		profileCerts := authority.ProfileCertsDER() // [cert] single-tier, [root, issuer] two-tier
		mountEnroll(enroll.Config{
			Organization:      org,
			CAAnchorsDER:      profileCerts,
			SCEPURL:           cfg.Server.PublicURL + "/scep",
			PerGrantChallenge: true, // the profile carries the grant token as the SCEP challenge
			MDMServerURL:      cfg.Server.PublicURL + cfg.Server.MDMPath,
			SubjectPrefix:     "devices." + host,
		})

		deps.CA = caDownloadHandler(profileCerts)
		deps.CRL = authority.CRLHandler() // embedded CA revocation list at GET /crl
		log.Info("embedded CA ready", "mode", cfg.CA.Mode, "scep_path", "/scep",
			"ca_cn", authority.Certificate().Subject.CommonName)
		log.Info("enrollment endpoint ready", "grant_path", "/e/{token}", "open", cfg.Enrollment.AllowOpen)
		return &pkiResult{
			Authority: authority,
			Org:       org,
			SCEPURL:   cfg.Server.PublicURL + "/scep",
			Challenge: cfg.CA.External.Challenge,
			Anchors:   profileCerts,
		}, nil
	}

	if cfg.CA.Mode == config.CABroker {
		// Broker mode: the device does grant-gated SCEP to CAIRN, which relays to a
		// backend SCEP CA over a restricted path signed by the RA identity. The Broker
		// reconstructs the certificate from policy+grant and fails closed to quarantine.
		raCert, raKey, err := loadRAIdentity(cfg.CA.Broker.RACertFile, cfg.CA.Broker.RAKeyFile)
		if err != nil {
			return nil, err
		}
		// Backend CA chain: trust anchors installed on the device (so it trusts the
		// issued leaf) and used to parse/verify SCEP replies.
		chainPEM, err := os.ReadFile(cfg.CA.Broker.CAChainFile)
		if err != nil {
			return nil, fmt.Errorf("read ca.broker.backend_ca_chain_file: %w", err)
		}
		anchors, err := ca.TrustAnchorsDER(chainPEM)
		if err != nil {
			return nil, err
		}
		be, err := broker.New(broker.Config{URL: cfg.CA.Broker.SCEPURL, RACert: raCert, RAKey: raKey})
		if err != nil {
			return nil, err
		}
		// Broker-lane policy: the backend CA sets the actual validity, so accept up to a
		// configurable ceiling (default brokerDefaultMaxLeafValidityDays) instead of our
		// own embedded LeafValidity. Every other verify check is unchanged.
		brokerPolicy := issue.DefaultPolicy()
		days := cfg.CA.Broker.MaxLeafValidityDays
		if days <= 0 {
			days = brokerDefaultMaxLeafValidityDays
		}
		brokerPolicy.MaxLeafValidity = time.Duration(days) * 24 * time.Hour
		if cfg.CA.Broker.CRLURL != "" {
			brokerPolicy.CRLDistributionPoint = cfg.CA.Broker.CRLURL
		}
		brk := issue.NewBroker(be, store, resolver, brokerPolicy)
		// Device-facing SCEP endpoint: the RA identity is the SCEP server cert the
		// device encrypts to; the Broker is the signer. The backend SCEP is never
		// exposed to devices.
		scepHandler, err := brokerSCEPHandler(raCert, raKey, brk)
		if err != nil {
			return nil, err
		}
		deps.SCEP = scepHandler
		mountEnroll(enroll.Config{
			Organization:      org,
			CAAnchorsDER:      anchors,
			SCEPURL:           cfg.Server.PublicURL + "/scep", // device talks to Cairn, not the backend
			PerGrantChallenge: true,
			MDMServerURL:      cfg.Server.PublicURL + cfg.Server.MDMPath,
			SubjectPrefix:     "devices." + host,
		})
		deps.CA = caDownloadHandler(anchors)
		log.Info("broker SCEP configured", "backend", cfg.CA.Broker.SCEPURL,
			"device_scep_path", "/scep", "trust_anchors", len(anchors))
		log.Info("enrollment endpoint ready", "grant_path", "/e/{token}", "open", cfg.Enrollment.AllowOpen)
		return &pkiResult{
			Org:     org,
			SCEPURL: cfg.Server.PublicURL + "/scep",
			Anchors: anchors,
		}, nil
	}

	// external mode: delegate SCEP to a third-party server (OpenXPKI, NDES).
	chainPEM, err := os.ReadFile(cfg.CA.External.CAChainFile)
	if err != nil {
		return nil, fmt.Errorf("read ca.external.ca_chain_file: %w", err)
	}
	anchors, err := ca.TrustAnchorsDER(chainPEM)
	if err != nil {
		return nil, err
	}
	// With a lookup the CA asks Cairn about every request, so each profile
	// gets a challenge of its own and the static one is not used.
	var challenges *challenge.Service
	var mintEnroll func(context.Context, string, string, string) (string, error)
	var mintRenew func(context.Context, string, string) (string, error)
	if l := cfg.CA.External.Lookup; l.Enabled {
		var sources []netip.Prefix
		for _, src := range l.AllowedSources {
			p, err := config.ParseSource(src)
			if err != nil {
				return nil, fmt.Errorf("ca.external.challenge_lookup.allowed_sources: %w", err)
			}
			sources = append(sources, p)
		}
		if challenges, err = challenge.New(store, challenge.Options{Secret: l.Secret, AllowedSources: sources}, log); err != nil {
			return nil, err
		}
		deps.SCEPChallenge = challenges.Handler()
		mintEnroll, mintRenew = challenges.ForEnrollment, challenges.ForRenewal
		log.Info("one-time SCEP challenges enabled; the CA must look each one up", "lookup_path", "/scep-challenge/{name}/{keyid}/{challenge}", "allowed_sources", len(sources))
	}
	mountEnroll(enroll.Config{
		Organization:  org,
		CAAnchorsDER:  anchors,
		SCEPURL:       cfg.CA.External.SCEPURL,
		Challenge:     cfg.CA.External.Challenge,
		MintChallenge: mintEnroll,
		MDMServerURL:  cfg.Server.PublicURL + cfg.Server.MDMPath,
		SubjectPrefix: "devices." + host,
	})

	deps.CA = caDownloadHandler(anchors)
	log.Info("external SCEP configured", "scep_url", cfg.CA.External.SCEPURL, "trust_anchors", len(anchors))
	log.Info("enrollment endpoint ready", "grant_path", "/e/{token}", "open", cfg.Enrollment.AllowOpen)
	renewalProfile := externalRenewalProfile(org, anchors, cfg.CA.External.SCEPURL, cfg.CA.External.Challenge, mintRenew, signer)
	return &pkiResult{
		Challenges:     challenges,
		Org:            org,
		SCEPURL:        cfg.CA.External.SCEPURL,
		Challenge:      cfg.CA.External.Challenge,
		Anchors:        anchors,
		RenewalProfile: renewalProfile,
	}, nil
}

// renewalKeyCheck is the renewal service's key check when the CA looks
// challenges up with Cairn, and nil when it does not.
func renewalKeyCheck(c *challenge.Service) func(context.Context, string, *x509.Certificate, time.Time) error {
	if c == nil {
		return nil
	}
	return c.RenewedKey
}

// externalRenewalProfile returns the builder for the profile that renews a
// device's identity certificate in external mode. A renewal is the enrollment
// profile pushed over MDM: the device asks the external CA for a new
// certificate exactly as it did when it enrolled.
func externalRenewalProfile(org string, anchors [][]byte, scepURL, static string, mint func(context.Context, string, string) (string, error), signer *profile.Signer) func(renew.Target) ([]byte, error) {
	return func(t renew.Target) ([]byte, error) {
		challenge := static
		if mint != nil {
			var err error
			if challenge, err = mint(context.Background(), t.DeviceID, t.CommonName); err != nil {
				return nil, fmt.Errorf("one-time challenge: %w", err)
			}
		}
		// The device's own topic, not the server default: a server can hold
		// several push certificates, and a device refuses an enrollment
		// profile whose topic differs from the one it enrolled under.
		if t.Topic == "" {
			return nil, errors.New("the device has no push topic on record")
		}
		prof, err := profile.BuildEnrollment(profile.EnrollmentParams{
			Organization:      org,
			ProfileIdentifier: t.Identifier,
			DisplayName:       t.DisplayName,
			OrganizationName:  t.Organization,
			CAAnchorsDER:      anchors,
			SCEPURL:           scepURL,
			SubjectCN:         t.CommonName,
			OwnerRFC822:       t.OwnerEmail,
			Challenge:         challenge,
			MDMServerURL:      t.ServerURL,
			MDMCheckInURL:     t.ServerURL,
			Topic:             t.Topic,
		})
		if err != nil {
			return nil, err
		}
		body, err := profile.Marshal(prof)
		if err != nil || signer == nil {
			return body, err
		}
		return profile.Sign(body, *signer)
	}
}

// caDownloadHandler serves the trust anchors as a PEM bundle at GET /ca, so a
// device can install the root out-of-band before enrolling (needed for
// fully-offline / private-TLS deployments).
func caDownloadHandler(anchorsDER [][]byte) http.Handler {
	var buf []byte
	for _, der := range anchorsDER {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="cairn-ca.pem"`)
		_, _ = w.Write(buf)
	})
}

// loadRAIdentity loads the broker's RA cert + RSA key from PEM files. The key must
// be RSA: SCEP encrypts the backend's reply to the envelope signer via PKCS#7 key
// transport.
func loadRAIdentity(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	if certFile == "" || keyFile == "" {
		return nil, nil, fmt.Errorf("broker: ra_cert_file and ra_key_file are required")
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read ra_cert_file: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("ra_cert_file is not a PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ra cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read ra_key_file: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("ra_key_file is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(kb.Bytes); err == nil {
		return cert, k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ra key (PKCS1/PKCS8): %w", err)
	}
	rk, ok := k8.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("broker: RA key must be RSA (SCEP reply decryption)")
	}
	return cert, rk, nil
}

// brokerSCEPHandler builds the device-facing SCEP HTTP handler for broker mode: the
// RA identity is the SCEP server cert/key (the device encrypts its request to it) and
// the enrollment-authorization Broker is the signer.
func brokerSCEPHandler(cert *x509.Certificate, key *rsa.PrivateKey, signer scepserver.CSRSignerContext) (http.Handler, error) {
	svc, err := scepserver.NewService(cert, key, signer)
	if err != nil {
		return nil, fmt.Errorf("broker: new scep service: %w", err)
	}
	e := scepserver.MakeServerEndpoints(svc)
	return scepserver.MakeHTTPHandler(e, svc, kitlog.NewNopLogger()), nil
}

// renewalRecorder adapts the storage layer to issue.RenewalObserver without the
// storage package importing issue.
type renewalRecorder struct{ db *sqlite.DB }

func (r renewalRecorder) RecordRenewalAttempt(ctx context.Context, a issue.RenewalAttempt) error {
	return r.db.RecordRenewalAttempt(ctx, sqlite.RenewalAttempt{
		SPKISHA256: a.SPKISHA256, SignerSerial: a.SignerSerial, SignerSHA256: a.SignerSHA256,
		SignerSubject: a.SignerSubject, SignerExpires: a.SignerExpires, Reason: a.Reason,
	})
}
