package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	directoryldap "github.com/nickpdawson/cairn-mdm/internal/auth/ldap"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/alert"
	"github.com/nickpdawson/cairn-mdm/internal/assign"
	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/enroll"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/push"
	"github.com/nickpdawson/cairn-mdm/internal/quarantine"
	"github.com/nickpdawson/cairn-mdm/internal/server"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/targeting"
	"github.com/nickpdawson/cairn-mdm/internal/version"
	"github.com/nickpdawson/cairn-mdm/internal/web"
)

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	log := version.NewLogger(cfg.Log.Format, cfg.Log.Level)
	log.Info("starting", "build", version.Info(), "public_url", cfg.Server.PublicURL)

	// Storage.
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("storage driver %q not yet implemented (Phase 4)", cfg.Storage.Driver)
	}
	db, err := sqlite.Open(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()
	log.Info("storage ready", "driver", cfg.Storage.Driver, "path", cfg.Storage.Path)

	// Assemble the embedded NanoMDM service over our storage. The SQLite DB is
	// the device-inventory projector — enrollments update the inventory as they
	// happen (no polling).
	nanoStore := db.NanoStorage(log)
	core := mdmcore.New(nanoStore, mdmcore.NewLogAdapter(log), db, db, log)
	log.Info("mdm service ready", "path", cfg.Server.MDMPath)

	deps := server.Deps{MDM: core.Handler()}

	// One verified-directory provider serves owner checks at redemption and
	// issuance, console lookups and directory targeting. Absent a directory ID,
	// owner-authorized grants fail closed everywhere.
	var directoryProvider *directoryldap.Provider
	if cfg.Auth.LDAP.Enabled && cfg.Auth.LDAP.DirectoryID != "" {
		directoryProvider, err = directoryldap.New(cfg.Auth.LDAP, log)
		if err != nil {
			return err
		}
	}
	resolver := grantResolver{db: db}
	if directoryProvider != nil {
		resolver.directory = directoryProvider
	}

	// Configure SCEP + enrollment per ca.mode (generate | import | external).
	pki, err := wirePKI(ctx, cfg, db, db, resolver, log, &deps)
	if err != nil {
		return err
	}

	// Admin console.
	pusher := push.NewPusher(nanoStore, mdmcore.NewLogAdapter(log))
	notificationCtx, stopNotifications := context.WithCancel(ctx)
	notificationDone := make(chan struct{})
	go func() {
		defer close(notificationDone)
		mdmcore.RunNotifications(notificationCtx, nanoStore.(mdmcore.NotificationStore), pusher, log)
	}()
	defer func() { stopNotifications(); <-notificationDone }()
	commander := mdmcore.NewCommander(nanoStore, pusher).WithRecorder(db, log)

	// Login abuse controls (MDM-AUTH-001): session idle timeout + absolute cap
	// come from the login policy; a bare [auth.login] table still yields working
	// defaults via WithDefaults.
	loginPolicy := cfg.Auth.Login.WithDefaults()
	sessions := auth.NewSessionStore(db.SQL(), time.Duration(loginPolicy.IdleTimeoutMins)*time.Minute)
	sessions.SetMaxLifetime(time.Duration(loginPolicy.MaxLifetimeMins) * time.Minute)
	loginThrottle := auth.NewLoginThrottle(cfg.Auth.Login)

	// Session cleanup: purge expired rows hourly.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := sessions.DeleteExpired(ctx); err != nil {
					log.Warn("session cleanup failed", "err", err)
				} else if n > 0 {
					log.Info("session cleanup", "purged", n)
				}
			}
		}
	}()
	// Assignment reconciler: pushes assigned profiles when devices enroll and
	// when admins change groups/assignments. Event-driven — no polling loop.
	reconciler := assign.New(db, commander, log)
	// Directory targeting runs ahead of the reconciler on enrollment: bind the
	// verified owner, apply group/OU rules, then push. Without a verified
	// directory it still binds owners and reconciles manual memberships.
	var targetingDirectory targeting.Directory
	if directoryProvider != nil {
		targetingDirectory = directoryProvider
	}
	targeter := targeting.New(db, targetingDirectory, reconciler, log)
	core.OnPushable(targeter.DeviceNowPushable)

	authn, err := buildAuthenticator(cfg, db, log)
	if err != nil {
		return err
	}

	console, err := web.New(sessions, authn, db, commander, reconciler,
		web.Config{
			PublicURL:           cfg.Server.PublicURL,
			OwnerEnrollment:     cfg.CA.Mode.Embedded() || cfg.CA.Mode == config.CABroker,
			Organization:        pki.Org,
			SCEPURL:             pki.SCEPURL,
			SCEPChallenge:       pki.Challenge,
			CAAnchorsDER:        pki.Anchors,
			TrustedProxies:      cfg.Server.TLS.TrustedProxies,
			CAMode:              string(cfg.CA.Mode),
			TLSMode:             string(cfg.Server.TLS.Mode),
			LDAPEnabled:         cfg.Auth.LDAP.Enabled,
			DirectoryConfigured: cfg.Auth.LDAP.Enabled && cfg.Auth.LDAP.DirectoryID != "",
			AlertsConfigured:    cfg.Alerts.Enabled(),
		}, log)
	if err != nil {
		return err
	}
	// Browser first-run: open only until the first local account exists, gated
	// by a token file beside the database that only the host user can read.
	setupGate := auth.NewSetupGate(db.SQL(), cfg.Storage.Path)
	if open, err := setupGate.Prepare(ctx); err != nil {
		return err
	} else if open {
		log.Warn("no administrator exists: first-time setup is open", "url", strings.TrimRight(cfg.Server.PublicURL, "/")+"/setup", "token_file", setupGate.TokenPath())
	}
	console.SetSetup(setupGate)
	if directoryProvider != nil {
		console.SetDirectory(directoryProvider)
		console.SetTargeting(targeter)
	}
	console.SetLoginThrottle(loginThrottle)
	// Local-account management in the console (admin-only). Directory-backed
	// (LDAP/OIDC) identities are owned by their provider and stay outside this.
	console.SetUsers(auth.NewLocalStore(db.SQL()))
	mfaKey, err := auth.OpenMFAKey(ctx, db.SQL(), cfg.Storage.Path)
	if err != nil {
		return err
	}
	mfa, err := auth.NewMFAStore(db.SQL(), sessions, mfaKey)
	if err != nil {
		return err
	}
	console.SetMFA(mfa)
	// Evidence-gated quarantine release. Only the embedded CA can produce the
	// fence and enumeration manifests; other backends leave holds read-only.
	console.SetQuarantineResolver(quarantine.New(db, pki.Authority, cfg.RADIUS.AcceptancePoints))
	console.SetRadiusIngestToken(cfg.RADIUS.IngestToken)
	console.SetAPNS(push.RequestManager{Root: filepath.Join(pushcertDir(cfg), "requests")}, db)

	// OIDC single sign-on (redirect flow) is wired separately from the
	// username/password authenticator chain.
	oidcProvider, err := buildOIDC(ctx, cfg, log)
	if err != nil {
		return err
	}
	if oidcProvider != nil {
		console.SetOIDC(oidcProvider)
	}

	deps.UI = console
	log.Info("admin console ready", "path", "/admin")

	// Out-of-band alerts: hourly checks for certificate expiry, quarantine and
	// backup freshness, with transitions, reminders and a heartbeat posted to
	// the webhook. Without a webhook the conditions are still recorded for the
	// dashboard, so the console shows them either way.
	var notifier *alert.Notifier
	if cfg.Alerts.Enabled() {
		notifier = alert.NewNotifier(cfg.Alerts.WebhookURL)
		log.Info("alerts enabled", "heartbeat_hours", cfg.Alerts.WithDefaults().HeartbeatHours, "backup_dir", cfg.Alerts.BackupDir)
	} else {
		log.Warn("alerts.webhook_url not set: expiry, quarantine and backup alerts stay on the dashboard only")
	}
	go alert.New(db, notifier, cfg.Alerts, log).Loop(ctx, time.Hour)

	srv := server.New(cfg, log, db, deps)
	httpSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,  // full request incl. body (uploads cap at 2 MiB)
		WriteTimeout:      60 * time.Second,  // profile downloads / rendered pages
		IdleTimeout:       120 * time.Second, // keep-alive reuse window
		MaxHeaderBytes:    1 << 20,           // 1 MiB of request headers
	}

	serveTLS, err := configureTLS(cfg, httpSrv, log)
	if err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Server.Listen, "tls", cfg.Server.TLS.Mode)
		if err := serveTLS(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Info("stopped")
	return nil
}

// grantRedeemer adapts *sqlite.DB to enroll.Redeemer (translating the storage
// Redemption type to the enroll one).
type grantRedeemer struct {
	db       *sqlite.DB
	resolver grantResolver
}

func (g grantRedeemer) RedeemGrant(ctx context.Context, rawToken string) (enroll.Redemption, error) {
	if _, err := g.resolver.validate(ctx, rawToken); err != nil {
		return enroll.Redemption{}, err
	}
	r, err := g.db.RedeemGrant(ctx, rawToken)
	if err != nil {
		return enroll.Redemption{}, err
	}
	return enroll.Redemption{Platform: r.Platform, Owner: r.Owner, ExpectedSerial: r.ExpectedSerial}, nil
}

// publicHost extracts the host from the configured public URL for use in the CA
// subject. It falls back to the raw value if parsing fails (validation has
// already ensured it is a URL, so this is defensive).
func publicHost(publicURL string) string {
	if u, err := url.Parse(publicURL); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return publicURL
}

func (g grantRedeemer) InspectGrant(ctx context.Context, rawToken string) error {
	info, err := g.resolver.validate(ctx, rawToken)
	if err != nil {
		return err
	}
	grant, err := g.db.GetGrant(ctx, info.ID)
	if err != nil {
		return err
	}
	if grant.Status() != "active" {
		return sqlite.ErrGrantInvalid
	}
	return nil
}
