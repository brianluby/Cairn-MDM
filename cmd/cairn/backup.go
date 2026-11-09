package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nickpdawson/cairn-mdm/internal/alert"
	"github.com/nickpdawson/cairn-mdm/internal/backup"
	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/version"

	_ "modernc.org/sqlite"
)

// runBackup writes a backup bundle: a consistent online snapshot of the SQLite
// database (VACUUM INTO, safe while the server runs), the MFA encryption key,
// the configuration file and every file it references, plus a manifest with
// hashes and record counts. With -db-only it writes just the database snapshot
// as before. When a webhook is configured the outcome is reported there, so a
// backup that stops running is noticed.
func runBackup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	out := fs.String("out", "", "destination file (required): .tar.gz bundle, or .db with -db-only")
	dbOnly := fs.Bool("db-only", false, "write only the database snapshot (legacy behavior)")
	verify := fs.Bool("verify", true, "verify the bundle by extracting it into a scratch directory")
	notify := fs.Bool("notify", true, "report the outcome to alerts.webhook_url when configured")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("-out <file> is required")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("backup supports the sqlite driver only (driver is %q)", cfg.Storage.Driver)
	}
	var notifier *alert.Notifier
	if *notify && cfg.Alerts.Enabled() {
		notifier = alert.NewNotifier(cfg.Alerts.WebhookURL)
	}
	report := func(ok bool, detail string) {
		if notifier == nil {
			return
		}
		title, priority := "Cairn backup completed", "low"
		if !ok {
			title, priority = "Cairn backup FAILED", "high"
		}
		if err := notifier.Send(ctx, title, detail, priority); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not report backup outcome: %v\n", err)
		}
	}

	if *dbOnly {
		err := snapshotOnly(ctx, cfg, *out, *verify)
		if err != nil {
			report(false, err.Error())
			return err
		}
		report(true, "Database snapshot written to "+*out)
		return nil
	}

	opts := backup.Options{
		DBPath:     cfg.Storage.Path,
		MFAKeyPath: filepath.Join(cfg.Storage.Path+".mfa", "key"),
		ConfigPath: *configPath,
		Extra:      referencedFiles(cfg),
		Out:        *out,
		Version:    version.Version,
		Commit:     version.Commit,
	}
	m, err := backup.Create(ctx, opts)
	if err != nil {
		report(false, err.Error())
		return err
	}
	fi, _ := os.Stat(*out)
	fmt.Printf("bundle written: %s", *out)
	if fi != nil {
		fmt.Printf(" (%d bytes)", fi.Size())
	}
	fmt.Println()
	fmt.Printf("  files: %d · devices: %d (%d pushable) · profiles: %d · groups: %d · grants: %d · quarantined: %d\n",
		len(m.Files), m.Counts.Devices, m.Counts.Pushable, m.Counts.Profiles, m.Counts.Groups, m.Counts.Grants, m.Counts.Quarantined)
	for _, t := range m.Topics {
		fmt.Printf("  APNs topic %s expires %s\n", t.Topic, t.NotAfter)
	}
	fmt.Printf("  MFA key included: %v\n", m.MFAKeyIncluded)
	for _, n := range m.Notes {
		fmt.Printf("  note: %s\n", n)
	}
	summary := fmt.Sprintf("%s: %d devices, %d profiles, MFA key %v", *out, m.Counts.Devices, m.Counts.Profiles, m.MFAKeyIncluded)
	if *verify {
		scratch, err := os.MkdirTemp(filepath.Dir(*out), ".cairn-verify-*")
		if err != nil {
			report(false, "bundle written but verification could not start: "+err.Error())
			return err
		}
		defer os.RemoveAll(scratch)
		rep, err := backup.Verify(ctx, *out, scratch)
		if err != nil {
			report(false, "bundle written but verification failed: "+err.Error())
			return err
		}
		if !rep.OK() {
			for _, p := range rep.Problems {
				fmt.Printf("  PROBLEM: %s\n", p)
			}
			report(false, "bundle written but verification found problems: "+strings.Join(rep.Problems, "; "))
			return fmt.Errorf("bundle verification found %d problem(s)", len(rep.Problems))
		}
		fmt.Println("  verification: ok (hashes, integrity, counts)")
		summary += ", verified"
	}
	if len(m.Notes) > 0 {
		summary += ". Notes: " + strings.Join(m.Notes, "; ")
	}
	report(true, summary)
	fmt.Println("\nCopy the bundle off-host; it contains private keys. Rehearse a restore with:")
	fmt.Printf("  cairn restore -bundle %s -rehearse\n", *out)
	return nil
}

// snapshotOnly is the legacy single-file database backup.
func snapshotOnly(ctx context.Context, cfg config.Config, out string, verify bool) error {
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("destination %s already exists; choose a new path", out)
	}
	if dir := filepath.Dir(out); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	src, err := sql.Open("sqlite", cfg.Storage.Path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return fmt.Errorf("open source db: %w", err)
	}
	defer src.Close()
	if err := src.PingContext(ctx); err != nil {
		return fmt.Errorf("source db unreachable: %w", err)
	}
	if _, err := src.ExecContext(ctx, `VACUUM INTO ?`, out); err != nil {
		return fmt.Errorf("vacuum into %s: %w", out, err)
	}
	if err := os.Chmod(out, 0o600); err != nil {
		return fmt.Errorf("tighten backup perms: %w", err)
	}
	fmt.Printf("backup written: %s\n", out)
	if verify {
		bak, err := sql.Open("sqlite", out)
		if err != nil {
			return fmt.Errorf("reopen backup: %w", err)
		}
		defer bak.Close()
		var result string
		if err := bak.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
			return fmt.Errorf("integrity check: %w", err)
		}
		if result != "ok" {
			return fmt.Errorf("backup integrity check FAILED: %s", result)
		}
		fmt.Println("integrity check: ok")
	}
	fmt.Printf("This snapshot omits the MFA key (%s.mfa/key) and configuration; prefer a bundle (omit -db-only).\n", cfg.Storage.Path)
	return nil
}

// referencedFiles lists every file path the configuration points at, so a bundle
// carries the certificates, keys and secret files a restore needs.
func referencedFiles(cfg config.Config) []string {
	candidates := []string{
		cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile,
		cfg.Profile.Signing.CertFile, cfg.Profile.Signing.KeyFile,
		cfg.CA.Import.CertFile, cfg.CA.Import.KeyFile, cfg.CA.Import.RootCertFile,
		cfg.CA.External.CAChainFile, cfg.CA.External.ChallengeFile,
		cfg.CA.Broker.RACertFile, cfg.CA.Broker.RAKeyFile, cfg.CA.Broker.CAChainFile, cfg.CA.Broker.ChallengeFile,
		cfg.Auth.LDAP.BindPasswordFile, cfg.Auth.OIDC.ClientSecretFile, cfg.Alerts.WebhookURLFile,
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}
