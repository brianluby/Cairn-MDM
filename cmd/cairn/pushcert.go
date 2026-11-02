package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/push"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func runPushcert(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: cairn pushcert <request|decrypt|import|renew|check> [flags]")
	}
	switch args[0] {
	case "request":
		return runPushcertRequest(ctx, args[1:])
	case "decrypt":
		return runPushcertDecrypt(ctx, args[1:])
	case "import":
		return runPushcertImport(ctx, args[1:])
	case "renew":
		return runPushcertWrite(ctx, args[1:], true)
	case "check":
		return runPushcertCheck(ctx, args[1:])
	default:
		return fmt.Errorf("unknown pushcert subcommand %q (want: request, decrypt, import, renew, check)", args[0])
	}
}

func runPushcertImport(ctx context.Context, args []string) error {
	return runPushcertWrite(ctx, args, false)
}

func runPushcertWrite(ctx context.Context, args []string, renewal bool) error {
	name := "pushcert import"
	if renewal {
		name = "pushcert renew"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	certFile := fs.String("cert", "", "APNs push certificate (PEM)")
	keyFile := fs.String("key", "", "APNs push private key (PEM)")
	loadedBy := fs.String("by", "cli", "operator recorded as having imported the cert")
	topicFlag := fs.String("topic", "", "existing topic to renew (required for renew)")
	makeDefault := fs.Bool("make-default", false, "select an initially imported topic for new enrollments")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if renewal && (*topicFlag == "" || *makeDefault) {
		return fmt.Errorf("renew requires -topic and cannot use -make-default")
	}
	if !renewal && *topicFlag != "" {
		return fmt.Errorf("use pushcert renew with -topic")
	}
	if *certFile == "" || *keyFile == "" {
		return fmt.Errorf("-cert and -key are required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("storage driver %q not yet implemented (Phase 4)", cfg.Storage.Driver)
	}

	pemCert, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	pemKey, err := os.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	db, err := sqlite.OpenExisting(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	info, err := push.InstallCertificate(ctx, db, pemCert, pemKey, push.CertificateWriteOptions{
		RenewTopic: *topicFlag, MakeDefault: *makeDefault, Actor: *loadedBy, Provider: "cli",
	})
	if err != nil {
		return err
	}
	topic, notAfter := info.Topic, info.NotAfter

	if renewal {
		fmt.Printf("APNs push certificate renewed; enrollment default preserved.\n")
	} else {
		fmt.Printf("APNs push certificate imported.\n")
	}
	fmt.Printf("  topic:     %s\n", topic)
	if !notAfter.IsZero() {
		fmt.Printf("  expires:   %s\n", notAfter.Format("2006-01-02"))
	}
	fmt.Printf("\nIMPORTANT: this topic is baked into every enrolled device. When you\n")
	fmt.Printf("renew, renew the SAME certificate under the SAME Apple Account so the\n")
	fmt.Printf("topic does not change — a changed topic orphans every enrollment.\n")
	return nil
}

// runPushcertCheck reports every recorded APNs topic with its expiry and
// renewal tier. It reads the apns_topics table (table-only; it does not open a
// live APNs socket) so it works offline and surfaces each fleet's expiry — the
// visibility MDM-APNS-001 was about.
func runPushcertCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pushcert check", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to cairn.toml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Storage.Driver != config.DriverSQLite {
		return fmt.Errorf("storage driver %q not yet implemented (Phase 4)", cfg.Storage.Driver)
	}

	db, err := sqlite.OpenExisting(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	topics, err := db.ListAPNSTopics(ctx)
	if err != nil {
		return err
	}
	if len(topics) == 0 {
		fmt.Println("No APNs push certificates recorded. Run: cairn pushcert import ...")
		return nil
	}

	fmt.Printf("%-45s  %-12s  %-6s  %s\n", "TOPIC", "EXPIRES", "DAYS", "STATUS")
	for _, t := range topics {
		exp := t.NotAfter
		var days int
		status := "unknown"
		if parsed, perr := time.Parse(time.RFC3339, t.NotAfter); perr == nil {
			exp = parsed.Format("2006-01-02")
			var sev string
			days, sev, status = push.RenewalTier(parsed)
			status = fmt.Sprintf("%s (%s)", status, sev)
		}
		fmt.Printf("%-45s  %-12s  %-6d  %s\n", t.Topic, exp, days, status)
	}
	return nil
}
