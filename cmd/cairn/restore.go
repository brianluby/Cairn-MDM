package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nickpdawson/cairn-mdm/internal/backup"
)

// runRestore rehearses or performs a restore from a backup bundle. The default
// is a rehearsal: extract into a scratch directory, check every hash, the
// database's integrity and record counts, and report. With -into DIR it places
// the files into an empty directory; migrating and starting a service against
// them stay explicit operator steps, and nothing here contacts devices or APNs.
func runRestore(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	bundle := fs.String("bundle", "", "backup bundle (.tar.gz) to restore from (required)")
	rehearse := fs.Bool("rehearse", true, "verify the bundle in a scratch directory and report")
	workdir := fs.String("workdir", "", "scratch directory for the rehearsal (default: temporary)")
	keep := fs.Bool("keep", false, "keep the rehearsal directory for inspection")
	into := fs.String("into", "", "restore the bundle's files into this empty directory (disables the rehearsal-only default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundle == "" {
		return fmt.Errorf("-bundle <file> is required")
	}
	if *into != "" {
		rep, err := backup.Restore(ctx, *bundle, *into)
		if rep != nil {
			printReport(rep)
		}
		if err != nil {
			return err
		}
		fmt.Printf("\nrestored into %s\n", *into)
		fmt.Println("Next: point storage.path at the restored cairn.db (and keep cairn.db.mfa/key beside it),")
		fmt.Println("review config/ for the restored cairn.toml and referenced files, run `cairn migrate`, then start.")
		fmt.Println("Do not start a restored copy where it can reach the production fleet unless it is the production replacement.")
		return nil
	}
	if !*rehearse {
		return fmt.Errorf("nothing to do: use -rehearse (default) or -into <dir>")
	}
	dir := *workdir
	if dir == "" {
		d, err := os.MkdirTemp("", "cairn-restore-rehearsal-*")
		if err != nil {
			return err
		}
		dir = d
	} else {
		if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
			return fmt.Errorf("-workdir %s is not empty", dir)
		}
	}
	if !*keep {
		defer os.RemoveAll(dir)
	}
	rep, err := backup.Verify(ctx, *bundle, dir)
	if err != nil {
		return err
	}
	printReport(rep)
	if *keep {
		fmt.Printf("\nrehearsal files kept in %s (contains private keys; delete when done)\n", filepath.Clean(dir))
	}
	if !rep.OK() {
		return fmt.Errorf("rehearsal found %d problem(s)", len(rep.Problems))
	}
	fmt.Println("\nrehearsal: ok — the bundle restores cleanly")
	return nil
}

func printReport(rep *backup.Report) {
	m := rep.Manifest
	fmt.Printf("bundle created %s by %s (%s)\n", m.CreatedAt, m.Version, m.Commit)
	fmt.Printf("  schema versions: %d · files: %d · MFA key: %v\n", len(m.Schema), len(m.Files), m.MFAKeyIncluded)
	fmt.Printf("  manifest counts: devices %d (%d pushable), profiles %d, groups %d, grants %d, quarantined %d, local users %d\n",
		m.Counts.Devices, m.Counts.Pushable, m.Counts.Profiles, m.Counts.Groups, m.Counts.Grants, m.Counts.Quarantined, m.Counts.LocalUsers)
	fmt.Printf("  observed counts: devices %d (%d pushable), profiles %d, groups %d, grants %d, quarantined %d, local users %d\n",
		rep.Observed.Devices, rep.Observed.Pushable, rep.Observed.Profiles, rep.Observed.Groups, rep.Observed.Grants, rep.Observed.Quarantined, rep.Observed.LocalUsers)
	for _, t := range m.Topics {
		fmt.Printf("  APNs topic %s expires %s\n", t.Topic, t.NotAfter)
	}
	for _, n := range m.Notes {
		fmt.Printf("  note: %s\n", n)
	}
	for _, p := range rep.Problems {
		fmt.Printf("  PROBLEM: %s\n", p)
	}
}
