package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"golang.org/x/term"
)

func runMFABootstrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin mfa-bootstrap", flag.ContinueOnError)
	path := fs.String("config", defaultConfigPath, "path to cairn.toml")
	reset := fs.Bool("reset", false, "host recovery: revoke this local administrator factor, recovery codes and sessions")
	username := fs.String("username", "", "existing local administrator")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("-username is required")
	}
	if !isTerminal() || !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("MFA bootstrap requires an interactive terminal on the Cairn host")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	db, err := sqlite.OpenExisting(ctx, cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()
	key, err := auth.OpenMFAKey(ctx, db.SQL(), cfg.Storage.Path)
	if err != nil {
		return err
	}
	m, err := auth.NewMFAStore(db.SQL(), auth.NewSessionStore(db.SQL(), 0), key)
	if err != nil {
		return err
	}
	var raw string
	if *reset {
		raw, err = m.ResetLocalAdmin(ctx, *username)
	} else {
		raw, err = m.BootstrapLocal(ctx, *username)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Sign in as local administrator %q and open Account security.\nRegistration approval code (single use, expires in 15 minutes):\n%s\nKeep this code private. This is not an authenticator secret.\n", *username, raw)
	return nil
}
