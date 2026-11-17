package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func TestCLIPasswordResetKeepsOtherProviders(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "db")
	cfg := filepath.Join(dir, "cairn.toml")
	body := fmt.Sprintf("[server]\npublic_url = \"https://example.org\"\n[server.tls]\nmode = \"proxy\"\n[storage]\ndriver = \"sqlite\"\npath = %q\n", path)
	if e := os.WriteFile(cfg, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	db, e := sqlite.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	local := auth.NewLocalStore(db.SQL())
	if e = local.CreateUser(ctx, "same", "test-password-before", auth.RoleAdmin, ""); e != nil {
		t.Fatal(e)
	}
	sessions := auth.NewSessionStore(db.SQL(), 0)
	tokens := map[string]string{}
	for _, provider := range []string{"local", "ldap", "oidc"} {
		s, e := sessions.Create(ctx, auth.Identity{Provider: provider, Username: "same", Role: auth.RoleAdmin})
		if e != nil {
			t.Fatal(e)
		}
		tokens[provider] = s.Token
	}
	if e = runAdminPasswd(ctx, []string{"-config", cfg, "-username", "same", "-password", "test-password-after"}); e != nil {
		t.Fatal(e)
	}
	if _, e = sessions.Get(ctx, tokens["local"]); e == nil {
		t.Fatal("local session survived")
	}
	for _, provider := range []string{"ldap", "oidc"} {
		if _, e = sessions.Get(ctx, tokens[provider]); e != nil {
			t.Fatalf("%s session revoked: %v", provider, e)
		}
	}
}

func TestMFABootstrapRejectsNonInteractiveUse(t *testing.T) {
	if e := runMFABootstrap(context.Background(), []string{"-username", "admin", "-config", "missing"}); e == nil {
		t.Fatal("noninteractive bootstrap accepted")
	}
}
