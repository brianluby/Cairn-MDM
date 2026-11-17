package auth

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func TestSetupGateTokenLifecycle(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/cairn.db"
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	gate := NewSetupGate(db.SQL(), path)

	open, err := gate.Prepare(ctx)
	if err != nil || !open {
		t.Fatalf("prepare %v %v", open, err)
	}
	info, err := os.Stat(gate.TokenPath())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token file %v %v", info, err)
	}
	first, _ := os.ReadFile(gate.TokenPath())
	if _, err = gate.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(gate.TokenPath()); string(again) != string(first) {
		t.Fatal("restart rotated the token the operator already copied")
	}
	token := strings.TrimSpace(string(first))

	if err = gate.Complete(ctx, strings.Repeat("0", 64), "admin", "correct horse battery"); !errors.Is(err, ErrSetupToken) {
		t.Fatalf("wrong token: %v", err)
	}
	if err = gate.Complete(ctx, token, "admin", "short"); !errors.Is(err, ErrSetupPassword) {
		t.Fatalf("short password: %v", err)
	}
	if err = gate.Complete(ctx, token, "ad min", "correct horse battery"); err == nil {
		t.Fatal("username with spaces accepted")
	}
	if n, _ := NewLocalStore(db.SQL()).CountUsers(ctx); n != 0 {
		t.Fatal("rejected attempts created an account")
	}
	if _, err = os.Stat(gate.TokenPath()); err != nil {
		t.Fatal("rejected attempt removed the token file")
	}

	if err = gate.Complete(ctx, token, "admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(gate.TokenPath()); !os.IsNotExist(err) {
		t.Fatal("token file survived setup")
	}
	id, err := NewLocalStore(db.SQL()).Authenticate(ctx, "admin", "correct horse battery")
	if err != nil || id.Role != RoleAdmin || len(id.SubjectID) != 64 {
		t.Fatalf("administrator %+v %v", id, err)
	}
	var audits int
	if err = db.SQL().QueryRow(`SELECT count(*) FROM audit_log WHERE action='setup.complete'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit %d %v", audits, err)
	}

	// Closed for good: no second administrator through this door, and Prepare
	// clears any token file left behind.
	if open, err = gate.Open(ctx); err != nil || open {
		t.Fatal("setup still open")
	}
	if err = gate.Complete(ctx, token, "second", "correct horse battery"); !errors.Is(err, ErrSetupClosed) {
		t.Fatalf("closed gate accepted: %v", err)
	}
	if err = os.WriteFile(gate.TokenPath(), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if open, err = gate.Prepare(ctx); err != nil || open {
		t.Fatal("prepare reopened setup")
	}
	if _, err = os.Stat(gate.TokenPath()); !os.IsNotExist(err) {
		t.Fatal("stale token file kept after close")
	}
}
