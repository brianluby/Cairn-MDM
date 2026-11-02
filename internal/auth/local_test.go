package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func testStore(t *testing.T) *LocalStore {
	t.Helper()
	db, err := sqlite.Open(context.Background(), t.TempDir()+"/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewLocalStore(db.SQL())
}

func TestCreateAndAuthenticate(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	if err := s.CreateUser(ctx, "nick", "correct horse battery", RoleAdmin, "Nick"); err != nil {
		t.Fatalf("create: %v", err)
	}

	id, err := s.Authenticate(ctx, "nick", "correct horse battery")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.Role != RoleAdmin || id.Provider != "local" || id.DisplayName != "Nick" {
		t.Errorf("identity = %+v", id)
	}

	if _, err := s.Authenticate(ctx, "nick", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := s.Authenticate(ctx, "ghost", "whatever"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("missing user err = %v, want ErrInvalidCredentials", err)
	}
}

func TestDuplicateUserRejected(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	if err := s.CreateUser(ctx, "a", "pw12345678", RoleOperator, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, "a", "pw12345678", RoleOperator, ""); err == nil {
		t.Fatal("expected duplicate username to be rejected")
	}
}

func TestCountUsersAndFirstRun(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	if n, _ := s.CountUsers(ctx); n != 0 {
		t.Fatalf("fresh store has %d users, want 0", n)
	}
	_ = s.CreateUser(ctx, "a", "pw12345678", RoleAdmin, "")
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("after create: %d users, want 1", n)
	}
}

func TestMinPasswordLen(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	// Default (0) imposes no minimum.
	if err := s.CreateUser(ctx, "nopolicy", "x", RoleUser, ""); err != nil {
		t.Fatalf("zero-minimum store rejected a short password: %v", err)
	}

	s.SetMinPasswordLen(8)
	if err := s.CreateUser(ctx, "a", "short", RoleAdmin, ""); err == nil {
		t.Fatal("expected CreateUser to reject a password below the minimum")
	}
	if err := s.CreateUser(ctx, "a", "longenough", RoleAdmin, ""); err != nil {
		t.Fatalf("CreateUser rejected a compliant password: %v", err)
	}
	if err := s.SetPassword(ctx, "a", "tiny"); err == nil {
		t.Fatal("expected SetPassword to reject a password below the minimum")
	}
	if err := s.SetPassword(ctx, "a", "anotherlongone"); err != nil {
		t.Fatalf("SetPassword rejected a compliant password: %v", err)
	}
}

func TestRoleAtLeast(t *testing.T) {
	if !RoleAdmin.AtLeast(RoleOperator) {
		t.Error("admin should outrank operator")
	}
	if RoleUser.AtLeast(RoleAdmin) {
		t.Error("user should not satisfy admin")
	}
	if !RoleOperator.AtLeast(RoleOperator) {
		t.Error("operator should satisfy operator")
	}
}

func TestListAndDeleteUsers(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	if err := s.CreateUser(ctx, "admin1", "hunter2hunter2", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, "op1", "hunter2hunter2", RoleOperator, "Op One"); err != nil {
		t.Fatal(err)
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}

	// Deleting the last admin is refused.
	if err := s.DeleteUser(ctx, "admin1"); err == nil {
		t.Fatal("deleting the last admin should be refused")
	}

	// A second admin makes the first deletable.
	if err := s.CreateUser(ctx, "admin2", "hunter2hunter2", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, "admin1"); err != nil {
		t.Fatalf("delete admin1 with admin2 present: %v", err)
	}
	if _, err := s.Authenticate(ctx, "admin1", "hunter2hunter2"); err == nil {
		t.Error("deleted user can still authenticate")
	}
	if err := s.DeleteUser(ctx, "nosuch"); err == nil {
		t.Error("deleting unknown user should error")
	}
}

func TestLocalMutationsRevokeOnlyLocalSessionsAndFenceOldLogin(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	sessions := NewSessionStore(s.db, time.Hour)
	for _, name := range []string{"admin", "nick"} {
		if err := s.CreateUser(ctx, name, "original password", RoleAdmin, ""); err != nil {
			t.Fatal(err)
		}
	}
	identity, err := s.Authenticate(ctx, "nick", "original password")
	if err != nil {
		t.Fatal(err)
	}
	local, err := sessions.Create(ctx, *identity)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := sessions.Create(ctx, Identity{Username: "nick", Provider: "ldap", Role: RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetPassword(ctx, "nick", "replacement password"); err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.Get(ctx, local.Token); !errors.Is(err, ErrNoSession) {
		t.Fatal("password reset retained local session")
	}
	if _, err = sessions.Get(ctx, directory.Token); err != nil {
		t.Fatal("local change removed directory session", err)
	}
	if _, err = sessions.Create(ctx, *identity); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("in-flight old login survived reset")
	}
	identity, err = s.Authenticate(ctx, "nick", "replacement password")
	if err != nil {
		t.Fatal(err)
	}
	local, err = sessions.Create(ctx, *identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetRole(ctx, "nick", RoleUser); err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.Get(ctx, local.Token); !errors.Is(err, ErrNoSession) {
		t.Fatal("demotion retained elevated session")
	}
	if _, err = sessions.Create(ctx, *identity); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("in-flight elevated login survived demotion")
	}
	if err = s.SetRole(ctx, "admin", RoleUser); err == nil {
		t.Fatal("last admin demoted")
	}
	if err = s.DeleteUser(ctx, "nick"); err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.Get(ctx, directory.Token); err != nil {
		t.Fatal("local deletion removed directory session", err)
	}
}

func TestAccountMutationRollsBackIfRevocationFails(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	if err := s.CreateUser(ctx, "nick", "original password", RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	sessions := NewSessionStore(s.db, time.Hour)
	if _, err := sessions.Create(ctx, Identity{Username: "nick", Provider: "local", Role: RoleUser}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_session_revoke BEFORE DELETE ON app_sessions BEGIN SELECT RAISE(ABORT,'unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole(ctx, "nick", RoleAdmin); err == nil {
		t.Fatal("mutation ignored revocation failure")
	}
	if role, err := s.UserRole(ctx, "nick"); err != nil || role != RoleUser {
		t.Fatalf("partial mutation: %s %v", role, err)
	}
	if err := s.SetPassword(ctx, "nick", "replacement password"); err == nil {
		t.Fatal("reset ignored revocation failure")
	}
	if _, err := s.Authenticate(ctx, "nick", "original password"); err != nil {
		t.Fatal("password changed despite rollback", err)
	}
}

func TestConcurrentAdminRemovalKeepsAnAdmin(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	for _, name := range []string{"one", "two"} {
		if err := s.CreateUser(ctx, name, "original password", RoleAdmin, ""); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	done := make(chan error, 2)
	go func() { <-start; done <- s.SetRole(ctx, "one", RoleUser) }()
	go func() { <-start; done <- s.DeleteUser(ctx, "two") }()
	close(start)
	first, second := <-done, <-done
	if first == nil && second == nil {
		t.Fatal("both administrators removed")
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM app_users WHERE role='admin'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("admin count %d: %v", count, err)
	}
}
