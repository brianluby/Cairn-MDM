package auth

import (
	"context"
	"encoding/base32"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testMFA(t *testing.T) (*MFAStore, *Session) {
	t.Helper()
	s := testSessionStore(t)
	id := Identity{Username: "admin", Provider: "local", Role: RoleAdmin, SubjectID: strings.Repeat("a", 64)}
	_, e := s.db.Exec(`INSERT INTO app_users(username,password_hash,role,subject_id) VALUES('admin','unused','admin',?)`, id.SubjectID)
	if e != nil {
		t.Fatal(e)
	}
	sess, e := s.Create(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	m, e := NewMFAStore(s.db, s, make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	m.now = func() time.Time { return now }
	return m, sess
}
func setupMFA(t *testing.T, m *MFAStore, s *Session) (string, []string) {
	t.Helper()
	ctx := context.Background()
	raw, e := m.BootstrapLocal(ctx, "admin")
	if e != nil {
		t.Fatal(e)
	}
	setup, e := m.Begin(ctx, s.Token, raw)
	if e != nil {
		t.Fatal(e)
	}
	secret, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if e != nil {
		t.Fatal(e)
	}
	codes, e := m.Confirm(ctx, s.Token, hotp(secret, m.now().Unix()/30))
	if e != nil {
		t.Fatal(e)
	}
	return setup.Secret, codes
}
func TestHOTPReferenceVectors(t *testing.T) {
	// RFC 4226 Appendix D, independently published expected outputs.
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if g := hotp([]byte("12345678901234567890"), int64(i)); g != w {
			t.Fatalf("counter %d: %s != %s", i, g, w)
		}
	}
	// RFC 6238 Appendix B SHA1 vectors, reduced from eight to six digits.
	for _, v := range []struct {
		at   int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		if g := hotp([]byte("12345678901234567890"), v.at/30); g != v.code {
			t.Fatalf("TOTP %d: %s", v.at, g)
		}
	}
}
func TestMFAConfirmationReplayRecoveryAndRestart(t *testing.T) {
	ctx := context.Background()
	m, s := testMFA(t)
	if _, e := m.Begin(ctx, s.Token, "password-only"); !errors.Is(e, ErrMFACode) {
		t.Fatal(e)
	}
	secret, codes := setupMFA(t, m, s)
	if len(codes) != 10 {
		t.Fatal(codes)
	}
	if e := m.Fresh(ctx, s.Token); e != nil {
		t.Fatal(e)
	}
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e := m.Verify(ctx, s.Token, hotp(raw, m.now().Unix()/30)); !errors.Is(e, ErrMFACode) {
		t.Fatalf("confirmation code replay accepted: %v", e)
	}
	// Restarting the service does not discard the accepted counter.
	restarted, _ := NewMFAStore(m.db, m.sessions, make([]byte, 32))
	restarted.now = m.now
	if e := restarted.Verify(ctx, s.Token, hotp(raw, m.now().Unix()/30)); !errors.Is(e, ErrMFACode) {
		t.Fatal(e)
	}
	var enc []byte
	if e := m.db.QueryRow(`SELECT secret FROM mfa_factors`).Scan(&enc); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(enc), secret) || strings.Contains(string(enc), string(raw)) {
		t.Fatal("plaintext factor persisted")
	}
	other, e := m.sessions.Create(ctx, s.Identity)
	if e != nil {
		t.Fatal(e)
	}
	invite, e := m.Recover(ctx, s.Token, codes[0])
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Fresh(ctx, s.Token); e == nil {
		t.Fatal("recovery silently grants MFA")
	}
	if _, e = m.sessions.Get(ctx, other.Token); e == nil {
		t.Fatal("other session survived recovery")
	}
	if _, e = m.Recover(ctx, s.Token, codes[1]); !errors.Is(e, ErrMFACode) {
		t.Fatal("unused recovery code survived", e)
	}
	if _, e = m.BootstrapLocal(ctx, "admin"); e == nil {
		t.Fatal("bootstrap reopened after recovery")
	}
	if _, e = m.Begin(ctx, s.Token, invite); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Begin(ctx, s.Token, invite); !errors.Is(e, ErrMFACode) {
		t.Fatal("invite replay", e)
	}
}
func TestMFARateLimitAcrossSessionsAndExpiry(t *testing.T) {
	ctx := context.Background()
	m, s := testMFA(t)
	secret, _ := setupMFA(t, m, s)
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	now := time.Now()
	m.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if e := m.Verify(ctx, s.Token, "invalid"); !errors.Is(e, ErrMFACode) {
			t.Fatal(e)
		}
	}
	other, e := m.sessions.Create(ctx, s.Identity)
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(31 * time.Second)
	if e = m.Verify(ctx, other.Token, hotp(raw, now.Unix()/30)); !errors.Is(e, ErrMFACode) {
		t.Fatal("lockout bypass via session", e)
	}
	now = now.Add(16 * time.Minute)
	if e = m.Fresh(ctx, s.Token); e == nil {
		t.Fatal("stale MFA accepted")
	}
	if e = m.Verify(ctx, other.Token, hotp(raw, now.Unix()/30)); e != nil {
		t.Fatal(e)
	}
}
func TestMFAInvitationsBoundToPrincipalAndSession(t *testing.T) {
	ctx := context.Background()
	m, s := testMFA(t)
	setupMFA(t, m, s)
	target := Identity{Provider: "local", Username: "user", Role: RoleUser, SubjectID: strings.Repeat("b", 64)}
	if _, e := m.db.Exec(`INSERT INTO app_users(username,password_hash,role,subject_id) VALUES('user','unused','user',?)`, target.SubjectID); e != nil {
		t.Fatal(e)
	}
	invite, e := m.Invite(ctx, s.Token, target, false)
	if e != nil {
		t.Fatal(e)
	}
	user, e := m.sessions.Create(ctx, target)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Invite(ctx, user.Token, s.Identity, false); e == nil {
		t.Fatal("nonadmin invited")
	}
	if _, e = m.Begin(ctx, s.Token, invite); e == nil {
		t.Fatal("wrong principal redeemed")
	}
	setup, e := m.Begin(ctx, user.Token, invite)
	if e != nil {
		t.Fatal(e)
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	second, e := m.sessions.Create(ctx, target)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Confirm(ctx, second.Token, hotp(secret, m.now().Unix()/30)); e == nil {
		t.Fatal("different session confirmed")
	}
	if _, e = m.Confirm(ctx, user.Token, hotp(secret, m.now().Unix()/30)); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Invite(ctx, s.Token, target, false); e == nil {
		t.Fatal("existing factor replaced without reset")
	}
	if _, e = m.Invite(ctx, s.Token, target, true); e != nil {
		t.Fatal(e)
	}
	if _, e = m.sessions.Get(ctx, user.Token); e == nil {
		t.Fatal("reset preserved session")
	}
	// Identical usernames at another provider do not share factor identity.
	ldapID := Identity{Provider: "ldap", Username: "user", Directory: &DirectoryIdentity{DirectoryID: "dzsec", ObjectID: strings.Repeat("c", 32)}}
	if mfaPrincipal(ldapID) == mfaPrincipal(target) {
		t.Fatal("providers conflated")
	}
	changed := target
	changed.SubjectID = strings.Repeat("d", 64)
	if _, e = m.Invite(ctx, s.Token, changed, false); e == nil {
		t.Fatal("unverified local subject accepted")
	}
}
func TestMFAConcurrentCodeAndAuditRollback(t *testing.T) {
	ctx := context.Background()
	m, s := testMFA(t)
	secret, _ := setupMFA(t, m, s)
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	now := time.Now().Add(31 * time.Second)
	m.now = func() time.Time { return now }
	code := hotp(raw, now.Unix()/30)
	if _, e := m.db.Exec(`CREATE TRIGGER reject_mfa_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); e != nil {
		t.Fatal(e)
	}
	if e := m.Verify(ctx, s.Token, code); e == nil {
		t.Fatal("audit failure ignored")
	}
	if _, e := m.db.Exec(`DROP TRIGGER reject_mfa_audit`); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	result := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); result <- m.Verify(ctx, s.Token, code) }()
	}
	wg.Wait()
	close(result)
	success := 0
	for e := range result {
		if e == nil {
			success++
		} else if !errors.Is(e, ErrMFACode) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatalf("code accepted %d times", success)
	}
}
func TestMFAInvitationAndSetupExpiry(t *testing.T) {
	ctx := context.Background()
	m, s := testMFA(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	invite, e := m.BootstrapLocal(ctx, "admin")
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(15 * time.Minute)
	if _, e = m.Begin(ctx, s.Token, invite); e == nil {
		t.Fatal("expired invitation")
	}
	invite, e = m.BootstrapLocal(ctx, "admin")
	if e != nil {
		t.Fatal(e)
	}
	setup, e := m.Begin(ctx, s.Token, invite)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	now = now.Add(10 * time.Minute)
	if _, e = m.Confirm(ctx, s.Token, hotp(raw, now.Unix()/30)); e == nil {
		t.Fatal("expired setup")
	}
}
func TestMFAKeyProtectionAndMissingKey(t *testing.T) {
	ctx := context.Background()
	m, s := testMFA(t)
	path := filepath.Join(t.TempDir(), "db")
	key, e := OpenMFAKey(ctx, m.db, path)
	if e != nil {
		t.Fatal(e)
	}
	if len(key) != 32 {
		t.Fatal(len(key))
	}
	again, e := OpenMFAKey(ctx, m.db, path)
	if e != nil || string(again) != string(key) {
		t.Fatal("key changed", e)
	}
	if e = os.Chmod(path+".mfa/key", 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenMFAKey(ctx, m.db, path); e == nil {
		t.Fatal("public key file accepted")
	}
	setupMFA(t, m, s)
	if _, e = OpenMFAKey(ctx, m.db, filepath.Join(t.TempDir(), "missing")); e == nil {
		t.Fatal("missing key replaced")
	}
}

func TestMFAHostRecoveryAndLocalRecreation(t *testing.T) {
	ctx := context.Background()
	m, s := testMFA(t)
	_, codes := setupMFA(t, m, s)
	raw, e := m.ResetLocalAdmin(ctx, "admin")
	if e != nil || raw == "" {
		t.Fatal(e)
	}
	if _, e = m.sessions.Get(ctx, s.Token); e == nil {
		t.Fatal("host reset retained session")
	}
	second, e := m.sessions.Create(ctx, s.Identity)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Recover(ctx, second.Token, codes[0]); e == nil {
		t.Fatal("host reset retained codes")
	}
	// A replacement account with the same name cannot redeem the prior approval.
	if _, e = m.db.Exec(`UPDATE app_users SET subject_id=? WHERE username='admin'`, strings.Repeat("d", 64)); e != nil {
		t.Fatal(e)
	}
	replacement := s.Identity
	replacement.SubjectID = strings.Repeat("d", 64)
	next, e := m.sessions.Create(ctx, replacement)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Begin(ctx, next.Token, raw); e == nil {
		t.Fatal("recreated account inherited invitation")
	}
}

func TestMFASecretBindingAndDirectoryIdentity(t *testing.T) {
	m, _ := testMFA(t)
	enc := m.encrypt("principal-a", []byte("private-secret"))
	if _, e := m.decrypt("principal-b", enc); e == nil {
		t.Fatal("encrypted secret moved across principals")
	}
	wrong, _ := NewMFAStore(m.db, m.sessions, []byte(strings.Repeat("z", 32)))
	if _, e := wrong.decrypt("principal-a", enc); e == nil {
		t.Fatal("wrong key accepted")
	}
	id := Identity{Provider: "ldap", Username: "before", Directory: &DirectoryIdentity{DirectoryID: "dzsec", ObjectID: strings.Repeat("a", 32), UPN: "before@example.org"}}
	principal := mfaPrincipal(id)
	id.Username = "after"
	id.Directory.UPN = "after@example.org"
	if mfaPrincipal(id) != principal {
		t.Fatal("mutable name changed factor identity")
	}
	id.Directory.DirectoryID = "other"
	if mfaPrincipal(id) == principal {
		t.Fatal("directory namespaces conflated")
	}
	if mfaPrincipal(Identity{Provider: "oidc", Username: "before"}) != "" {
		t.Fatal("OIDC display name used as principal")
	}
}

func TestMFALocalIDSurvivesPasswordChangeButNotRecreation(t *testing.T) {
	ctx := context.Background()
	m, _ := testMFA(t)
	local := NewLocalStore(m.db)
	if e := local.CreateUser(ctx, "person", "first-password", RoleUser, ""); e != nil {
		t.Fatal(e)
	}
	before, e := local.Authenticate(ctx, "person", "first-password")
	if e != nil {
		t.Fatal(e)
	}
	if before.SubjectID == "" {
		t.Fatal("missing immutable local ID")
	}
	if e = local.SetPassword(ctx, "person", "second-password"); e != nil {
		t.Fatal(e)
	}
	after, e := local.Authenticate(ctx, "person", "second-password")
	if e != nil {
		t.Fatal(e)
	}
	if before.SubjectID != after.SubjectID {
		t.Fatal("password reset changed factor identity")
	}
	if _, e = m.sessions.Create(ctx, *before); e == nil {
		t.Fatal("stale password verification created a session")
	}
	if e = local.DeleteUser(ctx, "person"); e != nil {
		t.Fatal(e)
	}
	if e = local.CreateUser(ctx, "person", "second-password", RoleUser, ""); e != nil {
		t.Fatal(e)
	}
	recreated, e := local.Authenticate(ctx, "person", "second-password")
	if e != nil {
		t.Fatal(e)
	}
	if recreated.SubjectID == after.SubjectID {
		t.Fatal("recreated account inherited factor identity")
	}
}
