package sqlite

import (
	"context"
	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"strings"
	"testing"
	"time"
)

func TestAuthorizedGrantTransactionAndOwnerBinding(t *testing.T) {
	ctx := context.Background()
	db := newGrantDB(t)
	session := "session-secret"
	subject := strings.Repeat("a", 64)
	for _, stmt := range []string{`INSERT INTO app_users(username,password_hash,role,subject_id) VALUES('admin','unused','admin','` + subject + `')`, `INSERT INTO mfa_factors(principal,secret) VALUES('local:` + subject + `',x'01')`} {
		if _, e := db.sql.Exec(stmt); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := db.sql.Exec(`INSERT INTO app_sessions(token,username,role,provider,csrf_token,expires_at,auth_subject,mfa_verified_at) VALUES(?,'admin','admin','local','csrf',? ,?,?)`, HashGrantToken(session), time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "local:"+subject, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	owner := directory.DirectoryIdentity{DirectoryID: "dzsec", ObjectID: strings.Repeat("b", 32), UPN: "person@example.org"}
	preview, e := db.SaveEnrollmentPreview(ctx, session, EnrollmentPreview{Owner: owner, Platform: "macos", Hours: 1})
	if e != nil {
		t.Fatal(e)
	}
	_, hash := NewGrantToken()
	wrong := owner
	wrong.ObjectID = strings.Repeat("c", 32)
	if _, e = db.CreateAuthorizedGrant(ctx, session, preview, hash, wrong); e == nil {
		t.Fatal("owner substitution accepted")
	}
	if _, e = db.sql.Exec(`UPDATE app_sessions SET mfa_verified_at=?`, time.Now().Add(-6*time.Minute).Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e = db.CreateAuthorizedGrant(ctx, session, preview, hash, owner); e == nil {
		t.Fatal("stale MFA accepted")
	}
	if _, e = db.sql.Exec(`UPDATE app_sessions SET mfa_verified_at=?`, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e = db.sql.Exec(`CREATE TRIGGER deny_grant_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'audit offline'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e = db.CreateAuthorizedGrant(ctx, session, preview, hash, owner); e == nil {
		t.Fatal("audit failure ignored")
	}
	grants, e := db.ListGrants(ctx)
	if e != nil || len(grants) != 0 {
		t.Fatal("partial grant committed", e)
	}
	if _, e = db.sql.Exec(`DROP TRIGGER deny_grant_audit`); e != nil {
		t.Fatal(e)
	}
	if _, e = db.CreateAuthorizedGrant(ctx, session, preview, hash, owner); e != nil {
		t.Fatal(e)
	}
	if _, e = db.CreateAuthorizedGrant(ctx, session, preview, hash, owner); e == nil {
		t.Fatal("preview reused")
	}
	grants, e = db.ListGrants(ctx)
	if e != nil || len(grants) != 1 || grants[0].CreatedBy != "admin" || grants[0].Owner != owner.UPN {
		t.Fatal("actor/owner conflation", e)
	}
}
