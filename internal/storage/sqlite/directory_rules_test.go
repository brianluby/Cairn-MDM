package sqlite

import (
	"context"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
)

func TestDirectoryRulesAreAuditedAndDoNotAlterManualMembership(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	group, err := db.CreateGroup(ctx, "Lynchburg", "")
	if err != nil {
		t.Fatal(err)
	}
	scope := auth.DirectoryScope{DirectoryID: "dzsec-ad", ObjectID: "0102030405060708090a0b0c0d0e0f10", Kind: "group", Mode: "nested", Name: "Lynchburg Users", DN: "CN=Lynchburg Users,DC=example,DC=org"}
	if err = db.SaveDirectoryProfileRule(ctx, group, scope, "admin", "local"); err != nil {
		t.Fatal(err)
	}
	scope.Name = "Renamed"
	if err = db.SaveDirectoryProfileRule(ctx, group, scope, "admin", "local"); err != nil {
		t.Fatal(err)
	}
	rules, err := db.ListDirectoryProfileRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].Scope.Name != "Renamed" {
		t.Fatalf("rules %+v %v", rules, err)
	}
	var count int
	if err = db.sql.QueryRow(`SELECT count(*) FROM group_devices`).Scan(&count); err != nil || count != 0 {
		t.Fatal("preview rule changed device membership")
	}
	if _, err = db.sql.Exec(`CREATE TRIGGER fail_rule_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteDirectoryProfileRule(ctx, rules[0].ID, "admin", "local"); err == nil {
		t.Fatal("delete ignored audit failure")
	}
	rules, err = db.ListDirectoryProfileRules(ctx)
	if err != nil || len(rules) != 1 {
		t.Fatal("partial delete survived")
	}
	scope.Name = "Must roll back"
	if err = db.SaveDirectoryProfileRule(ctx, group, scope, "admin", "local"); err == nil {
		t.Fatal("save ignored audit failure")
	}
	rules, _ = db.ListDirectoryProfileRules(ctx)
	if rules[0].Scope.Name != "Renamed" {
		t.Fatal("partial update survived")
	}
}
