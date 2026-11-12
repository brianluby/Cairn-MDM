package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

func seed(t *testing.T) (dir string, opts Options) {
	t.Helper()
	ctx := context.Background()
	dir = t.TempDir()
	dbPath := filepath.Join(dir, "cairn.db")
	db, err := sqlite.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "D1", UDID: "D1", Name: "Mac"}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeviceTokenUpdated(ctx, "D1"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveProfile(ctx, sqlite.Profile{Identifier: "com.example.p", UUID: "p", Name: "P", Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := auth.NewLocalStore(db.SQL()).CreateUser(ctx, "admin", "correct horse battery", auth.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`INSERT INTO mfa_factors(principal,secret) VALUES('local:x', x'01')`); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertAPNSTopic(ctx, "com.apple.mgmt.External.t", "2030-01-01T00:00:00Z", "", "test"); err != nil {
		t.Fatal(err)
	}
	keyDir := dbPath + ".mfa"
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "key"), []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "cairn.toml")
	if err := os.WriteFile(cfgPath, []byte("[server]\npublic_url=\"https://mdm.example.org\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chain := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(chain, []byte("-----BEGIN CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, Options{DBPath: dbPath, MFAKeyPath: filepath.Join(keyDir, "key"), ConfigPath: cfgPath, Extra: []string{chain, filepath.Join(dir, "missing.pem")}, Out: filepath.Join(dir, "out", "cairn.tar.gz"), Version: "test", Commit: "abc"}
}

func TestBundleRoundTripVerifyAndRestore(t *testing.T) {
	ctx := context.Background()
	dir, opts := seed(t)
	m, err := Create(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if m.Counts.Devices != 1 || m.Counts.Pushable != 1 || m.Counts.Profiles != 1 || m.Counts.LocalUsers != 1 || m.Counts.MFAFactors != 1 || !m.MFAKeyIncluded || len(m.Topics) != 1 {
		t.Fatalf("manifest %+v", m)
	}
	if len(m.Notes) != 1 || !strings.Contains(m.Notes[0], "missing.pem") {
		t.Fatalf("missing referenced file not noted: %v", m.Notes)
	}
	info, err := os.Stat(opts.Out)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle %v %v", info, err)
	}
	if _, err = Create(ctx, opts); err == nil {
		t.Fatal("overwrote an existing bundle")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "out", ".cairn-backup-*")); len(leftovers) != 0 {
		t.Fatalf("scratch left behind: %v", leftovers)
	}

	rep, err := Verify(ctx, opts.Out, filepath.Join(dir, "verify"))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Observed != m.Counts {
		t.Fatalf("verify problems %v", rep.Problems)
	}
	for _, p := range []string{"cairn.db", "mfa/key", "config/cairn.toml", "config/chain.pem", ManifestName} {
		if _, err := os.Stat(filepath.Join(dir, "verify", filepath.FromSlash(p))); err != nil {
			t.Fatalf("extracted %s missing", p)
		}
	}

	target := filepath.Join(dir, "restored")
	rep, err = Restore(ctx, opts.Out, target)
	if err != nil || !rep.OK() {
		t.Fatalf("restore %v %v", err, rep)
	}
	for _, p := range []string{"cairn.db", "cairn.db.mfa/key", "config/cairn.toml", "config/chain.pem"} {
		fi, err := os.Stat(filepath.Join(target, filepath.FromSlash(p)))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("restored %s: %v %v", p, fi, err)
		}
	}
	restored, err := sqlite.Open(ctx, filepath.Join(target, "cairn.db"))
	if err != nil {
		t.Fatal(err)
	}
	devices, _ := restored.ListDevices(ctx)
	restored.Close()
	if len(devices) != 1 || devices[0].Name != "Mac" {
		t.Fatalf("restored devices %+v", devices)
	}
	if _, err = Restore(ctx, opts.Out, target); err == nil {
		t.Fatal("restored over a non-empty directory")
	}
}

func TestVerifyDetectsTamperingAndMissingKey(t *testing.T) {
	ctx := context.Background()
	dir, opts := seed(t)
	if _, err := Create(ctx, opts); err != nil {
		t.Fatal(err)
	}
	// Rebuild the bundle with one byte of the database changed after hashing.
	work := filepath.Join(dir, "tamper")
	if _, err := Extract(opts.Out, work); err != nil {
		t.Fatal(err)
	}
	dbBytes, _ := os.ReadFile(filepath.Join(work, "cairn.db"))
	dbBytes[len(dbBytes)-1] ^= 0xff
	if err := os.WriteFile(filepath.Join(work, "cairn.db"), dbBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(dir, "tampered.tar.gz")
	if err := writeTar(work, tampered); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(ctx, tampered, filepath.Join(dir, "v1"))
	if err != nil || rep.OK() || !strings.Contains(strings.Join(rep.Problems, ";"), "hash mismatch: cairn.db") {
		t.Fatalf("tamper undetected: %v %v", err, rep)
	}
	if _, err = Restore(ctx, tampered, filepath.Join(dir, "r1")); err == nil {
		t.Fatal("restored a tampered bundle")
	}
	if _, err := os.Stat(filepath.Join(dir, "r1", "cairn.db")); err == nil {
		t.Fatal("tampered restore wrote the database")
	}

	// A bundle made without the MFA key while factors exist is flagged.
	noKey := opts
	noKey.MFAKeyPath = filepath.Join(dir, "absent", "key")
	noKey.Out = filepath.Join(dir, "nokey.tar.gz")
	m, err := Create(ctx, noKey)
	if err != nil || m.MFAKeyIncluded || len(m.Notes) < 1 {
		t.Fatalf("nokey manifest %+v %v", m, err)
	}
	rep, err = Verify(ctx, noKey.Out, filepath.Join(dir, "v2"))
	if err != nil || rep.OK() || !strings.Contains(strings.Join(rep.Problems, ";"), "no mfa/key") {
		t.Fatalf("missing key undetected: %v %v", err, rep)
	}

	// A crafted archive with a parent-relative member is refused outright.
	evilTar := filepath.Join(dir, "evil.tar.gz")
	f, err := os.Create(evilTar)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	f.Close()
	if _, err := Extract(evilTar, filepath.Join(dir, "v3")); err == nil || !strings.Contains(err.Error(), "refusing member") {
		t.Fatalf("traversal accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "escape")); err == nil {
		t.Fatal("traversal wrote outside the extraction directory")
	}
}

func TestBundleCarriesVPNKey(t *testing.T) {
	ctx := context.Background()
	dir, opts := seed(t)
	db, err := sqlite.OpenExisting(ctx, opts.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateVPNServer(ctx, sqlite.VPNServerRow{Name: "Office", Slug: "office", Config: []byte("{}"), SealedKey: []byte{1}}, "admin"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Sealed keys without the key file: noted at creation, refused at verification.
	opts.VPNKeyPath = filepath.Join(opts.DBPath+".vpn", "key")
	opts.Out = filepath.Join(dir, "novpnkey.tar.gz")
	m, err := Create(ctx, opts)
	if err != nil || m.VPNKeyIncluded || m.Counts.VPNKeys != 1 {
		t.Fatalf("manifest %+v %v", m, err)
	}
	rep, err := Verify(ctx, opts.Out, filepath.Join(dir, "v-novpn"))
	if err != nil || rep.OK() || !strings.Contains(strings.Join(rep.Problems, ";"), "no vpn/key") {
		t.Fatalf("missing VPN key undetected: %v %v", err, rep)
	}

	if err := os.MkdirAll(filepath.Dir(opts.VPNKeyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.VPNKeyPath, []byte("fedcba9876543210fedcba9876543210"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.Out = filepath.Join(dir, "vpnkey.tar.gz")
	if m, err = Create(ctx, opts); err != nil || !m.VPNKeyIncluded {
		t.Fatalf("manifest %+v %v", m, err)
	}
	restored := filepath.Join(dir, "restored")
	if rep, err = Restore(ctx, opts.Out, restored); err != nil || !rep.OK() {
		t.Fatalf("restore: %v %v", err, rep)
	}
	got, err := os.ReadFile(filepath.Join(restored, "cairn.db.vpn", "key"))
	if err != nil || string(got) != "fedcba9876543210fedcba9876543210" {
		t.Fatalf("restored VPN key = %q, %v", got, err)
	}
}
