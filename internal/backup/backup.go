// Package backup produces and verifies Cairn backup bundles: one tar.gz holding
// a consistent SQLite snapshot, the MFA encryption key, the configuration file
// and the files it references, and a manifest with hashes and record counts.
// Verify extracts a bundle into a scratch directory, checks every hash and the
// database's integrity, and compares counts against the manifest, so a backup is
// proven restorable before it is needed. Nothing here contacts APNs or devices.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ManifestName is the manifest's path inside a bundle.
const ManifestName = "manifest.json"

// FileEntry describes one file in the bundle.
type FileEntry struct {
	Path   string `json:"path"`   // path inside the bundle
	Source string `json:"source"` // original host path
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}

// Counts are the record counts captured from the snapshot.
type Counts struct {
	Devices     int `json:"devices"`
	Pushable    int `json:"pushable"`
	Profiles    int `json:"profiles"`
	Groups      int `json:"groups"`
	Grants      int `json:"grants"`
	Quarantined int `json:"quarantined"`
	MFAFactors  int `json:"mfa_factors"`
	LocalUsers  int `json:"local_users"`
	VPNKeys     int `json:"vpn_keys"`    // VPN servers holding a sealed TLS key
	VPNPending  int `json:"vpn_pending"` // VPN profiles queued for a device, private key included
}

// TopicInfo is one APNs topic and its expiry.
type TopicInfo struct {
	Topic    string `json:"topic"`
	NotAfter string `json:"not_after"`
}

// Manifest is written into every bundle.
type Manifest struct {
	CreatedAt      string      `json:"created_at"`
	Version        string      `json:"version"`
	Commit         string      `json:"commit"`
	Schema         []string    `json:"schema"`
	Files          []FileEntry `json:"files"`
	Counts         Counts      `json:"counts"`
	Topics         []TopicInfo `json:"topics"`
	MFAKeyIncluded bool        `json:"mfa_key_included"`
	VPNKeyIncluded bool        `json:"vpn_key_included"`
	Notes          []string    `json:"notes,omitempty"`
}

// Options control Create.
type Options struct {
	DBPath     string
	MFAKeyPath string   // <storage.path>.mfa/key; skipped when absent
	VPNKeyPath string   // <storage.path>.vpn/key; skipped when absent
	ConfigPath string   // cairn.toml
	Extra      []string // files referenced by the config (certs, keys, chains, challenge files)
	Out        string   // destination .tar.gz (must not exist)
	Version    string
	Commit     string
}

// Create writes a bundle to opts.Out and returns its manifest.
func Create(ctx context.Context, opts Options) (*Manifest, error) {
	if opts.Out == "" || opts.DBPath == "" {
		return nil, errors.New("backup: database path and output path are required")
	}
	if _, err := os.Stat(opts.Out); err == nil {
		return nil, fmt.Errorf("backup: %s already exists; choose a new path", opts.Out)
	}
	if err := os.MkdirAll(filepath.Dir(opts.Out), 0o700); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(filepath.Dir(opts.Out), ".cairn-backup-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)

	snapshot := filepath.Join(work, "cairn.db")
	if err := snapshotDB(ctx, opts.DBPath, snapshot); err != nil {
		return nil, err
	}
	m := &Manifest{CreatedAt: time.Now().UTC().Format(time.RFC3339), Version: opts.Version, Commit: opts.Commit}
	if err := inspect(ctx, snapshot, m); err != nil {
		return nil, err
	}
	entry, err := describe(snapshot, "cairn.db", opts.DBPath)
	if err != nil {
		return nil, err
	}
	m.Files = append(m.Files, entry)

	if opts.MFAKeyPath != "" {
		if _, err := os.Stat(opts.MFAKeyPath); err == nil {
			if err := copyInto(opts.MFAKeyPath, filepath.Join(work, "mfa", "key"), 0o600); err != nil {
				return nil, err
			}
			entry, err := describe(filepath.Join(work, "mfa", "key"), "mfa/key", opts.MFAKeyPath)
			if err != nil {
				return nil, err
			}
			m.Files = append(m.Files, entry)
			m.MFAKeyIncluded = true
		} else if m.Counts.MFAFactors > 0 {
			m.Notes = append(m.Notes, "MFA factors exist but the key file was not found at "+opts.MFAKeyPath+"; this bundle cannot restore MFA.")
		}
	}
	if m.Counts.VPNPending > 0 {
		m.Notes = append(m.Notes, fmt.Sprintf("%d VPN profile(s) were waiting for their device when this bundle was made; the bundle holds their private keys. Store it accordingly.", m.Counts.VPNPending))
	}
	if opts.VPNKeyPath != "" {
		if _, err := os.Stat(opts.VPNKeyPath); err == nil {
			if err := copyInto(opts.VPNKeyPath, filepath.Join(work, "vpn", "key"), 0o600); err != nil {
				return nil, err
			}
			entry, err := describe(filepath.Join(work, "vpn", "key"), "vpn/key", opts.VPNKeyPath)
			if err != nil {
				return nil, err
			}
			m.Files = append(m.Files, entry)
			m.VPNKeyIncluded = true
		} else if m.Counts.VPNKeys > 0 {
			m.Notes = append(m.Notes, "VPN servers hold sealed TLS keys but the key file was not found at "+opts.VPNKeyPath+"; this bundle cannot restore them.")
		}
	}
	names := map[string]int{}
	for i, src := range append([]string{opts.ConfigPath}, opts.Extra...) {
		if src == "" {
			continue
		}
		if _, err := os.Stat(src); err != nil {
			m.Notes = append(m.Notes, "referenced file missing: "+src)
			continue
		}
		base := filepath.Base(src)
		if names[base] > 0 {
			base = fmt.Sprintf("%d-%s", names[base], base)
		}
		names[filepath.Base(src)]++
		rel := filepath.Join("config", base)
		if i == 0 {
			rel = filepath.Join("config", "cairn.toml")
		}
		if err := copyInto(src, filepath.Join(work, rel), 0o600); err != nil {
			return nil, err
		}
		entry, err := describe(filepath.Join(work, rel), filepath.ToSlash(rel), src)
		if err != nil {
			return nil, err
		}
		m.Files = append(m.Files, entry)
	}
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(work, ManifestName), manifest, 0o600); err != nil {
		return nil, err
	}
	if err := writeTar(work, opts.Out); err != nil {
		os.Remove(opts.Out)
		return nil, err
	}
	return m, nil
}

// snapshotDB writes a consistent single-file copy of a live WAL database.
func snapshotDB(ctx context.Context, src, dst string) error {
	db, err := sql.Open("sqlite", src+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("backup: source database unreachable: %w", err)
	}
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return fmt.Errorf("backup: vacuum into: %w", err)
	}
	return os.Chmod(dst, 0o600)
}

// inspect fills schema, counts and topics from a snapshot and checks integrity.
func inspect(ctx context.Context, path string, m *Manifest) error {
	db, err := sql.Open("sqlite", path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return fmt.Errorf("backup: snapshot integrity check failed: %s", integrity)
	}
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("backup: schema_migrations unreadable: %w", err)
	}
	m.Schema = nil
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		m.Schema = append(m.Schema, v)
	}
	rows.Close()
	count := func(q string, dst *int) error {
		if err := db.QueryRowContext(ctx, q).Scan(dst); err != nil {
			if strings.Contains(err.Error(), "no such table") {
				*dst = 0
				return nil
			}
			return err
		}
		return nil
	}
	c := &m.Counts
	for _, q := range []struct {
		sql string
		dst *int
	}{
		{`SELECT count(*) FROM devices`, &c.Devices},
		{`SELECT count(*) FROM devices WHERE checked_out_at IS NULL AND token_updated_at IS NOT NULL`, &c.Pushable},
		{`SELECT count(*) FROM profiles`, &c.Profiles},
		{`SELECT count(*) FROM groups`, &c.Groups},
		{`SELECT count(*) FROM enrollment_grants`, &c.Grants},
		{`SELECT count(*) FROM cert_issuance WHERE state='QUARANTINED'`, &c.Quarantined},
		{`SELECT count(*) FROM mfa_factors`, &c.MFAFactors},
		{`SELECT count(*) FROM app_users`, &c.LocalUsers},
		{`SELECT count(*) FROM vpn_servers WHERE tls_key IS NOT NULL`, &c.VPNKeys},
		{`SELECT count(*) FROM vpn_identities WHERE deploy_status='sent'`, &c.VPNPending},
	} {
		if err := count(q.sql, q.dst); err != nil {
			return err
		}
	}
	m.Topics = nil
	trows, err := db.QueryContext(ctx, `SELECT topic, not_after FROM apns_topics ORDER BY topic`)
	if err == nil {
		for trows.Next() {
			var t TopicInfo
			if err := trows.Scan(&t.Topic, &t.NotAfter); err != nil {
				trows.Close()
				return err
			}
			m.Topics = append(m.Topics, t)
		}
		trows.Close()
	}
	return nil
}

func describe(path, rel, source string) (FileEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileEntry{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return FileEntry{}, err
	}
	info, err := f.Stat()
	if err != nil {
		return FileEntry{}, err
	}
	return FileEntry{Path: rel, Source: source, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n, Mode: uint32(info.Mode().Perm())}, nil
}

func copyInto(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// writeTar packs dir into a gzip tarball at out with mode 0600.
func writeTar(dir, out string) error {
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	var paths []string
	err = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		f.Close()
		return err
	}
	sort.Strings(paths)
	for _, p := range paths {
		rel, _ := filepath.Rel(dir, p)
		info, err := os.Stat(p)
		if err != nil {
			f.Close()
			return err
		}
		hdr := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0o600, Size: info.Size(), ModTime: info.ModTime(), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			f.Close()
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			f.Close()
			return err
		}
		_, err = io.Copy(tw, in)
		in.Close()
		if err != nil {
			f.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Report is the result of Verify.
type Report struct {
	Manifest *Manifest
	Dir      string // extraction directory
	Problems []string
	Observed Counts
}

// OK reports whether verification found no problems.
func (r *Report) OK() bool { return len(r.Problems) == 0 }

// Extract unpacks a bundle into dir (created 0700), refusing absolute or
// parent-relative member names, and returns the manifest.
func Extract(bundle, dir string) (*Manifest, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.Open(bundle)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("backup: not a gzip bundle: %w", err)
	}
	tr := tar.NewReader(gz)
	var manifest *Manifest
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("backup: refusing member %q", hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		dst := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, 4<<30)); err != nil {
			out.Close()
			return nil, err
		}
		if err := out.Close(); err != nil {
			return nil, err
		}
		if name == ManifestName {
			b, err := os.ReadFile(dst)
			if err != nil {
				return nil, err
			}
			manifest = &Manifest{}
			if err := json.Unmarshal(b, manifest); err != nil {
				return nil, fmt.Errorf("backup: manifest unreadable: %w", err)
			}
		}
	}
	if manifest == nil {
		return nil, errors.New("backup: bundle has no manifest")
	}
	return manifest, nil
}

// Verify extracts bundle into dir and checks hashes, database integrity, counts
// and MFA key presence. It is a restore rehearsal: it never touches the live
// database and never starts a server.
func Verify(ctx context.Context, bundle, dir string) (*Report, error) {
	m, err := Extract(bundle, dir)
	if err != nil {
		return nil, err
	}
	r := &Report{Manifest: m, Dir: dir}
	seenDB := false
	for _, fe := range m.Files {
		p := filepath.Join(dir, filepath.FromSlash(fe.Path))
		got, gerr := describe(p, fe.Path, fe.Source)
		switch {
		case gerr != nil:
			r.Problems = append(r.Problems, "missing from bundle: "+fe.Path)
		case got.SHA256 != fe.SHA256 || got.Size != fe.Size:
			r.Problems = append(r.Problems, "hash mismatch: "+fe.Path)
		}
		if fe.Path == "cairn.db" {
			seenDB = true
		}
	}
	if !seenDB {
		r.Problems = append(r.Problems, "manifest lists no database")
		return r, nil
	}
	observed := &Manifest{}
	if err := inspect(ctx, filepath.Join(dir, "cairn.db"), observed); err != nil {
		r.Problems = append(r.Problems, "database: "+err.Error())
		return r, nil
	}
	r.Observed = observed.Counts
	if observed.Counts != m.Counts {
		r.Problems = append(r.Problems, fmt.Sprintf("record counts differ from manifest: manifest %+v, bundle %+v", m.Counts, observed.Counts))
	}
	if strings.Join(observed.Schema, ",") != strings.Join(m.Schema, ",") {
		r.Problems = append(r.Problems, "schema versions differ from manifest")
	}
	if observed.Counts.MFAFactors > 0 && !m.MFAKeyIncluded {
		r.Problems = append(r.Problems, "database holds MFA factors but the bundle has no mfa/key; restored administrators would be locked out of MFA")
	}
	if m.MFAKeyIncluded {
		if _, err := os.Stat(filepath.Join(dir, "mfa", "key")); err != nil {
			r.Problems = append(r.Problems, "manifest claims an MFA key but mfa/key is absent")
		}
	}
	if observed.Counts.VPNKeys > 0 && !m.VPNKeyIncluded {
		r.Problems = append(r.Problems, "database holds sealed VPN server keys but the bundle has no vpn/key; restored VPN servers could not issue profiles")
	}
	if m.VPNKeyIncluded {
		if _, err := os.Stat(filepath.Join(dir, "vpn", "key")); err != nil {
			r.Problems = append(r.Problems, "manifest claims a VPN key but vpn/key is absent")
		}
	}
	for _, t := range observed.Topics {
		if exp, err := time.Parse(time.RFC3339, t.NotAfter); err != nil {
			r.Problems = append(r.Problems, "APNs expiry unreadable for "+t.Topic)
		} else if !exp.After(time.Now()) {
			r.Problems = append(r.Problems, "APNs certificate for "+t.Topic+" expired "+exp.Format("2006-01-02")+"; a restore would need renewal first")
		}
	}
	return r, nil
}

// Restore places a verified bundle's data under dataDir: cairn.db, cairn.db.mfa/key, cairn.db.vpn/key
// and config/ files. dataDir must not exist or must be empty. It writes files
// only; migrating and starting the service remain explicit operator steps.
func Restore(ctx context.Context, bundle, dataDir string) (*Report, error) {
	if entries, err := os.ReadDir(dataDir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("backup: %s is not empty; restore into an empty directory", dataDir)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	scratch, err := os.MkdirTemp(filepath.Dir(filepath.Clean(dataDir)), ".cairn-restore-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	r, err := Verify(ctx, bundle, scratch)
	if err != nil {
		return nil, err
	}
	if !r.OK() {
		return r, errors.New("backup: bundle failed verification; nothing restored")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return r, err
	}
	if err := copyInto(filepath.Join(scratch, "cairn.db"), filepath.Join(dataDir, "cairn.db"), 0o600); err != nil {
		return r, err
	}
	if r.Manifest.MFAKeyIncluded {
		if err := copyInto(filepath.Join(scratch, "mfa", "key"), filepath.Join(dataDir, "cairn.db.mfa", "key"), 0o600); err != nil {
			return r, err
		}
	}
	if r.Manifest.VPNKeyIncluded {
		if err := copyInto(filepath.Join(scratch, "vpn", "key"), filepath.Join(dataDir, "cairn.db.vpn", "key"), 0o600); err != nil {
			return r, err
		}
	}
	for _, fe := range r.Manifest.Files {
		if !strings.HasPrefix(fe.Path, "config/") {
			continue
		}
		if err := copyInto(filepath.Join(scratch, filepath.FromSlash(fe.Path)), filepath.Join(dataDir, filepath.FromSlash(fe.Path)), 0o600); err != nil {
			return r, err
		}
	}
	r.Dir = dataDir
	return r, nil
}
