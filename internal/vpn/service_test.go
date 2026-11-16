package vpn_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	npush "github.com/micromdm/nanomdm/push"
	"github.com/micromdm/plist"

	"github.com/nickpdawson/cairn-mdm/internal/ca"
	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/vpn"
)

type okPush struct{}

func (okPush) Push(_ context.Context, ids []string) (map[string]*npush.Response, error) {
	out := map[string]*npush.Response{}
	for _, id := range ids {
		out[id] = &npush.Response{}
	}
	return out, nil
}

type fakeDirectory struct {
	owner    directory.DirectoryIdentity
	disabled bool
}

func (d *fakeDirectory) ResolveOwner(_ context.Context, account string) (*directory.DirectoryIdentity, error) {
	if d.disabled || !strings.EqualFold(account, d.owner.AccountName) {
		return nil, errors.New("not eligible")
	}
	o := d.owner
	return &o, nil
}
func (d *fakeDirectory) RevalidateOwner(_ context.Context, owner directory.DirectoryIdentity) (*directory.DirectoryIdentity, error) {
	if d.disabled || owner.ObjectID != d.owner.ObjectID {
		return nil, errors.New("not eligible")
	}
	o := d.owner
	return &o, nil
}

// heldBackend answers like a remote CA whose reply was lost.
type heldBackend struct{ issue.CABackend }

func (heldBackend) Capabilities() issue.Capability { return issue.Capability{Name: "remote"} }
func (heldBackend) Issue(context.Context, issue.IssueRequest) (issue.IssueResult, error) {
	return issue.IssueResult{Status: issue.StatusAmbiguous}, errors.New("reply lost")
}

// wrongNameBackend signs for a different subject than it was asked for.
type wrongNameBackend struct{ issue.CABackend }

func (b wrongNameBackend) Issue(ctx context.Context, req issue.IssueRequest) (issue.IssueResult, error) {
	t := *req.Template
	t.Subject.CommonName = "administrator"
	req.Template = &t
	return b.CABackend.Issue(ctx, req)
}

type fixture struct {
	db      *sqlite.DB
	dir     *fakeDirectory
	servers *vpn.Servers
	backend issue.CABackend
	cmd     *mdmcore.Commander
	server  int64
}

const testStaticKey = "-----BEGIN OpenVPN Static key V1-----\n" +
	"0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n" +
	"0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n" +
	"0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n" +
	"0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef\n" +
	"-----END OpenVPN Static key V1-----"

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, t.TempDir()+"/vpn.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	authority, err := ca.Ensure(ctx, db.SQL(), ca.Options{CommonName: "Test CA", Organization: "Test", KeyBits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"PHONE1", "PHONE2"} {
		if err := db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: id, UDID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
		if err := db.DeviceTokenUpdated(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	servers, err := vpn.NewServers(db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := servers.Create(ctx, vpn.Server{
		Name: "Office VPN", Slug: "office",
		Remotes:        []vpn.Remote{{Host: "vpn.example.org", Port: 443, Proto: "udp"}},
		VerifyX509Name: "vpn.example.org", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.Certificate().Raw})),
		TLSKeyMode: vpn.TLSKeyAuth, KeyDirection: 1, TLSKey: testStaticKey, UserAuth: true,
	}, "nick")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &fixture{
		db: db, servers: servers, backend: authority.EmbeddedBackend(), server: serverID,
		dir: &fakeDirectory{owner: directory.DirectoryIdentity{DirectoryID: "test", ObjectID: strings.Repeat("a", 32), UPN: "alice@example.org", AccountName: "alice"}},
		cmd: mdmcore.NewCommander(db.NanoStorage(log), okPush{}).WithRecorder(db, log),
	}
}

func (f *fixture) service(t *testing.T, backend issue.CABackend) *vpn.Service {
	t.Helper()
	pol := issue.Policy{LeafValidity: 365 * 24 * time.Hour, Backdate: 5 * time.Minute}
	svc, err := vpn.NewService(f.servers, f.db, f.dir, backend, f.cmd, vpn.Options{Organization: "org.example", Policy: pol},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// device plays the phone: fetch the next command, answer with status.
func (f *fixture) device(t *testing.T, id, status string) *mdm.Command {
	t.Helper()
	store := f.db.NanoStorage(nil)
	r := mdm.NewRequestWithContext(context.Background(), nil)
	r.EnrollID = &mdm.EnrollID{ID: id}
	cmd, err := store.RetrieveNextCommand(r, false)
	if err != nil {
		t.Fatal(err)
	}
	if cmd == nil || status == "" {
		return cmd
	}
	if err = store.StoreCommandReport(r, &mdm.CommandResults{CommandUUID: cmd.CommandUUID, Status: status, Raw: []byte("report")}); err != nil {
		t.Fatal(err)
	}
	return cmd
}

// keyAtRest reports whether the database still holds the private key. Command
// bodies carry the profile as base64 data, so each queued body is decoded; a
// plain text search of the database would find nothing either way.
func (f *fixture) keyAtRest(t *testing.T) bool {
	t.Helper()
	rows, err := f.db.SQL().Query(`SELECT v FROM nano_kv`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var v []byte
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(v, []byte("PRIVATE KEY")) {
			return true
		}
		var c struct{ Command struct{ Payload []byte } }
		if plist.Unmarshal(v, &c) == nil && bytes.Contains(c.Command.Payload, []byte("PRIVATE KEY")) {
			return true
		}
	}
	var m int
	if err := f.db.SQL().QueryRow(`SELECT count(*) FROM vpn_identities WHERE instr(fail_reason, 'PRIVATE KEY') > 0`).Scan(&m); err != nil {
		t.Fatal(err)
	}
	return m > 0
}

func profileOf(t *testing.T, cmd *mdm.Command) (identifier string, vendor map[string]any) {
	t.Helper()
	var c struct {
		Command struct {
			RequestType string
			Payload     []byte
		}
	}
	if err := plist.Unmarshal(cmd.Raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Command.RequestType != "InstallProfile" {
		t.Fatalf("command is %s, want InstallProfile", c.Command.RequestType)
	}
	if err := vpn.Check(c.Command.Payload); err != nil {
		t.Fatalf("queued profile fails the install rules: %v", err)
	}
	var top map[string]any
	if err := plist.Unmarshal(c.Command.Payload, &top); err != nil {
		t.Fatal(err)
	}
	return top["PayloadIdentifier"].(string), top["PayloadContent"].([]any)[0].(map[string]any)["VendorConfig"].(map[string]any)
}

func TestIssueDeliverAcknowledgeAndScrub(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc := f.service(t, f.backend)

	v, err := svc.Issue(ctx, "PHONE1", f.server, "alice", "nick")
	if err != nil {
		t.Fatal(err)
	}
	if v.State != sqlite.VPNIssued || v.DeployStatus != "sent" || v.CertSerial == "" || v.Owner.UPN != "alice@example.org" || v.Actor != "nick" {
		t.Fatalf("identity after issue = %+v", v)
	}
	leaf, err := x509.ParseCertificate(v.LeafDER)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "alice" || len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "alice@example.org" ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || leaf.IsCA {
		t.Fatalf("leaf subject=%q SAN=%v EKU=%v CA=%v", leaf.Subject.CommonName, leaf.EmailAddresses, leaf.ExtKeyUsage, leaf.IsCA)
	}
	if !f.keyAtRest(t) {
		t.Fatal("expected the key inside the queued command before the device answers")
	}

	cmd := f.device(t, "PHONE1", "Acknowledged")
	identifier, vendor := profileOf(t, cmd)
	if identifier != "org.example.vpn.office" || vendor["USERNAME"] != "alice" {
		t.Fatalf("profile identifier=%q USERNAME=%v", identifier, vendor["USERNAME"])
	}
	if !strings.Contains(vendor["key"].(string), "PRIVATE KEY") || !strings.Contains(vendor["cert"].(string), "BEGIN CERTIFICATE") {
		t.Fatal("delivered profile lacks the identity")
	}

	v, _ = f.db.GetVPNIdentity(ctx, v.ID)
	if v.DeployStatus != "installed" {
		t.Fatalf("deploy status after ack = %q", v.DeployStatus)
	}
	if f.keyAtRest(t) {
		t.Fatal("private key still in the database after the device acknowledged")
	}
	var raw []byte
	f.db.SQL().QueryRow(`SELECT v FROM nano_kv WHERE bucket='queue' AND k=?`, cmd.CommandUUID+".raw").Scan(&raw)
	if !bytes.Contains(raw, []byte("ProfileList")) {
		t.Fatalf("queued body was not replaced with the placeholder: %.80s", raw)
	}
}

func TestReissueReplacesAndRetiresTheOldCertificate(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc := f.service(t, f.backend)
	first, err := svc.Issue(ctx, "PHONE1", f.server, "alice", "nick")
	if err != nil {
		t.Fatal(err)
	}
	firstCmd := f.device(t, "PHONE1", "Acknowledged")
	second, err := svc.Issue(ctx, "PHONE1", f.server, "alice", "nick")
	if err != nil {
		t.Fatal(err)
	}
	secondCmd := f.device(t, "PHONE1", "")
	if secondCmd == nil || secondCmd.CommandUUID == firstCmd.CommandUUID {
		t.Fatal("re-issue did not queue a new command")
	}
	if identifier, _ := profileOf(t, secondCmd); identifier != "org.example.vpn.office" {
		t.Fatalf("re-issued profile identifier = %q; it would not replace the installed one", identifier)
	}

	// Until the new profile is installed the old certificate stays current.
	if old, _ := f.db.GetVPNIdentity(ctx, first.ID); old.State != sqlite.VPNIssued {
		t.Fatalf("old identity = %s before the replacement installed", old.State)
	}
	f.device(t, "PHONE1", "Acknowledged")
	old, _ := f.db.GetVPNIdentity(ctx, first.ID)
	cur, _ := f.db.GetVPNIdentity(ctx, second.ID)
	if old.State != sqlite.VPNSuperseded || cur.State != sqlite.VPNIssued || cur.DeployStatus != "installed" || cur.CertSerial == old.CertSerial {
		t.Fatalf("after re-issue: old=%s new=%s/%s", old.State, cur.State, cur.DeployStatus)
	}

	// The sweep revokes the replaced certificate at a CA that can revoke.
	svc.Sweep(ctx)
	old, _ = f.db.GetVPNIdentity(ctx, first.ID)
	if !old.RevokedAt.Valid {
		t.Fatal("superseded certificate was not revoked")
	}
	var revoked int
	f.db.SQL().QueryRow(`SELECT count(*) FROM revoked_certs WHERE serial=?`, old.CertSerial).Scan(&revoked)
	if revoked != 1 {
		t.Fatalf("CA revocation rows for the old serial = %d", revoked)
	}
	if cur, _ = f.db.GetVPNIdentity(ctx, second.ID); cur.RevokedAt.Valid {
		t.Fatal("the current certificate was revoked")
	}
}

func TestIssueRefusals(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc := f.service(t, f.backend)

	if _, err := svc.Issue(ctx, "PHONE1", f.server, "", "nick"); !errors.Is(err, vpn.ErrOwnerRequired) {
		t.Fatalf("no owner named: %v", err)
	}
	if _, err := svc.Issue(ctx, "PHONE1", f.server, "mallory", "nick"); !errors.Is(err, vpn.ErrOwnerIneligible) {
		t.Fatalf("unknown owner: %v", err)
	}
	f.dir.disabled = true
	if _, err := svc.Issue(ctx, "PHONE1", f.server, "alice", "nick"); !errors.Is(err, vpn.ErrOwnerIneligible) {
		t.Fatalf("disabled owner: %v", err)
	}
	f.dir.disabled = false
	if _, err := svc.Issue(ctx, "NOPE", f.server, "alice", "nick"); !errors.Is(err, vpn.ErrDeviceGone) {
		t.Fatalf("unknown device: %v", err)
	}
	var n int
	f.db.SQL().QueryRow(`SELECT count(*) FROM vpn_identities`).Scan(&n)
	if n != 0 {
		t.Fatalf("refusals left %d identity rows", n)
	}
	if f.device(t, "PHONE1", "") != nil {
		t.Fatal("a refused request queued a command")
	}
}

func TestUntrustedCAOutcomesAreHeldAndSendNothing(t *testing.T) {
	ctx := context.Background()
	for name, backend := range map[string]func(issue.CABackend) issue.CABackend{
		"lost reply":    func(b issue.CABackend) issue.CABackend { return heldBackend{b} },
		"wrong subject": func(b issue.CABackend) issue.CABackend { return wrongNameBackend{b} },
	} {
		f := setup(t)
		svc := f.service(t, backend(f.backend))
		if _, err := svc.Issue(ctx, "PHONE1", f.server, "alice", "nick"); !errors.Is(err, vpn.ErrHeld) {
			t.Fatalf("%s: err = %v, want held", name, err)
		}
		held, _ := f.db.QuarantinedVPNIdentities(ctx)
		if len(held) != 1 {
			t.Fatalf("%s: quarantined = %d", name, len(held))
		}
		if f.device(t, "PHONE1", "") != nil || f.keyAtRest(t) {
			t.Fatalf("%s: a held request reached the device queue", name)
		}
	}
}

func TestKeyLeavesTheQueueWhenTheDeviceFailsOrDisappears(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc := f.service(t, f.backend)

	// Install error on the device.
	v, err := svc.Issue(ctx, "PHONE1", f.server, "alice", "nick")
	if err != nil {
		t.Fatal(err)
	}
	f.device(t, "PHONE1", "Error")
	if v, _ = f.db.GetVPNIdentity(ctx, v.ID); v.DeployStatus != "failed" || f.keyAtRest(t) {
		t.Fatalf("after install error: deploy=%q keyAtRest=%v", v.DeployStatus, f.keyAtRest(t))
	}

	// Never collected: the sweep withdraws it and the device gets a placeholder.
	v2, err := svc.Issue(ctx, "PHONE2", f.server, "alice", "nick")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.SQL().Exec(`UPDATE vpn_identities SET updated_at=datetime('now','-8 days') WHERE id=?`, v2.ID); err != nil {
		t.Fatal(err)
	}
	svc.Sweep(ctx)
	if v2, _ = f.db.GetVPNIdentity(ctx, v2.ID); v2.DeployStatus != "expired" || f.keyAtRest(t) {
		t.Fatalf("after sweep: deploy=%q keyAtRest=%v", v2.DeployStatus, f.keyAtRest(t))
	}
	late := f.device(t, "PHONE2", "Acknowledged")
	if late == nil || !bytes.Contains(late.Raw, []byte("ProfileList")) || bytes.Contains(late.Raw, []byte("InstallProfile")) {
		t.Fatal("a late device did not receive the placeholder")
	}
	if v2, _ = f.db.GetVPNIdentity(ctx, v2.ID); v2.DeployStatus != "expired" {
		t.Fatalf("a late answer changed a withdrawn delivery to %q", v2.DeployStatus)
	}
	// Both undelivered certificates are revoked by the sweep.
	svc.Sweep(ctx)
	for _, id := range []int64{v.ID, v2.ID} {
		if got, _ := f.db.GetVPNIdentity(ctx, id); !got.RevokedAt.Valid {
			t.Fatalf("undelivered certificate %d not revoked", id)
		}
	}
}

func TestRevokeWithoutCARevocationStaysListed(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	// Same signer, but declared unable to revoke, like an external SCEP CA.
	svc := f.service(t, noRevoke{f.backend})
	v, err := svc.Issue(ctx, "PHONE1", f.server, "alice", "nick")
	if err != nil {
		t.Fatal(err)
	}
	f.device(t, "PHONE1", "Acknowledged")
	if err = svc.Revoke(ctx, v.ID, "nick"); err != nil {
		t.Fatal(err)
	}
	waiting, _ := f.db.VPNIdentitiesAwaitingRevocation(ctx)
	if len(waiting) != 1 || waiting[0].State != sqlite.VPNRevoked || waiting[0].RevokedAt.Valid {
		t.Fatalf("awaiting revocation = %+v", waiting)
	}
	if err = svc.ConfirmRevokedAtCA(ctx, v.ID, "nick"); err != nil {
		t.Fatal(err)
	}
	if waiting, _ = f.db.VPNIdentitiesAwaitingRevocation(ctx); len(waiting) != 0 {
		t.Fatal("confirmed revocation still listed")
	}
}

type noRevoke struct{ issue.CABackend }

func (b noRevoke) Capabilities() issue.Capability {
	c := b.CABackend.Capabilities()
	c.CanRevoke = false
	return c
}

// ackOnQueue plays a device that answers the instant the command is queued,
// before the service has done anything else.
type ackOnQueue struct {
	vpn.Commander
	f *fixture
	t *testing.T
}

func (c ackOnQueue) SendInstallProfileAs(ctx context.Context, uuid string, profile []byte, id string) error {
	err := c.Commander.SendInstallProfileAs(ctx, uuid, profile, id)
	if err == nil {
		c.f.device(c.t, id, "Acknowledged")
	}
	return err
}

func TestImmediateAnswerIsRecordedAndScrubbed(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc, err := vpn.NewService(f.servers, f.db, f.dir, f.backend, ackOnQueue{f.cmd, f, t},
		vpn.Options{Organization: "org.example", Policy: issue.Policy{LeafValidity: 365 * 24 * time.Hour, Backdate: 5 * time.Minute}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	v, err := svc.Issue(ctx, "PHONE1", f.server, "alice", "nick")
	if err != nil {
		t.Fatal(err)
	}
	if v.DeployStatus != "installed" || f.keyAtRest(t) {
		t.Fatalf("deploy=%q keyAtRest=%v; an answer that beats the service must still be recorded and scrubbed", v.DeployStatus, f.keyAtRest(t))
	}
}

// failAfterQueue stores the command and then reports failure, as a commander
// does when a later step of queueing breaks.
type failAfterQueue struct{ vpn.Commander }

func (c failAfterQueue) SendInstallProfileAs(ctx context.Context, uuid string, profile []byte, id string) error {
	if err := c.Commander.SendInstallProfileAs(ctx, uuid, profile, id); err != nil {
		return err
	}
	return errors.New("history write failed")
}

func TestFailedQueueingLeavesNoKey(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc, err := vpn.NewService(f.servers, f.db, f.dir, f.backend, failAfterQueue{f.cmd},
		vpn.Options{Organization: "org.example", Policy: issue.Policy{LeafValidity: 365 * 24 * time.Hour, Backdate: 5 * time.Minute}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Issue(ctx, "PHONE1", f.server, "alice", "nick"); err == nil {
		t.Fatal("issue reported success although queueing failed")
	}
	if f.keyAtRest(t) {
		t.Fatal("the key stayed in the queue after queueing was reported failed")
	}
	waiting, _ := f.db.VPNIdentitiesAwaitingRevocation(ctx)
	if len(waiting) != 1 || waiting[0].DeployStatus != "failed" {
		t.Fatalf("the certificate without a holder is not listed for revocation: %+v", waiting)
	}
}

func TestCancelledRequestStillRecordsOutcome(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	svc, err := vpn.NewService(f.servers, f.db, f.dir, cancelDuringIssue{f.backend, cancel}, f.cmd,
		vpn.Options{Organization: "org.example", Policy: issue.Policy{LeafValidity: 365 * 24 * time.Hour, Backdate: 5 * time.Minute}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Issue(ctx, "PHONE1", f.server, "alice", "nick"); err != nil {
		t.Fatalf("issue after the browser went away: %v", err)
	}
	list, _ := f.db.DeviceVPNIdentities(context.Background(), "PHONE1")
	if len(list) != 1 || list[0].State != sqlite.VPNIssued || list[0].DeployStatus != "sent" {
		t.Fatalf("identity = %+v", list)
	}
}

// cancelDuringIssue cancels the caller's context while the CA is signing.
type cancelDuringIssue struct {
	issue.CABackend
	cancel context.CancelFunc
}

func (b cancelDuringIssue) Issue(ctx context.Context, req issue.IssueRequest) (issue.IssueResult, error) {
	b.cancel()
	return b.CABackend.Issue(ctx, req)
}

func TestAbandonedRequestIsHeld(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	id, err := f.db.BeginVPNIdentity(ctx, sqlite.VPNIdentity{ServerID: f.server, DeviceID: "PHONE1", Owner: f.dir.owner, Actor: "nick", SPKISHA256: "x", Backend: "embedded", CommandUUID: "u-1"})
	if err != nil {
		t.Fatal(err)
	}
	svc := f.service(t, f.backend)
	svc.Sweep(ctx)
	if v, _ := f.db.GetVPNIdentity(ctx, id); v.State != sqlite.VPNIssuing {
		t.Fatalf("a request seconds old was moved to %s", v.State)
	}
	if _, err = svc.Issue(ctx, "PHONE1", f.server, "alice", "nick"); !errors.Is(err, vpn.ErrAwaitingDevice) {
		t.Fatalf("second request while one is unresolved: %v", err)
	}
	if _, err = f.db.SQL().Exec(`UPDATE vpn_identities SET updated_at=datetime('now','-1 hour') WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	svc.Sweep(ctx)
	v, _ := f.db.GetVPNIdentity(ctx, id)
	if v.State != sqlite.VPNQuarantined {
		t.Fatalf("abandoned request is %s, want held", v.State)
	}
	// A held request with no certificate on record can be closed, and the
	// device can then be issued to again.
	if err = svc.Revoke(ctx, id, "nick"); err != nil {
		t.Fatalf("close hold without a serial: %v", err)
	}
	if v, _ = f.db.GetVPNIdentity(ctx, id); v.State != sqlite.VPNFailed {
		t.Fatalf("closed hold is %s", v.State)
	}
	if _, err = svc.Issue(ctx, "PHONE1", f.server, "alice", "nick"); err != nil {
		t.Fatalf("issue after closing the hold: %v", err)
	}
}

func TestConfirmRevokedRefusedForCertificateInUse(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	for _, backend := range []issue.CABackend{f.backend, noRevoke{f.backend}} {
		svc := f.service(t, backend)
		v, err := svc.Issue(ctx, "PHONE1", f.server, "alice", "nick")
		if err != nil {
			t.Fatal(err)
		}
		f.device(t, "PHONE1", "Acknowledged")
		if err = svc.ConfirmRevokedAtCA(ctx, v.ID, "nick"); err == nil {
			t.Fatalf("%s: a certificate in use was recorded as revoked at the CA", backend.Capabilities().Name)
		}
		if got, _ := f.db.GetVPNIdentity(ctx, v.ID); got.RevokedAt.Valid {
			t.Fatal("revoked_at was set")
		}
		if err = svc.Revoke(ctx, v.ID, "nick"); err != nil {
			t.Fatal(err)
		}
	}
}

// otherIssuer is the same signer under another backend name, standing in for
// the CA a site used before it changed issuers.
type otherIssuer struct{ issue.CABackend }

func (b otherIssuer) Capabilities() issue.Capability {
	c := b.CABackend.Capabilities()
	c.Name, c.CanRevoke = "external-scep", false
	return c
}

func TestRevocationStaysWithTheIssuingCA(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	old := f.service(t, otherIssuer{f.backend})
	v, err := old.Issue(ctx, "PHONE1", f.server, "alice", "nick")
	if err != nil {
		t.Fatal(err)
	}
	f.device(t, "PHONE1", "Acknowledged")
	if err = old.Revoke(ctx, v.ID, "nick"); err != nil {
		t.Fatal(err)
	}
	// The site now issues from Cairn's own CA. Its sweep must not take the old
	// certificate's serial to the new CA and call it revoked.
	now := f.service(t, f.backend)
	now.Sweep(ctx)
	got, _ := f.db.GetVPNIdentity(ctx, v.ID)
	if got.RevokedAt.Valid || now.CanRevokeIdentity(got) {
		t.Fatal("a certificate from an earlier issuer was revoked at the current one")
	}
	if waiting, _ := f.db.VPNIdentitiesAwaitingRevocation(ctx); len(waiting) != 1 {
		t.Fatal("the certificate dropped off the revocation list")
	}
	if err = now.ConfirmRevokedAtCA(ctx, v.ID, "nick"); err != nil {
		t.Fatalf("manual confirmation for the earlier issuer: %v", err)
	}
}

// A password sign-in profile is never pushed: a device cannot store the
// password for a VPN that MDM installed. It is downloaded for an account.
func TestIKEv2PasswordProfileIsDownloadedNotPushed(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	office, err := f.servers.Get(ctx, f.server)
	if err != nil {
		t.Fatal(err)
	}
	record := vpn.Server{
		Name: "Office IKEv2", Slug: "office-ikev2", Kind: vpn.KindIKEv2, CAPEM: office.CAPEM, OnDemand: true,
		IKEv2: vpn.IKEv2{RemoteAddress: "vpn.example.org", ServerCertIssuerCN: "Test CA", SignIn: vpn.IKEv2Password,
			Encryption: "AES-256-GCM", Integrity: "SHA2-256", DHGroup: 20},
	}
	id, err := f.servers.Create(ctx, record, "nick")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.servers.Get(ctx, id)
	if err != nil || !stored.IsIKEv2() || stored.IKEv2.RemoteAddress != "vpn.example.org" || stored.IKEv2.DHGroup != 20 {
		t.Fatalf("stored record = %+v, %v", stored, err)
	}
	signed := false
	pol := issue.Policy{LeafValidity: 365 * 24 * time.Hour, Backdate: 5 * time.Minute}
	svc, err := vpn.NewService(f.servers, f.db, f.dir, f.backend, f.cmd, vpn.Options{Organization: "org.example", Policy: pol,
		Sign: func(b []byte) ([]byte, error) { signed = true; return b, nil }}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Issue(ctx, "PHONE1", id, "alice", "nick"); !errors.Is(err, vpn.ErrDownloadOnly) {
		t.Fatalf("push of a password profile: err = %v, want ErrDownloadOnly", err)
	}
	if cmd := f.device(t, "PHONE1", ""); cmd != nil {
		t.Fatal("a password profile was queued for the device")
	}
	name, body, err := svc.Download(ctx, id, "alice", "nick")
	if err != nil {
		t.Fatal(err)
	}
	if name != "office-ikev2-alice.mobileconfig" || !signed {
		t.Fatalf("download name=%q signed=%v", name, signed)
	}
	if err = vpn.CheckIKEv2(body); err != nil {
		t.Fatalf("downloaded profile fails its checks: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "store your password under Settings") || strings.Contains(text, "AuthPassword") || strings.Contains(text, "PRIVATE KEY") {
		t.Fatal("downloaded profile lacks the install note or holds a secret")
	}
	if _, again, _ := svc.Download(ctx, id, "alice", "nick"); string(again) != text {
		t.Fatal("two downloads for one account differ, so a newer copy would not replace the older")
	}
	if _, _, err = svc.Download(ctx, id, "mallory", "nick"); !errors.Is(err, vpn.ErrOwnerIneligible) {
		t.Fatalf("download for an unknown account: %v", err)
	}
	if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 0 {
		t.Fatal("a password profile created a certificate row")
	}

	// A certificate record is sent from a device page, never downloaded, and
	// needs the SCEP endpoint this service was built without.
	record.Slug, record.IKEv2.SignIn = "office-eap-tls", vpn.IKEv2EAPTLS
	certID, err := f.servers.Create(ctx, record, "nick")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = svc.Download(ctx, certID, "alice", "nick"); err == nil {
		t.Fatal("a certificate profile was offered as a download")
	}
	if _, err = svc.Issue(ctx, "PHONE1", certID, "alice", "nick"); !errors.Is(err, vpn.ErrDeviceKeyed) {
		t.Fatalf("certificate sign-in without the endpoint: err = %v, want ErrDeviceKeyed", err)
	}
	if _, _, err = svc.Download(ctx, f.server, "alice", "nick"); err == nil {
		t.Fatal("an OpenVPN profile was offered as a download")
	}
}
