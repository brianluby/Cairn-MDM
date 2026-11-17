package vpn_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/vpn"
)

// clock is a settable time for a service under test.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) forward(d time.Duration) { c.t = c.t.Add(d) }

const day = 24 * time.Hour

// renewing builds a service that replaces certificates renewBefore ahead of
// expiry, on a clock the test moves. Certificates last 365 days.
func renewing(t *testing.T, f *fixture, renewBefore time.Duration) (*vpn.Service, *clock) {
	t.Helper()
	c := &clock{t: time.Now()}
	pol := issue.Policy{LeafValidity: 365 * day, Backdate: 5 * time.Minute}
	svc, err := vpn.NewService(f.servers, f.db, f.dir, f.backend, f.cmd,
		vpn.Options{Organization: "org.example", Policy: pol, DeviceSCEPURL: "https://mdm.example.org/scep/vpn", RenewBefore: renewBefore, Now: c.now},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return svc, c
}

func installed(t *testing.T, f *fixture, svc *vpn.Service, device string) sqlite.VPNIdentity {
	t.Helper()
	v, err := svc.Issue(context.Background(), device, f.server, "alice", "nick")
	if err != nil {
		t.Fatal(err)
	}
	f.device(t, device, "Acknowledged")
	return v
}

func TestSweepReplacesACertificateNearExpiry(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc, c := renewing(t, f, 45*day)
	first := installed(t, f, svc, "PHONE1")

	svc.Sweep(ctx)
	c.forward(300 * day)
	svc.Sweep(ctx)
	if cmd := f.device(t, "PHONE1", ""); cmd != nil {
		t.Fatal("a profile was sent 65 days before expiry with a 45 day window")
	}

	c.forward(30 * day)
	svc.Sweep(ctx)
	rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1")
	if len(rows) != 2 || rows[0].Actor != vpn.RenewalActor || rows[0].Owner != first.Owner || rows[0].DeployStatus != "sent" {
		t.Fatalf("identities after the sweep = %+v", rows)
	}
	if old, _ := f.db.GetVPNIdentity(ctx, first.ID); old.State != sqlite.VPNIssued {
		t.Fatalf("old certificate = %s before the device installed the new one", old.State)
	}
	if identifier, _ := profileOf(t, f.device(t, "PHONE1", "Acknowledged")); identifier != "org.example.vpn.office" {
		t.Fatalf("profile identifier = %q; it would not replace the installed one", identifier)
	}
	old, _ := f.db.GetVPNIdentity(ctx, first.ID)
	cur, _ := f.db.GetVPNIdentity(ctx, rows[0].ID)
	if old.State != sqlite.VPNSuperseded || cur.DeployStatus != "installed" || !cur.Expires().After(old.Expires().Add(300*day)) {
		t.Fatalf("after install: old=%s new=%s expires %s", old.State, cur.DeployStatus, cur.NotAfter)
	}

	// The new certificate is not due, and the old one is no longer current.
	c.forward(2 * day)
	svc.Sweep(ctx)
	if rows, _ = f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 2 {
		t.Fatalf("identities after a later sweep = %d, want 2", len(rows))
	}
}

func TestSweepLeavesCertificatesAloneWhenRenewalIsOff(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc, c := renewing(t, f, 0)
	installed(t, f, svc, "PHONE1")
	c.forward(360 * day)
	svc.Sweep(ctx)
	if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 1 {
		t.Fatalf("identities = %d with renewal off, want 1", len(rows))
	}
}

// A window longer than the certificate's life must not replace certificates as
// fast as they are issued.
func TestSweepWaitsForHalfTheCertificateLife(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc, c := renewing(t, f, 400*day)
	installed(t, f, svc, "PHONE1")
	c.forward(100 * day)
	svc.Sweep(ctx)
	if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 1 {
		t.Fatalf("identities = %d after 100 of 365 days, want 1", len(rows))
	}
	c.forward(100 * day)
	svc.Sweep(ctx)
	if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 2 {
		t.Fatalf("identities = %d after 200 of 365 days, want 2", len(rows))
	}
}

func TestSweepDoesNotRenewForADisabledOwnerAndRetriesDaily(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc, c := renewing(t, f, 45*day)
	installed(t, f, svc, "PHONE1")
	c.forward(330 * day)

	f.dir.disabled = true
	svc.Sweep(ctx)
	if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 1 {
		t.Fatal("a certificate was requested for a disabled owner")
	}

	// One attempt a day: the account is back, but the next try waits.
	f.dir.disabled = false
	c.forward(time.Hour)
	svc.Sweep(ctx)
	if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 1 {
		t.Fatal("a second attempt ran within a day of the first")
	}
	c.forward(24 * time.Hour)
	svc.Sweep(ctx)
	if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 2 {
		t.Fatal("no attempt a day after the refused one")
	}
}

func TestSweepDoesNotRenewWhenTheAccountChanged(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc, c := renewing(t, f, 45*day)
	installed(t, f, svc, "PHONE1")
	c.forward(330 * day)
	f.dir.owner.UPN = "alice.renamed@example.org"
	svc.Sweep(ctx)
	if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 1 {
		t.Fatal("a certificate was requested though the directory describes the account differently")
	}
}

func TestSweepSkipsADeviceThatLeftManagement(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	svc, c := renewing(t, f, 45*day)
	installed(t, f, svc, "PHONE1")
	if err := f.db.DeviceCheckedOut(ctx, "PHONE1"); err != nil {
		t.Fatal(err)
	}
	c.forward(330 * day)
	svc.Sweep(ctx)
	if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 1 {
		t.Fatal("a certificate was requested for a device that left management")
	}
}

// For a key the device makes, renewal sends a new offer; the certificate is
// asked for only when the device answers it.
func TestSweepOffersANewCertificateForADeviceMadeKey(t *testing.T) {
	ctx := context.Background()
	f, _, serverID := deviceKeyFixture(t)
	svc, c := renewing(t, f, 45*day)
	if _, err := svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
		t.Fatal(err)
	}
	cmd := f.device(t, "PHONE1", "")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := svc.SignCSRContext(ctx, requestWithKey(t, key, "alice", offeredChallenge(t, cmd))); err != nil {
		t.Fatal(err)
	}
	f.device(t, "PHONE1", "Acknowledged")
	rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1")
	if len(rows) != 1 || rows[0].DeployStatus != "installed" {
		t.Fatalf("identities before renewal = %+v", rows)
	}

	c.forward(330 * day)
	svc.Sweep(ctx)
	next := f.device(t, "PHONE1", "")
	challenge := offeredChallenge(t, next)
	if rows, _ = f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 1 {
		t.Fatal("a certificate was requested before the device asked")
	}
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf, err := svc.SignCSRContext(ctx, requestWithKey(t, newKey, "alice", challenge))
	if err != nil {
		t.Fatal(err)
	}
	f.device(t, "PHONE1", "Acknowledged")
	rows, _ = f.db.DeviceVPNIdentities(ctx, "PHONE1")
	if len(rows) != 2 || rows[0].Actor != vpn.RenewalActor || rows[0].DeployStatus != "installed" || rows[1].State != sqlite.VPNSuperseded ||
		!leaf.NotAfter.After(c.now().Add(300*day)) {
		t.Fatalf("identities after renewal = %+v", rows)
	}
}
