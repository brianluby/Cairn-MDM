package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/plist"

	"github.com/nickpdawson/cairn-mdm/internal/ca"
	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/push"
	"github.com/nickpdawson/cairn-mdm/internal/server"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/vpn"
)

// TestIKEv2CertificateOverDeviceSCEP sends an EAP-TLS IKEv2 profile and plays
// the device over HTTP: it reads the SCEP payload, makes a key, asks the URL in
// the profile for a certificate and gets one for the offer's owner. The
// endpoint is mounted through the real server routes, beside device enrollment.
func TestIKEv2CertificateOverDeviceSCEP(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := sqlite.Open(ctx, t.TempDir()+"/vpn-e2e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	authority, err := ca.Ensure(ctx, db.SQL(), ca.Options{CommonName: "Cairn E2E CA", Organization: "Cairn", KeyBits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(nil)
	cfg := config.Default()
	cfg.Server.PublicURL = "http://" + ts.Listener.Addr().String()

	owner := directory.DirectoryIdentity{DirectoryID: "example", ObjectID: strings.Repeat("a", 32), UPN: "alice@example.org", AccountName: "alice"}
	dir := &e2eDirectory{owner: owner}
	nanoStore := db.NanoStorage(log)
	commander := mdmcore.NewCommander(nanoStore, push.NewPusher(nanoStore, mdmcore.NewLogAdapter(log))).WithRecorder(db, log)
	if err = db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: "PHONE1", UDID: "PHONE1", Name: "PHONE1"}); err != nil {
		t.Fatal(err)
	}
	if err = db.DeviceTokenUpdated(ctx, "PHONE1"); err != nil {
		t.Fatal(err)
	}
	servers, err := vpn.NewServers(db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := servers.Create(ctx, vpn.Server{
		Name: "Office IKEv2", Slug: "office-ikev2", Kind: vpn.KindIKEv2,
		IKEv2: vpn.IKEv2{RemoteAddress: "vpn.example.org", ServerCertIssuerCN: "Cairn E2E CA", SignIn: vpn.IKEv2EAPTLS,
			Encryption: "AES-256-GCM", Integrity: "SHA2-256", DHGroup: 20},
	}, "nick")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vpn.NewService(servers, db, dir, authority.EmbeddedBackend(), commander, vpn.Options{
		Organization: "org.example", Policy: issue.Policy{LeafValidity: 365 * 24 * time.Hour, Backdate: 5 * time.Minute},
		DeviceSCEPURL: cfg.Server.PublicURL + "/scep/vpn",
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	var deps server.Deps
	if deps.VPNSCEP, err = authority.SCEPHandlerWith(svc); err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = server.New(cfg, log, db, deps).Handler()
	ts.Start()
	defer ts.Close()

	if _, err = svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
		t.Fatal(err)
	}
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{ID: "PHONE1"}
	cmd, err := nanoStore.RetrieveNextCommand(r, false)
	if err != nil || cmd == nil {
		t.Fatalf("queued command: %v %v", cmd, err)
	}
	var c struct {
		Command struct{ Payload []byte }
	}
	if err = plist.Unmarshal(cmd.Raw, &c); err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err = plist.Unmarshal(c.Command.Payload, &top); err != nil {
		t.Fatal(err)
	}
	var scepURL, challenge, vpnCertUUID, scepUUID string
	for _, raw := range top["PayloadContent"].([]any) {
		p := raw.(map[string]any)
		switch p["PayloadType"] {
		case "com.apple.security.scep":
			content := p["PayloadContent"].(map[string]any)
			scepURL, challenge, scepUUID = content["URL"].(string), content["Challenge"].(string), p["PayloadUUID"].(string)
		case "com.apple.vpn.managed":
			vpnCertUUID = p["IKEv2"].(map[string]any)["PayloadCertificateUUID"].(string)
		}
	}
	if scepURL != cfg.Server.PublicURL+"/scep/vpn" || challenge == "" || scepUUID == "" || vpnCertUUID != scepUUID {
		t.Fatalf("profile: scep=%q cert=%q uuid=%q", scepURL, vpnCertUUID, scepUUID)
	}

	leaf, _ := scepEnroll(t, ctx, scepURL, challenge, pkix.Name{CommonName: "alice"}, nil)
	if leaf.Subject.CommonName != "alice" || len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "alice@example.org" {
		t.Fatalf("leaf subject=%q SAN=%v", leaf.Subject.CommonName, leaf.EmailAddresses)
	}
	if err = leaf.CheckSignatureFrom(authority.Certificate()); err != nil {
		t.Fatalf("leaf is not from the CA: %v", err)
	}
	if !enrolledKey.PublicKey.Equal(leaf.PublicKey) {
		t.Fatal("certificate is not for the device's key")
	}
	rows, err := db.DeviceVPNIdentities(ctx, "PHONE1")
	if err != nil || len(rows) != 1 || rows[0].State != sqlite.VPNIssued || rows[0].CertSerial == "" {
		t.Fatalf("identity rows = %+v, %v", rows, err)
	}
	stored, err := x509.ParseCertificate(rows[0].LeafDER)
	if err != nil || !stored.Equal(leaf) {
		t.Fatal("stored certificate differs from the one the device received")
	}

	// A second device key cannot reuse the challenge, and a stranger gets nothing.
	if _, err = scepEnrollResult(t, ctx, scepURL, challenge); err == nil {
		t.Fatal("the challenge certified a second key")
	}
	if _, err = scepEnrollResult(t, ctx, scepURL, "guess"); err == nil {
		t.Fatal("an unknown challenge was accepted")
	}
}
