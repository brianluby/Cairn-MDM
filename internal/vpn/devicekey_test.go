package vpn_test

import (
	"bytes"
	"context"
	"encoding/asn1"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/plist"
	scep "github.com/smallstep/scep"

	"github.com/nickpdawson/cairn-mdm/internal/issue"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/vpn"
)

// deviceKeyFixture adds an EAP-TLS IKEv2 server and a service with the device
// SCEP endpoint switched on.
func deviceKeyFixture(t *testing.T) (*fixture, *vpn.Service, int64) {
	t.Helper()
	f := setup(t)
	ctx := context.Background()
	office, err := f.servers.Get(ctx, f.server)
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := f.servers.Create(ctx, vpn.Server{
		Name: "Office IKEv2", Slug: "office-ikev2", Kind: vpn.KindIKEv2, CAPEM: office.CAPEM, OnDemand: true,
		IKEv2: vpn.IKEv2{RemoteAddress: "vpn.example.org", ServerCertIssuerCN: "Test CA", SignIn: vpn.IKEv2EAPTLS,
			Encryption: "AES-256-GCM", Integrity: "SHA2-256", DHGroup: 20},
	}, "nick")
	if err != nil {
		t.Fatal(err)
	}
	pol := issue.Policy{LeafValidity: 365 * 24 * time.Hour, Backdate: 5 * time.Minute}
	svc, err := vpn.NewService(f.servers, f.db, f.dir, f.backend, f.cmd,
		vpn.Options{Organization: "org.example", Policy: pol, DeviceSCEPURL: "https://mdm.example.org/scep/vpn"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return f, svc, serverID
}

// offeredChallenge reads the SCEP challenge out of the profile queued for the device.
func offeredChallenge(t *testing.T, cmd *mdm.Command) string {
	t.Helper()
	if cmd == nil {
		t.Fatal("no profile queued")
	}
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
	if err := vpn.CheckIKEv2(c.Command.Payload); err != nil {
		t.Fatalf("queued profile fails its checks: %v", err)
	}
	if bytes.Contains(c.Command.Payload, []byte("PRIVATE KEY")) {
		t.Fatal("queued profile carries a private key")
	}
	var top map[string]any
	if err := plist.Unmarshal(c.Command.Payload, &top); err != nil {
		t.Fatal(err)
	}
	for _, raw := range top["PayloadContent"].([]any) {
		p := raw.(map[string]any)
		if p["PayloadType"] == "com.apple.security.scep" {
			content := p["PayloadContent"].(map[string]any)
			if content["URL"] != "https://mdm.example.org/scep/vpn" {
				t.Fatalf("SCEP URL = %v", content["URL"])
			}
			return content["Challenge"].(string)
		}
	}
	t.Fatal("profile has no SCEP payload")
	return ""
}

// queuedChallenge returns the challenge in the command body now stored for the
// UUID, or "" once the profile has been replaced. The profile sits base64
// encoded inside the command, so a text search of the body finds nothing.
func queuedChallenge(t *testing.T, f *fixture, commandUUID string) string {
	t.Helper()
	var raw []byte
	if err := f.db.SQL().QueryRow(`SELECT v FROM nano_kv WHERE bucket='queue' AND k=?`, commandUUID+".raw").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var c struct {
		Command struct {
			RequestType string
			Payload     []byte
		}
	}
	if err := plist.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Command.RequestType != "InstallProfile" {
		return ""
	}
	var top map[string]any
	if err := plist.Unmarshal(c.Command.Payload, &top); err != nil {
		t.Fatal(err)
	}
	for _, p := range top["PayloadContent"].([]any) {
		if m := p.(map[string]any); m["PayloadType"] == "com.apple.security.scep" {
			return m["PayloadContent"].(map[string]any)["Challenge"].(string)
		}
	}
	return ""
}

func deviceRequest(t *testing.T, cn, challenge string) *scep.CSRReqMessage {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return requestWithKey(t, key, cn, challenge)
}

func requestWithKey(t *testing.T, key *rsa.PrivateKey, cn, challenge string) *scep.CSRReqMessage {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return &scep.CSRReqMessage{CSR: csr, ChallengePassword: challenge}
}

func TestDeviceMadeKeyGetsACertificateOnce(t *testing.T) {
	ctx := context.Background()
	f, svc, serverID := deviceKeyFixture(t)

	if _, err := svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
		t.Fatal(err)
	}
	if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 0 {
		t.Fatal("a certificate was requested before the device asked")
	}
	if _, err := svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != vpn.ErrAwaitingDevice {
		t.Fatalf("second offer: err = %v, want ErrAwaitingDevice", err)
	}
	challenge := offeredChallenge(t, f.device(t, "PHONE1", ""))
	var stored int
	f.db.SQL().QueryRow(`SELECT count(*) FROM vpn_offers WHERE instr(challenge_sha256, ?) > 0`, challenge).Scan(&stored)
	if stored != 0 {
		t.Fatal("the challenge itself is stored")
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf, err := svc.SignCSRContext(ctx, requestWithKey(t, key, "alice", challenge))
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "alice" || len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "alice@example.org" ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || leaf.IsCA || !key.PublicKey.Equal(leaf.PublicKey) {
		t.Fatalf("leaf subject=%q SAN=%v EKU=%v", leaf.Subject.CommonName, leaf.EmailAddresses, leaf.ExtKeyUsage)
	}
	rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1")
	if len(rows) != 1 || rows[0].State != sqlite.VPNIssued || rows[0].DeployStatus != "sent" || rows[0].Actor != "nick" || rows[0].ServerID != serverID {
		t.Fatalf("identity rows = %+v", rows)
	}

	// The same key may ask again when the reply was lost; any other key may not.
	again, err := svc.SignCSRContext(ctx, requestWithKey(t, key, "alice", challenge))
	if err != nil || !again.Equal(leaf) {
		t.Fatalf("repeat request: %v", err)
	}
	if _, err = svc.SignCSRContext(ctx, deviceRequest(t, "alice", challenge)); err == nil {
		t.Fatal("a second key was certified with a used challenge")
	}
	if rows, _ = f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 1 {
		t.Fatalf("identity rows after the refused request = %d", len(rows))
	}

	// The device reports the profile installed; the challenge leaves the queue.
	pending := f.device(t, "PHONE1", "")
	if queuedChallenge(t, f, pending.CommandUUID) != challenge {
		t.Fatal("test cannot see the challenge in the queued profile")
	}
	cmd := f.device(t, "PHONE1", "Acknowledged")
	if rows, _ = f.db.DeviceVPNIdentities(ctx, "PHONE1"); rows[0].DeployStatus != "installed" {
		t.Fatalf("deploy status after ack = %q", rows[0].DeployStatus)
	}
	if queuedChallenge(t, f, cmd.CommandUUID) != "" {
		t.Fatal("the queued profile, with its challenge, was not replaced after the device answered")
	}
	if _, err = svc.SignCSRContext(ctx, requestWithKey(t, key, "alice", challenge)); err == nil {
		t.Fatal("the challenge still works after the profile was installed")
	}
}

func TestDeviceKeyRefusals(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *fixture, svc *vpn.Service)
		cn      string
		wrong   bool // present a challenge nobody was given
	}{
		{name: "unknown challenge", cn: "alice", wrong: true},
		{name: "another account's name", cn: "administrator"},
		{name: "owner disabled since the offer", cn: "alice", prepare: func(_ *testing.T, f *fixture, _ *vpn.Service) { f.dir.disabled = true }},
		{name: "offer expired", cn: "alice", prepare: func(t *testing.T, f *fixture, svc *vpn.Service) {
			if _, err := f.db.SQL().Exec(`UPDATE vpn_offers SET expires_at='2000-01-01T00:00:00Z'`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "device unenrolled since the offer", cn: "alice", prepare: func(t *testing.T, f *fixture, _ *vpn.Service) {
			r := mdm.NewRequestWithContext(context.Background(), nil)
			r.EnrollID = &mdm.EnrollID{ID: "PHONE1"}
			if err := f.db.NanoStorage(nil).Disable(r); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, svc, serverID := deviceKeyFixture(t)
			if _, err := svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
				t.Fatal(err)
			}
			challenge := offeredChallenge(t, f.device(t, "PHONE1", ""))
			if c.wrong {
				challenge = "not-a-challenge-anyone-was-given"
			}
			if c.prepare != nil {
				c.prepare(t, f, svc)
			}
			if leaf, err := svc.SignCSRContext(ctx, deviceRequest(t, c.cn, challenge)); err == nil {
				t.Fatalf("certificate issued for %q", leaf.Subject.CommonName)
			}
			if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 0 {
				t.Fatalf("a certificate request was recorded: %+v", rows)
			}
		})
	}
}

func TestDeviceRequestCannotAddNames(t *testing.T) {
	ctx := context.Background()
	f, svc, serverID := deviceKeyFixture(t)
	if _, err := svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
		t.Fatal(err)
	}
	challenge := offeredChallenge(t, f.device(t, "PHONE1", ""))
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	alice := pkix.Name{CommonName: "alice"}
	// An AD user principal name as a SAN otherName, which Go's parsed request
	// fields do not show.
	upn, _ := asn1.Marshal(struct {
		OID   asn1.ObjectIdentifier
		Value string `asn1:"explicit,tag:0,utf8"`
	}{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}, "administrator@example.org"})
	otherName, _ := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: upn[2:]}})
	ca, _ := asn1.Marshal(struct {
		IsCA bool
	}{true})
	for name, extra := range map[string]x509.CertificateRequest{
		"another address": {Subject: alice, EmailAddresses: []string{"administrator@example.org"}},
		"a DNS name":      {Subject: alice, DNSNames: []string{"vpn.example.org"}},
		// Go reads the last common name, OpenSSL-based software the first.
		"two common names": {Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "administrator"}, {Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "alice"}}}},
		"an organizational unit": {Subject: pkix.Name{CommonName: "alice", OrganizationalUnit: []string{"Domain Admins"}}},
		"a principal name":       {Subject: alice, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: otherName}}},
		"CA rights":              {Subject: alice, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: ca}}},
	} {
		der, err := x509.CreateCertificateRequest(rand.Reader, &extra, key)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err = svc.SignCSRContext(ctx, &scep.CSRReqMessage{CSR: csr, ChallengePassword: challenge}); err == nil {
			t.Fatalf("a request with %s was certified", name)
		}
	}
	if rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 0 {
		t.Fatal("a refused request reached the certificate authority")
	}
	// What a device sends: the name, the owner's address, a key usage.
	usage, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{0xa0}, BitLength: 3})
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: alice, EmailAddresses: []string{"alice@example.org"},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: usage}}}, key)
	csr, _ := x509.ParseCertificateRequest(der)
	if _, err := svc.SignCSRContext(ctx, &scep.CSRReqMessage{CSR: csr, ChallengePassword: challenge}); err != nil {
		t.Fatalf("a device-shaped request was refused: %v", err)
	}
}

func TestUnansweredOfferIsWithdrawn(t *testing.T) {
	ctx := context.Background()
	f, svc, serverID := deviceKeyFixture(t)
	if _, err := svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
		t.Fatal(err)
	}
	cmd := f.device(t, "PHONE1", "")
	challenge := offeredChallenge(t, cmd)
	if _, err := f.db.SQL().Exec(`UPDATE vpn_offers SET expires_at='2000-01-01T00:00:00Z'`); err != nil {
		t.Fatal(err)
	}
	if queuedChallenge(t, f, cmd.CommandUUID) != challenge {
		t.Fatal("test cannot see the challenge in the queued profile")
	}
	svc.Sweep(ctx)
	if queuedChallenge(t, f, cmd.CommandUUID) != "" {
		t.Fatal("an expired offer's profile is still queued with its challenge")
	}
	// A new offer can then be made.
	if _, err := svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
		t.Fatalf("new offer after the old one expired: %v", err)
	}
}

// A device that reports the profile failed will not ask for its certificate,
// so the challenge stops working and a new profile can be sent.
func TestDeviceErrorClosesTheOffer(t *testing.T) {
	ctx := context.Background()
	f, svc, serverID := deviceKeyFixture(t)
	if _, err := svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
		t.Fatal(err)
	}
	challenge := offeredChallenge(t, f.device(t, "PHONE1", ""))
	cmd := f.device(t, "PHONE1", "Error")
	if queuedChallenge(t, f, cmd.CommandUUID) != "" {
		t.Fatal("the failed profile is still stored with its challenge")
	}
	if _, err := svc.SignCSRContext(ctx, deviceRequest(t, "alice", challenge)); err == nil {
		t.Fatal("the challenge works after the device reported the profile failed")
	}
	if _, err := svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
		t.Fatalf("new profile after a failed one: %v", err)
	}
}

func TestAdministratorWithdrawsAnOffer(t *testing.T) {
	ctx := context.Background()
	f, svc, serverID := deviceKeyFixture(t)
	if _, err := svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
		t.Fatal(err)
	}
	cmd := f.device(t, "PHONE1", "")
	challenge := offeredChallenge(t, cmd)
	if found, err := svc.Withdraw(ctx, "PHONE1", serverID, "nick"); err != nil || !found {
		t.Fatalf("Withdraw = %v, %v", found, err)
	}
	if queuedChallenge(t, f, cmd.CommandUUID) != "" {
		t.Fatal("the withdrawn profile is still stored with its challenge")
	}
	if _, err := svc.SignCSRContext(ctx, deviceRequest(t, "alice", challenge)); err == nil {
		t.Fatal("a withdrawn challenge still works")
	}
	if found, _ := svc.Withdraw(ctx, "PHONE1", serverID, "nick"); found {
		t.Fatal("a second withdrawal found something")
	}
	if _, err := svc.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
		t.Fatalf("new profile after a withdrawal: %v", err)
	}
}

// duringIssue runs a hook while the CA is working, to stand in for a slow CA.
type duringIssue struct {
	issue.CABackend
	hook func()
}

func (b duringIssue) Issue(ctx context.Context, req issue.IssueRequest) (issue.IssueResult, error) {
	b.hook()
	return b.CABackend.Issue(ctx, req)
}

func deviceKeyService(t *testing.T, f *fixture, backend issue.CABackend) *vpn.Service {
	t.Helper()
	svc, err := vpn.NewService(f.servers, f.db, f.dir, backend, f.cmd,
		vpn.Options{Organization: "org.example", Policy: issue.Policy{LeafValidity: 365 * 24 * time.Hour, Backdate: 5 * time.Minute},
			DeviceSCEPURL: "https://mdm.example.org/scep/vpn"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestCertificateReadyTooLateIsNotHandedOver(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(f *fixture){
		"device gave up on the profile": func(f *fixture) { f.device(t, "PHONE1", "Error") },
		"owner disabled":                func(f *fixture) { f.dir.disabled = true },
		"device re-enrolled": func(f *fixture) {
			r := mdm.NewRequestWithContext(ctx, nil)
			r.EnrollID = &mdm.EnrollID{ID: "PHONE1"}
			if err := f.db.NanoStorage(nil).Disable(r); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, first, serverID := deviceKeyFixture(t)
			if _, err := first.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
				t.Fatal(err)
			}
			cmd := f.device(t, "PHONE1", "")
			challenge := offeredChallenge(t, cmd)
			svc := deviceKeyService(t, f, duringIssue{CABackend: f.backend, hook: func() { change(f) }})
			if _, err := svc.SignCSRContext(ctx, deviceRequest(t, "alice", challenge)); err == nil {
				t.Fatal("the certificate was handed over")
			}
			rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1")
			if len(rows) != 1 || rows[0].State != sqlite.VPNIssued || rows[0].DeployStatus != "failed" || rows[0].CertSerial == "" {
				t.Fatalf("identity = %+v; want issued, not delivered, with its serial for revocation", rows)
			}
			if queuedChallenge(t, f, cmd.CommandUUID) != "" {
				t.Fatal("the profile is still stored with its challenge")
			}
		})
	}
}

func TestUntrustedCAAnswerForADeviceKeyIsHeld(t *testing.T) {
	ctx := context.Background()
	f, first, serverID := deviceKeyFixture(t)
	if _, err := first.Issue(ctx, "PHONE1", serverID, "alice", "nick"); err != nil {
		t.Fatal(err)
	}
	cmd := f.device(t, "PHONE1", "")
	challenge := offeredChallenge(t, cmd)
	svc := deviceKeyService(t, f, heldBackend{f.backend})
	req := deviceRequest(t, "alice", challenge)
	if _, err := svc.SignCSRContext(ctx, req); err == nil {
		t.Fatal("a certificate came back from a CA whose answer was lost")
	}
	rows, _ := f.db.DeviceVPNIdentities(ctx, "PHONE1")
	if len(rows) != 1 || rows[0].State != sqlite.VPNQuarantined {
		t.Fatalf("identity = %+v, want held", rows)
	}
	if queuedChallenge(t, f, cmd.CommandUUID) != "" {
		t.Fatal("the profile is still stored with its spent challenge")
	}
	// The same key asking again gets nothing and starts nothing.
	if _, err := first.SignCSRContext(ctx, req); err == nil {
		t.Fatal("a held request was answered on retry")
	}
	if rows, _ = f.db.DeviceVPNIdentities(ctx, "PHONE1"); len(rows) != 1 {
		t.Fatalf("identity rows after the retry = %d", len(rows))
	}
}
