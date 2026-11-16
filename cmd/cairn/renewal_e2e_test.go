package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	nanotest "github.com/micromdm/nanomdm/test"
	"github.com/micromdm/nanomdm/test/protocol"
	"github.com/micromdm/plist"

	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/push"
	"github.com/nickpdawson/cairn-mdm/internal/renew"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
)

// renewalCA signs device certificates for the renewal test.
type renewalCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newRenewalCA(t *testing.T, name string) renewalCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-2 * 365 * 24 * time.Hour), NotAfter: time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return renewalCA{cert: cert, key: key}
}

type deviceIdentity struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func (d deviceIdentity) hash() string {
	sum := sha256.Sum256(d.cert.Raw)
	return hex.EncodeToString(sum[:])
}

func (ca renewalCA) issue(t *testing.T, cn string, notBefore, notAfter time.Time) deviceIdentity {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return deviceIdentity{cert: cert, key: key}
}

// hostClient sends every request with a fixed Host header, the way a device
// that was enrolled under another server name does.
type hostClient struct {
	host    string
	handler http.Handler
}

func (c hostClient) Do(req *http.Request) (*http.Response, error) {
	req.Host = c.host
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// A device whose identity certificate has expired, inside the grace period,
// is given only its renewal: Cairn asks for the profile list, sends the
// enrollment profile under the identifier and server name the device already
// uses, accepts the new certificate, and only then hands over other work.
func TestExpiredDeviceIsRenewedAndNothingElse(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := sqlite.Open(ctx, t.TempDir()+"/renew-e2e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const (
		udid  = "RENEW-UDID-0001"
		topic = "com.apple.mgmt.External.renew-test"
		cn    = "C02RENEW01.devices.legacy.example"
	)
	// The server default is another push certificate's topic: the renewal
	// profile must repeat the device's own.
	if err = db.SetSetting(ctx, push.SettingTopic, "com.apple.mgmt.External.server-default"); err != nil {
		t.Fatal(err)
	}
	ca := newRenewalCA(t, "Renewal Test CA")
	otherCA := newRenewalCA(t, "Some Other CA")
	now := time.Now()
	enrolled := ca.issue(t, cn, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	expired := ca.issue(t, cn, now.Add(-120*24*time.Hour), now.Add(-10*24*time.Hour))

	nanoStore := db.NanoStorage(log)
	core := mdmcore.New(nanoStore, mdmcore.NewLogAdapter(log), db, db, log, mdmcore.Options{ExpiredGrace: 180 * 24 * time.Hour})
	core.OnIdentity(func(c *x509.Certificate, ok bool) { _ = db.ObserveIdentityCertificate(ctx, c, ok) })
	commander := mdmcore.NewCommander(nanoStore, vpnE2EPush{}).WithRecorder(db, log)
	renewals, err := renew.New(db, commander, renew.Options{
		RenewBefore:  60 * 24 * time.Hour,
		ExpiredGrace: 180 * 24 * time.Hour,
		ServerURL:    "https://cairn.example.org/mdm",
		Hosts:        []string{"mdm.legacy.example"},
		Anchors:      []*x509.Certificate{ca.cert},
		Profile:      externalRenewalProfile("cairn.cairn.example.org", [][]byte{ca.cert.Raw}, "https://ca.example.org/scep/mdm", "challenge", nil),
		ManualOnly:   true,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	core.OnLifecycle(renewals)

	current := enrolled
	transport := protocol.NewTransport(protocol.WithSignMessage(),
		protocol.WithIdentityProvider(func(context.Context) (*x509.Certificate, crypto.PrivateKey, error) {
			return current.cert, current.key, nil
		}),
		protocol.WithMDMURLs("https://mdm.legacy.example/mdm", ""),
		protocol.WithClient(hostClient{host: "mdm.legacy.example", handler: core.Handler()}))

	checkIn := func(msg any) int {
		t.Helper()
		body, _ := nanotest.PlistReader(msg)
		resp, err := transport.DoCheckIn(ctx, body)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// report sends a command result and returns the next command, if any.
	report := func(status, commandUUID string, extra map[string]any) (int, map[string]any) {
		t.Helper()
		m := map[string]any{"UDID": udid, "Status": status}
		if commandUUID != "" {
			m["CommandUUID"] = commandUUID
		}
		for k, v := range extra {
			m[k] = v
		}
		raw, err := plist.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := transport.DoReportResultsAndFetchNext(ctx, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || len(bytes.TrimSpace(out)) == 0 {
			return resp.StatusCode, nil
		}
		var cmd map[string]any
		if err := plist.Unmarshal(out, &cmd); err != nil {
			t.Fatalf("command plist: %v", err)
		}
		return resp.StatusCode, cmd
	}
	requestType := func(cmd map[string]any) string {
		inner, _ := cmd["Command"].(map[string]any)
		rt, _ := inner["RequestType"].(string)
		return rt
	}
	tokenUpdate := &mdm.TokenUpdate{Enrollment: mdm.Enrollment{UDID: udid}, MessageType: mdm.MessageType{MessageType: "TokenUpdate"}, Push: mdm.Push{Topic: topic, PushMagic: "magic", Token: []byte("push-token")}}

	if code := checkIn(&mdm.Authenticate{Enrollment: mdm.Enrollment{UDID: udid}, MessageType: mdm.MessageType{MessageType: "Authenticate"}, Topic: topic, SerialNumber: "C02RENEW01"}); code != 200 {
		t.Fatalf("authenticate %d", code)
	}
	if code := checkIn(tokenUpdate); code != 200 {
		t.Fatalf("token update %d", code)
	}
	// Stand in for a device enrolled months ago: the only certificate on record
	// for it is one that has since expired.
	if _, err = db.SQL().ExecContext(ctx, `DELETE FROM cert_auth WHERE enrollment_id=?`, udid); err != nil {
		t.Fatal(err)
	}
	if _, err = db.SQL().ExecContext(ctx, `INSERT INTO cert_auth(enrollment_id, sha256) VALUES(?,?)`, udid, expired.hash()); err != nil {
		t.Fatal(err)
	}
	current = expired

	// Ordinary work is waiting for the device.
	if err = commander.SendDeviceInformation(ctx, udid); err != nil {
		t.Fatal(err)
	}
	if code, cmd := report("Idle", "", nil); code != 200 || cmd != nil {
		t.Fatalf("an expired device was given a command: %d %v", code, cmd)
	}
	// An expired certificate cannot enroll, and trying leaves nothing behind
	// that would let it update the device's push token afterwards.
	stranger := ca.issue(t, "STRANGER.devices.legacy.example", now.Add(-120*24*time.Hour), now.Add(-10*24*time.Hour))
	current = stranger
	if code := checkIn(&mdm.Authenticate{Enrollment: mdm.Enrollment{UDID: udid}, MessageType: mdm.MessageType{MessageType: "Authenticate"}, Topic: topic}); code != 403 {
		t.Fatalf("authenticate with an expired certificate = %d, want 403", code)
	}
	if code := checkIn(tokenUpdate); code == 200 {
		t.Fatal("an expired certificate that tried to enroll can now update the push token")
	}
	current = expired

	if err = renewals.Renew(ctx, udid, "tester"); err != nil {
		t.Fatal(err)
	}
	if err = renewals.Renew(ctx, udid, "tester"); err == nil {
		t.Fatal("a second renewal started while one was open")
	}
	code, cmd := report("Idle", "", nil)
	if code != 200 || requestType(cmd) != "ProfileList" {
		t.Fatalf("want the profile lookup first, got %d %q", code, requestType(cmd))
	}
	lookupUUID, _ := cmd["CommandUUID"].(string)
	profileList := []any{
		map[string]any{"PayloadIdentifier": "org.example.wifi", "PayloadDisplayName": "Wi-Fi",
			"PayloadContent": []any{map[string]any{"PayloadType": "com.apple.wifi.managed"}}},
		map[string]any{"PayloadIdentifier": "net.legacy.ota.minimal", "PayloadDisplayName": "Legacy Enrollment", "PayloadOrganization": "Legacy Org",
			"PayloadContent": []any{map[string]any{"PayloadType": "com.apple.security.scep"}, map[string]any{"PayloadType": "com.apple.mdm"}}},
	}
	if code, cmd = report("Acknowledged", lookupUUID, map[string]any{"ProfileList": profileList}); code != 200 || cmd != nil {
		t.Fatalf("after the lookup answer: %d %q", code, requestType(cmd))
	}
	code, cmd = report("Idle", "", nil)
	if code != 200 || requestType(cmd) != "InstallProfile" {
		t.Fatalf("want the enrollment profile, got %d %q", code, requestType(cmd))
	}
	installUUID, _ := cmd["CommandUUID"].(string)
	payload, _ := cmd["Command"].(map[string]any)["Payload"].([]byte)
	var prof map[string]any
	if err = plist.Unmarshal(payload, &prof); err != nil {
		t.Fatalf("enrollment profile: %v", err)
	}
	if prof["PayloadIdentifier"] != "net.legacy.ota.minimal" || prof["PayloadDisplayName"] != "Legacy Enrollment" || prof["PayloadOrganization"] != "Legacy Org" {
		t.Fatalf("profile does not replace the installed one: %v / %v / %v", prof["PayloadIdentifier"], prof["PayloadDisplayName"], prof["PayloadOrganization"])
	}
	var sawSCEP, sawMDM bool
	for _, p := range prof["PayloadContent"].([]any) {
		pm := p.(map[string]any)
		switch pm["PayloadType"] {
		case "com.apple.mdm":
			sawMDM = true
			if pm["ServerURL"] != "https://mdm.legacy.example/mdm" || pm["CheckInURL"] != "https://mdm.legacy.example/mdm" || pm["Topic"] != topic {
				t.Fatalf("management payload points elsewhere: %v %v %v", pm["ServerURL"], pm["CheckInURL"], pm["Topic"])
			}
		case "com.apple.security.scep":
			sawSCEP = true
			content := pm["PayloadContent"].(map[string]any)
			subject := content["Subject"].([]any)[0].([]any)[0].([]any)
			if subject[1] != cn || content["URL"] != "https://ca.example.org/scep/mdm" {
				t.Fatalf("certificate request: subject %v url %v", subject, content["URL"])
			}
		}
	}
	if !sawSCEP || !sawMDM {
		t.Fatal("enrollment profile lacks its SCEP or management payload")
	}
	if code, cmd = report("Acknowledged", installUUID, nil); code != 200 || cmd != nil {
		t.Fatalf("after installing: %d %q", code, requestType(cmd))
	}
	if last, _, _ := db.LastRenewal(ctx, udid); last.State != "installed" || last.ProfileIdentifier != "net.legacy.ota.minimal" {
		t.Fatalf("renewal after install: %+v", last)
	}

	// Certificates that must not be taken for the renewed one.
	current = otherCA.issue(t, cn, now.Add(-time.Minute), now.Add(365*24*time.Hour))
	if code := checkIn(tokenUpdate); code == 200 {
		t.Fatal("a certificate from another CA was accepted")
	}
	current = ca.issue(t, "SOMEONE-ELSE.devices.legacy.example", now.Add(-time.Minute), now.Add(365*24*time.Hour))
	if code := checkIn(tokenUpdate); code == 200 {
		t.Fatal("a certificate with another device's name was accepted")
	}
	if last, _, _ := db.LastRenewal(ctx, udid); last.State != "installed" || !strings.Contains(last.Error, "was not accepted") {
		t.Fatalf("a refused certificate should be noted on the open renewal: %+v", last)
	}

	// The device switches to its new certificate.
	renewed := ca.issue(t, cn, now.Add(-time.Minute), now.Add(365*24*time.Hour))
	current = renewed
	if code := checkIn(tokenUpdate); code != 200 {
		t.Fatalf("token update with the renewed certificate = %d", code)
	}
	last, _, _ := db.LastRenewal(ctx, udid)
	if last.State != "renewed" || last.NewSHA256 != renewed.hash() || last.Error != "" {
		t.Fatalf("renewal not completed: %+v", last)
	}
	// Back in good standing: the waiting work is delivered.
	if code, cmd = report("Idle", "", nil); code != 200 || requestType(cmd) != "DeviceInformation" {
		t.Fatalf("after renewal want the queued DeviceInformation, got %d %q", code, requestType(cmd))
	}
	candidate, ok, err := db.RenewalCandidate(ctx, udid)
	if err != nil || !ok || candidate.SHA256 != renewed.hash() || candidate.CheckInHost != "mdm.legacy.example" {
		t.Fatalf("current certificate after renewal: %+v %v %v", candidate, ok, err)
	}
	if st := renewals.Status(candidate); st.Due || st.Expired || st.Blocked != "" {
		t.Fatalf("renewed device still due: %+v", st)
	}

	// The replaced certificate keeps working for a day, then stops.
	current = expired
	if code, _ := report("Idle", "", nil); code != 200 {
		t.Fatalf("replaced certificate refused before its day is up: %d", code)
	}
	if n, err := db.RetireRenewedCertificates(ctx, time.Now().Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("retire: %d %v", n, err)
	}
	if code, _ := report("Idle", "", nil); code == 200 {
		t.Fatal("replaced certificate still accepted after it was retired")
	}
	current = renewed
	if code, _ := report("Idle", "", nil); code != 200 {
		t.Fatalf("renewed certificate refused: %d", code)
	}
}

// With no grace period an expired certificate is refused outright, whether or
// not the device states a signing time. Macs state none, and the signature
// library alone would let them through.
func TestExpiredCertificateIsRefusedWithoutGrace(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := sqlite.Open(ctx, t.TempDir()+"/expired.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ca := newRenewalCA(t, "Expiry Test CA")
	now := time.Now()
	current := ca.issue(t, "MAC.devices.example", now.Add(-time.Hour), now.Add(time.Hour))
	core := mdmcore.New(db.NanoStorage(log), mdmcore.NewLogAdapter(log), db, db, log)
	transport := protocol.NewTransport(protocol.WithSignMessage(),
		protocol.WithIdentityProvider(func(context.Context) (*x509.Certificate, crypto.PrivateKey, error) {
			return current.cert, current.key, nil
		}),
		protocol.WithMDMURLs("https://cairn.example.org/mdm", ""),
		protocol.WithClient(hostClient{host: "cairn.example.org", handler: core.Handler()}))
	send := func() int {
		body, _ := nanotest.PlistReader(&mdm.Authenticate{Enrollment: mdm.Enrollment{UDID: "MAC-UDID"}, MessageType: mdm.MessageType{MessageType: "Authenticate"}, Topic: "com.apple.mgmt.External.x"})
		resp, err := transport.DoCheckIn(ctx, body)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := send(); code != 200 {
		t.Fatalf("valid certificate: %d", code)
	}
	current = ca.issue(t, "MAC.devices.example", now.Add(-100*24*time.Hour), now.Add(-24*time.Hour))
	if code := send(); code != 400 {
		t.Fatalf("expired certificate with no grace = %d, want 400", code)
	}
}
