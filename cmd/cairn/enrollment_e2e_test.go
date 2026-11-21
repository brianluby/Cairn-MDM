package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	kitlog "github.com/go-kit/kit/log"
	"github.com/micromdm/nanomdm/mdm"
	nanotest "github.com/micromdm/nanomdm/test"
	"github.com/micromdm/nanomdm/test/protocol"
	"github.com/micromdm/plist"
	scepclient "github.com/micromdm/scep/v2/client"
	scep "github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"

	"github.com/nickpdawson/cairn-mdm/internal/assign"
	"github.com/nickpdawson/cairn-mdm/internal/auth"
	"github.com/nickpdawson/cairn-mdm/internal/ca"
	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/push"
	"github.com/nickpdawson/cairn-mdm/internal/server"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/targeting"
	"github.com/nickpdawson/cairn-mdm/internal/web"
)

// e2eDirectory stands in for Samba AD: one eligible owner who belongs to the
// Lynchburg scope. It serves the console (ResolveOwner/ResolveScope/
// EvaluateScopes), the issuance boundary (RevalidateOwner) and targeting.
type e2eDirectory struct {
	owner    directory.DirectoryIdentity
	scope    directory.DirectoryScope
	disabled bool
}

func (d *e2eDirectory) ResolveOwner(context.Context, string) (*directory.DirectoryIdentity, error) {
	if d.disabled {
		return nil, errors.New("owner disabled")
	}
	o := d.owner
	return &o, nil
}
func (d *e2eDirectory) ResolveScope(context.Context, string, string, string) (*directory.DirectoryScope, error) {
	s := d.scope
	return &s, nil
}
func (d *e2eDirectory) EvaluateScopes(_ context.Context, owner directory.DirectoryIdentity, scopes []directory.DirectoryScope) (*directory.DirectoryScopeEvaluation, error) {
	if d.disabled || owner.ObjectID != d.owner.ObjectID {
		return nil, errors.New("owner ineligible")
	}
	out := &directory.DirectoryScopeEvaluation{Owner: d.owner, CheckedAt: time.Now()}
	for _, s := range scopes {
		out.Matches = append(out.Matches, directory.DirectoryScopeMatch{Scope: s, Matches: s.ObjectID == d.scope.ObjectID})
	}
	return out, nil
}
func (d *e2eDirectory) RevalidateOwner(_ context.Context, owner directory.DirectoryIdentity) (*directory.DirectoryIdentity, error) {
	if d.disabled || owner.ObjectID != d.owner.ObjectID {
		return nil, errors.New("owner ineligible")
	}
	o := d.owner
	return &o, nil
}

// TestOwnerAuthorizedEnrollmentEndToEnd drives the administrator-assisted
// enrollment path over HTTP exactly as the console, a Mac and the embedded CA
// would see it: fresh-MFA admin previews the owner and creates a link; the
// device opens the link, downloads the profile, performs SCEP with the profile's
// challenge and receives a certificate reconstructed from the grant; it then
// authenticates to MDM with that certificate, gets bound to the owner, picks up
// the directory rule's group and is queued the group's profile. Only the
// directory and APNs are faked.
func TestOwnerAuthorizedEnrollmentEndToEnd(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := sqlite.Open(ctx, t.TempDir()+"/e2e.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A 2048-bit CA keeps the test fast; wirePKI reloads the persisted CA.
	if _, err = ca.Ensure(ctx, db.SQL(), ca.Options{CommonName: "Cairn E2E CA", Organization: "Cairn", KeyBits: 2048}); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewUnstartedServer(nil)
	cfg := config.Default()
	cfg.Server.PublicURL = "http://" + ts.Listener.Addr().String()
	cfg.Storage.Path = t.TempDir() + "/unused.db"

	owner := directory.DirectoryIdentity{DirectoryID: "dzsec", ObjectID: strings.Repeat("a", 32), UPN: "lynch.user@example.org", AccountName: "lynch.user"}
	dir := &e2eDirectory{owner: owner, scope: directory.DirectoryScope{DirectoryID: "dzsec", ObjectID: strings.Repeat("b", 32), Kind: "group", Mode: "nested", Name: "Lynchburg Users", DN: "CN=Lynchburg Users,DC=example,DC=org"}}

	nanoStore := db.NanoStorage(log)
	core := mdmcore.New(nanoStore, mdmcore.NewLogAdapter(log), db, db, log)
	deps := server.Deps{MDM: core.Handler()}
	resolver := grantResolver{db: db, directory: dir}
	pki, err := wirePKI(ctx, cfg, db, db, resolver, log, &deps)
	if err != nil {
		t.Fatal(err)
	}
	if err = trustIdentityIssuers(core, pki.Anchors, nil, log); err != nil {
		t.Fatal(err)
	}
	pusher := push.NewPusher(nanoStore, mdmcore.NewLogAdapter(log))
	commander := mdmcore.NewCommander(nanoStore, pusher).WithRecorder(db, log)
	reconciler := assign.New(db, commander, log)
	targeter := targeting.New(db, dir, reconciler, log)
	core.OnPushable(targeter.DeviceNowPushable)

	sessions := auth.NewSessionStore(db.SQL(), time.Hour)
	local := auth.NewLocalStore(db.SQL())
	if err = local.CreateUser(ctx, "nick", "hunter2hunter2", auth.RoleAdmin, "Nick"); err != nil {
		t.Fatal(err)
	}
	console, err := web.New(sessions, local, db, commander, reconciler, web.Config{
		PublicURL: cfg.Server.PublicURL, OwnerEnrollment: true, Organization: pki.Org, SCEPURL: pki.SCEPURL, CAAnchorsDER: pki.Anchors,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	console.SetDirectory(dir)
	mfa, err := auth.NewMFAStore(db.SQL(), sessions, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	console.SetMFA(mfa)
	console.SetTargeting(targeter)
	deps.UI = console
	ts.Config.Handler = server.New(cfg, log, db, deps).Handler()
	ts.Start()
	defer ts.Close()

	const topic = "com.apple.mgmt.External.e2e-topic"
	if err = db.SetSetting(ctx, push.SettingTopic, topic); err != nil {
		t.Fatal(err)
	}
	group, err := db.CreateGroup(ctx, "Lynchburg", "")
	if err != nil {
		t.Fatal(err)
	}
	wifi, err := db.SaveProfile(ctx, sqlite.Profile{Identifier: "net.example.lynchburg.wifi", UUID: "wifi", Name: "Lynchburg Wi-Fi", Data: []byte("<plist/>")})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AssignProfile(ctx, group, wifi); err != nil {
		t.Fatal(err)
	}
	if err = db.SaveDirectoryProfileRule(ctx, group, dir.scope, "nick", "local"); err != nil {
		t.Fatal(err)
	}

	// Administrator session with a confirmed factor verified moments ago.
	id, err := local.Authenticate(ctx, "nick", "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ctx, *id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.SQL().Exec(`INSERT INTO mfa_factors(principal,secret) VALUES(?,?)`, "local:"+id.SubjectID, []byte("seeded")); err != nil {
		t.Fatal(err)
	}
	if _, err = db.SQL().Exec(`UPDATE app_sessions SET mfa_verified_at=?`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	client := ts.Client()
	adminPost := func(path string, form url.Values) (*http.Response, string) {
		form.Set("csrf", sess.CSRF)
		req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: web.SessionCookie, Value: sess.Token})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(body)
	}
	createLink := func() string {
		resp, body := adminPost("/admin/enrollment/preview", url.Values{"label": {"Lynchburg Mac"}, "owner": {"lynch.user"}, "platform": {"macos"}, "expires_hours": {"2"}})
		if resp.StatusCode != 200 || !strings.Contains(body, "Lynchburg Wi-Fi") || !strings.Contains(body, "Lynchburg Users: matches") {
			t.Fatalf("preview %d %s", resp.StatusCode, body)
		}
		preview := regexp.MustCompile(`name="preview" value="([a-f0-9]+)"`).FindStringSubmatch(body)
		if len(preview) != 2 {
			t.Fatal("no confirmation token")
		}
		resp, body = adminPost("/admin/enrollment", url.Values{"preview": {preview[1]}})
		if resp.StatusCode != 200 {
			t.Fatalf("create %d %s", resp.StatusCode, body)
		}
		link := regexp.MustCompile(`value="(http://[^"]+/e/[a-f0-9]{64})"`).FindStringSubmatch(body)
		if len(link) != 2 {
			t.Fatalf("no link in %s", body)
		}
		return link[1]
	}
	link := createLink()
	token := link[strings.LastIndex(link, "/")+1:]

	// The remote user opens the link (instructions only) and then downloads.
	resp, err := client.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(page), "Download enrollment profile") {
		t.Fatalf("invitation %d %s", resp.StatusCode, page)
	}
	if g, _ := db.ListGrants(ctx); len(g) != 1 || g[0].UseCount != 0 {
		t.Fatal("viewing the invitation consumed it")
	}
	resp, err = client.Post(link, "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	profileXML, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-apple-aspen-config" {
		t.Fatalf("profile download %d %s", resp.StatusCode, profileXML)
	}
	var prof struct {
		PayloadContent []map[string]any
	}
	if err = plist.Unmarshal(profileXML, &prof); err != nil {
		t.Fatal(err)
	}
	var scepURL, challenge, mdmTopic, serverURL string
	for _, p := range prof.PayloadContent {
		switch p["PayloadType"] {
		case "com.apple.security.scep":
			content := p["PayloadContent"].(map[string]any)
			scepURL, _ = content["URL"].(string)
			challenge, _ = content["Challenge"].(string)
		case "com.apple.mdm":
			mdmTopic, _ = p["Topic"].(string)
			serverURL, _ = p["ServerURL"].(string)
		}
	}
	if challenge != token || scepURL != cfg.Server.PublicURL+"/scep" || mdmTopic != topic || serverURL != cfg.Server.PublicURL+"/mdm" {
		t.Fatalf("profile wiring: scep=%q challenge-matches=%v topic=%q server=%q", scepURL, challenge == token, mdmTopic, serverURL)
	}
	if resp, _ = client.Post(link, "application/x-www-form-urlencoded", nil); resp.StatusCode != http.StatusGone {
		t.Fatalf("second download %d", resp.StatusCode)
	}
	resp.Body.Close()

	// The device performs SCEP with a hostile CSR; Cairn reconstructs the identity.
	leaf, caCerts := scepEnroll(t, ctx, scepURL, challenge, pkix.Name{CommonName: "attacker-chosen", Organization: []string{"Mallory"}}, []string{"evil.example"})
	if leaf == nil {
		t.Fatal("no certificate issued")
	}
	if leaf.Subject.CommonName != owner.UPN || len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != owner.UPN || len(leaf.DNSNames) != 0 || leaf.Subject.Organization != nil {
		t.Fatalf("leaf not reconstructed from the grant: %+v", leaf.Subject)
	}
	roots := x509.NewCertPool()
	for _, c := range caCerts {
		roots.AddCert(c)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("leaf does not chain to the embedded CA: %v", err)
	}
	grants, _ := db.ListGrants(ctx)
	iss, err := db.GetIssuance(ctx, grants[0].ID)
	if err != nil || iss.State != sqlite.IssuanceIssued || iss.CertSerial != leaf.SerialNumber.Text(16) {
		t.Fatalf("issuance %+v %v", iss, err)
	}
	var recorded string
	if err = db.SQL().QueryRow(`SELECT leaf_sha256 FROM cert_issuance WHERE grant_id=?`, grants[0].ID).Scan(&recorded); err != nil || recorded != sqlite.LeafHash(leaf.Raw) {
		t.Fatalf("leaf hash %q %v", recorded, err)
	}
	// A second key presenting the same challenge cannot obtain a second certificate.
	if second, _ := scepEnrollResult(t, ctx, scepURL, challenge); second != nil {
		t.Fatal("grant issued twice")
	}

	// The device enrolls in MDM with the issued identity and becomes pushable.
	devKey := enrolledKey
	transport := protocol.NewTransport(protocol.WithSignMessage(), protocol.WithIdentityProvider(func(context.Context) (*x509.Certificate, crypto.PrivateKey, error) {
		return leaf, devKey, nil
	}), protocol.WithMDMURLs(serverURL, ""), protocol.WithClient(client))
	const udid = "E2E-UDID-0001"
	authenticate, _ := nanotest.PlistReader(&mdm.Authenticate{Enrollment: mdm.Enrollment{UDID: udid}, MessageType: mdm.MessageType{MessageType: "Authenticate"}, Topic: topic, SerialNumber: "C02E2E0001"})
	if resp, err = transport.DoCheckIn(ctx, authenticate); err != nil || resp.StatusCode != 200 {
		t.Fatalf("authenticate %v %v", err, resp)
	}
	resp.Body.Close()
	tokenUpdate, _ := nanotest.PlistReader(&mdm.TokenUpdate{Enrollment: mdm.Enrollment{UDID: udid}, MessageType: mdm.MessageType{MessageType: "TokenUpdate"}, Push: mdm.Push{Topic: topic, PushMagic: "magic", Token: []byte("push-token")}})
	if resp, err = transport.DoCheckIn(ctx, tokenUpdate); err != nil || resp.StatusCode != 200 {
		t.Fatalf("token update %v %v", err, resp)
	}
	resp.Body.Close()

	// Owner binding, rule application and the InstallProfile queue happen off the
	// check-in path; wait for the deploy row.
	var deploys []sqlite.DeviceDeploy
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if deploys, _ = db.DeviceDeploys(ctx, udid); len(deploys) == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(deploys) != 1 || deploys[0].ProfileID != wifi || deploys[0].Status != "sent" {
		t.Fatalf("profile not queued for the owned device: %+v", deploys)
	}
	bound, err := db.GetDeviceOwner(ctx, udid)
	if err != nil || bound.GrantID != grants[0].ID || bound.Owner != owner {
		t.Fatalf("owner %+v %v", bound, err)
	}
	memberships, _ := db.DeviceDirectoryMemberships(ctx, udid)
	if len(memberships) != 1 || memberships[0].GroupID != group {
		t.Fatalf("memberships %+v", memberships)
	}
	commands, _ := db.ListCommands(ctx, udid, 10)
	if len(commands) != 1 || commands[0].RequestType != "InstallProfile" {
		t.Fatalf("history %+v", commands)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/admin/devices/"+udid, nil)
	req.AddCookie(&http.Cookie{Name: web.SessionCookie, Value: sess.Token})
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	devicePage, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(devicePage), owner.UPN) || !strings.Contains(string(devicePage), "via group Lynchburg Users (nested)") || !strings.Contains(string(devicePage), "Lynchburg Wi-Fi") {
		t.Fatalf("device page %d %s", resp.StatusCode, devicePage)
	}

	// A second link whose owner is disabled before the device opens it is refused
	// without being spent.
	link2 := createLink()
	dir.disabled = true
	if resp, _ = client.Post(link2, "application/x-www-form-urlencoded", nil); resp.StatusCode != http.StatusGone {
		t.Fatalf("disabled owner downloaded profile: %d", resp.StatusCode)
	}
	resp.Body.Close()
	grants, _ = db.ListGrants(ctx)
	for _, g := range grants {
		if g.Status() == "active" && g.UseCount != 0 {
			t.Fatal("rejected redemption consumed the link")
		}
	}
	if _, err = scepEnrollResult(t, ctx, scepURL, link2[strings.LastIndex(link2, "/")+1:]); err == nil {
		t.Fatal("disabled owner obtained a certificate")
	}
}

// enrolledKey is the device key of the last successful scepEnroll, so the MDM
// transport can sign with the issued identity.
var enrolledKey *rsa.PrivateKey

// scepEnroll runs a full SCEP PKCSReq against url with the given CSR subject and
// challenge and returns the issued leaf plus the CA certificates.
func scepEnroll(t *testing.T, ctx context.Context, url, challenge string, subject pkix.Name, dns []string) (*x509.Certificate, []*x509.Certificate) {
	t.Helper()
	leaf, cas, err := scepRoundTrip(ctx, url, challenge, subject, dns)
	if err != nil {
		t.Fatalf("scep: %v", err)
	}
	return leaf, cas
}

// scepEnrollResult is scepEnroll without failing the test: it returns the leaf (nil
// when the server refused) and the error.
func scepEnrollResult(t *testing.T, ctx context.Context, url, challenge string) (*x509.Certificate, error) {
	t.Helper()
	leaf, _, err := scepRoundTrip(ctx, url, challenge, pkix.Name{CommonName: "retry"}, nil)
	return leaf, err
}

func scepRoundTrip(ctx context.Context, url, challenge string, subject pkix.Name, dns []string) (*x509.Certificate, []*x509.Certificate, error) {
	cl, err := scepclient.New(url, kitlog.NewNopLogger())
	if err != nil {
		return nil, nil, err
	}
	caBytes, num, err := cl.GetCACert(ctx, "")
	if err != nil {
		return nil, nil, err
	}
	var cas []*x509.Certificate
	if num > 1 {
		if cas, err = scep.CACerts(caBytes); err != nil {
			return nil, nil, err
		}
	} else {
		c, err := x509.ParseCertificate(caBytes)
		if err != nil {
			return nil, nil, err
		}
		cas = []*x509.Certificate{c}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{Subject: subject, DNSNames: dns, SignatureAlgorithm: x509.SHA256WithRSA},
		ChallengePassword:  challenge,
	}, key)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}
	// Apple devices sign the SCEP envelope with a temporary self-signed identity.
	selfTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: subject, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	selfDER, err := x509.CreateCertificate(rand.Reader, selfTmpl, selfTmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	self, _ := x509.ParseCertificate(selfDER)
	msg, err := scep.NewCSRRequest(csr, &scep.PKIMessage{MessageType: scep.PKCSReq, Recipients: cas, SignerKey: key, SignerCert: self})
	if err != nil {
		return nil, nil, err
	}
	respBytes, err := cl.PKIOperation(ctx, msg.Raw)
	if err != nil {
		return nil, cas, err
	}
	reply, err := scep.ParsePKIMessage(respBytes, scep.WithCACerts(cas))
	if err != nil {
		return nil, cas, err
	}
	if reply.PKIStatus != scep.SUCCESS {
		return nil, cas, fmt.Errorf("scep reply status %v failInfo %v", reply.PKIStatus, reply.FailInfo)
	}
	if err = reply.DecryptPKIEnvelope(self, key); err != nil {
		return nil, cas, err
	}
	enrolledKey = key
	return reply.CertRepMessage.Certificate, cas, nil
}
