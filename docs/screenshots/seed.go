//go:build ignore

// seed fills an empty Cairn database with a made-up fleet for the screenshots
// in the README. Every name, serial and address in it is invented. Run it once
// against a database made by `cairn init`, never against a real one:
//
//	go run docs/screenshots/seed.go -db /tmp/cairn-demo/cairn.db
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/directory"
	"github.com/nickpdawson/cairn-mdm/internal/keyfile"
	"github.com/nickpdawson/cairn-mdm/internal/mdmcore"
	"github.com/nickpdawson/cairn-mdm/internal/storage/sqlite"
	"github.com/nickpdawson/cairn-mdm/internal/vpn"
)

const (
	org   = "Example Org"
	topic = "com.apple.mgmt.External.6f1d2c34-8a5b-4e7f-9c10-2b3a4d5e6f70"
	admin = "admin"
	dirID = "example-ad"
)

type person struct{ account, object string }

func (p person) identity() directory.DirectoryIdentity {
	return directory.DirectoryIdentity{DirectoryID: dirID, ObjectID: p.object, UPN: p.account + "@example.org", AccountName: p.account}
}

type device struct {
	id, serial, name, model, product, os, build string
	owner                                       person
	capacity, battery                           string
	seenMinutesAgo, enrolledDaysAgo             int
	checkedOut                                  bool
}

var (
	mchen  = person{"mchen", "5c1e0b7a9d2f4e3a8b6c7d8e9f0a1b2c"}
	sortiz = person{"sortiz", "a2b3c4d5e6f708192a3b4c5d6e7f8091"}
	pnair  = person{"pnair", "0f1e2d3c4b5a69788796a5b4c3d2e1f0"}
	tbeck  = person{"tbecker", "7a8b9c0d1e2f30415263748596a7b8c9"}
)

var fleet = []device{
	{"7C2E5B1A-3F4D-5A6B-8C9D-0E1F2A3B4C5D", "FVX2K9Q4LM", "Maya's MacBook Air", "MacBook Air", "Mac15,12", "27.1", "27B74", mchen, "182 GB", "", 4, 143, false},
	{"00008140-001A2B3C4D5E6F70", "G7TQ4W2N9P", "Maya's iPhone", "iPhone", "iPhone17,1", "27.1", "24B83", mchen, "96 GB", "81%", 11, 143, false},
	{"00008130-000C1D2E3F4A5B6C", "H2LM8R5K3J", "Sam's iPhone", "iPhone", "iPhone16,1", "27.1", "24B83", sortiz, "41 GB", "64%", 38, 96, false},
	{"00008112-0019283746556473", "K9PD3V7X2C", "Priya's iPad", "iPad", "iPad14,3", "27.0.1", "24A348", pnair, "58 GB", "100%", 95, 61, false},
	{"A91F4C7D-2B3E-5C6D-9E8F-1A2B3C4D5E6F", "C02F8J4YQ6", "Tom's MacBook Pro", "MacBook Pro", "Mac15,6", "27.1", "27B74", tbeck, "411 GB", "", 2, 208, false},
	{"3B6D9F2A-7C8E-5D1F-A2B3-C4D5E6F7A8B9", "D5RW2M6TN8", "Workshop Mac mini", "Mac mini", "Mac16,10", "27.0", "27A312", tbeck, "203 GB", "", 60 * 26, 208, false},
	{"E4A7C1D8-9B2F-5E3A-B4C5-D6E7F8A9B0C1", "F9KX3P7VB2", "Front desk iMac", "iMac", "Mac15,5", "26.4", "25E246", sortiz, "", "", 60 * 24 * 40, 310, true},
}

func main() {
	dbPath := flag.String("db", "", "database made by `cairn init`")
	flag.Parse()
	if *dbPath == "" {
		log.Fatal("-db is required")
	}
	ctx := context.Background()
	db, err := sqlite.OpenExisting(ctx, *dbPath)
	must(err)
	defer db.Close()
	if n, _, _ := db.DeviceCounts(ctx); n != 0 {
		log.Fatal("database already has devices; seed only an empty demo database")
	}
	raw := db.SQL()
	exec := func(q string, args ...any) {
		_, err := raw.ExecContext(ctx, q, args...)
		must(err)
	}

	must(db.UpsertAPNSTopic(ctx, topic, time.Now().AddDate(0, 9, 12).UTC().Format(time.RFC3339),
		"UID="+topic+",CN=APSP:6f1d2c34-8a5b-4e7f-9c10-2b3a4d5e6f70,C=US", admin))

	caPEM, caCert, caKey := demoCA()

	staff, err := db.CreateGroup(ctx, "Staff", "Everyone's own Mac, iPhone or iPad")
	must(err)
	shared, err := db.CreateGroup(ctx, "Shared Macs", "Front desk and workshop")
	must(err)

	profiles := []sqlite.Profile{
		{Identifier: "org.example.trust.root", UUID: "0B6C2E0E-51C8-4E0C-9B0A-0D6E3A5B7C11", Name: "Example Org root certificate", Organization: org, PayloadTypes: "com.apple.security.root", Source: "upload"},
		{Identifier: "org.example.wifi.guest", UUID: "7D2F8A44-9C1B-4B6E-8F3A-5E4D3C2B1A90", Name: "Example Guest Wi-Fi", Organization: org, PayloadTypes: "com.apple.wifi.managed", Source: "builder:wifi"},
		{Identifier: "org.example.sso.kerberos", UUID: "C3A1F5B2-6D4E-4A7C-B8E9-1F0A2B3C4D5E", Name: "Single sign-on (Kerberos)", Organization: org, PayloadTypes: "com.apple.extensiblesso", Source: "builder:kerberos-sso"},
		{Identifier: "org.example.restrictions.shared", UUID: "E5F6A7B8-C9D0-4E1F-A2B3-C4D5E6F7A8B9", Name: "Shared Mac restrictions", Organization: org, PayloadTypes: "com.apple.applicationaccess,com.apple.loginwindow", Source: "upload"},
	}
	ids := make([]int64, len(profiles))
	for i, p := range profiles {
		p.Data = []byte(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>PayloadIdentifier</key><string>` + p.Identifier + `</string></dict></plist>`)
		ids[i], err = db.SaveProfile(ctx, p)
		must(err)
	}
	for _, pid := range ids[:3] {
		must(db.AssignProfile(ctx, staff, pid))
	}
	must(db.AssignProfile(ctx, shared, ids[0]))
	must(db.AssignProfile(ctx, shared, ids[3]))

	key, err := keyfile.Open(*dbPath+".vpn", "VPN", func() (bool, error) { return false, nil })
	must(err)
	servers, err := vpn.NewServers(db, key)
	must(err)
	ikev2, err := servers.Create(ctx, vpn.Server{
		Name: "Example Org VPN", Slug: "example-org-vpn", Kind: vpn.KindIKEv2, CAPEM: caPEM, OnDemand: true,
		IKEv2: vpn.IKEv2{
			RemoteAddress: "vpn.example.org", RemoteIdentifier: "vpn.example.org",
			ServerCertIssuerCN: "Example Org Root CA", ServerCertCN: "vpn.example.org",
			SignIn: vpn.IKEv2Certificate, Encryption: "AES-256-GCM", Integrity: "SHA2-256", DHGroup: 19, PFS: true,
			TrustedSSIDs: []string{"Example Staff"},
		},
	}, admin)
	must(err)
	wifi, err := servers.Create(ctx, vpn.Server{
		Name: "Example Staff Wi-Fi", Slug: "example-staff-wifi", Kind: vpn.KindWiFi, CAPEM: caPEM,
		WiFi: vpn.WiFi{SSID: "Example Staff", Security: vpn.WiFiWPA3Enterprise, ServerNames: []string{"radius1.example.org", "radius2.example.org"}},
	}, admin)
	must(err)

	for i, d := range fleet {
		must(db.DeviceEnrolled(ctx, mdmcore.DeviceRecord{ID: d.id, UDID: d.id, Serial: d.serial, Name: d.name, Model: d.model, Product: d.product, OSVersion: d.os, BuildVersion: d.build, Topic: topic}))
		must(db.DeviceTokenUpdated(ctx, d.id))
		must(db.DeviceInventory(ctx, d.id, mdmcore.DeviceInventory{Name: d.name, Model: d.model, Product: d.product, OSVersion: d.os, BuildVersion: d.build, Serial: d.serial, AvailableCapacity: d.capacity, Battery: d.battery}))
		seen := fmt.Sprintf("-%d minutes", d.seenMinutesAgo)
		enrolled := fmt.Sprintf("-%d days", d.enrolledDaysAgo)
		exec(`UPDATE devices SET enrolled_at=datetime('now',?), last_seen=datetime('now',?), token_updated_at=datetime('now',?), inventory_at=datetime('now',?), checkin_host='mdm.example.org' WHERE id=?`,
			enrolled, seen, enrolled, seen, d.id)

		_, hash := sqlite.NewGrantToken()
		gid, err := db.CreateGrant(ctx, sqlite.Grant{Label: d.name, Platform: "any", Owner: d.owner.identity().UPN, CreatedBy: admin,
			ExpiresAt: time.Now().AddDate(0, 0, -d.enrolledDaysAgo+1).UTC().Format("2006-01-02 15:04:05"), ExpectedSerial: d.serial}, hash)
		must(err)
		exec(`UPDATE enrollment_grants SET use_count=1, created_at=datetime('now',?), last_used_at=datetime('now',?) WHERE id=?`, enrolled, enrolled, gid)
		o := d.owner.identity()
		exec(`INSERT INTO device_owners(device_id,grant_id,directory_id,object_id,upn,account_name,actor_subject,bound_at,updated_at) VALUES(?,?,?,?,?,?,?,datetime('now',?),datetime('now',?))`,
			d.id, gid, o.DirectoryID, o.ObjectID, o.UPN, o.AccountName, admin, enrolled, enrolled)

		group, mine := staff, ids[:3]
		if i >= 5 {
			group, mine = shared, []int64{ids[0], ids[3]}
		}
		must(db.AddDeviceToGroup(ctx, group, d.id))
		if d.checkedOut {
			exec(`UPDATE devices SET checked_out_at=datetime('now',?) WHERE id=?`, seen, d.id)
			continue
		}

		installed := []mdmcore.InstalledProfile{
			{Identifier: "org.example.mdm.enroll", DisplayName: "Example Org device management", Organization: org, PayloadTypes: []string{"com.apple.mdm", "com.apple.security.scep"}},
		}
		for n, pid := range mine {
			p, err := db.GetProfile(ctx, pid)
			must(err)
			cmd := commandUUID(d.id, p.Identifier)
			status := "installed"
			if i == 2 && n == 2 {
				status = "sent" // one profile still waiting on a phone
			}
			must(db.CommandSent(ctx, d.id, cmd, "InstallProfile"))
			must(db.MarkDeploySent(ctx, d.id, pid, cmd, p.UpdatedAt))
			if status == "installed" {
				must(db.CommandResult(ctx, d.id, cmd, "Acknowledged", ""))
				exec(`UPDATE profile_deploys SET status='installed' WHERE device_id=? AND profile_id=?`, d.id, pid)
				installed = append(installed, mdmcore.InstalledProfile{Identifier: p.Identifier, DisplayName: p.Name, Organization: org, PayloadTypes: p.Types(), Managed: true})
			}
		}

		for _, cmd := range []string{"DeviceInformation", "ProfileList"} {
			id := commandUUID(d.id, cmd)
			must(db.CommandSent(ctx, d.id, id, cmd))
			must(db.CommandResult(ctx, d.id, id, "Acknowledged", ""))
		}

		// Personal devices get the VPN and the staff Wi-Fi; the workshop Mac
		// only the Wi-Fi.
		for _, sid := range []int64{ikev2, wifi} {
			if sid == ikev2 && i >= 5 {
				continue
			}
			s, err := servers.Get(ctx, sid)
			must(err)
			cmd := commandUUID(d.id, s.Slug)
			der, spki, serial, notAfter := leaf(caCert, caKey, d.owner.account, 365-d.enrolledDaysAgo%300)
			vid, err := db.BeginVPNIdentity(ctx, sqlite.VPNIdentity{ServerID: sid, DeviceID: d.id, Owner: o, Actor: admin, SPKISHA256: spki, Backend: "embedded", CommandUUID: cmd})
			must(err)
			must(db.CompleteVPNIdentity(ctx, vid, serial, der, notAfter))
			must(db.CommandSent(ctx, d.id, cmd, "InstallProfile"))
			must(db.CommandResult(ctx, d.id, cmd, "Acknowledged", ""))
			exec(`UPDATE vpn_identities SET deploy_status='installed' WHERE id=?`, vid)
			types := []string{"com.apple.security.scep", "com.apple.vpn.managed"}
			if s.IsWiFi() {
				types = []string{"com.apple.security.root", "com.apple.security.scep", "com.apple.wifi.managed"}
			}
			installed = append(installed, mdmcore.InstalledProfile{Identifier: vpn.PayloadIdentifier("org.example", s), DisplayName: s.Name, Organization: org, PayloadTypes: types, Managed: true})
		}
		must(db.SaveInstalledProfiles(ctx, d.id, installed))
		exec(`UPDATE command_history SET sent_at=datetime('now',?), result_at=datetime('now',?) WHERE device_id=?`, seen, seen, d.id)
		exec(`UPDATE command_history SET result_at=NULL WHERE device_id=? AND status='Sent'`, d.id)
	}

	// Devices that cannot enroll: one with a certificate close to expiry, one
	// with plenty of time, one waiting for its first profile.
	for _, m := range []struct {
		name, kind string
		owner      person
		days       int
	}{{"Kitchen HomePod", "homepod", sortiz, 21}, {"Maya's Vision Pro", "visionpro", mchen, 310}, {"Workshop HomePod", "homepod", tbeck, 0}} {
		mid, err := db.CreateManualDevice(ctx, sqlite.ManualDevice{Name: m.name, Kind: m.kind, Owner: m.owner.identity(), CreatedBy: admin})
		must(err)
		if m.days == 0 {
			continue
		}
		deviceID := sqlite.ManualDeviceID(mid)
		der, spki, serial, notAfter := leaf(caCert, caKey, m.owner.account, m.days)
		vid, err := db.BeginVPNIdentity(ctx, sqlite.VPNIdentity{ServerID: wifi, DeviceID: deviceID, Owner: m.owner.identity(), Actor: admin, SPKISHA256: spki, Backend: "embedded", CommandUUID: commandUUID(deviceID, "wifi")})
		must(err)
		must(db.CompleteVPNIdentity(ctx, vid, serial, der, notAfter))
		must(db.HandOverVPNIdentity(ctx, vid))
		exec(`UPDATE vpn_identities SET created_at=datetime('now',?) WHERE id=?`, fmt.Sprintf("-%d days", 365-m.days), vid)
	}

	_, hash := sqlite.NewGrantToken()
	_, err = db.CreateGrant(ctx, sqlite.Grant{Label: "Priya's MacBook Air", Platform: "macos", Owner: pnair.identity().UPN, CreatedBy: admin,
		ExpiresAt: time.Now().Add(20 * time.Hour).UTC().Format("2006-01-02 15:04:05")}, hash)
	must(err)

	exec(`DELETE FROM audit_log`)
	for _, a := range []struct{ ago, method, target, result string }{
		{"-3 days", "POST", "/admin/login", "303"},
		{"-3 days", "POST", "/admin/wifi", "303"},
		{"-3 days", "POST", "/admin/devices/7C2E5B1A-3F4D-5A6B-8C9D-0E1F2A3B4C5D/vpn/2/issue", "303"},
		{"-2 days", "POST", "/admin/login", "303"},
		{"-2 days", "POST", "/admin/profiles/upload", "303"},
		{"-2 days", "POST", "/admin/groups/1/profiles", "303"},
		{"-26 hours", "POST", "/admin/devices/3B6D9F2A-7C8E-5D1F-A2B3-C4D5E6F7A8B9/refresh", "303"},
		{"-5 hours", "POST", "/admin/login", "303"},
		{"-5 hours", "POST", "/admin/enrollment", "303"},
		{"-4 hours", "POST", "/admin/devices/00008130-000C1D2E3F4A5B6C/profile-list", "303"},
	} {
		exec(`INSERT INTO audit_log(at,username,provider,action,target,result,remote) VALUES(datetime('now',?),?,'local',?,?,?,'192.0.2.24')`, a.ago, admin, a.method, a.target, a.result)
	}
	fmt.Println("seeded", len(fleet), "devices")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// commandUUID is stable for a device and purpose, so reseeding gives the same rows.
func commandUUID(deviceID, purpose string) string {
	h := sha256.Sum256([]byte(deviceID + "\x00" + purpose))
	x := hex.EncodeToString(h[:16])
	return x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

func demoCA() (string, *x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Org Root CA", Organization: []string{org}},
		NotBefore: time.Now().AddDate(-1, 0, 0), NotAfter: time.Now().AddDate(9, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(err)
	cert, err := x509.ParseCertificate(der)
	must(err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert, key
}

func leaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, days int) (der []byte, spki, serial string, notAfter time.Time) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 79))
	must(err)
	notAfter = time.Now().AddDate(0, 0, days).UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: n, Subject: pkix.Name{CommonName: cn}, EmailAddresses: []string{cn + "@example.org"},
		NotBefore: notAfter.AddDate(-1, 0, 0), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	must(err)
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	must(err)
	sum := sha256.Sum256(pub)
	return der, hex.EncodeToString(sum[:]), fmt.Sprintf("%x", n), notAfter
}
