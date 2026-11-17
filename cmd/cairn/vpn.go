package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	kitlog "github.com/go-kit/kit/log"
	scepserver "github.com/micromdm/scep/v2/server"
	"github.com/smallstep/scep/x509util"

	"github.com/nickpdawson/cairn-mdm/internal/broker"
	"github.com/nickpdawson/cairn-mdm/internal/config"
	"github.com/nickpdawson/cairn-mdm/internal/issue"
)

// vpnSCEPIssuer builds the SCEP backend that signs VPN certificates.
func vpnSCEPIssuer(is config.VPNIssuer) (issue.CABackend, error) {
	raCert, raKey, err := loadRAIdentity(is.RACertFile, is.RAKeyFile)
	if err != nil {
		return nil, fmt.Errorf("vpn.issuer: %w", err)
	}
	chainPEM, err := os.ReadFile(is.CAChainFile)
	if err != nil {
		return nil, fmt.Errorf("vpn.issuer: read ca_chain_file: %w", err)
	}
	var anchors []*x509.Certificate
	for rest := chainPEM; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("vpn.issuer: ca_chain_file: %w", err)
		}
		anchors = append(anchors, c)
	}
	if len(anchors) == 0 {
		return nil, errors.New("vpn.issuer: ca_chain_file holds no certificates")
	}
	be, err := broker.New(broker.Config{URL: is.SCEPURL, RACert: raCert, RAKey: raKey, Anchors: anchors})
	if err != nil {
		return nil, fmt.Errorf("vpn.issuer: %w", err)
	}
	return be, nil
}

// vpnDeviceSCEPHandler builds the device-facing SCEP endpoint for an external
// VPN CA. Devices encrypt their requests to the RA certificate; the issuing CA
// is returned beside it so a device sees who signs what it gets back.
func vpnDeviceSCEPHandler(is config.VPNIssuer, signer scepserver.CSRSignerContext) (http.Handler, error) {
	raCert, raKey, err := loadRAIdentity(is.RACertFile, is.RAKeyFile)
	if err != nil {
		return nil, fmt.Errorf("vpn.issuer: %w", err)
	}
	chainPEM, err := os.ReadFile(is.CAChainFile)
	if err != nil {
		return nil, fmt.Errorf("vpn.issuer: read ca_chain_file: %w", err)
	}
	var opts []scepserver.ServiceOption
	for rest := chainPEM; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("vpn.issuer: ca_chain_file: %w", err)
		}
		if raCert.CheckSignatureFrom(c) == nil {
			opts = append(opts, scepserver.WithAddlCA(c))
			break
		}
	}
	svc, err := scepserver.NewService(raCert, raKey, signer, opts...)
	if err != nil {
		return nil, fmt.Errorf("vpn.issuer: device SCEP service: %w", err)
	}
	return scepserver.MakeHTTPHandler(scepserver.MakeServerEndpoints(svc), svc, kitlog.NewNopLogger()), nil
}

func runVPN(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "check-issuer" {
		return errors.New("usage: cairn vpn check-issuer -cn <account> -email <address> [-device-request] [-config cairn.toml] [-out cert.pem]")
	}
	return runVPNCheckIssuer(ctx, args[1:])
}

// runVPNCheckIssuer sends one real request through the configured SCEP issuer
// and reports what came back. It is the test to run before the first device
// gets a profile: a certificate authority profile that renames the subject,
// adds usages or drops the SAN shows up here, not as a held request later.
// The key is discarded and nothing is stored, so the certificate is unusable,
// but the CA did issue it and it should be revoked there.
func runVPNCheckIssuer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("vpn check-issuer", flag.ContinueOnError)
	path := fs.String("config", defaultConfigPath, "path to cairn.toml")
	cn := fs.String("cn", "", "account name to request, as the certificate common name; use a test name")
	email := fs.String("email", "", "address to request as the email SAN (the account's UPN)")
	out := fs.String("out", "", "also write the returned certificate to this file (PEM)")
	deviceRequest := fs.Bool("device-request", false, "send the request the way a device's SCEP client does, with a challenge password in it; run this before using certificate sign-in for IKEv2")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cn == "" || *email == "" {
		return errors.New("-cn and -email are required")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	vpnCfg := cfg.VPN.WithDefaults()
	if vpnCfg.Issuer.Backend != "scep" {
		return errors.New("[vpn.issuer] backend is not \"scep\"; Cairn's own CA needs no check")
	}
	be, err := vpnSCEPIssuer(vpnCfg.Issuer)
	if err != nil {
		return err
	}
	pol := issue.Policy{
		LeafValidity:    time.Duration(vpnCfg.LeafValidityDays) * 24 * time.Hour,
		Backdate:        5 * time.Minute,
		MaxLeafValidity: time.Duration(vpnCfg.Issuer.MaxLeafValidityDays) * 24 * time.Hour,
	}
	key, err := issue.NewServerKey(vpnCfg.KeyType)
	if err != nil {
		return err
	}
	now := time.Now()
	req, err := issue.ServerKeyedRequest(pol, issue.GrantFacts{Owner: *email, CommonName: *cn}, key, now)
	if err != nil {
		return err
	}
	if *deviceRequest {
		// A device puts Cairn's one-time challenge in its request and Cairn
		// passes the request on unchanged. The CA must issue on the RA's
		// signature and ignore a challenge it does not know.
		der, cerr := x509util.CreateCertificateRequest(rand.Reader, &x509util.CertificateRequest{
			CertificateRequest: x509.CertificateRequest{Subject: pkix.Name{CommonName: *cn}, EmailAddresses: []string{*email}},
			ChallengePassword:  "cairn-check-issuer-not-a-ca-challenge",
		}, key)
		if cerr != nil {
			return cerr
		}
		if req.DeviceCSR, cerr = x509.ParseCertificateRequest(der); cerr != nil {
			return cerr
		}
	}
	res, err := be.Issue(ctx, req)
	if res.Leaf == nil {
		if err == nil {
			err = errors.New("no certificate returned")
		}
		return fmt.Errorf("the CA did not issue (status %v): %w", res.Status, err)
	}
	leaf := res.Leaf
	var ekus []string
	for _, e := range leaf.ExtKeyUsage {
		ekus = append(ekus, ekuName(e))
	}
	for _, oid := range leaf.UnknownExtKeyUsage {
		ekus = append(ekus, oid.String())
	}
	fmt.Printf("subject:   %s\nissuer:    %s\nserial:    %s\nvalid:     %s to %s (%d days)\nemail SAN: %s\nother SAN: %d DNS, %d IP, %d URI\nusages:    %s\nCRL:       %s\n",
		leaf.Subject, leaf.Issuer, leaf.SerialNumber.Text(16),
		leaf.NotBefore.UTC().Format("2006-01-02"), leaf.NotAfter.UTC().Format("2006-01-02"), int(leaf.NotAfter.Sub(leaf.NotBefore).Hours()/24),
		strings.Join(leaf.EmailAddresses, ", "), len(leaf.DNSNames), len(leaf.IPAddresses), len(leaf.URIs),
		strings.Join(ekus, ", "), strings.Join(leaf.CRLDistributionPoints, ", "))
	if *out != "" {
		if werr := os.WriteFile(*out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o644); werr != nil {
			return werr
		}
	}
	fmt.Printf("\nThe key for this certificate was discarded. Revoke serial %s at the CA.\n", leaf.SerialNumber.Text(16))
	if err != nil {
		return fmt.Errorf("the CA issued, but Cairn would hold it: %w", err)
	}
	if verr := issue.VerifyLeaf(leaf, req, pol, now); verr != nil {
		return fmt.Errorf("the CA issued, but Cairn would hold it: %w", verr)
	}
	fmt.Println("Result: Cairn accepts this certificate.")
	return nil
}

func ekuName(e x509.ExtKeyUsage) string {
	switch e {
	case x509.ExtKeyUsageClientAuth:
		return "client authentication"
	case x509.ExtKeyUsageServerAuth:
		return "server authentication"
	case x509.ExtKeyUsageEmailProtection:
		return "email protection"
	case x509.ExtKeyUsageAny:
		return "any"
	}
	return fmt.Sprintf("usage %d", int(e))
}
