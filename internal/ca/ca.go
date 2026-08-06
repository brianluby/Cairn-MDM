// Package ca provides Cairn's embedded SCEP certificate authority: it bootstraps
// (or loads) a CA keypair stored in SQLite and serves a SCEP endpoint that
// issues device identity certificates. Deployments that use an external CA
// (e.g. OpenXPKI) do not construct this; their enrollment profiles point at the
// external SCEP URL instead.
package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"

	kitlog "github.com/go-kit/kit/log"
	scepdepot "github.com/micromdm/scep/v2/depot"
	scepserver "github.com/micromdm/scep/v2/server"
)

// Options configures CA bootstrap.
type Options struct {
	CommonName   string // CA subject CommonName
	Organization string // CA subject Organization
	KeyBits      int    // CA RSA key size (default 4096)
	Years        int    // CA validity in years (default 10)

	// ImportCertPEM / ImportKeyPEM, when both set, seed the CA from an existing
	// keypair (import mode — e.g. a subordinate CA from Microsoft AD CS) instead
	// of generating one. Ignored once a CA is already persisted.
	ImportCertPEM []byte
	ImportKeyPEM  []byte

	// Two-tier mode: ImportRootCertPEM is the OFFLINE root's certificate (public
	// only — its key never touches this host), and ImportIssuerCertPEM/
	// ImportIssuerKeyPEM are the ONLINE issuing CA (signed by the root) that lives
	// here and signs leaves. When ImportRootCertPEM is set, Cairn runs two-tier: the
	// root is the long-lived device trust anchor and the issuer chains to it. The
	// issuer must be signed by the root. Ignored once a CA is already persisted.
	ImportRootCertPEM   []byte
	ImportIssuerCertPEM []byte
	ImportIssuerKeyPEM  []byte

	// LeafValidityDays is the lifetime of issued device certs (default 365).
	LeafValidityDays int
	// AllowRenewalDays lets a device re-enroll this many days before expiry
	// (default 14).
	AllowRenewalDays int
	// Challenge, when non-empty, requires this static SCEP challenge password.
	// One-time per-enrollment challenges replace this in a later phase.
	Challenge string
}

// CA is the embedded certificate authority. In two-tier mode cert/key are the online
// ISSUING CA (which signs leaves) and root is the offline ROOT certificate (the trust
// anchor); in single-tier mode root is nil and cert is both anchor and signer.
type CA struct {
	cert  *x509.Certificate
	key   *rsa.PrivateKey
	root  *x509.Certificate // offline root (two-tier only); nil for single-tier
	depot *sqlDepot
	opts  Options
}

// Ensure loads the CA from the database, generating and persisting a new one on
// first run.
func Ensure(ctx context.Context, db *sql.DB, opts Options) (*CA, error) {
	if opts.KeyBits == 0 {
		opts.KeyBits = 4096
	}
	if opts.Years == 0 {
		opts.Years = 10
	}
	if opts.LeafValidityDays == 0 {
		opts.LeafValidityDays = 365
	}
	if opts.AllowRenewalDays == 0 {
		opts.AllowRenewalDays = 14
	}

	cert, key, root, err := loadCA(ctx, db)
	if errors.Is(err, sql.ErrNoRows) {
		switch {
		case len(opts.ImportRootCertPEM) > 0:
			cert, key, root, err = importTwoTier(ctx, db, opts)
		case len(opts.ImportCertPEM) > 0 || len(opts.ImportKeyPEM) > 0:
			cert, key, err = importCA(ctx, db, opts.ImportCertPEM, opts.ImportKeyPEM)
		default:
			cert, key, err = generateCA(ctx, db, opts)
		}
	}
	if err != nil {
		return nil, err
	}

	return &CA{
		cert:  cert,
		key:   key,
		root:  root,
		depot: &sqlDepot{db: db, caCert: cert, caKey: key},
		opts:  opts,
	}, nil
}

func loadCA(ctx context.Context, db *sql.DB) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate, error) {
	var certPEM, keyPEM, rootPEM []byte
	err := db.QueryRowContext(ctx, `SELECT cert_pem, key_pem, root_cert_pem FROM ca WHERE id = 1`).Scan(&certPEM, &keyPEM, &rootPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, nil, errors.New("ca: stored CA PEM is malformed")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ca: parse stored cert: %w", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ca: parse stored key: %w", err)
	}
	var root *x509.Certificate
	if len(rootPEM) > 0 { // two-tier
		rb, _ := pem.Decode(rootPEM)
		if rb == nil {
			return nil, nil, nil, errors.New("ca: stored root PEM is malformed")
		}
		if root, err = x509.ParseCertificate(rb.Bytes); err != nil {
			return nil, nil, nil, fmt.Errorf("ca: parse stored root: %w", err)
		}
	}
	return cert, key, root, nil
}

// importTwoTier seeds the CA singleton from an offline root certificate (public
// only) plus an online issuing CA cert+key signed by that root. The issuer signs
// leaves; the root is the device trust anchor. The issuer must be a CA certificate
// verifiably signed by the root.
func importTwoTier(ctx context.Context, db *sql.DB, opts Options) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate, error) {
	if len(opts.ImportIssuerCertPEM) == 0 || len(opts.ImportIssuerKeyPEM) == 0 {
		return nil, nil, nil, errors.New("ca: two-tier import requires the issuer cert and key (ImportIssuerCertPEM/KeyPEM)")
	}
	rb, _ := pem.Decode(opts.ImportRootCertPEM)
	if rb == nil {
		return nil, nil, nil, errors.New("ca: root cert is not valid PEM")
	}
	root, err := x509.ParseCertificate(rb.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ca: parse root cert: %w", err)
	}
	if !root.IsCA {
		return nil, nil, nil, errors.New("ca: root certificate is not a CA")
	}
	ib, _ := pem.Decode(opts.ImportIssuerCertPEM)
	if ib == nil {
		return nil, nil, nil, errors.New("ca: issuer cert is not valid PEM")
	}
	issuer, err := x509.ParseCertificate(ib.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ca: parse issuer cert: %w", err)
	}
	if !issuer.IsCA {
		return nil, nil, nil, errors.New("ca: issuer certificate is not a CA")
	}
	if err := issuer.CheckSignatureFrom(root); err != nil {
		return nil, nil, nil, fmt.Errorf("ca: issuer is not signed by the root: %w", err)
	}
	key, err := parseRSAKey(opts.ImportIssuerKeyPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	normIssuer := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})
	normKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	normRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	if _, err := db.ExecContext(ctx,
		`INSERT INTO ca (id, cert_pem, key_pem, root_cert_pem) VALUES (1, ?, ?, ?)`,
		normIssuer, normKey, normRoot); err != nil {
		return nil, nil, nil, fmt.Errorf("ca: persist two-tier CA: %w", err)
	}
	return issuer, key, root, nil
}

func generateCA(ctx context.Context, db *sql.DB, opts Options) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, opts.KeyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate key: %w", err)
	}

	caTmpl := scepdepot.NewCACert(
		scepdepot.WithCommonName(opts.CommonName),
		scepdepot.WithOrganization(opts.Organization),
		scepdepot.WithYears(opts.Years),
	)
	der, err := caTmpl.SelfSign(rand.Reader, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: self-sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse new cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if _, err := db.ExecContext(ctx,
		`INSERT INTO ca (id, cert_pem, key_pem) VALUES (1, ?, ?)`, certPEM, keyPEM); err != nil {
		return nil, nil, fmt.Errorf("ca: persist: %w", err)
	}
	return cert, key, nil
}

// importCA seeds the CA table from an existing certificate + RSA key (PEM). The
// key must be RSA (the SCEP depot signs with RSA). Accepts PKCS#1 or PKCS#8 keys.
func importCA(ctx context.Context, db *sql.DB, certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, errors.New("ca: import requires both cert and key PEM")
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, errors.New("ca: import cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse import cert: %w", err)
	}
	if !cert.IsCA {
		return nil, nil, errors.New("ca: import certificate is not a CA (BasicConstraints CA=false)")
	}

	key, err := parseRSAKey(keyPEM)
	if err != nil {
		return nil, nil, err
	}

	// Persist in the normalized PKCS#1 form loadCA expects.
	normCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	normKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if _, err := db.ExecContext(ctx, `INSERT INTO ca (id, cert_pem, key_pem) VALUES (1, ?, ?)`, normCert, normKey); err != nil {
		return nil, nil, fmt.Errorf("ca: persist imported CA: %w", err)
	}
	return cert, key, nil
}

// parseRSAKey decodes an RSA private key from PEM in either PKCS#1 or PKCS#8.
func parseRSAKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("ca: import key is not valid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(kb.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse import key (PKCS#1 and PKCS#8 both failed): %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca: import key must be RSA, got %T", parsed)
	}
	return rsaKey, nil
}

// RootPEM returns the TRUST ANCHOR certificate in PEM form — the offline root in
// two-tier mode, otherwise the single CA cert. This is what a relying party trusts.
func (c *CA) RootPEM() []byte {
	anchor := c.cert
	if c.root != nil {
		anchor = c.root
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw})
}

// ProfileCertsDER returns the certificate(s) to install on an enrolling device so it
// can build and trust the issued leaf's chain: in two-tier mode the root (anchor) and
// the issuer (intermediate); in single-tier mode just the CA cert.
func (c *CA) ProfileCertsDER() [][]byte {
	if c.root != nil {
		return [][]byte{c.root.Raw, c.cert.Raw} // root (anchor) + issuer (intermediate)
	}
	return [][]byte{c.cert.Raw}
}

// Certificate returns the CA certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// SCEPHandler builds the SCEP HTTP handler using the CA's built-in depot signer,
// which copies the CSR subject/SANs and gates on an optional STATIC challenge. This
// is the legacy path; the enrollment-authorization Broker (SCEPHandlerWith) replaces
// it wherever issuance must be authority-controlled (reconstruct-don't-validate).
func (c *CA) SCEPHandler() (http.Handler, error) {
	signerOpts := []scepdepot.Option{
		scepdepot.WithValidityDays(c.opts.LeafValidityDays),
		scepdepot.WithAllowRenewalDays(c.opts.AllowRenewalDays),
	}
	var signer scepserver.CSRSignerContext = scepserver.SignCSRAdapter(scepdepot.NewSigner(c.depot, signerOpts...))
	if c.opts.Challenge != "" {
		signer = scepserver.StaticChallengeMiddleware(c.opts.Challenge, signer)
	}
	return c.SCEPHandlerWith(signer)
}

// SCEPHandlerWith builds the SCEP HTTP handler (GetCACert / GetCACaps /
// PKIOperation) using the supplied signer — typically the Cairn enrollment-
// authorization Broker, which reconstructs the certificate from policy+grant and
// drives the issuance state machine instead of copying the CSR.
func (c *CA) SCEPHandlerWith(signer scepserver.CSRSignerContext) (http.Handler, error) {
	svc, err := scepserver.NewService(c.cert, c.key, signer)
	if err != nil {
		return nil, fmt.Errorf("ca: new scep service: %w", err)
	}
	e := scepserver.MakeServerEndpoints(svc)
	return scepserver.MakeHTTPHandler(e, svc, kitlog.NewNopLogger()), nil
}
