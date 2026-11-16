// Package config loads and validates Cairn's TOML configuration.
//
// Secrets are never inlined in the config file. Every secret-bearing field has
// a companion "<field>_file" or "<field>_env" that names where to read the
// value from at startup. This keeps the config file safe to commit to a private
// repo and safe to leave group-readable — the mistakes v1 made (LDAP bind
// passwords and API keys committed to git) are structurally impossible here.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// TLSMode selects how the server obtains its TLS certificate.
type TLSMode string

const (
	// TLSACME uses the built-in ACME client (Let's Encrypt) — the default for
	// public-DNS homelabs.
	TLSACME TLSMode = "acme"
	// TLSFiles uses an operator-supplied cert/key pair — for internal CAs
	// (DZsec/DigiCert) or any bring-your-own-cert setup.
	TLSFiles TLSMode = "files"
	// TLSProxy runs a plaintext listener behind a terminating reverse proxy
	// (nginx/caddy/traefik). Trusted-proxy header auth lives here.
	TLSProxy TLSMode = "proxy"
)

// StorageDriver selects the persistence backend.
type StorageDriver string

const (
	DriverSQLite   StorageDriver = "sqlite"
	DriverMySQL    StorageDriver = "mysql"
	DriverPostgres StorageDriver = "postgres"
)

// CAMode selects how device identity certificates are issued.
type CAMode string

const (
	// CAGenerate self-generates a device-identity CA on first boot and runs the
	// embedded SCEP endpoint. The zero-PKI default.
	CAGenerate CAMode = "generate"
	// CAImport runs the embedded SCEP endpoint but signs with an operator-supplied
	// CA cert+key (e.g. a subordinate CA from Microsoft AD CS or an existing org
	// root), so device certs chain to that CA.
	CAImport CAMode = "import"
	// CAExternal points enrollment profiles at a third-party SCEP server (OpenXPKI,
	// Microsoft NDES) and never issues certificates itself.
	CAExternal CAMode = "external"
	// CABroker runs Cairn's own device-facing SCEP endpoint through the enrollment-
	// authorization Broker, which relays to a backend SCEP CA (OpenXPKI/NDES) over a
	// restricted path signed by an RA identity. The backend SCEP is never exposed to
	// devices; Cairn owns authorization and reconstructs the certificate.
	CABroker CAMode = "broker"
)

// Embedded reports whether the mode runs Cairn's own SCEP endpoint (generate or
// import) as opposed to delegating to an external SCEP server.
func (m CAMode) Embedded() bool { return m == CAGenerate || m == CAImport }

// Config is the fully-resolved runtime configuration. Secrets have already been
// loaded from their _file/_env sources by the time a Config is returned.
type Config struct {
	Server     Server     `toml:"server"`
	Storage    Storage    `toml:"storage"`
	CA         CA         `toml:"ca"`
	Auth       Auth       `toml:"auth"`
	Enrollment Enrollment `toml:"enrollment"`
	Profile    Profile    `toml:"profile"`
	Alerts     Alerts     `toml:"alerts"`
	RADIUS     RADIUS     `toml:"radius"`
	Issuance   Issuance   `toml:"issuance"`
	VPN        VPN        `toml:"vpn"`
	Renewal    Renewal    `toml:"renewal"`
	Log        Log        `toml:"log"`
}

// Renewal controls what happens to the identity certificate a device checks in
// with as it nears and passes its expiry.
type Renewal struct {
	// Enabled makes Cairn push each device its enrollment profile again before
	// the certificate expires, so the device gets a new one without anyone
	// touching it. Built for ca.mode external.
	Enabled bool `toml:"enabled"`
	// RenewBeforeDays is how long before expiry a renewal starts. Default 60.
	RenewBeforeDays int `toml:"renew_before_days"`
	// ExpiredGraceDays lets a device whose certificate expired no longer ago
	// than this keep checking in, for renewal and nothing else. Default 0: an
	// expired certificate is refused and the device has to enroll again.
	ExpiredGraceDays int `toml:"expired_grace_days"`
	// ServerHosts are further host names (host or host:port) devices check in
	// through, besides the one in server.public_url. A renewed profile keeps
	// the name the device already uses, and only names listed here are trusted
	// for that.
	ServerHosts []string `toml:"server_hosts"`
	// ManualOnly starts renewals only from a device's page, never on the
	// schedule. Use it to try renewal on one device before the rest.
	ManualOnly bool `toml:"manual_only"`
}

// WithDefaults fills zero fields.
func (r Renewal) WithDefaults() Renewal {
	if r.RenewBeforeDays <= 0 {
		r.RenewBeforeDays = 60
	}
	return r
}

// VPN turns on per-device OpenVPN profiles: admin-managed server records and
// profiles rendered from them. Off by default.
type VPN struct {
	Enabled bool `toml:"enabled"`
	// LeafValidityDays is the VPN certificate lifetime when Cairn's own CA signs
	// it. Default 365: there is no automatic re-issue yet, so an administrator
	// issues the profile again before expiry.
	LeafValidityDays int `toml:"leaf_validity_days"`
	// KeyType is the key Cairn generates for each VPN certificate: "rsa2048"
	// (default) or "p256".
	KeyType string    `toml:"key_type"`
	Issuer  VPNIssuer `toml:"issuer"`
}

// VPNIssuer selects the CA that signs VPN certificates. It is separate from
// ca.mode because a VPN server usually trusts one particular CA, which need not
// be the one that signs device identities.
type VPNIssuer struct {
	// Backend is "embedded" (Cairn's own CA; the default) or "scep" (a SCEP CA
	// that accepts requests signed by Cairn's RA certificate).
	Backend    string `toml:"backend"`
	SCEPURL    string `toml:"scep_url"`
	RACertFile string `toml:"ra_cert_file"`
	RAKeyFile  string `toml:"ra_key_file"`
	// CAChainFile pins the SCEP CA: PEM certificates the endpoint's own
	// certificates and every issued certificate must chain to.
	CAChainFile string `toml:"ca_chain_file"`
	// MaxLeafValidityDays is the longest lifetime Cairn accepts from the SCEP CA,
	// which sets the real one. Default 400.
	MaxLeafValidityDays int `toml:"max_leaf_validity_days"`
}

// WithDefaults fills zero fields.
func (v VPN) WithDefaults() VPN {
	if v.Issuer.Backend == "" {
		v.Issuer.Backend = "embedded"
	}
	if v.Issuer.MaxLeafValidityDays <= 0 {
		v.Issuer.MaxLeafValidityDays = 400
	}
	if v.LeafValidityDays <= 0 {
		v.LeafValidityDays = 365
	}
	if v.KeyType == "" {
		v.KeyType = "rsa2048"
	}
	return v
}

// Issuance tunes certificates the embedded CA signs for devices.
type Issuance struct {
	// LeafValidityDays is the device certificate lifetime. Default 365: this
	// release has no renewal path, so a device must be re-enrolled before its
	// certificate expires, and a shorter life only brings that forward.
	LeafValidityDays int `toml:"leaf_validity_days"`
}

// WithDefaults fills zero fields.
func (i Issuance) WithDefaults() Issuance {
	if i.LeafValidityDays <= 0 {
		i.LeafValidityDays = 365
	}
	return i
}

// RADIUS names the network-access acceptance points that rely on Cairn-issued
// certificates and the token they use to report observed Access-Rejects. The
// quarantine release gate requires an ingested rejection for every enumerated
// serial from every acceptance point listed here; with none listed, release
// covers MDM only and the console says so.
type RADIUS struct {
	AcceptancePoints []string `toml:"acceptance_points"`
	IngestTokenFile  string   `toml:"ingest_token_file"`
	IngestTokenEnv   string   `toml:"ingest_token_env"`
	// resolved:
	IngestToken string `toml:"-"`
}

// Alerts configures the out-of-band notification path: a webhook (ntfy-style
// POST with Title/Priority headers, but any URL that accepts a text body works)
// that receives certificate-expiry, quarantine, backup-freshness and backup
// outcome messages plus a periodic heartbeat, so silence is not mistaken for
// health. Disabled unless a webhook URL is configured.
type Alerts struct {
	WebhookURL     string `toml:"webhook_url"`
	WebhookURLFile string `toml:"webhook_url_file"`
	WebhookURLEnv  string `toml:"webhook_url_env"`
	// HeartbeatHours is how often a heartbeat is sent (default 24).
	HeartbeatHours int `toml:"heartbeat_hours"`
	// APNSWarnDays is the expiry warning horizon (default 30).
	APNSWarnDays int `toml:"apns_warn_days"`
	// BackupDir, when set, is watched for bundles; none newer than
	// BackupMaxAgeHours (default 36) raises an alert.
	BackupDir         string `toml:"backup_dir"`
	BackupMaxAgeHours int    `toml:"backup_max_age_hours"`
}

// Enabled reports whether a webhook is configured.
func (a Alerts) Enabled() bool { return a.WebhookURL != "" }

// WithDefaults fills zero fields with the documented defaults.
func (a Alerts) WithDefaults() Alerts {
	if a.HeartbeatHours <= 0 {
		a.HeartbeatHours = 24
	}
	if a.APNSWarnDays <= 0 {
		a.APNSWarnDays = 30
	}
	if a.BackupMaxAgeHours <= 0 {
		a.BackupMaxAgeHours = 36
	}
	return a
}

// Enrollment configures device-enrollment access.
type Enrollment struct {
	// AllowOpen serves the bare, unauthenticated /enroll route. Default false:
	// enrollment requires a single-use grant link (/e/{token}). Set true only
	// for a low-stakes homelab that accepts an open enrollment endpoint.
	AllowOpen bool `toml:"allow_open"`
}

// Profile configures configuration-profile handling.
type Profile struct {
	Signing SigningCfg `toml:"signing"`
}

// SigningCfg is the identity used to CMS-sign enrollment profiles so devices
// show a verified signer. For the green "Verified" badge the cert must chain to
// a root the device already trusts before install — i.e. a publicly-trusted
// (Let's Encrypt/commercial) cert, not the device-identity CA. cert_file may be
// a full chain (leaf first); intermediates are included in the signature.
type SigningCfg struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

// Enabled reports whether profile signing is configured.
func (s SigningCfg) Enabled() bool { return s.CertFile != "" || s.KeyFile != "" }

// Auth configures the console's authentication providers. Local accounts are
// always enabled (they are the break-glass path); external providers are
// tried first when configured, with local as the fallback.
type Auth struct {
	LDAP  LDAPCfg     `toml:"ldap"`
	OIDC  OIDCCfg     `toml:"oidc"`
	Login LoginPolicy `toml:"login"`
}

// LoginPolicy configures brute-force throttling, the local password floor, and
// session-lifetime bounds (MDM-AUTH-001). Every field has a working default, so
// an omitted [auth.login] table still yields a safe policy — call WithDefaults
// before use to fill zero values.
type LoginPolicy struct {
	// MaxAttempts is the number of failed logins per user+IP within the window
	// before a lockout begins. Default 5.
	MaxAttempts int `toml:"max_attempts"`
	// WindowSeconds is the sliding window over which failures are counted.
	// Default 300 (5 minutes).
	WindowSeconds int `toml:"window_seconds"`
	// LockoutSeconds is how long a user+IP stays locked out once MaxAttempts is
	// reached. Default 900 (15 minutes).
	LockoutSeconds int `toml:"lockout_seconds"`
	// MinPasswordLen is the minimum length for a local-account password.
	// Default 8.
	MinPasswordLen int `toml:"min_password_len"`
	// IdleTimeoutMins is the session idle timeout; each authenticated request
	// slides the session's expiry forward by this amount. Default 60.
	IdleTimeoutMins int `toml:"idle_timeout_mins"`
	// MaxLifetimeMins caps a session's absolute lifetime regardless of activity.
	// Default 720 (12 hours).
	MaxLifetimeMins int `toml:"max_lifetime_mins"`
}

// WithDefaults returns a copy of p with any zero-valued field replaced by its
// default. It never mutates the receiver.
func (p LoginPolicy) WithDefaults() LoginPolicy {
	if p.MaxAttempts == 0 {
		p.MaxAttempts = 5
	}
	if p.WindowSeconds == 0 {
		p.WindowSeconds = 300
	}
	if p.LockoutSeconds == 0 {
		p.LockoutSeconds = 900
	}
	if p.MinPasswordLen == 0 {
		p.MinPasswordLen = 8
	}
	if p.IdleTimeoutMins == 0 {
		p.IdleTimeoutMins = 60
	}
	if p.MaxLifetimeMins == 0 {
		p.MaxLifetimeMins = 720
	}
	return p
}

// LDAPCfg configures directory (Active Directory / LDAP) login.
//
// Role assignment is always explicit: group DNs map to roles via group_roles;
// an authenticated user matching no mapped group gets default_role. There is
// deliberately no code path where "authenticated" implies "admin".
type LDAPCfg struct {
	// DirectoryID is a stable operator-assigned namespace for AD objectGUIDs.
	// Leave empty for legacy console-only LDAP; owner resolution then fails closed.
	DirectoryID string `toml:"directory_id"`
	Enabled     bool   `toml:"enabled"`
	// Servers are tried in order (failover), e.g. "ldaps://dc1.example.org:636".
	// Schemes: ldaps:// (TLS) or ldap:// (plaintext; combine with start_tls).
	Servers  []string `toml:"servers"`
	StartTLS bool     `toml:"start_tls"`
	// BaseDN is the search base, e.g. "DC=example,DC=org".
	BaseDN string `toml:"base_dn"`
	// BindDN is the service account used to locate users. Read-only directory
	// access is sufficient; use a least-privilege account.
	BindDN           string `toml:"bind_dn"`
	BindPassword     string `toml:"-"`
	BindPasswordFile string `toml:"bind_password_file"`
	BindPasswordEnv  string `toml:"bind_password_env"`
	// UserFilter locates the login account; %s is the escaped username.
	// Default matches Active Directory sAMAccountName or userPrincipalName.
	UserFilter string `toml:"user_filter"`
	// GroupRoles maps group DNs (case-insensitive) to "admin", "operator", or
	// "user". Membership is matched against the user's memberOf values.
	GroupRoles map[string]string `toml:"group_roles"`
	// DefaultRole applies when no mapped group matches (default "user").
	DefaultRole string `toml:"default_role"`
	// CAFile adds a PEM CA bundle for validating the directory's TLS cert
	// (internal-CA LDAPS). System roots are always included.
	CAFile string `toml:"ca_file"`
}

// OIDCCfg configures OpenID Connect single sign-on (the authorization-code
// login flow, e.g. against Authentik). Unlike LDAP this is a browser redirect
// flow, not a username/password check — the console gets separate /auth/oidc/*
// routes and mints a session after the callback.
//
// Role assignment is always explicit, exactly as for LDAP: a claim value from
// group_claim maps to a role via group_roles; an authenticated user matching no
// mapped group gets default_role. There is deliberately no code path where
// "authenticated via the IdP" implies "admin".
type OIDCCfg struct {
	Enabled bool `toml:"enabled"`
	// IssuerURL is the IdP's OIDC issuer (discovery base), e.g.
	// "https://portal.dzsec.net:7443/application/o/cairn/". Must be https.
	IssuerURL string `toml:"issuer_url"`
	// ClientID is the confidential client's identifier registered at the IdP.
	ClientID string `toml:"client_id"`
	// ClientSecret is never inlined; supply it via client_secret_file/env.
	ClientSecret     string `toml:"-"`
	ClientSecretFile string `toml:"client_secret_file"`
	ClientSecretEnv  string `toml:"client_secret_env"`
	// Scopes requested at authorization. Default ["openid","profile","email",
	// "groups"].
	Scopes []string `toml:"scopes"`
	// GroupClaim is the ID-token claim carrying the user's groups. Default
	// "groups".
	GroupClaim string `toml:"group_claim"`
	// GroupRoles maps a group value (case-insensitive) to "admin", "operator",
	// or "user". Matched against the values of group_claim.
	GroupRoles map[string]string `toml:"group_roles"`
	// DefaultRole applies when no mapped group matches (default "user").
	DefaultRole string `toml:"default_role"`
	// UsernameClaim is the claim used as the account username. Default
	// "preferred_username"; falls back to "sub" when the claim is absent.
	UsernameClaim string `toml:"username_claim"`
	// CAFile adds a PEM CA bundle for validating the IdP's TLS cert (internal
	// CA). System roots are always included.
	CAFile string `toml:"ca_file"`
}

// WithDefaults returns a copy of o with any unset field replaced by its default.
// It never mutates the receiver. Callers (the provider and the claim-mapping
// helper) call this so an omitted field behaves consistently everywhere.
func (o OIDCCfg) WithDefaults() OIDCCfg {
	if len(o.Scopes) == 0 {
		o.Scopes = []string{"openid", "profile", "email", "groups"}
	}
	if o.GroupClaim == "" {
		o.GroupClaim = "groups"
	}
	if o.DefaultRole == "" {
		o.DefaultRole = "user"
	}
	if o.UsernameClaim == "" {
		o.UsernameClaim = "preferred_username"
	}
	return o
}

// Server holds HTTP listener and public-identity settings.
type Server struct {
	// PublicURL is the externally-reachable base URL. It drives the MDM
	// ServerURL/CheckInURL, the SCEP URL, and enrollment links, so it must be
	// exactly what devices were (or will be) enrolled against.
	PublicURL string `toml:"public_url"`
	// Listen is the bind address, e.g. ":443" or "127.0.0.1:8080".
	Listen string `toml:"listen"`
	// MDMPath is the path devices POST check-ins and command results to.
	// Defaults to "/mdm" to match nanomdm and v1's installed profiles.
	MDMPath string `toml:"mdm_path"`

	TLS TLS `toml:"tls"`
}

// TLS configures certificate acquisition.
type TLS struct {
	Mode TLSMode `toml:"mode"`
	// Files mode:
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
	// ACME mode:
	ACMEEmail     string `toml:"acme_email"`
	ACMECacheDir  string `toml:"acme_cache_dir"`
	ACMEDirectory string `toml:"acme_directory"` // optional; defaults to Let's Encrypt prod
	// Proxy mode:
	TrustedProxies []string `toml:"trusted_proxies"`
}

// Storage configures the persistence backend.
type Storage struct {
	Driver StorageDriver `toml:"driver"`
	// Path is the SQLite database file (sqlite driver only).
	Path string `toml:"path"`
	// DSN is the connection string (mysql/postgres drivers only). Treated as a
	// secret: prefer DSNFile/DSNEnv.
	DSN     string `toml:"dsn"`
	DSNFile string `toml:"dsn_file"`
	DSNEnv  string `toml:"dsn_env"`
}

// CA configures certificate issuance for device identities.
type CA struct {
	Mode     CAMode        `toml:"mode"`
	Import   CAImportCfg   `toml:"import"`
	External CAExternalCfg `toml:"external"`
	Broker   CABrokerCfg   `toml:"broker"`
}

// CAImportCfg supplies an existing CA cert+key for import mode. When RootCertFile is
// also set, Cairn runs TWO-TIER: cert_file/key_file are the online ISSUING CA and
// root_cert_file is the OFFLINE ROOT's certificate (public only — its key never
// touches this host). The issuer must be signed by the root.
type CAImportCfg struct {
	CertFile     string `toml:"cert_file"`
	KeyFile      string `toml:"key_file"`
	RootCertFile string `toml:"root_cert_file"` // set → two-tier (cert/key = issuer)
}

// CAExternalCfg describes an external SCEP server (external mode only).
type CAExternalCfg struct {
	SCEPURL       string `toml:"scep_url"`
	CAChainFile   string `toml:"ca_chain_file"`
	CRLURL        string `toml:"crl_url"`
	ChallengeEnv  string `toml:"challenge_env"`
	ChallengeFile string `toml:"challenge_file"`
	// Lookup replaces the static challenge with one-time challenges the CA
	// checks with Cairn before it issues.
	Lookup CAChallengeLookupCfg `toml:"challenge_lookup"`
	// resolved:
	Challenge string `toml:"-"`
}

// CAChallengeLookupCfg turns on one-time SCEP challenges for an external CA
// that can ask another system whether a challenge is good (OpenXPKI with a
// connector, for one). The CA calls GET <cairn>/scep-challenge/<certificate
// name>/<request key identifier>/<presented challenge> with the secret as a
// bearer token.
type CAChallengeLookupCfg struct {
	Enabled    bool   `toml:"enabled"`
	SecretFile string `toml:"secret_file"`
	SecretEnv  string `toml:"secret_env"`
	// AllowedSources limits lookups to these addresses or networks, judged by
	// the connection's own address.
	AllowedSources []string `toml:"allowed_sources"`
	// resolved:
	Secret string `toml:"-"`
}

// CABrokerCfg describes the backend SCEP CA that Cairn brokers to (broker mode).
// The device does grant-gated SCEP to Cairn; Cairn relays the device CSR to this
// backend over a restricted path, signing the SCEP envelope with the RA identity
// (an authorized signer at the backend). The backend SCEP is never exposed to
// devices. The optional service challenge is loaded from env/file, never inline.
type CABrokerCfg struct {
	SCEPURL       string `toml:"backend_scep_url"`
	RACertFile    string `toml:"ra_cert_file"`
	RAKeyFile     string `toml:"ra_key_file"`
	CAChainFile   string `toml:"backend_ca_chain_file"` // trust anchor for enrollment profiles + reply parsing
	CRLURL        string `toml:"crl_url"`
	ChallengeEnv  string `toml:"challenge_env"`
	ChallengeFile string `toml:"challenge_file"`
	PollSeconds   int    `toml:"poll_seconds"` // reconciler poll cadence for PENDING/quarantined (default 3600)
	// MaxLeafValidityDays is the accepted ceiling (in days) on the validity span of a
	// certificate the backend CA returns. The backend sets the actual lifetime; a
	// longer-but-bounded value is a policy choice, not an escalation, so this lets an
	// operator accept the backend's validity without per-deployment profile tuning.
	// 0 uses the default (brokerDefaultMaxLeafValidityDays). All other verify checks are
	// unaffected.
	MaxLeafValidityDays int `toml:"max_leaf_validity_days"`
	// resolved:
	Challenge string `toml:"-"`
}

// Log configures structured logging.
type Log struct {
	// Format is "text" (default, for terminals) or "json" (for service mode).
	Format string `toml:"format"`
	// Level is "debug", "info" (default), "warn", or "error".
	Level string `toml:"level"`
}

// Default returns a Config with sane zero-config defaults applied. Callers layer
// file and env values on top before validation.
func Default() Config {
	return Config{
		Server: Server{
			Listen:  ":443",
			MDMPath: "/mdm",
			TLS:     TLS{Mode: TLSACME},
		},
		Storage: Storage{
			Driver: DriverSQLite,
			Path:   "/var/db/cairn/cairn.db",
		},
		CA:  CA{Mode: CAGenerate},
		Log: Log{Format: "text", Level: "info"},
	}
}

// Load reads the TOML file at path (if non-empty), applies environment overrides,
// resolves secret references, and validates the result.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config %q: %w", path, err)
		}
		dec := toml.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %q: %w", path, err)
		}
	}

	applyEnvOverrides(&cfg)

	if err := resolveSecrets(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// applyEnvOverrides applies a small set of explicit MDM_* environment overrides.
// These win over file values so a container/systemd unit can parameterize a
// baked-in config without editing it.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("CAIRN_PUBLIC_URL"); v != "" {
		cfg.Server.PublicURL = v
	}
	if v := os.Getenv("CAIRN_LISTEN"); v != "" {
		cfg.Server.Listen = v
	}
	if v := os.Getenv("CAIRN_STORAGE_PATH"); v != "" {
		cfg.Storage.Path = v
	}
	if v := os.Getenv("CAIRN_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("CAIRN_LOG_FORMAT"); v != "" {
		cfg.Log.Format = v
	}
}

// resolveSecrets reads secret values from their _file/_env references.
func resolveSecrets(cfg *Config) error {
	// Storage DSN.
	dsn, err := readSecret("storage.dsn", cfg.Storage.DSN, cfg.Storage.DSNFile, cfg.Storage.DSNEnv)
	if err != nil {
		return err
	}
	cfg.Storage.DSN = dsn

	// External CA challenge.
	ch, err := readSecret("ca.external.challenge", "", cfg.CA.External.ChallengeFile, cfg.CA.External.ChallengeEnv)
	if err != nil {
		return err
	}
	cfg.CA.External.Challenge = ch
	if cfg.CA.External.Lookup.Enabled {
		secret, err := readSecret("ca.external.challenge_lookup.secret", "", cfg.CA.External.Lookup.SecretFile, cfg.CA.External.Lookup.SecretEnv)
		if err != nil {
			return err
		}
		cfg.CA.External.Lookup.Secret = secret
	}

	// LDAP bind password.
	if cfg.Auth.LDAP.Enabled {
		pw, err := readSecret("auth.ldap.bind_password", "", cfg.Auth.LDAP.BindPasswordFile, cfg.Auth.LDAP.BindPasswordEnv)
		if err != nil {
			return err
		}
		cfg.Auth.LDAP.BindPassword = pw
	}

	// Alert webhook URL (treated as a secret: ntfy topics are bearer-like).
	hook, err := readSecret("alerts.webhook_url", cfg.Alerts.WebhookURL, cfg.Alerts.WebhookURLFile, cfg.Alerts.WebhookURLEnv)
	if err != nil {
		return err
	}
	cfg.Alerts.WebhookURL = hook

	// RADIUS rejection-ingest token.
	tok, err := readSecret("radius.ingest_token", "", cfg.RADIUS.IngestTokenFile, cfg.RADIUS.IngestTokenEnv)
	if err != nil {
		return err
	}
	cfg.RADIUS.IngestToken = tok

	// OIDC client secret.
	if cfg.Auth.OIDC.Enabled {
		sec, err := readSecret("auth.oidc.client_secret", "", cfg.Auth.OIDC.ClientSecretFile, cfg.Auth.OIDC.ClientSecretEnv)
		if err != nil {
			return err
		}
		cfg.Auth.OIDC.ClientSecret = sec
	}

	return nil
}

// readSecret resolves a secret from, in priority order: an env var name, a file
// path, or an inline literal. An inline literal is permitted (so tests and
// quick starts work) but is the least-preferred form.
func readSecret(name, inline, file, env string) (string, error) {
	if env != "" {
		if v, ok := os.LookupEnv(env); ok {
			return v, nil
		}
		return "", fmt.Errorf("%s: env var %q is not set", name, env)
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("%s: read secret file: %w", name, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return inline, nil
}

// ParseSource reads an address or a network in CIDR form.
func ParseSource(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Validate checks that the resolved config is internally consistent.
func (c Config) Validate() error {
	var errs []error

	if c.Issuance.LeafValidityDays < 0 || c.Issuance.LeafValidityDays > 825 {
		errs = append(errs, errors.New("issuance.leaf_validity_days must be between 1 and 825"))
	}
	if c.VPN.LeafValidityDays < 0 || c.VPN.LeafValidityDays > 825 {
		errs = append(errs, errors.New("vpn.leaf_validity_days must be between 1 and 825"))
	}
	if k := c.VPN.KeyType; k != "" && k != "rsa2048" && k != "p256" {
		errs = append(errs, fmt.Errorf("vpn.key_type must be rsa2048 or p256, got %q", k))
	}
	switch is := c.VPN.Issuer; is.Backend {
	case "", "embedded":
	case "scep":
		if is.SCEPURL == "" || is.RACertFile == "" || is.RAKeyFile == "" || is.CAChainFile == "" {
			errs = append(errs, errors.New("vpn.issuer backend scep needs scep_url, ra_cert_file, ra_key_file and ca_chain_file"))
		}
		if is.MaxLeafValidityDays < 0 || is.MaxLeafValidityDays > 825 {
			errs = append(errs, errors.New("vpn.issuer.max_leaf_validity_days must be between 1 and 825"))
		}
	default:
		errs = append(errs, fmt.Errorf("vpn.issuer.backend must be embedded or scep, got %q", is.Backend))
	}
	if c.Renewal.RenewBeforeDays < 0 || c.Renewal.RenewBeforeDays > 365 {
		errs = append(errs, errors.New("renewal.renew_before_days must be between 1 and 365"))
	}
	if c.Renewal.ExpiredGraceDays < 0 || c.Renewal.ExpiredGraceDays > 365 {
		errs = append(errs, errors.New("renewal.expired_grace_days must be between 0 and 365"))
	}
	if c.Renewal.Enabled && c.CA.Mode != CAExternal {
		errs = append(errs, fmt.Errorf("renewal.enabled needs ca.mode external; in mode %q devices are re-enrolled before expiry (see docs/certificate-lifecycle.md)", c.CA.Mode))
	}
	for _, h := range c.Renewal.ServerHosts {
		if u, err := url.Parse("https://" + h); err != nil || u.Host != h || strings.ContainsAny(h, "/ ") {
			errs = append(errs, fmt.Errorf("renewal.server_hosts entry %q must be a host name, optionally with a port", h))
		}
	}
	if len(c.RADIUS.AcceptancePoints) > 0 && c.RADIUS.IngestToken == "" {
		errs = append(errs, errors.New("radius.acceptance_points set but no radius.ingest_token_file/_env; rejections could not be ingested"))
	}
	if len(c.RADIUS.AcceptancePoints) == 0 && c.RADIUS.IngestToken != "" {
		errs = append(errs, errors.New("radius.ingest_token configured but radius.acceptance_points is empty"))
	}
	if c.Alerts.WebhookURL != "" {
		if u, err := url.Parse(c.Alerts.WebhookURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, errors.New("alerts.webhook_url must be an absolute http(s) URL"))
		}
	}

	if c.Server.PublicURL == "" {
		errs = append(errs, errors.New("server.public_url is required"))
	} else if u, err := url.Parse(c.Server.PublicURL); err != nil || u.Scheme != "https" || u.Host == "" {
		errs = append(errs, fmt.Errorf("server.public_url must be an absolute https URL, got %q", c.Server.PublicURL))
	}
	if c.Server.Listen == "" {
		errs = append(errs, errors.New("server.listen is required"))
	}
	if !strings.HasPrefix(c.Server.MDMPath, "/") {
		errs = append(errs, fmt.Errorf("server.mdm_path must start with '/', got %q", c.Server.MDMPath))
	}

	switch c.Server.TLS.Mode {
	case TLSACME:
		if c.Server.TLS.ACMEEmail == "" {
			errs = append(errs, errors.New("server.tls.acme_email is required when tls.mode=acme"))
		}
	case TLSFiles:
		if c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "" {
			errs = append(errs, errors.New("server.tls.cert_file and key_file are required when tls.mode=files"))
		}
	case TLSProxy:
		// nothing required; trusted_proxies may be empty (loopback-only).
	default:
		errs = append(errs, fmt.Errorf("server.tls.mode must be acme|files|proxy, got %q", c.Server.TLS.Mode))
	}

	switch c.Storage.Driver {
	case DriverSQLite:
		if c.Storage.Path == "" {
			errs = append(errs, errors.New("storage.path is required when storage.driver=sqlite"))
		}
	case DriverMySQL, DriverPostgres:
		if c.Storage.DSN == "" {
			errs = append(errs, fmt.Errorf("storage.dsn (or dsn_file/dsn_env) is required when storage.driver=%s", c.Storage.Driver))
		}
	default:
		errs = append(errs, fmt.Errorf("storage.driver must be sqlite|mysql|postgres, got %q", c.Storage.Driver))
	}

	switch c.CA.Mode {
	case CAGenerate:
		// CA is self-generated on first boot by the ca package.
	case CAImport:
		if c.CA.Import.CertFile == "" || c.CA.Import.KeyFile == "" {
			errs = append(errs, errors.New("ca.import.cert_file and key_file are required when ca.mode=import"))
		}
	case CAExternal:
		if c.CA.External.SCEPURL == "" {
			errs = append(errs, errors.New("ca.external.scep_url is required when ca.mode=external"))
		}
		if c.CA.External.CAChainFile == "" {
			errs = append(errs, errors.New("ca.external.ca_chain_file is required when ca.mode=external (trust anchor for the enrollment profile)"))
		}
		if l := c.CA.External.Lookup; l.Enabled {
			if len(l.Secret) < 32 {
				errs = append(errs, errors.New("ca.external.challenge_lookup needs secret_file or secret_env holding at least 32 characters"))
			}
			for _, src := range l.AllowedSources {
				if _, err := ParseSource(src); err != nil {
					errs = append(errs, fmt.Errorf("ca.external.challenge_lookup.allowed_sources: %q is not an address or network", src))
				}
			}
		}
	case CABroker:
		if c.CA.Broker.SCEPURL == "" {
			errs = append(errs, errors.New("ca.broker.backend_scep_url is required when ca.mode=broker"))
		}
		if c.CA.Broker.RACertFile == "" || c.CA.Broker.RAKeyFile == "" {
			errs = append(errs, errors.New("ca.broker.ra_cert_file and ra_key_file are required when ca.mode=broker (the RA identity that signs the backend SCEP envelope)"))
		}
		if c.CA.Broker.CAChainFile == "" {
			errs = append(errs, errors.New("ca.broker.backend_ca_chain_file is required when ca.mode=broker (trust anchor for enrollment profiles + reply parsing)"))
		}
	default:
		errs = append(errs, fmt.Errorf("ca.mode must be generate|import|external|broker, got %q", c.CA.Mode))
	}

	if s := c.Profile.Signing; s.Enabled() {
		if s.CertFile == "" || s.KeyFile == "" {
			errs = append(errs, errors.New("profile.signing needs both cert_file and key_file"))
		}
	}

	if l := c.Auth.LDAP; l.Enabled {
		if l.DirectoryID != "" && (len(l.DirectoryID) > 128 || strings.ContainsFunc(l.DirectoryID, func(r rune) bool {
			return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_')
		})) {
			errs = append(errs, errors.New("auth.ldap.directory_id must be at most 128 lowercase letters, digits, dots, underscores or hyphens"))
		}
		if len(l.Servers) == 0 {
			errs = append(errs, errors.New("auth.ldap.servers is required when ldap is enabled"))
		}
		for _, s := range l.Servers {
			u, err := url.Parse(s)
			if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
				errs = append(errs, fmt.Errorf("auth.ldap.servers entry %q must be ldap://host:port or ldaps://host:port", s))
				continue
			}
			// Reject plaintext transport: a bare ldap:// URL sends the bind
			// password (service account and user) in cleartext unless StartTLS
			// upgrades the connection. Require ldaps:// or start_tls=true.
			if u.Scheme == "ldap" && !l.StartTLS {
				errs = append(errs, fmt.Errorf("auth.ldap.servers entry %q uses plaintext ldap:// without start_tls; use ldaps:// or set start_tls=true", s))
			}
		}
		if l.BaseDN == "" {
			errs = append(errs, errors.New("auth.ldap.base_dn is required when ldap is enabled"))
		}
		if l.BindDN == "" || l.BindPassword == "" {
			errs = append(errs, errors.New("auth.ldap.bind_dn and bind_password_file/env are required when ldap is enabled"))
		}
		for dn, role := range l.GroupRoles {
			switch role {
			case "admin", "operator", "user":
			default:
				errs = append(errs, fmt.Errorf("auth.ldap.group_roles[%q] must be admin|operator|user, got %q", dn, role))
			}
		}
		if l.DefaultRole != "" && l.DefaultRole != "admin" && l.DefaultRole != "operator" && l.DefaultRole != "user" {
			errs = append(errs, fmt.Errorf("auth.ldap.default_role must be admin|operator|user, got %q", l.DefaultRole))
		}
	}

	if o := c.Auth.OIDC; o.Enabled {
		if o.IssuerURL == "" {
			errs = append(errs, errors.New("auth.oidc.issuer_url is required when oidc is enabled"))
		} else if u, err := url.Parse(o.IssuerURL); err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, fmt.Errorf("auth.oidc.issuer_url must be an absolute https URL, got %q", o.IssuerURL))
		}
		if o.ClientID == "" {
			errs = append(errs, errors.New("auth.oidc.client_id is required when oidc is enabled"))
		}
		// ClientSecret has already been resolved from _file/_env by resolveSecrets.
		if o.ClientSecret == "" {
			errs = append(errs, errors.New("auth.oidc.client_secret_file or client_secret_env is required when oidc is enabled"))
		}
		for g, role := range o.GroupRoles {
			switch role {
			case "admin", "operator", "user":
			default:
				errs = append(errs, fmt.Errorf("auth.oidc.group_roles[%q] must be admin|operator|user, got %q", g, role))
			}
		}
		if o.DefaultRole != "" && o.DefaultRole != "admin" && o.DefaultRole != "operator" && o.DefaultRole != "user" {
			errs = append(errs, fmt.Errorf("auth.oidc.default_role must be admin|operator|user, got %q", o.DefaultRole))
		}
	}

	// Login policy: reject any explicitly-negative value. Zero means "use the
	// default" (see LoginPolicy.WithDefaults), so only negatives are errors.
	lp := c.Auth.Login
	for _, f := range []struct {
		name string
		val  int
	}{
		{"max_attempts", lp.MaxAttempts},
		{"window_seconds", lp.WindowSeconds},
		{"lockout_seconds", lp.LockoutSeconds},
		{"min_password_len", lp.MinPasswordLen},
		{"idle_timeout_mins", lp.IdleTimeoutMins},
		{"max_lifetime_mins", lp.MaxLifetimeMins},
	} {
		if f.val < 0 {
			errs = append(errs, fmt.Errorf("auth.login.%s must not be negative, got %d", f.name, f.val))
		}
	}

	return errors.Join(errs...)
}
