# Installing Cairn

This guide covers the beta (v0.2). Pick your environment in the first section,
install the binary, then follow the steps for that environment.

## Pick your environment

Two things decide how you set Cairn up: whether you have an LDAP or Active
Directory server, and where device certificates come from.

| You have | Use | Enrollment links | Verified device owner | Certificate renewal | State |
|---|---|---|---|---|---|
| LDAP/AD, no certificate authority | `ca.mode = "generate"` | Yes | Yes | Re-enroll before expiry | Automated tests only |
| LDAP/AD and your own CA key (an AD CS subordinate, for one) | `ca.mode = "import"` | Yes | Yes | Re-enroll before expiry | Automated tests only |
| LDAP/AD and a SCEP CA; Cairn should decide every certificate | `ca.mode = "broker"` | Yes | Yes | Re-enroll before expiry | Automated tests, one run against OpenXPKI |
| LDAP/AD and a SCEP CA that can check a challenge with another system (OpenXPKI) | `ca.mode = "external"` with challenge lookup | Yes | No | Yes, by Cairn | Runs the author's fleet |
| A SCEP CA with one shared challenge (NDES, or OpenXPKI without the lookup) | `ca.mode = "external"` | No, open enrollment only | No | Yes, with a known limit | Ran the author's fleet until November 2026 |
| No LDAP/AD | See "No directory" below | No | No | | Limited |

"Verified device owner" means Cairn knows which directory account a device
belongs to, because Cairn built or approved the certificate itself. Profile
rules by AD group or OU, and a group chosen on the enrollment link, apply only
to devices with a verified owner. Without one, add devices to groups by hand.

VPN profiles need LDAP/AD in every mode.

### No directory

This beta does not serve a site with no LDAP or AD server well, and you should
know that before you install it:

- Enrollment links are made for an owner looked up in the directory. With no
  directory the console cannot make one.
- The embedded CA and the broker only issue for such a link. Open enrollment
  (`enrollment.allow_open = true`) hands out a profile, but its certificate
  request is refused.
- What does work with no directory is an external SCEP CA with a shared
  challenge and open enrollment: anyone who can reach `/enroll` can enroll.
  Use it on a network you control, or not at all.

If you run a home network and want the full feature set, a small Samba AD
domain is the supported route today.

## What every environment needs

- A host: Linux, FreeBSD or macOS on amd64 or arm64, or a container runtime.
  One process, one config file, one SQLite database.
- A public HTTPS name for the server, such as `https://mdm.example.org`.
  Devices are enrolled against that exact name, so do not change it later. The
  certificate has to be one the devices already trust; a public one (Let's
  Encrypt) is the easy choice.
- Outbound access from the server to Apple's push service, and from devices to
  the server.
- An APNs push certificate. Cairn walks you through requesting one; it is free.
- An authenticator app. An administrator needs a confirmed authenticator to
  create enrollment links and send VPN profiles.

## Install the binary

The installer downloads the release for your OS and architecture, checks its
SHA-256 against the published list, and installs `cairn` in `/usr/local/bin`.
A beta is a GitHub prerelease, which "latest" skips, so name the version:

```sh
curl -fsSL https://raw.githubusercontent.com/nickpdawson/Cairn-MDM/main/packaging/install.sh | sh -s -- v0.2.0-beta.2
```

Other ways:

- **Debian, Ubuntu, RHEL and relatives:** the `.deb` or `.rpm` from the
  releases page. It creates a `cairn` user, `/var/lib/cairn`, `/etc/cairn`, a
  systemd unit, and `/etc/cairn/cairn.example.toml`.
- **Container:** `ghcr.io/nickpdawson/cairn-mdm:<version>`. Mount a config at
  `/etc/cairn/cairn.toml` and a volume at `/var/lib/cairn` owned by UID 65532.
- **FreeBSD:** the release tarball carries `contrib/rc.d/cairn`. Copy it to
  `/usr/local/etc/rc.d/`, create a `cairn` user, and set `cairn_enable="YES"`
  in `/etc/rc.conf`.
- **From source:** `go build ./cmd/cairn` (Go 1.26 or later, no cgo).

Default paths:

| | Config | Data |
|---|---|---|
| Linux | `/etc/cairn/cairn.toml` | `/var/lib/cairn` |
| FreeBSD | `/usr/local/etc/cairn/cairn.toml` | `/var/db/cairn` |
| macOS | `/opt/homebrew/etc/cairn/cairn.toml` | `~/Library/Application Support/cairn` |

The config file and the data directory hold keys. Keep both readable by the
`cairn` user only.

## How devices reach the server

Set this under `[server.tls]`:

- `mode = "acme"`: Cairn listens on 443 and gets its own Let's Encrypt
  certificate. Needs public DNS and port 443 open to the internet. Set
  `acme_email`.
- `mode = "files"`: you supply `cert_file` and `key_file`.
- `mode = "proxy"`: a reverse proxy (nginx, Caddy, Nginx Proxy Manager)
  terminates TLS and forwards plain HTTP to Cairn. Set `listen` to the port the
  proxy forwards to, and list the proxy under `trusted_proxies` so logs and
  login throttling see the real client address.

## Set up by environment

`packaging/cairn.example.toml` documents every setting. The fragments below
show what differs between environments.

### LDAP/AD with Cairn's own CA

```sh
cairn init --public-url https://mdm.example.org --acme-email you@example.org
```

`init` writes the config, creates the CA in the database and creates the first
administrator. Then add your directory to the config:

```toml
[auth.ldap]
enabled = true
directory_id = "example-ad"        # a name you choose once and never change
servers = ["ldaps://dc1.example.org:636"]
base_dn = "DC=example,DC=org"
bind_dn = "CN=svc-mdm,CN=Users,DC=example,DC=org"
bind_password_file = "/etc/cairn/ldap-bind-pw"

[auth.ldap.group_roles]
"CN=MDM Admins,CN=Users,DC=example,DC=org" = "admin"
```

Running a CA is a security decision: the signing key lives in Cairn's
database. Read the certificate authority section of `SECURITY.md` first.

### LDAP/AD with your own CA key

As above, with `--ca-mode import --ca-cert issuing.crt --ca-key issuing.key`.
To keep the root offline, give Cairn an issuing certificate and key and name
the root separately:

```toml
[ca]
mode = "import"
[ca.import]
cert_file = "/etc/cairn/issuing-ca.crt"
key_file = "/etc/cairn/issuing-ca.key"
root_cert_file = "/etc/cairn/root-ca.crt"
```

### LDAP/AD with Cairn as a broker in front of a SCEP CA

Devices send their request to Cairn. Cairn checks the enrollment link, builds
the certificate request itself and relays it to your CA, signed with an RA
certificate the CA accepts. The CA's SCEP endpoint need not be reachable by
devices. `cairn init` does not write this mode; edit the config:

```toml
[ca]
mode = "broker"
[ca.broker]
backend_scep_url = "https://ca.example.org/scep/mdm"
ra_cert_file = "/etc/cairn/ra.crt"
ra_key_file = "/etc/cairn/ra.key"
backend_ca_chain_file = "/etc/cairn/ca-chain.pem"
```

Design and limits: [enrollment authorization](enrollment-authorization.md).

### An external SCEP CA that checks challenges with Cairn

Devices send their request straight to your CA. The CA asks Cairn whether the
challenge in each request is good for that certificate name and key.

```sh
cairn init --public-url https://mdm.example.org --ca-mode external \
  --scep-url https://ca.example.org/scep/mdm --ca-chain /etc/cairn/ca-chain.pem
```

```toml
[ca.external.challenge_lookup]
enabled = true
secret_file = "/etc/cairn/scep-lookup-secret"   # 32 characters or more
allowed_sources = ["192.0.2.20"]                # the CA's address

[renewal]
enabled = true
```

Add `[auth.ldap]` as above. The CA-side setup, with an OpenXPKI example, is in
[certificate lifecycle](certificate-lifecycle.md).

### An external SCEP CA with a shared challenge

```toml
[ca]
mode = "external"
[ca.external]
scep_url = "https://ca.example.org/scep/mdm"
ca_chain_file = "/etc/cairn/ca-chain.pem"
challenge_file = "/etc/cairn/scep-challenge"

[enrollment]
allow_open = true
```

The challenge is in every enrollment profile, and the CA issues to anyone who
presents it. Limit who can reach `/enroll` and the CA's SCEP endpoint. Do not
use these certificates for network access.

## After the config is written

1. Start the service: `systemctl enable --now cairn`, or `service cairn start`
   on FreeBSD. `GET /readyz` answers 200 when it is up.
2. If you did not use `cairn init`, open `https://<your name>/setup`. Cairn
   wrote a one-time token to `<storage.path>.setup-token` on the host; entering
   it creates the first administrator.
3. Set up the administrator's authenticator: [MFA](mfa.md).
4. Load the APNs push certificate from the console's APNs page, or with
   `cairn pushcert request -email you@example.org`:
   [APNs lifecycle](apns-lifecycle.md).
5. Sign profiles, so devices show a verified signer: `[profile.signing]` in
   the example config.
6. Enroll a first device: [enrollment and recovery](enrollment-onboarding.md).
7. Turn on backups and alerts before you depend on it:
   [backup and restore](backup-restore.md).

## Coming from NanoMDM

`cairn import -from-mysql <dsn>` brings an existing NanoMDM fleet over without
re-enrolling devices: [migrating from NanoMDM](migrating-from-nanomdm.md). Two
things to set for a migrated fleet, both explained in
[certificate lifecycle](certificate-lifecycle.md):

- `[renewal] expired_grace_days`, if any device certificate has already
  expired. Without it those devices are refused.
- `[enrollment] check_out_when_removed` and `bootstrap_token`, to match the
  enrollment profile the devices already carry.
