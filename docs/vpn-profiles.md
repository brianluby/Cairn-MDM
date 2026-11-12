# VPN profiles

Status: in development, November 2026. Server records, the profile renderer,
issuance from Cairn's own CA and delivery are implemented and covered by
automated tests. Issuance from an external SCEP CA is wired but has not run
against a real CA. No profile rendered by Cairn has been installed on a real
device yet, and macOS is not built.

## What it does

An administrator defines an OpenVPN server once. From a device's page they send
that device a profile for the server. Cairn generates a key, has the CA certify
it for the owner's directory account, and pushes a configuration profile that
OpenVPN Connect on iOS and iPadOS reads. The certificate's common name is the
account name, so a server set to match the certificate name against the login
name refuses a certificate used with someone else's password.

The certificate identifies the device and its owner. The directory decides at
every connection whether that owner may connect. Disable the account to cut off
a person; revoke the certificate for a lost device.

## Why Cairn makes the key

OpenVPN Connect on iOS keeps its own keychain and cannot use an identity that a
SCEP or PKCS#12 payload installs. The certificate and key have to travel inside
the VPN payload. Cairn therefore generates the key, which differs from device
enrollment, where the key never leaves the device.

Where the key exists:

| place | how long |
| --- | --- |
| memory of the Cairn process | while the profile is rendered |
| the queued InstallProfile command in the database | until the device answers, the device is disabled, or seven days pass |
| the device | until the profile is removed or replaced |

When the device acknowledges or rejects the profile, Cairn replaces the queued
command body with a placeholder in the same transaction. A profile no device
collects for seven days is withdrawn the same way and its certificate is
revoked. Cairn never writes the key to any other table or to its logs.

A backup taken while a profile waits in the queue contains that key. `cairn
backup` says so in the bundle's notes.

## Setup

```toml
[vpn]
enabled = true
# leaf_validity_days = 365
# key_type = "rsa2048"   # or "p256"

# Without this section Cairn's own CA signs VPN certificates.
# [vpn.issuer]
# backend = "scep"
# scep_url = "https://ca.example.org/scep/vpn"
# ra_cert_file = "/etc/cairn/vpn-ra.crt"
# ra_key_file = "/etc/cairn/vpn-ra.key"
# max_leaf_validity_days = 400
```

The VPN server decides which CA works: its client-certificate trust has to
include the CA that signs here. A server that trusts an existing CA needs the
`scep` backend pointed at that CA.

Requirements for issuing:

- A CA. Either `ca.mode` is `generate` or `import`, so Cairn has its own, or
  `[vpn.issuer] backend = "scep"` names a SCEP endpoint that accepts requests
  signed by the RA certificate in `ra_cert_file`. Cairn sends the account name
  as the common name and the account's UPN as an email SAN, and holds any
  certificate that comes back with a different common name, a different SAN
  set, a usage other than client authentication, or a longer lifetime than
  `max_leaf_validity_days`.
- `auth.ldap` is configured with a `directory_id`, so certificate owners are
  verified directory accounts.

With only `[vpn] enabled`, the server records page works and the console says
what is missing for issuing.

Cairn creates `<storage.path>.vpn/key` on first use. It encrypts each server's
shared TLS key in the database. `cairn backup` includes the file, and bundle
verification fails if the database holds encrypted keys and the file is absent.

## Server records

VPN > Add server. Paste a client `.ovpn` file exported for the server to fill in
the form, check the fields, save. A client certificate or key in the pasted file
is dropped. Fields:

- Addresses, one per line. Each becomes its own connection on the device and
  all share one certificate. Add a TCP address for networks that block UDP. A
  fourth value on a line sets the tunnel MTU for that address.
- Server certificate name: the exact common name of the server's certificate.
- CA chain that signed the server certificate.
- TLS key: `tls-auth` (with key direction) or `tls-crypt`, and the static key.
  The stored key is never shown again; paste a new one to replace it.
- Whether the server also asks for a username and password.
- Connect on demand, for servers that need no password.

The identifier cannot change after creation: it is part of the profile's
`PayloadIdentifier`, which is what makes a new profile replace the old one on
the device.

Creating, changing and deleting a server needs the admin role and an MFA code
verified in the last five minutes.

## Sending a profile

On the device page, under VPN, choose Send profile.

- A device enrolled through an owner-authorized link gets a certificate for its
  verified owner.
- Any other device has no verified owner. The administrator names the directory
  account, and Cairn resolves it in the directory before asking the CA.

The account is checked again immediately before the CA signs. A disabled or
missing account stops the request.

On iPhone and iPad, install OpenVPN Connect first, and make the first connection
from inside that app so the username is filled in and the password prompt
appears.

Sending again issues a new certificate and key under the same payload
identifier. The device replaces the installed profile, and the earlier
certificate is marked replaced once the new profile is acknowledged.

## Revocation

- Revoke certificate, on the device page, is for a lost or stolen device.
- With Cairn's own CA the certificate is revoked immediately and appears in the
  CRL. Replaced and never-installed certificates are revoked by an hourly sweep.
- With a SCEP CA, Cairn cannot revoke. The VPN page lists the serials to revoke
  at the CA, and an administrator confirms each one there.
- The VPN server has to read that CRL for a revocation to stop a connection.
  Until it does, disabling the directory account is what stops access.

## When the CA's answer cannot be trusted

If the CA returns a certificate that differs from the request, Cairn sends
nothing, records the request as held and raises an alert. The VPN page lists
held requests. Check the CA, revoke what it issued, close the hold and send a
new profile.

## Alerts

- VPN certificates expiring within 30 days, and expired ones.
- Requests held for review.
- Certificates retired in Cairn that the CA has not revoked after two hours.

## Not built yet

- A run of the SCEP issuer against a real CA.
- One connection that tries several addresses in turn.
- Native IKEv2 profiles that use the device's enrolled identity.
- macOS: a keychain identity pushed by MDM plus a Viscosity connection.
- Automatic re-issue before expiry.
- Certificate classes that keep a VPN certificate from being accepted where a
  device identity certificate is expected. VPN and device certificates from the
  embedded CA share an issuer and the client-authentication usage; they differ
  in subject. Treat this as open before relying on either for network access.
