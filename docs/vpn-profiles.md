# VPN profiles

Status: beta, November 2026. Server records, the profile renderers, issuance
from Cairn's own CA or an external SCEP CA, and delivery are implemented and
covered by automated tests.

On real devices so far (November 16, 2026, external SCEP CA, pfSense as the
IKEv2 server, FreeRADIUS for EAP):

- An IKEv2 password profile connected from an iPhone on Wi-Fi and on cellular.
- An IKEv2 EAP-TLS profile, with a key the iPhone made and a certificate issued
  through the external CA, connected from that iPhone. The same profile
  installed on a Mac and an iPad.
- The profile that sends all traffic through the tunnel installed on an iPhone;
  calling and AirDrop with it have not been recorded yet.

No OpenVPN profile from Cairn has a recorded connection from a device, and
macOS delivery for OpenVPN is not built.

## What it does

An administrator defines an OpenVPN server once. From a device's page they send
that device a profile for the server. Cairn generates a key, has the CA certify
it for the owner's directory account, and pushes a configuration profile that
OpenVPN Connect on iOS and iPadOS reads. The certificate's common name is the
account name, so a server set to match the certificate name against the login
name refuses a certificate used with someone else's password.

The certificate identifies the device and its owner. What it grants is decided
by the VPN server, not by Cairn. Cairn checks the owner's account when it
issues; it is not asked at each connection. For a disabled account to stop
access, the server has to ask the directory for a password as well as a
certificate. For a revoked certificate to stop access, the server has to check
the CA's revocation list. A server set to accept a certificate alone, with no
revocation list, keeps accepting it until it expires. Test both refusals on
your own server before relying on them.

Everyone's certificates for one person carry the same common name. An OpenVPN
server drops the earlier connection when a second one arrives with that name
unless it allows duplicate names, so a person with two devices needs that
setting.

Supported today: Active Directory or Samba as the owner directory, and either
Cairn's own CA or a SCEP CA that accepts requests signed by an RA certificate.
Profiles are for OpenVPN Connect on iPhone and iPad; Cairn refuses to send one
to a Mac.

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

Replacing the body removes the key from the live database rows. It does not
wipe earlier copies in the SQLite write-ahead log, free pages, filesystem
snapshots or backups taken while the profile waited. Protect the database
volume and backups accordingly.

A backup taken while a profile waits in the queue contains that key. `cairn
backup` says so in the bundle's notes.

## Setup

```toml
[vpn]
enabled = true
# leaf_validity_days = 365
# key_type = "rsa2048"   # or "p256"
# renew_before_days = 45 # replace certificates this long before expiry; 0 (default) is off

# Without this section Cairn's own CA signs VPN certificates.
# [vpn.issuer]
# backend = "scep"
# scep_url = "https://ca.example.org/scep/vpn"
# ra_cert_file = "/etc/cairn/vpn-ra.crt"
# ra_key_file = "/etc/cairn/vpn-ra.key"
# ca_chain_file = "/etc/cairn/ca-chain.pem"
# max_leaf_validity_days = 400
```

The VPN server decides which CA works: its client-certificate trust has to
include the CA that signs here. A server that trusts an existing CA needs the
`scep` backend pointed at that CA.

`ca_chain_file` pins the SCEP CA. Cairn refuses an endpoint whose certificates
do not chain to it and holds any issued certificate that does not.

Before the first device, test the CA with a throwaway account name:

```
cairn vpn check-issuer -cn vpn-test -email vpn-test@example.org
```

It sends one real request, prints the certificate the CA returned and says
whether Cairn would accept it. The key is discarded and nothing is stored.
Revoke the test certificate at the CA afterwards.

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

## Renewal before expiry

With `[vpn] renew_before_days` set, Cairn sends a device a new profile and
certificate by itself when the installed certificate has that many days left.
It is off by default. It runs in the hourly sweep and does what Send profile
does, with these differences:

- No administrator and no authenticator code take part. The device already
  holds a certificate an administrator approved; Cairn replaces it for the same
  account on the same device.
- The account is checked in the directory first. If it is disabled, missing, or
  its name or sign-in name has changed, nothing is sent and the certificate
  runs out. Send a profile by hand if the change is intended.
- A device that has left management gets nothing.
- Each certificate is tried once a day. A profile the device has not collected
  is withdrawn after seven days and sent again at the next sweep.
- A certificate in the first half of its life is never replaced, whatever the
  setting says.

The audit log records these under the name `cairn-vpn-renewal`. Set the window longer than 30 days, so the "expire within
30 days" alert means renewal has been failing and not that it has just begun.

With a CA Cairn cannot revoke at, the replaced certificate stays valid at the
CA until it expires and is listed on the VPN page like any other replaced
certificate. It has at most the renewal window left.

This is tested in-process only. No device has been through it.

## Revocation

- Revoke certificate, on the device page, is for a lost or stolen device.
- With Cairn's own CA the certificate is revoked immediately and appears in the
  CRL. Replaced and never-installed certificates are revoked by an hourly sweep.
- With a SCEP CA, Cairn cannot revoke. The VPN page lists the serials to revoke
  at the CA, and an administrator confirms each one there.
- The VPN server has to read that CRL for a revocation to stop a connection.
- Cairn revokes only at the CA that issued the certificate. After a change of
  issuer, certificates from the earlier CA are listed for revocation by hand.
- Disabling a device in Cairn or removing the profile does not retire the
  certificate. Revoke it.

## When the CA's answer cannot be trusted

If the CA returns a certificate that differs from the request, Cairn sends
nothing, records the request as held and raises an alert. The VPN page lists
held requests. Check the CA, revoke what it issued, close the hold and send a
new profile. A request is also held when Cairn stopped before it recorded the
CA's answer.

## Alerts

- VPN certificates expiring within 30 days, and expired ones.
- Requests held for review.
- Certificates retired in Cairn that the CA has not revoked after two hours.

## IKEv2 servers

A server record can also describe a native IKEv2 server. The device's built-in
client is used, so no app is needed, and the profile works on a Mac as well as
an iPhone or iPad. Add one from VPN > Add IKEv2 server.

The record holds the server address, the IKE identifier, the server
certificate's name and issuer, one encryption proposal used for both security
associations, and how devices sign in:

| Sign-in | What the profile carries | State |
|---|---|---|
| Account name and password (EAP-MSCHAPv2) | The account name and no password. Downloaded and installed by hand; the user stores the password in Settings | A pushed copy connected from an iPhone; the download is tested in-process only |
| Certificate over EAP (EAP-TLS) | A SCEP request, so the device makes its own key | Built and tested in-process over HTTP against Cairn's own CA; no device test, no run against an external CA |
| Certificate (IKE certificate authentication) | The same | The same |

Cairn never puts a password, a shared secret or a private key in an IKEv2
profile, and checks every rendered profile for all three before it is queued.

With On Demand the profile connects on Wi-Fi and cellular and stays off the VPN
on any other network. Wi-Fi networks listed as trusted disconnect it. The user
can switch On Demand off in Settings unless the record locks it.

Every IKEv2 profile sends all traffic through the tunnel while the VPN is up.
What the tunnel cannot carry is dropped and never leaves by the local network:
IPv6 on a server that hands out IPv4 only, for one. The device also does not
answer other machines on the same Wi-Fi. The profile sets these keys at the
top of the VPN payload, beside the On Demand keys:

| Key | Value | Why |
|---|---|---|
| `IncludeAllNetworks` | 1 | every flow enters the tunnel or is dropped |
| `ExcludeLocalNetworks` | 0 | 1 would put the device back in reach of the local subnet; Cairn refuses a profile that has it |
| `ExcludeCellularServices` | 1 | carrier calling and voicemail break inside a tunnel |
| `ExcludeDeviceCommunication` | 1 | AirDrop and Continuity use their own link and keep working |
| `ExcludeAPNs` | 0 | push notifications ride the tunnel |

The user's own VPN switch is the way past a sign-in page on a hotel network,
so leave On Demand unlocked on such a record. A record meant to carry a few
networks and leave the rest alone has "Let traffic the tunnel does not carry
use the local network" ticked, and its profiles carry none of these keys.

A password sign-in profile is not pushed by MDM. A VPN that MDM installs is
read-only in the device's settings, so the user cannot store the password and
is asked at every connection, and On Demand cannot run. Download the profile
for an account from the server's page (it needs a fresh MFA code), give the
file to that person, and have them store their password under Settings > VPN
> (i) after installing it. The file holds the account name and the server
settings and no secret, and is signed when profile signing is configured.

On trial: a password record can be set to push its profile with an empty
password field, which is reported to make a device ask once and keep the
password even for a pushed profile. It has not been confirmed on a device.
A rendered profile with any value in that field is refused.

### Certificate sign-in

The device makes the key and it never leaves the device. Sending the profile
records an offer and puts a one-time challenge in the profile's SCEP payload;
nothing is asked of the CA yet. When the profile installs, the device sends
its request to `<public_url>/scep/vpn`. Cairn then:

1. Finds the offer by the challenge. Only a hash of the challenge is stored.
2. Refuses unless the device is still enrolled, the owner is still enabled in
   the directory, and the request asks for the offer's account name and
   nothing else: one common name, at most the owner's address, and no
   extension beyond a key usage. An external CA is sent the device's request
   as it is, so a request that says more never reaches it.
3. Binds the offer to that public key. The same key may repeat its request
   until the profile is reported installed; any other key is refused.
4. Builds the certificate from the offer, has the configured CA sign it (its
   own, or an external one through the RA certificate), and checks what came
   back the same way as for an OpenVPN certificate.

An offer nobody answers is withdrawn after seven days, when the device
reports that the profile failed, or as soon as the device's enrollment ends;
its queued profile is replaced. "Withdraw profile" on the device page ends one
sooner, for a profile sent to the wrong device or for the wrong account.

If the device gave up, left management, or its owner was disabled while the CA
was working, the certificate is not handed over. It is recorded as issued with
no holder and listed for revocation.

The endpoint is reachable by anyone who can reach Cairn; the challenge is what
authorizes a request. Someone who reads the challenge out of the profile on the
device before the device uses it could get the certificate for a key of their
own. They would be the device's own user getting a certificate in their own
name, and the device's request would then fail.

With an external SCEP CA, the device's request is passed on with Cairn's
challenge still in it. The CA must issue on the RA's signature and ignore a
challenge it does not know. Check this once with
`cairn vpn check-issuer -device-request -cn <test> -email <address>` and revoke
the test certificate.

The CA chain is optional in an IKEv2 record. Devices normally trust the CA
already, from their enrollment profile, and the profile then carries no
certificates. Give the chain to have the issuer name checked against it, and
tick "Install this chain with every profile" only when the VPN server's CA is
not one the devices trust yet.

## Not built or not proven yet

- A recorded device connection with an OpenVPN profile.
- Whether an empty password field lets a pushed IKEv2 password profile keep
  the password (the trial setting).
- Gateway refusals: a disabled account, a revoked certificate, and two devices
  for one owner.
- A deployment record for a pushed password profile. It shows in the device's
  command history only.
- A setting for the server certificate revocation check in IKEv2 profiles. It
  is off.
- One connection that tries several addresses in turn.
- More than one value for an option such as `route` or `dhcp-option`; the
  server form refuses a repeat and the importer keeps the first.
- macOS: a keychain identity pushed by MDM plus a Viscosity connection.
- Renewal before expiry on a real device.
- Certificate classes that keep a VPN certificate from being accepted where a
  device identity certificate is expected. VPN and device certificates from the
  embedded CA share an issuer and the client-authentication usage; they differ
  in subject. Treat this as open before relying on either for network access.
