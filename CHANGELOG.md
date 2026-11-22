# Changelog

## Unreleased

- **Other devices.** A page for devices that cannot enroll in MDM (a HomePod,
  an Apple Vision Pro without Apple Business Manager, an Apple Watch). Add one,
  download its Wi-Fi profile and install it by hand; the device makes its own
  key and asks Cairn for the certificate. The file works once, for ten
  minutes. Cairn tracks each certificate's expiry, since it cannot renew
  these. `[vpn] manual_leaf_validity_days` sets a longer life for them. Tested
  on a HomePod; not yet on a Vision Pro or watch. Adds migration 40. See
  [VPN profiles](docs/vpn-profiles.md#devices-outside-mdm).

## v0.2.0-beta.2 (November 21, 2026)

Upgrade to this release: it fixes a hole in device check-in. Still a beta, with
the same limits as beta.1.

- **Security.** Device check-in accepted any certificate that signed its own
  request. A client with a certificate it made itself could register as a new
  device, or send Authenticate under an enrolled device's UDID and receive
  commands queued for that device afterwards, profiles included. Check-in now
  requires a certificate from the configured CA. Reported privately.
  **Upgrading:** if devices were imported from NanoMDM or enrolled under an
  earlier CA, list that CA in `[ca] identity_ca_files` before you upgrade, or
  those devices are refused. The server log names the issuer of every
  certificate it refuses.
- VPN certificates can be replaced before they expire without an
  administrator: `[vpn] renew_before_days` (off by default). The owner's
  account is checked in the directory first. See
  [VPN profiles](docs/vpn-profiles.md).
- Wi-Fi networks that sign in with a certificate (EAP-TLS). Sending a network's
  profile from a device's page issues
  a new certificate for the account and installs it with the network's
  settings. The device makes its own key. Networks
  have their own page and their own card on a device's page. Run on an iPhone,
  an iPad and a Mac; on a Mac the network is set up for the system. See
  [VPN profiles](docs/vpn-profiles.md#wi-fi-networks).
- A device's page lists the profiles the device reports as installed, on
  request, and can remove any that MDM installed, including ones an earlier
  MDM server left. The enrollment profile cannot be removed there. Adds
  migration 39.
- Docs: screenshots of the console in the README, taken from an invented
  fleet, and a guide to the three ways of getting an MDM push certificate
  request signed, including an organization signing its own. See
  [obtaining an MDM certificate](docs/obtain_mdm_cert_guide.md).

## v0.2.0-beta.1 (November 16, 2026)

A beta for testers. It has not passed the release gate in
[docs/completion-prd.md](docs/completion-prd.md); that file lists what has run
on real devices and what has only run in automated tests.

### Before you upgrade from v0.1.x

- Take a backup first. Migrations run at start and bring the schema to 38.
- Expiry now applies to every device. v0.1.x kept managing a Mac whose identity
  certificate had expired, because Macs do not state a signing time. This
  release refuses it. If your fleet has expired certificates, set
  `[renewal] expired_grace_days` before the first start, or those devices are
  cut off until they enroll again. See
  [docs/certificate-lifecycle.md](docs/certificate-lifecycle.md).
- Privileged actions (enrollment links, VPN profiles) need an administrator
  with a confirmed authenticator. Set one up from the console or with
  `cairn admin mfa-bootstrap`. See [docs/mfa.md](docs/mfa.md).
- With `ca.mode = "external"` and a static challenge, the console no longer
  creates enrollment links. Turn on `[ca.external.challenge_lookup]`, or use
  the broker or embedded CA.

### Added

- Enrollment authorization: owner-bound, single-use enrollment links created
  with a fresh MFA code; a grant-bound issuance state machine with quarantine;
  an embedded two-tier CA; a SCEP broker in front of an external CA
  (`ca.mode = "broker"`); revocation and a CRL.
- MFA with authenticator codes, recovery codes and administrator approvals.
- Browser first-run setup, gated by a one-time token on the host.
- LDAP/AD owner lookup, devices bound to verified owners, and profile rules by
  AD group or OU with a preview at enrollment.
- APNs certificate request and same-topic renewal in the console; a durable
  command queue with notification retry.
- `cairn backup` (verified bundle) and `cairn restore` (rehearsal or restore
  into an empty directory); webhook alerts with a heartbeat.
- Evidence-gated release of quarantined issuances for the embedded CA.
- VPN profiles (`[vpn]`): OpenVPN server records and per-device profiles with a
  certificate from Cairn's CA or an external SCEP CA; import from an `.ovpn`
  file; re-issue, removal, revocation and expiry alerts.
- Native IKEv2 profiles: password sign-in as a signed download; EAP-TLS or IKE
  certificate sign-in pushed by MDM, with a key the device makes and a
  certificate requested through Cairn at `/scep/vpn`; On Demand with trusted
  Wi-Fi networks; all traffic through the tunnel by default.
- Device identity certificates: Cairn records the certificate each device
  checks in with, warns before it expires, and with an external CA renews it by
  pushing the enrollment profile again (`[renewal]`).
- One-time SCEP challenges an external CA checks with Cairn
  (`[ca.external.challenge_lookup]`).
- `[enrollment] check_out_when_removed` and `bootstrap_token`, written into
  enrollment and renewal profiles.
- `cairn vpn check-issuer` to test the CA configured for VPN certificates.

### Changed

- The device certificate lifetime from the embedded CA defaults to 365 days.
- A SCEP request signed with an existing device certificate is recorded as a
  renewal attempt and refused in the embedded CA and broker modes.
- The dashboard and `cairn init` point at enrollment links unless
  `allow_open` is set.
- Console: narrow-screen layout, labeled form controls, AA contrast for links
  and errors, alerts that link to their fix.

### Fixed

- A device that answered a command after its queue was cleared could strand
  every later command for that device.
- A refused check-in now names the device's certificate, not its CA.
- Console sign-in works for directory accounts without a routable UPN, and
  Samba referrals are ignored.

### Known gaps

- EAP-TLS Wi-Fi is not proven on hardware. Do not rely on device certificates
  for network access yet.
- Renewal exists for an external CA only. Without challenge lookup, a renewal
  accepts the first certificate from the CA that carries the device's name.
- No automatic re-issue of VPN certificates. No recorded device connection for
  OpenVPN profiles. The IKEv2 server certificate revocation check is off.
- The independent review of November 16, 2026 has three findings open: renewal
  without challenge lookup, the IKEv2 revocation check, and deployment records
  for pushed password profiles.

## v0.1.1 and v0.1.0

See the GitHub releases page.
