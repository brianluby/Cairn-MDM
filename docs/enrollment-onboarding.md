# Enrollment and recovery

Accepted product behavior, November 2, 2026. This document records requirements;
MFA and the directory-authorized grant flows are not yet implemented.

## An administrator adds a device for someone

1. The administrator signs into Cairn with their own account and completes
   second-factor verification for the enrollment action.
2. They choose **Add device for a user**, resolve an AD account and confirm the
   returned name and UPN. Cairn binds the owner to directory namespace and
   objectGUID; a submitted display name or email is not authority.
3. They enter a device label and platform. Cairn creates an expiring, single-use
   enrollment authorization and displays its link and QR code.
4. On the new device, the administrator opens that link using guest Wi-Fi,
   cellular or Ethernet and follows the platform's installation instructions.
5. Cairn rechecks the owner's eligibility before certificate issuance and shows
   enrollment, certificate issuance, profile delivery and network acceptance as
   separate outcomes.

The owner need not be present, sign in, provide credentials or have an enrolled
second factor. The administrator's MFA authorizes this route. Record the
administrator as the actor and the selected user as the owner; do not manufacture
an owner login or mark the owner as MFA-verified.

Manual enrollment requires installation approval on the device. The link is a
bearer credential and must not appear in logs, audit records or analytics.
Record a grant identifier instead. An expected serial is an additional check,
not hardware attestation. This flow does not promise ADE, supervision or
unattended installation.

The initial permission is admin-only. Ordinary operators do not inherit the
ability to issue for arbitrary owners from their device-management role. Any
future delegated enrollment permission must be explicit and separately tested.

## A user sets up MFA and enrolls devices

For first registration, an administrator verifies the person and approves an
expiring invitation tied to their directory identity. The user authenticates
through AD, adds Cairn's QR code or setup key to an authenticator app, confirms a
generated code and saves single-use recovery codes. A setup-key or app handoff
must support registration when the browser and authenticator share one device.

The password alone cannot authorize second-factor registration, replacement or
recovery. Never activate an unconfirmed authenticator secret. An administrator
must not register a factor on the user's behalf and keep a copy of its secret.
Administrator-assisted device enrollment does not require registering user MFA.

For subsequent self-service device enrollment, the user signs into Cairn on the
new device and verifies using their existing authenticator. Cairn fixes the owner
to that authenticated directory identity; changing a form field cannot select
someone else. Self-service and administrator-assisted enrollment use the same
issuance and owner-eligibility checks.

## Lost devices and factors

A user who cannot access their authenticator can use a single-use recovery code
or complete administrator-assisted identity verification and factor reset.
Recovery revokes the prior factor and unused recovery credentials and invalidates
relevant sessions. It must be auditable and must not restore a disabled owner's
eligibility. Recovery cannot silently bypass the certificate replacement and
retirement policy.

First-administrator MFA bootstrap must use a protected local installation or
recovery procedure, since no previously enrolled administrator exists. That
procedure still needs an implementation and review; do not expose an anonymous
web bootstrap or make a directory password sufficient to replace an admin factor.

## Required acceptance

- An administrator enrolls for an enabled AD user who has never signed into
  Cairn and has no MFA registration. The owner supplies no credentials.
- Missing/stale administrator MFA, a non-admin actor, a disabled or expired owner,
  a changed directory identity, unavailable directory or altered owner selection
  cannot create or redeem an authorized grant.
- Owner disable after grant creation prevents issuance. Replayed, expired or
  revoked links cannot authorize another device certificate.
- Audit records distinguish actor provider/identity, authorization mode, owner
  namespace/objectGUID, current UPN, grant and resulting certificate identity.
- A user enrolls a replacement device with their established factor, including
  a Mac using a phone authenticator and a phone using an existing authenticator.
- First registration, same-device setup, lost-phone recovery and administrator
  bootstrap have tested positive and rejection paths. Codes cannot be replayed;
  guessing is rate-limited and recovery does not erase audit history.
- A device joins secure Wi-Fi without an interactive MFA prompt. RADIUS still
  validates certificate trust, owner authorization and revocation separately.

The unreviewed renewal/lineage contract remains a separate gate. Approval of
these user flows does not establish certificate lifecycle safety or real-device
Wi-Fi acceptance.
