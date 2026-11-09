# Enrollment and recovery

Accepted product behavior, November 2, 2026. This document records requirements;
MFA registration/recovery is implemented in the completion candidate; verified-owner previews, MFA-bound grants, owner revalidation at issuance and directory-rule profile targeting for owned devices are implemented. Hardware and live-directory acceptance remain pending. See [MFA operation](mfa.md) and [directory profile targeting](directory-profile-targeting.md).

## An administrator adds a device for someone

1. The administrator signs into Cairn with their own account and completes
   second-factor verification for the enrollment action.
2. They choose **Add device for a user**, resolve an AD account and confirm the
   returned name and UPN. Cairn binds the owner to directory namespace and
   objectGUID; a submitted display name or email is not authority.
3. Cairn shows matching directory group/OU profile rules and the resulting
   profiles. The administrator can also select an explicit Cairn device group
   for a site-specific assignment. Conflicts need resolution before enrollment.
4. They enter a device label and platform. Cairn creates an expiring, single-use
   enrollment authorization and displays its link and QR code.
5. The administrator provides the link to the person holding the device. That
   person opens it using guest Wi-Fi, cellular or Ethernet and approves the
   platform's installation steps. The administrator need not access the device.
6. Cairn rechecks the owner's eligibility before certificate issuance and shows
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

## Remote users and devices

Required scenario: the administrator is in Bozeman and the owner/device is in
Lynchburg. The administrator selects the owner and profile assignments, verifies
their own MFA and creates the enrollment invitation from Cairn. The remote user
only needs to open the invitation on the device and approve manual enrollment;
they do not sign into Cairn or supply AD credentials or their own MFA.

Provide a copyable HTTPS link as well as QR, with Mac and iPhone/iPad instructions.
The enrollment endpoint must be reachable with a trusted certificate from the
remote site's initial network. Show resumable progress and clear expired-link
recovery. Creating a link does not send it automatically or prove delivery.

After enrollment, the administrator can assign and push profiles from Bozeman.
Offline devices remain pending until they return; APNs success is a notification
result, not installation. Show each device's acknowledgement or failure. Neither
physical access, remote shell nor screen sharing is a prerequisite. Initial
manual installation still requires action by the person holding the device;
fully unattended ADE enrollment remains outside the current release scope.

## Group and OU profile selection

Directory group/OU rules select profiles for the enrolled devices of matching
owners. The owner remains an individual verified directory identity. A policy
selection does not move the user in AD or change their group memberships.
See [directory profile targeting](directory-profile-targeting.md) for rule,
preview and membership-change requirements.

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
recovery procedure, since no previously enrolled administrator exists. The candidate implements a host-only local administrator approval/reset command;
its operational review remains pending; do not expose an anonymous
web bootstrap or make a directory password sufficient to replace an admin factor.

## Required acceptance

- Complete enrollment with the administrator in Bozeman and a user/device in
  Lynchburg, without administrator device access, owner login or owner MFA.
  Then assign another profile remotely and observe its device acknowledgement.
- Exercise same-device links, expired links, interrupted installation and an
  offline device returning. Pending and failed states must remain distinguishable
  from installed; remote access must not be needed to discover normal next steps.

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

## Current candidate limits

Initial owner-bound grants require a configured LDAP directory ID and embedded
or broker CA mode. Direct external SCEP cannot enforce Cairn's issuance checks:
owner previews work there, but new grant creation is disabled. Old free-text-owner
grants do not acquire verified authorization through migration. Existing device
check-ins and installed profiles are unchanged. This is an intentional boundary,
not proof that external broker deployment has been qualified.

Owner confirmation is session-bound and expires in five minutes. Grant creation
rechecks current MFA within the grant/audit transaction. LDAP administrators are
rechecked by GUID and current role mapping. Issuance and profile delivery recheck
the owner by directory namespace/GUID; an owner UPN change requires a fresh grant.
AD reads and CA/database transactions are not atomic with one another. Loss of
authorization after signing quarantines the outcome. Revocation during signing
also remains quarantined; it cannot be called a proven clean failure.

Opening an invitation shows instructions and does not consume it. Explicit POST
starts the download. A missing APNs topic does not spend the link. Reopening an
already-downloaded profile supports installation recovery; a lost download needs
administrator replacement. Self-service issuance,
renewal and cross-site hardware qualification remain open.

Installation instructions follow Apple's [iPhone/iPad profile installation](https://support.apple.com/en-ie/102400)
and [Mac Device Management](https://support.apple.com/en-gb/guide/mac-help/mh35474/26/mac/26)
guidance. Browser form requests retain only an origin referrer, never a bearer
path; this avoids the [null-Origin behavior of no-referrer](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
without accepting null or cross-origin CSRF requests.
