# Cairn completion requirements

Status: implementation in progress, November 2, 2026. This document defines
completion; it does not claim that the listed requirements have passed.

## Product

A single Go binary with SQLite and a browser admin console for small Apple
fleets. Manual enrollment is first-class. Beginner setup is guided; existing
PKI remains supported. Secure EAP-TLS Wi-Fi and working LDAP/Active Directory
are required outcomes, not optional post-release work.

## Acceptance matrix

| ID | Requirement | Required evidence | Current gap |
| --- | --- | --- | --- |
| APNS-1 | Initial issuance and same-topic renewal through shared CLI/web service | Atomic commit, wrong-topic/key/date rejection, unchanged other fleet/default, real push acknowledgement | CLI/storage/admin workflow implemented and automated tests pass; durable receipt and previous pair retained; browser, operator rollback and live acknowledgement qualification pending |
| APNS-2 | Resumable signing requests and Apple portal handoff | Independent requests, retained keys after timeout/restart, encrypted attachment round trip | Shared request service and admin workflow implemented; automated timeout/resume/decryption checks pass; live wizard qualification pending |
| CMD-1 | Durable queue, notification retry and truthful history | Failure after queue commit, restart, duplicate action, late ACK and NotNow tests | Atomic queue/history and durable notification retries implemented; operator-action idempotency, notification-only retry and checkout cancellation tested; live qualification pending |
| AUTH-1 | Direct LDAP/AD login and explicit authorization | Real Samba AD, TLS verification, disabled user, group roles and DC failover | Cancellable TLS connections and parsed group-DN matching tested; namespaced objectGUID/UPN resolution and revalidation tested; grant/issuance owner checks implemented; real Samba acceptance pending |
| AUTH-2 | Optional local/OIDC auth; privileged-issuance MFA | Session revocation, role boundaries, recovery and MFA acceptance | Local mutations/session revocation and stale-login fencing tested; TOTP setup/recovery, host bootstrap and admin approvals implemented; fresh-MFA grants and local WebKit setup/recovery tested; OIDC stable subjects and live AD acceptance pending |
| WIFI-1 | Authorized user receives certificate and joins EAP-TLS | Real Mac and iPhone/iPad: AD → Cairn → external CA → profile → RADIUS → network | Not proven |
| WIFI-2 | Renewal, revocation and offline recovery | Renewed device reconnects; revoked/disabled identity rejected; server-name/trust validation; current-session policy stated | Renewal deliberately refused and recorded (no reviewed design); leaf lifetime configurable (default 365 days); expiry and refused-renewal alerts and device-page certificate view implemented; revocation/CRL and quarantine retirement implemented; interim re-enroll procedure documented in `certificate-lifecycle.md`; design decisions and review pending before renewal is built; hardware tests pending |
| CA-1 | Embedded default and external broker with honest capability limits | Independent authorization/recovery review, restart/rollback and ambiguity tests | Evidence-gated quarantine release implemented for the embedded CA (backend fence manifest, complete per-key enumeration, revocation plus MDM association removal plus server-ingested RADIUS rejections, content-validated release, no force path; external holds read-only) and unit-tested; renewal lineage, identity/lineage contract review and hardware qualification pending |
| UX-1 | Guided setup, enrollment, profiles, groups, recovery and settings | Task-based browser review, keyboard/VoiceOver/zoom/narrow-layout checks | Browser first-run and Settings checklist, profile removal/deletion with named consequences and assignment/acknowledgement gates, per-device outcomes on group pages, owner and profile-status columns on the device list implemented and unit-tested; APNs, enrollment, directory and quarantine flows exist; rendered-browser, keyboard and assistive-technology review pending |
| ENROLL-REMOTE | Administrator enrolls and manages a remote user's device without device access | Bozeman admin → Lynchburg user installs via link → later remote profile acknowledgement; interruption/offline recovery | Full chain (fresh-MFA preview and link, invitation page, profile download, SCEP with reconstructed identity, MDM check-in with that certificate, owner binding, rule membership, InstallProfile queued; replay, second-key and disabled-owner refusals) passes an in-process HTTP test against the embedded CA with faked directory and APNs; real Mac/iPhone, live Samba and cross-site network qualification pending |
| PROFILE-1 | Profile targeting by owner AD group/OU and explicit Cairn device group | Enrollment preview, membership refresh, scope/conflict handling and per-device outcomes | Owner binding from the issued certificate, rule evaluation on enrollment and on refresh, directory memberships feeding deployment, enrollment preview with explicit group, and console explanation implemented and unit-tested; live Samba, real-device and remote-site qualification pending |
| OPS-1 | Backup, restore, upgrade, alerts and heartbeat | Isolated restore, protected off-host material, alert delivery, release upgrade/rollback | `cairn backup` bundle (snapshot, MFA key, config and referenced files, manifest, self-verification, webhook outcome), `cairn restore -rehearse`/`-into`, hourly webhook alerts with reminders, recovery messages and heartbeat, dashboard alert list and systemd timer implemented and unit-tested; live webhook delivery, off-host copy, upgrade/rollback rehearsal from `c25eb67` and a real restore drill pending |
| RELEASE-1 | Reproducible supported release | Exact candidate SHA, automated checks, hardware matrix, independent review and recorded soak | No completed release gate |

## Decisions

- Keep the existing server-rendered console. Do not revive the legacy portal.
- Default to embedded PKI for new users; support an external CA broker for
  organizations with PKI. Easier setup must not weaken certificate authority
  custody or authorization requirements.
- Apple account sign-in and certificate approval happen in Apple's portal.
  Cairn manages the request, keys, attachment decryption, import and validation.
  It does not collect Apple passwords or require access to the operator's email.
- Direct LDAP/AD must work without requiring OIDC. Optional authentication
  providers do not remove privileged-issuance controls.
- Administrator-assisted enrollment is first-class: an administrator with fresh
  MFA selects a verified AD owner and enrolls a device without the owner signing
  in or providing credentials. Audit actor and owner separately. Self-service
  remains supported using the owner's established factor.
- Remote-site enrollment must work with the administrator in Bozeman and users
  and devices in Lynchburg. Remote users open an administrator-authorized link
  and approve installation without a Cairn login; subsequent profile management
  works through MDM without administrator physical or remote-desktop access.
- Initial MFA uses authenticator-app codes, verified setup and single-use
  recovery codes. First setup and lost-factor recovery require administrator
  assistance. MFA is checked in Cairn; RADIUS needs no MFA integration.
- See [enrollment and recovery](enrollment-onboarding.md) for the accepted flows
  and rejection tests. These are requirements, not completed implementation.
- Profile targeting supports verified owner AD group membership or OU scope,
  plus explicit Cairn device groups. Preview effective profiles during enrollment;
  do not change AD membership or certificate ownership through that selection.
  See [directory profile targeting](directory-profile-targeting.md).
- No silent profile removal when a library item or assignment is deleted.
- ABM/ADE, DDM, Platform SSO, app distribution and alternative databases are
  separate future increments.

## Order and evidence

First fix APNs request/certificate safety, then prove AD and secure Wi-Fi with
the command reliability needed for profile delivery. Finish broad UI polish and
release qualification after the core workflow is demonstrated. A Wi-Fi join
does not substitute for renewal/revocation acceptance.

Existing enrollment authorization documents remain design input. The private
renewal/rollback addendum has no completed adversarial gate; reconcile and
review that design before implementing its sensitive transitions. Passing
unit tests never authorizes EAP-TLS trust or a production rollout.
