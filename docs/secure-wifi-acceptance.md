# Direct AD and secure Wi-Fi acceptance

Status: not qualified. Implementation work is authorized; changing live device
enrollment, RADIUS policy, SSIDs or infrastructure requires a named test scope.
Use an isolated test SSID and a Mac plus iPhone/iPad. Record the exact build,
device OS versions and server configuration for every result.

## Current implementation gaps

- Direct LDAP login exists. Connections now have per-DC and total login
  deadlines, cancellation, verified LDAPS/StartTLS and parsed group-DN matching.
  An invalid-credentials response does not trigger another DC attempt.
- With `auth.ldap.directory_id` configured, directory login records a namespace,
  AD objectGUID, current UPN and account name. The resolver rejects disabled,
  expired, ambiguous or incomplete users and revalidates by objectGUID. These
  methods are preparatory: enrollment grants do not yet call them, and login
  facts become stale. Grant-time owner checks and privileged-issuance MFA still
  need implementation and review. An editable owner field is not directory proof.
  Legacy sessions and LDAP without a namespace carry no verified owner identity.
- The Wi-Fi builder currently creates a shared profile with a SCEP request.
  That is not the finished per-device, owner-authorized network identity flow.
  Do not deploy a shared enrollment challenge as the network authorization model.
- The builder now requires explicit RADIUS server certificate names as well as
  trust anchors. It rejects blank names, wildcards and URLs. This constrains
  which server certificates the generated profile names; hardware tests must
  still prove rejection of an unexpected server and an untrusted issuer.
- The renewal/lineage addendum remains unreviewed. Its identity anchor,
  rollback detection and retirement evidence must be reconciled before the
  sensitive lifecycle is implemented or trusted by RADIUS.

Apple's published schema describes the server-name and anchor fields:
[Wi-Fi payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.wifi.managed.yaml).
Cairn's exact-name requirement is a product policy stricter than the schema's
optional field. It is not evidence of a working network connection.

## Required evidence

| Step | Positive check | Rejection/recovery check |
| --- | --- | --- |
| Direct AD | Actual Samba login and configured direct group role | Wrong password; disabled user; unmapped group has no elevated role; DC outage; TLS hostname and issuer failure |
| Identity authorization | Server resolves immutable identity and current UPN; self-service binds the authenticated owner | Altered owner, missing UPN, disabled owner, privilege/MFA failure |
| Issuance | OpenXPKI issues the reconstructed identity and allowed usage | CSR-supplied identity ignored; repeated grant/key mismatch rejected; ambiguous result quarantined |
| Profile delivery | Queue/history agree; device acknowledges intended profile | APNs outage, server restart, duplicate action and early acknowledgement |
| Wi-Fi join | Mac and iPhone/iPad join without a Wi-Fi password; RADIUS records intended identity | Wrong RADIUS name, untrusted issuer, unavailable/stale revocation information |
| Renewal | Authorized replacement reconnects and preserves intended continuity | Expired parent, disabled owner, duplicate lineage, interrupted issuance |
| Revocation | Revoked identity is rejected at each accepting RADIUS endpoint | Stale CRL fails closed; record current-session termination policy separately |
| Recovery | Offline device and restored server follow reviewed recovery policy | Rollback cannot silently reissue an authorization-bearing identity |

Keep certificate serials, sanitized RADIUS decisions, device acknowledgements
and timestamps in the private canonical development log or referenced private
artifacts. Never commit private keys, bind passwords, challenges or raw device
responses. Headless issuance and unit tests do not close these acceptance rows.

## Directory identity configuration

Set a stable, unique `auth.ldap.directory_id` for the directory, such as
`dzsec-ad`. Use lowercase letters, digits, dots, underscores or hyphens (128
characters maximum). Keep it unchanged when changing domain controllers or
restoring Cairn. Never reuse it for a different forest. This is an operator
assertion of the directory boundary, not automatic forest verification.

`objectGUID` is stored as the hexadecimal encoding of the 16 raw LDAP bytes,
not the endian-adjusted Windows GUID display string. Names and UPN can change;
owner revalidation searches by those original bytes. Session persistence does
not replace a fresh directory lookup before an authorization-bearing action.
The default login filter accepts either account name or UPN; an explicit custom
filter retains its configured behavior.

Microsoft documents [AD naming properties](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/AD/naming-properties.md)
and [account-control flags](https://learn.microsoft.com/en-US/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties).
The resolver requires a normal enabled user and an unexpired account; directory
facts alone do not prove MFA, device possession or permission to issue.
