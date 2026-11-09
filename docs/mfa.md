# Authenticator registration and recovery

Completion candidate, November 4, 2026. This implements account factor setup,
verification and recovery for local accounts and namespaced LDAP identities.
New owner-bound grants now require fresh administrator MFA and current directory
authorization. Owner eligibility is rechecked at profile delivery and before/after
certificate signing. This is not a Wi-Fi release gate; lifecycle review remains open.
OIDC still works for login; OIDC MFA registration is refused until the verified
issuer and subject are retained as a stable principal. Email/name matching is
not a substitute.

## First administrator

Browser first-run (`/setup`, open only while no local account exists) creates
the first administrator from the host token file `<storage.path>.setup-token`
and shows the authenticator approval code at the end; the token file proves
host access and is deleted on completion. Alternatively, on the Cairn host,
with access to its protected configuration/database, run:

```
cairn admin mfa-bootstrap -config /etc/cairn/cairn.toml -username admin
```

This requires an existing local administrator and interactive input/output.
The database must already have migration 027; the command never creates or
migrates a database. It displays a single-use 15-minute approval code, not an
authenticator secret. Sign in as that local administrator, open Account
security, enter the approval code and add the displayed QR or setup key to
your authenticator. Confirm a generated code within 10 minutes. Save the ten
recovery codes shown once after confirmation.

The first confirmed factor permanently closes initial bootstrap. Reissuing
initial approval before confirmation invalidates earlier pending setup. There
is no anonymous web registration or password-only factor replacement.
Old sessions predating migration 027 must sign out and sign back in to obtain
a stable principal. The first administrator can then approve the AD account
used for daily administration; an owner's MFA is not required for future
administrator-assisted device enrollment.

## Approving another account

Verify your own authenticator code on Account security. Within five minutes,
select Local Cairn account or Active Directory, enter the person's account
name/UPN, and create approval. AD lookup resolves the current eligible account
and pins its directory namespace/objectGUID. Local accounts use a random ID
that changes when an account is deleted and recreated. Provider namespaces are
separate. A person must sign in as the approved account to redeem its code.
Deliver approval only after verifying the person's identity. Cairn does not
send a message automatically. Self-approval is refused.

For a lost factor without saved recovery codes, select the explicit reset
checkbox. Reset revokes the old factor, all recovery codes, pending setup and
sessions for that principal, then creates a new approval. It does not change
AD credentials or re-enable a disabled account.

## Recovering your factor

Sign in with your normal first factor and use one saved recovery code on
Account security. Cairn revokes the old factor, all old recovery codes and other
sessions. The retained session loses its MFA verification. Use the returned
approval code to register and confirm a replacement. Recovery alone does not
grant fresh MFA authorization. A lost response may require administrator help;
raw approval/recovery codes cannot be retrieved from the database.

If the local recovery administrator loses all codes and no other administrator
can help, protected host access can authorize reset:

```
cairn admin mfa-bootstrap -config /etc/cairn/cairn.toml -username admin -reset
```

This revokes that local administrator's factor/codes/sessions and records a host
recovery audit event. Sign in again to redeem the returned approval code.
Host filesystem access is the authority for this command. Protect it as you
protect access to local account password-reset tooling.

## Storage and verification

- TOTP uses six digits, HMAC-SHA1, 30-second steps and one adjacent step for clock
  skew, following [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) and
  [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226). Successful confirmation and
  verification persist the accepted counter. The same counter cannot be reused
  across sessions or service restart.
- Five rejected approval/code attempts block the principal for 15 minutes.
  Failures persist across sessions/restart; reissuing approval cannot clear the
  attempt budget. Setup expires after 10 minutes. Fresh verification lasts five
  minutes and remains subject to session expiry and revocation.
- AES-256-GCM encrypts pending/confirmed authenticator secrets with the principal
  as authenticated data. The key is a separate private file next to the database;
  see [backup and restore](backup-restore.md). Approval tokens are random 256-bit
  values; each recovery code has 128 bits of randomness. Only hashes are stored.
- Confirmation, verification, reset and recovery update their authorization state
  and audit record in one transaction. Missing audit storage rolls back success.
  Secret pages use no-store and strict-origin headers (no referrer path or query). Codes are POST body fields, not
  URL components. Setup secrets and recovery codes are shown once.

## Remaining acceptance

Automated tests cover published algorithm vectors, confirmation/replay,
principal/session binding, expiry, durable throttling, concurrent verification,
audit rollback, encryption-key custody and HTTP role/CSRF boundaries. Rendered
browser use with an authenticator, actual Samba login and host recovery remain
unqualified. LDAP session facts do not prove current actor eligibility: live
privileged authorization must be checked when integrating grant issuance.

The candidate now integrates fresh actor MFA and current directory owner checks
at grant and issuance boundaries, preserving separate actor/owner identities. Profile
selection and remote manual installation still need that complete flow. This
change neither modifies RADIUS nor validates the unreviewed certificate renewal
and replacement contract.
