# Quarantine resolution

Completion candidate, November 9, 2026. Implements the GUI Phase-1 enforcement
contract from the private quarantine-operations procedure (August 5) for the
embedded CA, and keeps external-backend holds read-only. This is implementation
and unit-test evidence; it has not been exercised against a quarantine produced
by real Apple hardware.

## What a hold is

A certificate issuance enters QUARANTINED when Cairn cannot prove the CA did not
sign: a lost or ambiguous backend reply, a returned leaf that does not match the
reconstructed intent, or owner authorization that changed after signing. The
hold is terminal for that grant. Cairn never retries it and never reissues from
it; the device enrolls again with a new link once the hold is released.

## The four steps

Each step stores a manifest produced by the backend or the server. A later step
is refused (HTTP 409) until the previous step's evidence exists, enforced in the
storage transaction, and release re-validates the content of every manifest.
There is no force release. Every step needs administrator role and a fresh
authenticator code and is written to the audit log with the actor.

1. **Fence.** For the embedded CA the fence is a storage fact: `cert_issuance`
   binds each grant once (UNIQUE), the binding is terminal, and the signer runs
   synchronously in-process, so no attempt for this grant can still complete.
   The manifest records the CA fingerprint, grant, transaction id, public-key
   hash, binding state and that justification. Re-fencing resets later steps.
2. **Enumerate.** Cairn scans the embedded CA's complete issued-certificate
   record for every certificate carrying the attempt's public key and reconciles
   the list with the cached leaf and serial on the issuance row. The manifest
   records the scan size, completeness and any discrepancy. A discrepancy blocks
   release.
3. **Confirm rejected.** Cairn revokes every enumerated certificate
   (keyCompromise), removes any MDM certificate-authentication association for
   it, and requires an observed Access-Reject from every configured RADIUS
   acceptance point, reported after the revocation time through the ingest
   endpoint. When coverage is incomplete the revocations stand, the manifest is
   not recorded, and the page lists what is missing. With no acceptance points
   configured the release is MDM-only and the page says so.
4. **Release.** Re-validates: the fence manifest names this CA and this attempt
   and proves a terminal, atomic binding; the enumeration manifest is complete,
   reconciled and bound to this key, and a fresh scan finds no certificate that
   appeared since; the rejection manifest covers exactly the configured
   acceptance points and every enumerated serial, and every serial is still
   revoked. Only then is the hold released. The issuance row stays QUARANTINED.

## RADIUS rejection ingest

```
POST /api/v1/radius/rejections
Authorization: Bearer <radius.ingest_token>
{"acceptance_point":"radius-a.example.org","serial":"1f3a","observed_at":"2026-11-09T19:04:05Z","source":"freeradius post-auth"}
```

`radius.acceptance_points` lists the servers whose rejections count;
`radius.ingest_token_file` or `_env` holds the bearer token. Reports from an
unknown acceptance point, an invalid serial, or a future time are refused. A
FreeRADIUS post-auth hook that posts the certificate serial on reject is the
intended caller; operator-entered text is never accepted.

## External backends

Holds whose backend is `external-scep` cannot be fenced or enumerated by Cairn:
OpenXPKI offers no per-transaction fence or complete per-key enumeration that
Cairn can verify. The page shows these holds read-only with instructions to
revoke at the backend CA and keep the device off the network. This is the
quarantine-fallback behavior accepted for the external lane.

## Not implemented

Renewal-lineage holds (RENEWAL_QUARANTINED) and the §20.4a escalations depend
on the renewal/replacement contract that remains unreviewed; the current
implementation covers initial-enrollment holds only. Two-person approval on
release is not implemented.
