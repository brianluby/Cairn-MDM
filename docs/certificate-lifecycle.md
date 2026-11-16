# Device certificate lifecycle: current behavior and the renewal decision

Updated November 13, 2026. This document records what Cairn does about device
identity certificates: how expiry is applied, how renewal works when an
external CA issues them, and why renewal is still absent for the embedded CA
and broker modes, with the interim procedure and the decisions needed there.
The private protocol addendum (§21, August 6) specifies the intended
renewal/replacement sub-machine for those modes; its adversarial review never
completed, so nothing here implements it.

## What exists

- Each owner-authorized enrollment grant produces exactly one certificate,
  reconstructed from server policy and the grant (never the CSR), through the
  issuance state machine with its single-use binding and quarantine on any
  ambiguity.
- Lifetime is `issuance.leaf_validity_days` (default 365). The earlier
  development default of 60 days assumed a renewal path that does not exist and
  would have cut every device off within two months.
- A SCEP request signed with a certificate this CA issued is classified as a
  renewal attempt and refused before any grant is consulted. The attempt is
  recorded with the signing certificate's serial and expiry, attributed to the
  device that authenticates with it, shown on the device page, and raised as an
  alert ("device tried to renew its certificate"). Nothing is spent and nothing
  is issued.
- The console and the alert checker list device certificates that expire within
  14 days or have expired while still associated with an enrolled device.
- Whichever CA issued it, Cairn records the certificate each device presents
  at check-in. The device page shows its expiry, and alerts fire 30 days before
  it and after it.
- Cairn applies the expiry date itself, by its own clock. The signature
  library refuses an expired certificate only when the device states a signing
  time in its signature. iPhones state one and Macs do not, so until November
  2026 an expired Mac kept full management while an expired iPhone was cut
  off. Now both get the same answer (see "Expired certificates" below).
- In `ca.mode = "external"` Cairn can renew the certificate (see "Renewal with
  an external CA"). In the other modes renewal is still absent and the interim
  procedure applies.
- Revocation exists (per-serial, keyCompromise/superseded, served through the
  CRL) and is exercised by the quarantine release flow.

## Expired certificates

```toml
[renewal]
expired_grace_days = 0   # default
```

With the default, a check-in signed with an expired certificate is refused
with HTTP 400 and logged with the certificate's name, serial and expiry. The
device can be told nothing, so it has to remove the management profile and
enroll again.

With `expired_grace_days` set, a device whose certificate expired no longer
ago than that may still check in, for renewal and nothing else:

- It may report command results, update its push token and check out.
- The only command it is given is the one that renews it. Everything else
  stays queued until it presents a certificate that has not expired.
- It may not enroll, use the user channel, or fetch a bootstrap token.

Cairn identifies a device by the exact certificate it enrolled with, not by
the date on it, so the grace period does not let any other certificate in. It
does mean a stolen device key stays useful for that many more days, for the
little an expired device is allowed. Turn it on to recover devices that
expired before renewal existed, and to cover a device that was switched off
through its renewal window.

Upgrading note: an installation that relied on expired Macs still checking in
has to set a grace period before upgrading, or those Macs are refused.

## Renewal with an external CA

```toml
[renewal]
enabled = true
renew_before_days = 60          # default
expired_grace_days = 180
# server_hosts = ["mdm.old-name.example"]
# manual_only = true
```

Apple devices never renew the identity certificate themselves. Cairn pushes
the device's own enrollment profile again over MDM. Installing it makes the
device ask the CA for a new certificate, exactly as at enrollment, and switch
to it. Nobody touches the device.

Steps for one device, each shown on its page:

1. Cairn asks the device for its profile list and finds the one that carries
   the management payload. The new profile has to reuse that profile's
   identifier, or the device treats it as a second enrollment and refuses it.
   This is what lets Cairn renew devices that another server enrolled.
2. Cairn sends the enrollment profile under that identifier. It asks the CA
   for the same common name (and owner address, if the current certificate has
   one) and keeps the server name the device already checks in through.
3. The device installs it, gets its certificate from the CA and checks in
   with it. Cairn accepts the new certificate if it chains to
   `ca.external.ca_chain_file`, carries the same common name as the one being
   replaced, and has never been seen for any enrollment.
4. A day later Cairn stops accepting the replaced certificate.

The schedule runs hourly and starts a renewal when a certificate is within
`renew_before_days` of expiry, or has expired inside the grace period. A
failed attempt is retried after a day. An attempt the device does not answer
within seven days is closed and retried.

`manual_only = true` turns the schedule off and leaves the "Renew certificate
now" button on the device page. Use it to renew one device first.

Server names. A fleet moved from another MDM server may still check in
through that server's name. The renewed profile keeps whatever name the device
uses, but only if the name is the one in `server.public_url` or is listed in
`server_hosts`. Any other name is likely a proxy's internal one, and a profile
pointing there would strand the device, so Cairn refuses to renew it and says
so on the device page and in an alert.

What renewal does not do:

- It does not revoke the replaced certificate at the external CA. Cairn stops
  accepting it for MDM; anything else that trusts that CA accepts it until it
  expires. Revoke it at the CA if that matters.
- The profile's management payload is the one Cairn writes for new
  enrollments. Settings another server put there, such as bootstrap token
  escrow or `CheckOutWhenRemoved`, are not carried over.
- The CA has to allow a second certificate for the same name while the first
  is still valid.

Known limit with a static challenge. In external mode the CA issues to anyone
who presents its enrollment challenge, and by default that challenge is the
same in every enrollment profile. Cairn does not see the request, so it cannot
tell the CA or itself that a new certificate was asked for by the same device.
During a renewal, and for 30 days after one starts, Cairn accepts the first
new certificate for that device that comes from the CA and carries the
device's existing name. Someone who holds the challenge, knows a device's ID
and certificate name, and acts in that window can have their own certificate
accepted in the device's place; the real device is then refused. One-time
challenges, below, close this.

### One-time challenges checked by the CA

Some CAs can ask another system whether a request's challenge is good.
OpenXPKI does it with a connector on the SCEP endpoint; NDES has its own form.
With `[ca.external.challenge_lookup]` on, Cairn stops using the static
challenge:

- Every enrollment profile and every renewal profile carries a challenge of
  its own. Cairn stores only its SHA-256.
- The CA calls `GET <cairn>/scep-challenge/<certificate name>/<request key
  identifier>/<presented challenge>` with a shared secret as a bearer token.
  Cairn answers 200 with the challenge when the request may proceed and 404
  for everything else.
- A challenge is good once, for one certificate name and one key. A renewal
  challenge fits only the device's existing name. An enrollment challenge
  fits the exact name when the grant fixed the serial number, and otherwise
  any name ending in this server's device suffix. It expires after a day
  (enrollment) or seven days (renewal).
- A renewal accepts a new certificate only when its key is the one that used
  that device's renewal challenge. A certificate in the device's name for any
  other key is refused.

```toml
[ca.external.challenge_lookup]
enabled = true
secret_file = "/etc/cairn/scep-lookup-secret"   # 32 characters or more
allowed_sources = ["10.0.5.20"]                 # the CA, when it connects directly
```

OpenXPKI, in the SCEP endpoint's policy file (check the connector path and
context names against your version before relying on them):

```yaml
challenge:
    value@: connector:scep.<endpoint>.connectors.cairn
    args:
      - "[% context.cert_subject_parts.CN.0 %]"
      - "[% context.csr_subject_key_identifier %]"
      - "[% context.req_attributes.challengePassword %]"

connectors:
    cairn:
        class: Connector::Proxy::HTTP
        LOCATION: https://cairn.example.org/scep-challenge
        undef_on_404: 1
        chomp_result: 1
        header:
            Authorization: "Bearer <the secret>"
```

The CA compares what Cairn returns with what the device presented, so a 404
is a refusal. Switch Cairn and the CA over together: between the two changes
enrollments and renewals fail, and nothing else is affected.

What this does not cover: the lookup endpoint is reachable wherever Cairn is,
and the secret is all that guards it, so keep the secret out of the CA's
logs and limit the source address where you can. The key identifier comes from
the CA, so the check is as good as the CA's reading of the request. State:
built and tested in-process; not yet run against a CA.

## Interim procedure: re-enroll before expiry (embedded CA and broker modes)

Until renewal is designed, reviewed and built, a device whose certificate is
nearing expiry is re-enrolled:

1. The administrator creates a new owner-authorized enrollment link for the same
   owner (fresh MFA, same verified directory identity). This is a new lineage:
   a new grant, a new key on the device, a new certificate.
2. The remote user opens the link on the device and installs the profile. The
   device's MDM enrollment continues under the same enrollment ID; the new
   certificate is associated at the next check-in.
3. Once the device has authenticated with the new certificate and (where
   applicable) joined Wi-Fi with it, the administrator revokes the old
   certificate from the device page. The CRL carries the revocation; RADIUS
   servers that check the CRL reject the old certificate from then on.

Two certificates for one device are live between steps 2 and 3. That is the
same bounded overlap §21 describes for renewal, with the administrator rather
than a state machine closing it. It is acceptable for a small fleet and is
visible on the device page.

## Why renewal is not built for the embedded CA and broker modes

Renewal is the point where a device proves possession of an existing identity
to obtain the next one without an administrator. §21 derives the rules from a
single primitive, an identity anchor outside any one rollback domain, and a
uniform retirement rule: a certificate leaves the live set only after every
relying service has been observed rejecting it. Those rules have no completed
adversarial review. Implementing a renewal path before that review would mean
shipping the exact mechanism the review is meant to check, so this release
refuses renewals explicitly instead of accepting them loosely.

## Decisions needed before building renewal

1. **Anchor scope.** §21 wants an append-only checkpoint outside Cairn's own
   database so a restore is detectable. For the embedded CA the candidate's
   signer is atomic and local; the open question is whether the anchor can be
   Cairn's database plus the verified backup bundle manifest (which records
   schema and counts), or needs a live second store.
2. **Retirement evidence without RADIUS.** The quarantine flow already treats
   "no acceptance points configured" as MDM-only. Renewal retirement needs the
   same decision: is revocation plus CRL plus MDM-association removal enough to
   retire the parent in a standalone MDM deployment?
3. **Overlap bound.** §21 allows one bounded overlap window. Proposed: the
   parent stays live until the child has authenticated to MDM once and at most
   14 days, after which the parent is revoked automatically and retirement
   evidence is gathered.
4. **Review path.** The §21 Codex gate was lost to quota; the human blue team was
   unavailable. Decide who reviews, against the §21 text plus this document and
   the quarantine implementation.

## What the code is ready for

The pieces renewal will need are in place and tested: owner binding from the
issued certificate, the issuance state machine with quarantine, revocation and
CRL, enumeration of issued certificates by key, the RADIUS rejection ingest and
the evidence-gated release discipline. A renewal implementation would add a
`gen` to the lineage, a parent-authenticated path through the Broker (the
envelope signer is already extracted), and the retirement sub-machine over the
same evidence.
