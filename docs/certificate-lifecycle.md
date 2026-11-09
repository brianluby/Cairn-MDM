# Device certificate lifecycle: current behavior and the renewal decision

Completion candidate, November 9, 2026. This document records what the
candidate does today about device identity certificates issued by the embedded
CA, why renewal is deliberately absent, the interim operating procedure, and the
design decision the maintainers must take before renewal is built. The private
protocol addendum (§21, August 6) specifies the intended renewal/replacement
sub-machine; its adversarial review never completed, so nothing here implements
it.

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
- Revocation exists (per-serial, keyCompromise/superseded, served through the
  CRL) and is exercised by the quarantine release flow.

## Interim procedure: re-enroll before expiry

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

## Why renewal is not built yet

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
