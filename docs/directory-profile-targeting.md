# Directory profile targeting

Product requirement added November 2, 2026. Existing Cairn groups are manual
collections of devices with assigned profiles. Directory rules are stored
separately from those tables and from LDAP login role mapping. Rules now apply
automatically to devices with a verified owner (see "Implemented behavior");
live Samba and real-device qualification remain pending.

## Lynchburg example

Configure an assignment from an AD group, for example `Lynchburg Users`, to the
Lynchburg Wi-Fi/settings profiles. A new device owned by a matching user receives
those assignments after enrollment. Alternatively, select a Lynchburg user OU
and specify whether to include child OUs. These names illustrate the workflow;
no AD object has been created or moved.

A group is the recommended starting point when the purpose is profile assignment.
An OU can be used when it already represents the intended organizational scope.
Microsoft describes [security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
and [OU administration](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/delegating-administration-by-using-ou-objects).
Cairn's mapping of either object to Apple profiles is application policy, not
Windows Group Policy processing.

## Enrollment preview

After choosing the user, show matched directory rules, an optional explicit
Cairn device group, effective profiles, supported platforms and any conflicts.
Show why each profile applies. Assigning a device to a Cairn group can support a
site exception without relocating its owner's AD account. An owner-based rule
applies across that owner's enrolled devices unless a stated platform/device
condition limits it; it does not infer the device's physical location.

Directory membership is read from the selected owner's verified object. A
submitted group name or OU string cannot make the user eligible. Preserve owner,
admin actor and profile-assignment scope as separate records. Choosing a profile
scope does not change AD, grant console roles, authorize certificate issuance or
replace the RADIUS network-access policy.

## Rule identity and refresh

Bind selected directory groups/OUs to the configured directory namespace and
immutable object identity; display current names and DNs. Renames must not
silently redirect a rule to an unrelated object with the old name.

Make group membership semantics explicit: direct or nested. Do not claim nested
or primary-group coverage from the LDAP memberOf attribute alone. OU matching
uses parsed directory ancestry, with an explicit descendants option; never a
raw substring match. Validate supported behavior against Samba AD.

Evaluate rules at enrollment and refresh them after enrollment with recorded
freshness, errors and an operator-triggered refresh. A directory timeout,
partial result or inaccessible scope is an unknown result, not empty membership.
Do not remove profiles or add newly privileged assignments from unknown data.
The fresh owner/issuance authorization checks remain separate and fail closed.

Merge identical profile assignments once and retain all assignment sources.
Conflicting versions or incompatible settings require an explicit resolution;
rule evaluation order must not silently choose a winner. When membership changes,
show the resulting deployment/removal actions and each device's actual status.
Do not silently remove working Wi-Fi. Removing a profile from desired scope does
not itself prove the device has lost network access.

## Acceptance

- Enroll an owner's iPhone and Mac through the admin flow without owner login;
  preview and deliver the applicable Lynchburg profiles for each platform.
- Support both group targeting and OU targeting, including explicit descendant
  and nested-group semantics, escaped DNs and cross-directory name collisions.
- A user outside a scope cannot gain membership by altering the enrollment form.
- Group/OU rename, owner move and group membership changes produce explainable
  results; stale or failed directory reads cause no mass removal.
- Overlapping rules do not duplicate installation, and conflicts are surfaced.
- Manually assigned Cairn device groups remain distinguishable from directory
  rules and survive refresh unless the administrator changes them.
- Device acknowledgement and actual Wi-Fi acceptance remain separate evidence.

## Implemented behavior (candidate, November 9)

A device gets a verified owner when it authenticates to MDM with a certificate
Cairn issued for an owner-authorized grant: `cert_auth` (the hash NanoMDM records
for the device's identity certificate) joins `cert_issuance.leaf_sha256` to the
grant's pinned owner identity and actor. Nothing on the enrollment form or the
device's own claims can set an owner. Devices enrolled through direct external
SCEP, open enrollment or the NanoMDM import have no verified owner, and rules do
not apply to them; the device page says so. If a device later authenticates with
a certificate from a newer grant, ownership follows that grant and the change is
audited.

When an owned device becomes pushable (TokenUpdate) Cairn evaluates every saved
rule against the owner's current directory object in one round, replaces that
device's directory-derived memberships with the matched rules' groups, then runs
the ordinary assignment reconciler. Directory memberships live in their own table
and count for deployment exactly like manual membership (profiles to deploy,
group fan-out and group status all read the union). The optional explicit Cairn
group chosen at authorization is applied as manual membership at binding time.

An unknown directory answer (timeout, failover exhaustion, missing or replaced
object, short result) records an "unavailable" evaluation and leaves the previous
memberships in place. A successful evaluation that no longer matches removes the
membership but never sends RemoveProfile; the device page keeps showing the
deployed profile until an administrator removes it explicitly. Owner eligibility
is not enforced here; it is enforced at grant creation and certificate issuance.

Administrators can re-evaluate one device from its page ("Re-evaluate directory
rules") or every owned device from the rules page; both push newly entitled
profiles afterwards. The device page shows the owner, each directory membership
with the rule that produced it, and the time/status of the last evaluation. The
enrollment preview runs the same evaluation for the chosen owner and lists the
resulting profiles with their sources before the link is created.

Not yet done: platform/device-type conditions on rules, membership change
notifications, scheduled (unattended) refresh, and acceptance against a real
Samba directory and Apple devices.

## Implemented preview

The Groups page links administrators to **Directory profile rules and preview**.
Select an existing Cairn group (and its assigned profiles), resolve an AD group
or OU by exact name, and save a rule. Ambiguous names require a full DN. Saved
rules pin the configured directory namespace and raw objectGUID; later preview
resolves the current object rather than trusting a saved name or path.

Preview accepts a user account name or UPN, resolves an eligible owner and
revalidates that owner by GUID. It evaluates the whole rule set on one DC per
attempt; a failed attempt contributes no partial results to failover. Reads have
bounded deadlines. This is not an atomic directory snapshot or an issuance
permission. At most 100 scopes can be evaluated per preview.

Group checks include primary membership reconstructed from objectSid and
primaryGroupID. Nested checks query the LDAP transitive matching rule for both
the user and their primary group. OU matching uses parsed DN ancestry; direct
scope excludes child OUs. See Microsoft's [LDAP matching rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e638665-f466-4597-93c4-12f2ebfabab5).
The configured search base must contain the owners, target scopes and primary
group objects. Real Samba support and service-account read permissions still
need qualification;
an ACL-hidden membership is not made trustworthy by a successful empty search.

The console reports each match and its profile sources, deduplicates identical
profile IDs and detects repeated profile identifiers. It explicitly does not
validate device-platform compatibility or conflicting settings across different
identifiers. A failed directory read produces an unavailable preview, never a
successful empty assignment set.

Rules and audit writes commit together. Saving, deleting and previewing rules
never changes manual membership, creates enrollment grants or queues device
commands. Existing manual groups continue to work independently. Deleting a
rule removes the memberships it produced; installed profiles stay.
