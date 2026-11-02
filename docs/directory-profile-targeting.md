# Directory profile targeting

Product requirement added November 2, 2026. Existing Cairn groups are manual
collections of devices with assigned profiles. Directory-backed targeting is
not implemented by those tables or by LDAP login role mapping.

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
