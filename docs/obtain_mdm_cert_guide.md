# Obtain an Apple MDM signing certificate

Updated: 2026-11-18. This guide covers requesting vendor signing access, obtaining an MDM push certificate, and loading the push certificate into Cairn. It does not submit an application or change an existing deployment.

## Know which certificate you need

| Credential | Owner | Purpose |
| --- | --- | --- |
| MDM Vendor CSR Signing Certificate and private key | The approved developer organization | Sign certificate requests for its own deployment or approved MDM customers |
| MDM APNs push certificate and private key | Each deploying organization | Authenticate its MDM server to Apple's push service |
| Enrollment/device identity certificate | The deployment's PKI | Authenticate the enrolled device to MDM |

The first two are the subject of this guide. A normal app push certificate is not a substitute for an MDM push certificate. Obtaining vendor signing access replaces the outside CSR signer; Apple still issues the push certificate and operates APNs. [Apple certificate types](https://developer.apple.com/help/account/certificates/certificates-overview/).

## Choose who signs the push certificate request

Apple issues an MDM push certificate only for a request that an approved MDM vendor has signed. A Cairn deployment has three ways to get that signature. All three end at the same place: the operator uploads the signed request to Apple's Push Certificates Portal and loads the certificate Apple returns into Cairn.

| Route | Who signs | What it needs | Fits |
| --- | --- | --- | --- |
| mdmcert.download | An outside signing service | A registered email address. Free | A first install, a homelab, anyone without an Apple Developer membership |
| Sign your own | Your organization, with its own vendor signing certificate | A paid Apple Developer Program or Enterprise Program membership, and Apple's approval of the request in sections 1 to 3 | An organization that wants no outside party in its renewal path |
| A vendor signs for you | Another approved developer organization | That organization's agreement, and Apple's approval of it signing for customers | Deployments supported by the project's developer or a service provider |

Signing your own is the self-enrollment route: the organization that runs the server applies to Apple in its own name, holds the vendor credential itself and signs only its own requests. Apple's page describes this use directly ("sign your own Certificate Signing Requests"). The request to Apple is narrower than a vendor's, because it covers internal management only. The cost is a developer membership, Apple's decision on the request, and a second credential to guard and renew each year.

Cairn's console and `cairn pushcert request` use mdmcert.download today; see [APNs lifecycle](apns-lifecycle.md). For the other two routes, sign the request outside Cairn (section 5) and load the result with `cairn pushcert import` or `renew` (section 6).

A fleet can move between routes at renewal, as long as the renewal is made on the same Portal entry so the topic stays the same. Section 5 covers the check to make before switching signers.

## 1. Confirm eligibility and intended scope

This section and the next three apply to an organization signing its own requests and to a vendor signing for others. Have the Account Holder sign in to the correct Apple Developer team. Standard Apple Developer Program and Enterprise Program members can request MDM Vendor CSR Signing access. Apple enables it by request; membership alone does not guarantee approval. [Apple's request instructions](https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/).

Describe internal deployment and third-party distribution separately. Apple's agreement permits specified internal management and requires Apple selection for third-party MDM products. It requires a secure server, prohibits unauthorized monitoring, restricts non-commercial personal-use products without written permission, and imposes customer verification and credential-protection duties on signers. Do not ship the vendor credential with the software or generate/access customers' push private keys. Review Attachment 10 against the actual operating model. [Apple Developer Program License Agreement](https://developer.apple.com/support/terms/apple-developer-program-license-agreement/).

Open-source licensing does not itself establish Apple's authorization. Record which organization is the developer, which organization operates each deployment, and whether the developer will sign requests for others.

## 2. Prepare the request

Collect these details. This is a preparation checklist, not an Apple-published mandatory questionnaire:

- Legal developer-team name, Team ID, and Account Holder contact.
- Product name, repository or project page, and development/release status.
- Who uses the system now and the scope requested for future use.
- How enrollment is authorized and what device information is collected.
- Where signing keys will be held and who can use them.
- Whether you seek your own deployment's signing only or customer signing too.

Use accurate descriptions of current controls. Mark planned controls as planned. A certificate request is not evidence that the software passed a security audit.

## 3. Ask Apple to enable vendor signing

1. Open [Apple's MDM signing access page](https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/).
2. Follow its **contact us** link and authenticate as the Account Holder. Select the intended developer team if prompted.
3. Request **MDM Vendor CSR Signing Certificate access**. The support form is authenticated; its category labels can change. If there is no MDM category, use the relevant certificate/account support route and name the capability in the subject.
4. Submit the product description and scope. Save the case number and exact request privately.
5. Answer follow-up questions in that case. Ask for clarification if approval excludes part of the intended use. Apple does not publish a guaranteed approval time or complete scoring checklist on the request page.

## 4. Create the vendor credential after approval

1. Prepare a restricted signing workspace outside the repository, shared cloud folders, and build artifacts. Decide who owns backup and renewal responsibility.
2. Generate a private key and CSR. On macOS, Keychain Access has **Certificate Assistant > Request a Certificate From a Certificate Authority**; save the CSR to disk. Export/convert the key only as needed for the signing tool. [Apple's CSR instructions](https://developer.apple.com/help/account/certificates/create-a-certificate-signing-request/).
3. In the approved team's **Certificates, Identifiers & Profiles**, add the MDM CSR/vendor signing certificate using that CSR. Download the resulting certificate and retain its matching private key.
4. Record team, certificate fingerprint, expiry, custody, and recovery instructions. Keep an encrypted off-host backup. Never attach the private key to a support case.

If the option is missing, confirm the team and Account Holder session, then reply to the approval case. Do not choose a similarly named app APNs certificate.

## 5. Obtain the deployment's push certificate

The deployment operator generates a separate push key and CSR. The vendor signs that CSR with its vendor credential. `mdmutil mdmcsr-sign` produces the encoded request accepted by Apple's Push Certificates Portal. Follow the upstream command examples and check the flags against the installed tool version. [MicroMDM signing procedure](https://github.com/micromdm/mdmutil/blob/main/docs/operations-guide.md#mdmutil-mdmcsr-sign).

The operator uploads the signed request at [Apple Push Certificates Portal](https://identity.apple.com/pushcert/), then retains the issued certificate with its matching push key. Both certificate types expire annually; record their actual expiry dates. The Portal account can differ from the developer Account Holder. [MicroMDM lifecycle notes](https://github.com/micromdm/mdmutil/blob/main/docs/operations-guide.md#tips-and-fyis).

For an existing fleet, use **Renew** on its existing Portal entry. Creating another entry changes the topic and requires re-enrollment. Before switching CSR signers, confirm the existing entry can be renewed with the new signer; if rejected, ask Apple to resolve it rather than creating a replacement topic. The general signing guide is not proof that a particular cross-vendor renewal will succeed.

## 6. Install and verify in Cairn

Use a CLI matching the deployed database version. Back up the database and protected key material first. These are operator instructions; run the appropriate command only after reviewing the certificate, key, and target topic.

For an existing topic:

```sh
cairn pushcert renew -config /etc/cairn/cairn.toml \
  -topic com.apple.mgmt.External.EXISTING_ID \
  -cert renewed.pem -key /secure/path/push.key -by operator
```

For a new deployment/topic:

```sh
cairn pushcert import -config /etc/cairn/cairn.toml \
  -cert new-push.pem -key /secure/path/push.key -by operator
```

These commands and their validation rules are documented in [Cairn's APNs lifecycle guide](apns-lifecycle.md). The current `pushcert request`/`decrypt` workflow uses the external signing provider; it is not the self-signing step above. Import the completed Apple certificate with the key used for its CSR.

Confirm the topic, fingerprint, expiry, and enrollment default. Then send a harmless inventory request to an online canary device on that topic and verify its acknowledgment. Successful import alone does not prove APNs delivery. If verification fails, preserve the existing configuration and diagnose it before changing other topics or enrolling devices.

## 7. Maintain the credentials

Assign an owner and backup owner. Set reminders ahead of both expiries, keep the Portal account recoverable, and renew the same fleet entry. Record each renewal and canary result. Treat vendor signing-key compromise separately from a deployment push-key compromise; identify the affected credentials before requesting revocation from Apple.
