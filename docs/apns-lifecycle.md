# APNs issuance and renewal

The completion branch adds APNs administration under **APNs** in the admin
console. This workflow has automated coverage but has not completed browser,
live-provider or device acceptance. Do not treat it as a qualified rollout.

## Admin workflow

1. Select the existing topic for renewal, or initial issuance for a new fleet.
   Enter the email registered with mdmcert.download. An optional Apple Account
   reference helps the next operator find the owning account.
2. Prepare the request. Cairn retains separate keys under a random request ID.
   Send the vendor-signature request using the explicit button. If submission
   times out, check email before resubmitting; the same request keeps its keys.
3. Upload the encrypted email attachment. Download the resulting request
   without editing its contents; the provider's base64 plist encoding is kept.
4. Sign in to Apple's Push Certificates Portal. For renewal, choose **Renew**
   on the existing certificate whose UID matches the selected topic. Upload
   the request and download the PEM certificate.
5. Upload the PEM to Cairn. Review its topic, expiry and SHA-256 fingerprint.
   Install it, then refresh an online device using that topic and confirm its
   acknowledgement and fresh inventory.

Cairn never needs an Apple password. Request keys remain on the server. Only
admins can access this workflow, and mutations require the session CSRF token.
A successful import does not prove delivery to a device.

## CLI

Prepare and submit a request (use the same `-config` throughout):

```sh
cairn pushcert request -config /etc/cairn/cairn.toml -email operator@example.org
cairn pushcert decrypt -config /etc/cairn/cairn.toml -request-id REQUEST_ID -in attachment.p7
```

The request command prints its ID and private directory before contacting the
provider. To resubmit after checking email:

```sh
cairn pushcert request -config /etc/cairn/cairn.toml -resume REQUEST_ID
```

After renewing the matching Apple portal entry, use the saved `push.key`:

```sh
cairn pushcert renew -config /etc/cairn/cairn.toml -topic com.apple.mgmt.External.EXISTING_ID -cert renewed.pem -key /path/to/request/push.key -by operator
```

For a new topic, use `pushcert import`. Import rejects existing topics. The
first import becomes the enrollment default; later imports preserve it unless
`-make-default` is supplied. Renewal rejects that flag and preserves the default.
Pre-request-ID attachments require explicit `pushcert decrypt -legacy`; there
is no automatic fallback to keys belonging to another request.

## Validation and recovery limits

The shared CLI/web installer verifies the certificate/key pair, MDM UID and
extension, TLS client usage, validity and chain to the bundled Apple root.
See `internal/push/trust/README.md` for bundle provenance and trust limits.
There is no online certificate-revocation check. Real APNs delivery remains
an acceptance step.

Material, expiry metadata, provider cache invalidation and certificate audit
record, installation receipt and previous certificate/key commit in one SQLite transaction. Any failure rolls the transaction
back. Renewal must extend the old certificate's expiry. Replaying the same wizard request returns its recorded result without changing
certificate state. The completed page survives logout/restart. An attempt to
reuse its ID for a different certificate or default-selection intent is rejected.
The previous pair is retained in protected database storage; this is recovery
material, not an off-host backup or proof that Apple still accepts that certificate.

Back up the SQLite database consistently and protect the request directory
before deployment or certificate changes. File permissions are 0700 for new
request directories and 0600 for artifacts. Backups include private keys and
must have equivalent protection. Automatic pre-change backup, an operator
rollback workflow, expiry notifications and a topic-filtered canary action
remain completion work. APNs and enqueue operational CLIs require an existing
database with exactly the supported migration set. They refuse missing, older
or newer schemas without creating or migrating a database. Back up and upgrade
the server explicitly before running a CLI from the completion branch.
