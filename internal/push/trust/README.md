# Apple APNs certificate trust

Public certificates downloaded November 2, 2026 from Apple's PKI directory:

- `apple-root.der`: https://www.apple.com/appleca/AppleIncRootCertificate.cer
- `apple-aai2.der`: https://www.apple.com/certificateauthority/AppleAAI2CA.cer

Source index: https://www.apple.com/certificateauthority/

The initial verifier bundles Apple Inc. Root and Application Integration 2,
the chain used by the reviewed MDM push certificate. Uploaded intermediates
may extend that chain; uploaded roots never become trust anchors. No system
root trust, AIA downloads or network-dependent certificate validation.

This is not an online revocation check or proof of APNs delivery. Future Apple
issuer/root changes require a reviewed trust-bundle update. Expand the bundle
only with official Apple certificates and corresponding chain tests.
