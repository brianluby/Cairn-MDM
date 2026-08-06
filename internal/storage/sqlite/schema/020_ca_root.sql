-- 020_ca_root: add the offline-root certificate to the CA singleton for two-tier
-- mode. In two-tier mode cert_pem/key_pem hold the ONLINE ISSUING CA (which signs
-- leaves and lives on this host) and root_cert_pem holds the OFFLINE ROOT's
-- certificate (public only — the root key never touches this host). The root is the
-- long-lived device trust anchor; the issuer chains to it. root_cert_pem is NULL for
-- single-tier (generate/import) deployments.
ALTER TABLE ca ADD COLUMN root_cert_pem BLOB;
