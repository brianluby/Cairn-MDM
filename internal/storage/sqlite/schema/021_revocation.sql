-- 021_revocation: certificate revocation for the embedded CA. One row per revoked
-- leaf; serial is the certificate SerialNumber in lowercase hex (big.Int.Text(16),
-- matching the serial the issuance path records). reason is the RFC 5280 CRLReason
-- code (0 unspecified, 1 keyCompromise, 4 superseded). The CRL is generated from
-- this table on demand and signed by the online issuing CA.
CREATE TABLE revoked_certs (
	serial     TEXT PRIMARY KEY,
	reason     INTEGER NOT NULL DEFAULT 0,
	revoked_at TEXT NOT NULL DEFAULT (datetime('now'))
);
