-- 034_vpn_identities: one row per VPN certificate Cairn asked a CA to issue for
-- a device, and the delivery of the profile that carries it.
--
-- The private key is never stored here. It exists in memory while the profile
-- is rendered and inside the queued InstallProfile command until the device
-- reports; the queued body is then replaced (see ScrubVPNPayload).
--
-- state follows the same fail-closed rule as cert_issuance: ISSUING is written
-- before the CA is contacted, an ambiguous CA outcome becomes QUARANTINED and
-- is never retried with the same key, and a new attempt is a new row with a new
-- key. SUPERSEDED marks an earlier certificate once its replacement is on the
-- device.
CREATE TABLE vpn_identities (
    id             INTEGER PRIMARY KEY,
    server_id      INTEGER NOT NULL REFERENCES vpn_servers(id) ON DELETE RESTRICT,
    device_id      TEXT NOT NULL,
    directory_id   TEXT NOT NULL,
    object_id      TEXT NOT NULL,
    upn            TEXT NOT NULL,
    account_name   TEXT NOT NULL,
    actor          TEXT NOT NULL,           -- administrator who authorized it
    state          TEXT NOT NULL DEFAULT 'ISSUING',
    spki_sha256    TEXT NOT NULL,
    cert_serial    TEXT NOT NULL DEFAULT '',
    leaf_der       BLOB,
    not_after      TEXT NOT NULL DEFAULT '', -- RFC 3339, set when ISSUED
    backend        TEXT NOT NULL DEFAULT '',
    fail_reason    TEXT NOT NULL DEFAULT '',
    command_uuid   TEXT NOT NULL DEFAULT '',
    deploy_status  TEXT NOT NULL DEFAULT '', -- '' | sent | installed | failed | expired
    revoked_at     TEXT,                     -- set when the CA accepted a revocation
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK (state IN ('ISSUING', 'ISSUED', 'FAILED', 'QUARANTINED', 'SUPERSEDED', 'REVOKED')),
    CHECK (deploy_status IN ('', 'sent', 'installed', 'failed', 'expired')),
    CHECK ((state IN ('ISSUING', 'FAILED')) = (length(cert_serial) = 0) OR state = 'QUARANTINED')
);

-- One attempt in flight per device and server.
CREATE UNIQUE INDEX idx_vpn_identities_inflight ON vpn_identities (device_id, server_id) WHERE state = 'ISSUING';
CREATE INDEX idx_vpn_identities_device ON vpn_identities (device_id, server_id, id DESC);
CREATE INDEX idx_vpn_identities_command ON vpn_identities (command_uuid) WHERE command_uuid <> '';
