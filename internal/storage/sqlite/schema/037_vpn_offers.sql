-- 037_vpn_offers: one row per invitation for a device to request a VPN
-- certificate for a key it makes itself (IKEv2 certificate sign-in).
--
-- The profile sent to the device carries a one-time SCEP challenge. Only its
-- SHA-256 is stored. The first request that presents it claims the offer for
-- that public key and creates the vpn_identities row; a request with any other
-- key is refused from then on, and the same key may retry. An offer nobody
-- claims closes when it expires or the device's enrollment ends.
CREATE TABLE vpn_offers (
    id               INTEGER PRIMARY KEY,
    server_id        INTEGER NOT NULL REFERENCES vpn_servers(id) ON DELETE RESTRICT,
    device_id        TEXT NOT NULL,
    directory_id     TEXT NOT NULL,
    object_id        TEXT NOT NULL,
    upn              TEXT NOT NULL,
    account_name     TEXT NOT NULL,
    actor            TEXT NOT NULL,
    challenge_sha256 TEXT NOT NULL UNIQUE,
    command_uuid     TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'OFFERED',
    spki_sha256      TEXT NOT NULL DEFAULT '',
    identity_id      INTEGER REFERENCES vpn_identities(id),
    close_reason     TEXT NOT NULL DEFAULT '',
    expires_at       TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK (state IN ('OFFERED', 'CLAIMED', 'CLOSED')),
    CHECK ((state = 'CLAIMED') = (identity_id IS NOT NULL))
);

-- One open offer per device and server.
CREATE UNIQUE INDEX idx_vpn_offers_open ON vpn_offers (device_id, server_id) WHERE state = 'OFFERED';
CREATE INDEX idx_vpn_offers_device ON vpn_offers (device_id, id DESC);
