-- 038_scep_challenges: one-time SCEP challenges Cairn hands to devices when an
-- external CA checks each request's challenge with Cairn before it issues
-- ([ca.external.challenge_lookup]).
--
-- Only the SHA-256 of a challenge is stored: the CA sends the challenge the
-- device presented and Cairn looks the hash up. A challenge is good for one
-- certificate name and one key. common_name is the exact name the request must
-- carry when Cairn knows it (a renewal, or an enrollment with an expected
-- serial); otherwise cn_suffix is the ending it must have. used_key_id is the
-- request's subject key identifier as the CA reported it, which lets a renewal
-- accept only the key that used that device's challenge.
CREATE TABLE scep_challenges (
    id               INTEGER PRIMARY KEY,
    challenge_sha256 TEXT NOT NULL UNIQUE,
    purpose          TEXT NOT NULL,
    device_id        TEXT NOT NULL DEFAULT '',
    common_name      TEXT NOT NULL DEFAULT '',
    cn_suffix        TEXT NOT NULL DEFAULT '',
    note             TEXT NOT NULL DEFAULT '',
    state            TEXT NOT NULL DEFAULT 'OPEN',
    used_cn          TEXT NOT NULL DEFAULT '',
    used_key_id      TEXT NOT NULL DEFAULT '',
    expires_at       TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    used_at          TEXT,
    CHECK (purpose IN ('enroll', 'renew')),
    CHECK (state IN ('OPEN', 'USED', 'CLOSED'))
);

CREATE INDEX idx_scep_challenges_device ON scep_challenges (device_id, purpose, state);
