-- 032_renewal_attempts: SCEP requests signed with a certificate this CA issued.
-- Renewal is not implemented in this release; each attempt is refused and kept
-- here so the operator sees which device needs a new enrollment link.
CREATE TABLE renewal_attempts (
    id             INTEGER PRIMARY KEY,
    observed_at    TEXT NOT NULL DEFAULT (datetime('now')),
    spki_sha256    TEXT NOT NULL DEFAULT '',
    signer_serial  TEXT NOT NULL,
    signer_sha256  TEXT NOT NULL,
    signer_subject TEXT NOT NULL DEFAULT '',
    signer_expires TEXT NOT NULL DEFAULT '',
    enrollment_id  TEXT NOT NULL DEFAULT '',
    reason         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_renewal_attempts_enrollment ON renewal_attempts (enrollment_id, observed_at);
