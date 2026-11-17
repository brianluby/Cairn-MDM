-- 019_issuance_quarantine: add the QUARANTINED terminal state and the
-- ambiguity/caching columns to cert_issuance.
--
-- QUARANTINED holds an *ambiguous* outcome — a response lost after the CA may have
-- signed — so it is never relabeled a definitive FAILED and never retried as a fresh
-- issuance (that would risk double-issuance). It is distinct from FAILED (a clean,
-- proven-not-signed failure). leaf_der caches the issued certificate so an idempotent
-- SCEP retry returns the identical CertRep without re-hitting the backend CA. backend
-- / backend_txn record which CA backend produced the outcome and its transaction id,
-- for reconciliation.
--
-- SQLite cannot ALTER a CHECK constraint, so the table is rebuilt (create new, copy,
-- drop, rename). Nothing references cert_issuance, and the copied rows keep satisfying
-- the FK to enrollment_grants, so the rebuild is safe inside the migration
-- transaction. FK/UNIQUE(grant_id)/the two CHECKs and the txn index are preserved.

CREATE TABLE cert_issuance_new (
    id           INTEGER PRIMARY KEY,
    grant_id     INTEGER NOT NULL REFERENCES enrollment_grants(id) ON DELETE RESTRICT,
    txn_id       TEXT NOT NULL,
    spki_sha256  TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'ISSUING', -- ISSUING | ISSUED | FAILED | QUARANTINED
    cert_serial  TEXT NOT NULL DEFAULT '',
    fail_reason  TEXT NOT NULL DEFAULT '',
    quarantine_reason TEXT NOT NULL DEFAULT '',
    quarantined_at    TEXT,
    backend      TEXT NOT NULL DEFAULT '',
    backend_txn  TEXT NOT NULL DEFAULT '',
    leaf_der     BLOB,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (grant_id),
    -- QUARANTINED carries no serial, so it satisfies the ISSUED<=>serial invariant.
    CHECK (state IN ('ISSUING', 'ISSUED', 'FAILED', 'QUARANTINED')),
    CHECK ((state = 'ISSUED') = (length(cert_serial) > 0))
);

INSERT INTO cert_issuance_new
    (id, grant_id, txn_id, spki_sha256, request_hash, state, cert_serial, fail_reason, created_at, updated_at)
SELECT id, grant_id, txn_id, spki_sha256, request_hash, state, cert_serial, fail_reason, created_at, updated_at
FROM cert_issuance;

DROP TABLE cert_issuance;
ALTER TABLE cert_issuance_new RENAME TO cert_issuance;
CREATE INDEX idx_issuance_txn ON cert_issuance (txn_id);
