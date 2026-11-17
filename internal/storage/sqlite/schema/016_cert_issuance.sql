-- 016_cert_issuance: the issuance state machine that binds an enrollment grant to
-- exactly one certificate issuance, idempotent under SCEP retries and ambiguous
-- CA responses.
--
-- Distinct from grant redemption (profile delivery): a grant authorizes issuance,
-- but issuance itself is tracked here and keyed by the idempotency triple
-- (txn_id, spki_sha256, request_hash). UNIQUE(grant_id) enforces a single issuance
-- per grant (single-use at Cairn). States: ISSUING -> ISSUED (records serial), or
-- ISSUING -> FAILED (recoverable: a fresh request may rebind a FAILED slot).
-- Moving straight from "profile served" to "issued" would risk double-issuance or
-- burning a grant on a CA timeout; the ISSUING row is what makes retries safe.
-- See issuance.go for the transition semantics.

CREATE TABLE cert_issuance (
    id           INTEGER PRIMARY KEY,
    -- ON DELETE RESTRICT: a grant that has an issuance record cannot be deleted,
    -- so its rowid can never be reused by a later grant and inherit this binding.
    grant_id     INTEGER NOT NULL REFERENCES enrollment_grants(id) ON DELETE RESTRICT,
    txn_id       TEXT NOT NULL,
    spki_sha256  TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'ISSUING', -- ISSUING | ISSUED | FAILED
    cert_serial  TEXT NOT NULL DEFAULT '',
    fail_reason  TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (grant_id),
    CHECK (state IN ('ISSUING', 'ISSUED', 'FAILED')),
    -- A serial exists exactly when ISSUED: ISSUING/FAILED carry no serial, and an
    -- ISSUED row cannot exist without one (no "issued but empty serial" state).
    CHECK ((state = 'ISSUED') = (length(cert_serial) > 0))
);

CREATE INDEX idx_issuance_txn ON cert_issuance (txn_id);
