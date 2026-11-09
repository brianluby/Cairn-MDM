-- 029_device_ownership: connect enrolled devices to the verified owner whose
-- grant produced their identity certificate, and let directory rules apply to
-- those devices.
--
-- The chain is device -> cert_auth (the certificate the device authenticates
-- with) -> cert_issuance (Cairn issued that leaf for exactly one grant) ->
-- enrollment_grants.owner_identity. cert_issuance gains the leaf hash so the
-- join does not have to hash leaf_der at query time (backfilled in Go on open).
ALTER TABLE cert_issuance ADD COLUMN leaf_sha256 TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_issuance_leaf ON cert_issuance (leaf_sha256);

-- An administrator may pick one explicit Cairn device group at authorization
-- time (a site exception that does not need a directory change). It is applied
-- as ordinary manual membership once the device is bound to its owner.
ALTER TABLE enrollment_grants ADD COLUMN assign_group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL;

CREATE TABLE device_owners (
    device_id    TEXT PRIMARY KEY,
    grant_id     INTEGER NOT NULL REFERENCES enrollment_grants(id) ON DELETE RESTRICT,
    directory_id TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    upn          TEXT NOT NULL,
    account_name TEXT NOT NULL DEFAULT '',
    actor_subject TEXT NOT NULL DEFAULT '',
    bound_at     TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Directory-derived membership is kept apart from manual group_devices so a
-- refresh can replace it without touching administrator choices. A row names
-- the rule that produced it, so the console can explain each membership.
CREATE TABLE directory_memberships (
    device_id    TEXT NOT NULL,
    group_id     INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    rule_id      INTEGER NOT NULL REFERENCES directory_profile_rules(id) ON DELETE CASCADE,
    evaluated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (device_id, group_id, rule_id)
);
CREATE INDEX idx_directory_memberships_group ON directory_memberships (group_id);

-- One row per owned device: when rules were last evaluated and whether that
-- evaluation was usable. 'unavailable' means the previous memberships were kept
-- because the directory answer was unknown, not that the owner left every scope.
CREATE TABLE directory_evaluations (
    device_id    TEXT PRIMARY KEY,
    attempted_at TEXT NOT NULL DEFAULT (datetime('now')),
    evaluated_at TEXT,
    status       TEXT NOT NULL CHECK (status IN ('ok', 'unavailable')),
    detail       TEXT NOT NULL DEFAULT ''
);
