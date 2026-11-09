-- 031_quarantine_resolution: durable evidence for releasing a quarantined
-- issuance. Each step stores the manifest the backend or server produced, not an
-- operator checkbox; release re-validates manifest content. A grant with
-- released_at set no longer appears in the quarantine work list, but its
-- cert_issuance row stays QUARANTINED: the slot is never reissued, the device
-- re-enrolls with a new grant.
CREATE TABLE quarantine_resolutions (
    grant_id             INTEGER PRIMARY KEY REFERENCES enrollment_grants(id) ON DELETE RESTRICT,
    fence_manifest       TEXT NOT NULL DEFAULT '',
    fenced_at            TEXT,
    fenced_by            TEXT NOT NULL DEFAULT '',
    enumeration_manifest TEXT NOT NULL DEFAULT '',
    enumerated_at        TEXT,
    enumerated_by        TEXT NOT NULL DEFAULT '',
    rejection_manifest   TEXT NOT NULL DEFAULT '',
    rejected_at          TEXT,
    rejected_by          TEXT NOT NULL DEFAULT '',
    released_at          TEXT,
    released_by          TEXT NOT NULL DEFAULT ''
);

-- Observed Access-Rejects reported by RADIUS acceptance points through the
-- authenticated ingest endpoint. Never written from a console form.
CREATE TABLE radius_rejections (
    id               INTEGER PRIMARY KEY,
    serial           TEXT NOT NULL,
    acceptance_point TEXT NOT NULL,
    observed_at      TEXT NOT NULL,
    received_at      TEXT NOT NULL DEFAULT (datetime('now')),
    source           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_radius_rejections_serial ON radius_rejections (serial, acceptance_point, observed_at);
