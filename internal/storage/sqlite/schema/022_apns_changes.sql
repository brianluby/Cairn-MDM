-- Protected recovery material and install receipt are committed with APNs state.
-- These keys have the same sensitivity as nano_kv and belong in protected backups.
CREATE TABLE apns_changes (
    id INTEGER PRIMARY KEY,
    request_id TEXT UNIQUE,
    topic TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    subject TEXT NOT NULL,
    not_after TEXT NOT NULL,
    renew_topic TEXT NOT NULL,
    make_default INTEGER NOT NULL CHECK(make_default IN (0,1)),
    previous_cert BLOB,
    previous_key BLOB,
    installed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    actor TEXT NOT NULL,
    provider TEXT NOT NULL
);
