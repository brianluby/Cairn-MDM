-- 039_device_profiles: the profiles a device last reported as installed, from
-- its answer to a ProfileList command. Each answer replaces the device's rows.
--
-- This is what lets the console remove a profile Cairn did not install, such
-- as one left by an earlier MDM server: a removal needs the profile's
-- identifier, and only the device knows it.
CREATE TABLE device_profiles (
    device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    identifier    TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    organization  TEXT NOT NULL DEFAULT '',
    payload_types TEXT NOT NULL DEFAULT '', -- comma separated
    managed       INTEGER NOT NULL DEFAULT 0, -- installed by MDM, so MDM can remove it
    seen_at       TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (device_id, identifier)
);
