-- 036_device_renewals: renewing the identity certificate a device checks in with.
--
-- Apple devices never renew this certificate themselves. Cairn pushes the
-- enrollment profile again before it expires; the device asks the CA for a new
-- certificate and switches to it. A renewal row follows one attempt:
--
--   lookup    asked the device which profile holds its enrollment
--   sent      enrollment profile queued for the device
--   installed the device reported the profile installed
--   renewed   the device checked in with the new certificate
--   failed    the device reported an error, or never answered
--
-- The row is written with its CommandUUID before the command is queued, so the
-- device's answer always finds it.
CREATE TABLE device_renewals (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id          TEXT NOT NULL,
    state              TEXT NOT NULL CHECK (state IN ('lookup','sent','installed','renewed','failed')),
    command_uuid       TEXT NOT NULL,             -- the command the device has to answer next
    old_sha256         TEXT NOT NULL,             -- certificate being replaced, as in cert_auth
    new_sha256         TEXT NOT NULL DEFAULT '',
    profile_identifier TEXT NOT NULL DEFAULT '',  -- PayloadIdentifier of the enrollment profile on the device
    actor              TEXT NOT NULL DEFAULT '',  -- 'schedule', or the administrator who asked
    error              TEXT NOT NULL DEFAULT '',
    started_at         TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at         TEXT NOT NULL DEFAULT (datetime('now')),
    old_retired_at     TEXT                       -- when the replaced certificate stopped being accepted
);

-- One attempt in flight per device.
CREATE UNIQUE INDEX idx_device_renewals_open ON device_renewals (device_id) WHERE state IN ('lookup','sent','installed');
CREATE INDEX idx_device_renewals_device ON device_renewals (device_id, id);

-- The renewal request repeats the current certificate's name and owner address.
ALTER TABLE device_identity_certs ADD COLUMN common_name TEXT NOT NULL DEFAULT '';
ALTER TABLE device_identity_certs ADD COLUMN san_email TEXT NOT NULL DEFAULT '';

-- The host name the device last checked in through. A fleet moved from another
-- server can still use an earlier name, and the renewed profile has to keep it.
ALTER TABLE devices ADD COLUMN checkin_host TEXT NOT NULL DEFAULT '';
