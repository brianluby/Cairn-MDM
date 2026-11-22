-- 040_manual_devices: devices that cannot enroll in MDM (a HomePod, an Apple
-- Vision Pro without Apple Business Manager, an Apple Watch) but still need a
-- certificate for Wi-Fi. An administrator records one here and downloads a
-- profile to install on it by hand.
--
-- The device has no enrollment ID, so its certificates are kept in
-- vpn_offers and vpn_identities under the device_id 'manual:<id>'. Cairn
-- cannot renew or remove anything on such a device; it can only show when the
-- certificate was issued and when it expires.
CREATE TABLE manual_devices (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'other', -- appletv | homepod | visionpro | watch | other
    directory_id TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    upn          TEXT NOT NULL,
    account_name TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    removed_at   TEXT
);
