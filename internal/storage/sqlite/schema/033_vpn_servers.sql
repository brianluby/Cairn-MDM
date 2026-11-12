-- 033_vpn_servers: admin-managed OpenVPN server definitions that per-device VPN
-- profiles are rendered from.
--
-- config is JSON of the non-secret settings (addresses, server certificate name,
-- CA chain, cipher, flags). tls_key is the server's shared tls-auth/tls-crypt
-- key, sealed with a key file kept outside this database (<db>.vpn/key); a copy
-- of the database alone cannot recover it. slug is immutable: it is part of the
-- profile's PayloadIdentifier, the device-side key that makes a re-issued
-- profile replace the installed one.
CREATE TABLE vpn_servers (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    config     TEXT NOT NULL,
    tls_key    BLOB,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
