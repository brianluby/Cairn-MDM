-- 035_device_identity_certs: the identity certificate each device presents at
-- check-in, whichever CA issued it.
--
-- Cairn's own CA records what it issues in scep_certs. A device enrolled
-- through an external CA gets its certificate from that CA directly, so until
-- now Cairn never learned when it expires. A device with an expired identity
-- certificate is refused at check-in and cannot be told to do anything,
-- including enroll again, so the expiry has to be known well beforehand.
--
-- Rows are written only for certificates already associated with an enrollment
-- (cert_auth), so an unauthenticated caller cannot add any.
CREATE TABLE device_identity_certs (
    sha256        TEXT PRIMARY KEY,          -- hex SHA-256 of the DER certificate, as in cert_auth
    subject       TEXT NOT NULL DEFAULT '',
    issuer        TEXT NOT NULL DEFAULT '',
    serial        TEXT NOT NULL DEFAULT '',
    not_after     TEXT NOT NULL,             -- RFC 3339
    last_accepted TEXT,                      -- last check-in whose signature verified
    last_refused  TEXT,                      -- last check-in refused at signature verification
    refusals      INTEGER NOT NULL DEFAULT 0
);
