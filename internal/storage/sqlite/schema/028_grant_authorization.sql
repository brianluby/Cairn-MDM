ALTER TABLE enrollment_grants ADD COLUMN owner_identity TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollment_grants ADD COLUMN actor_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollment_grants ADD COLUMN actor_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollment_grants ADD COLUMN mfa_verified_at INTEGER NOT NULL DEFAULT 0;
CREATE TABLE enrollment_previews (
 token_hash TEXT PRIMARY KEY,
 session_hash TEXT NOT NULL,
 payload TEXT NOT NULL,
 expires_at INTEGER NOT NULL
);
