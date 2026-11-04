-- Stable local identities prevent delete/recreate from inheriting a factor.
ALTER TABLE app_users ADD COLUMN subject_id TEXT NOT NULL DEFAULT '';
UPDATE app_users SET subject_id=lower(hex(randomblob(32)));
CREATE UNIQUE INDEX app_users_subject ON app_users(subject_id) WHERE subject_id<>'';
ALTER TABLE app_sessions ADD COLUMN auth_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE app_sessions ADD COLUMN mfa_verified_at INTEGER NOT NULL DEFAULT 0;
CREATE TABLE mfa_factors (
 principal TEXT PRIMARY KEY,
 secret BLOB NOT NULL,
 last_counter INTEGER NOT NULL DEFAULT -1
);
CREATE TABLE mfa_invitations (
 principal TEXT PRIMARY KEY,
 token_hash TEXT NOT NULL UNIQUE,
 expires_at INTEGER NOT NULL
);
CREATE TABLE mfa_setups (
 principal TEXT PRIMARY KEY,
 session_hash TEXT NOT NULL,
 secret BLOB NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE TABLE mfa_recovery (
 principal TEXT NOT NULL,
 code_hash TEXT NOT NULL,
 PRIMARY KEY(principal,code_hash)
);
CREATE TABLE mfa_attempts (
 principal TEXT PRIMARY KEY,
 failures INTEGER NOT NULL DEFAULT 0,
 blocked_until INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE mfa_state (id INTEGER PRIMARY KEY CHECK(id=1), bootstrap_closed INTEGER NOT NULL DEFAULT 0);
INSERT INTO mfa_state(id) VALUES(1);
