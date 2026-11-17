-- Old sessions retain no verified directory identity; they must sign in again
-- to obtain one. Names are never retroactively promoted to immutable identities.
ALTER TABLE app_sessions ADD COLUMN directory_identity TEXT NOT NULL DEFAULT '';
