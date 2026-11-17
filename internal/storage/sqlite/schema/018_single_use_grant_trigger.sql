-- 018_single_use_grant_trigger: durable, rollback-safe enforcement that enrollment
-- grants are single-use. Code-level enforcement (CreateGrant pins max_uses=1) and
-- the 017 data clamp are not rollback-safe on their own: a binary rolled back past
-- the code enforcement could insert a multi-use grant. These triggers live in the
-- database schema, so single-use holds regardless of the application binary.
-- (017 clamps existing rows before this runs; no existing row can violate it.)

CREATE TRIGGER trg_grants_single_use_insert
BEFORE INSERT ON enrollment_grants
WHEN NEW.max_uses <> 1
BEGIN
    SELECT RAISE(ABORT, 'enrollment grants are single-use (max_uses must be 1)');
END;

CREATE TRIGGER trg_grants_single_use_update
BEFORE UPDATE OF max_uses ON enrollment_grants
WHEN NEW.max_uses <> 1
BEGIN
    SELECT RAISE(ABORT, 'enrollment grants are single-use (max_uses must be 1)');
END;
