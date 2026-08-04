-- 017_single_use_grants: enrollment grants are single-use in the issuance model
-- (one grant -> one device -> one owner -> one certificate). The issuance state
-- machine (016) binds exactly one certificate per grant via UNIQUE(grant_id), so
-- a multi-use grant could never issue past the first device. Clamp any legacy
-- multi-use grants to single-use so storage and behavior agree.
UPDATE enrollment_grants SET max_uses = 1 WHERE max_uses > 1;
