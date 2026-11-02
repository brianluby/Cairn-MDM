CREATE TABLE push_retry_actions (
 action_hash TEXT PRIMARY KEY,
 command_uuid TEXT NOT NULL,
 device_id TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT(datetime('now'))
);
