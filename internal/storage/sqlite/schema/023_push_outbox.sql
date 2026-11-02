CREATE TABLE push_outbox (
 command_uuid TEXT NOT NULL,
 device_id TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','accepted','exhausted','resolved')),
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt INTEGER NOT NULL DEFAULT 0,
 lease_until INTEGER NOT NULL DEFAULT 0,
 lease_token TEXT NOT NULL DEFAULT '',
 last_error TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(command_uuid,device_id),
 FOREIGN KEY(command_uuid,device_id) REFERENCES command_history(command_uuid,device_id) ON DELETE CASCADE
);
