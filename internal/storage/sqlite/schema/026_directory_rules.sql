-- Preview-only rules; separate from manual device membership and deployment.
CREATE TABLE directory_profile_rules (
 id INTEGER PRIMARY KEY,
 group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
 directory_id TEXT NOT NULL,
 object_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('group','ou')),
 mode TEXT NOT NULL,
 name TEXT NOT NULL,
 dn TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT (datetime('now')),
 UNIQUE(group_id,directory_id,object_id,kind,mode),
 CHECK((kind='group' AND mode IN ('direct','nested')) OR (kind='ou' AND mode IN ('direct','descendants')))
);
