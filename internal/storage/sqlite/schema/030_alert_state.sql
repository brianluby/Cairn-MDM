-- 030_alert_state: remembered alert conditions so the notifier sends one
-- message when a condition appears, a reminder while it persists, and a
-- recovery message when it clears, instead of repeating itself every check.
CREATE TABLE alert_state (
    key         TEXT PRIMARY KEY,
    active      INTEGER NOT NULL DEFAULT 0,
    message     TEXT NOT NULL DEFAULT '',
    changed_at  TEXT NOT NULL DEFAULT (datetime('now')),
    notified_at TEXT
);
