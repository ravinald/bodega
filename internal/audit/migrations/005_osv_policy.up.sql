CREATE TABLE IF NOT EXISTS osv_policy (
    ecosystem  TEXT PRIMARY KEY,
    action     TEXT NOT NULL CHECK(action IN ('warn','block','ignore')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
