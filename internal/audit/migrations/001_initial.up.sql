CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    event_type  TEXT    NOT NULL,
    pkg_type    TEXT    NOT NULL,
    pkg_name    TEXT    NOT NULL,
    pkg_version TEXT    DEFAULT '',
    client_ip   TEXT    DEFAULT '',
    user_agent  TEXT    DEFAULT '',
    status      TEXT    DEFAULT '',
    duration_ms INTEGER DEFAULT 0,
    details     TEXT    DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_pkg ON events(pkg_type, pkg_name);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_client ON events(client_ip);

CREATE TABLE IF NOT EXISTS checksums (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pkg_type    TEXT NOT NULL,
    pkg_name    TEXT NOT NULL,
    pkg_version TEXT NOT NULL DEFAULT '',
    s3_key      TEXT NOT NULL UNIQUE,
    algorithm   TEXT NOT NULL DEFAULT 'sha256',
    value       TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_checksums_pkg ON checksums(pkg_type, pkg_name);

CREATE TABLE IF NOT EXISTS api_tokens (
    id         TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    hash       TEXT NOT NULL,
    comment    TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT,
    last_used  TEXT
);
