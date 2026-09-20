CREATE TABLE IF NOT EXISTS upstream_discovery (
    registry_type TEXT NOT NULL,
    host          TEXT NOT NULL DEFAULT '',
    pattern_hint  TEXT NOT NULL,
    pkg_name      TEXT NOT NULL DEFAULT '',
    pkg_version   TEXT NOT NULL DEFAULT '',
    decision      TEXT NOT NULL CHECK(decision IN ('allowed','denied','would_deny','no_policy')),
    first_seen    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_client   TEXT NOT NULL DEFAULT '',
    request_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (registry_type, pattern_hint, pkg_name, pkg_version, decision)
);

CREATE INDEX IF NOT EXISTS idx_discovery_type_pattern ON upstream_discovery(registry_type, pattern_hint);
CREATE INDEX IF NOT EXISTS idx_discovery_last_seen   ON upstream_discovery(last_seen);
