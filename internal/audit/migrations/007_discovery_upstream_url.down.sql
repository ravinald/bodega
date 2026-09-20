-- SQLite < 3.35 cannot DROP COLUMN; recreate the table without upstream_url.
-- Copy existing rows, drop original, rename, restore indexes.
CREATE TABLE upstream_discovery_pre007 (
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

INSERT INTO upstream_discovery_pre007
    (registry_type, host, pattern_hint, pkg_name, pkg_version, decision,
     first_seen, last_seen, last_client, request_count)
SELECT
    registry_type, host, pattern_hint, pkg_name, pkg_version, decision,
    first_seen, last_seen, last_client, request_count
FROM upstream_discovery;

DROP INDEX IF EXISTS idx_discovery_last_seen;
DROP INDEX IF EXISTS idx_discovery_type_pattern;
DROP TABLE upstream_discovery;
ALTER TABLE upstream_discovery_pre007 RENAME TO upstream_discovery;

CREATE INDEX IF NOT EXISTS idx_discovery_type_pattern ON upstream_discovery(registry_type, pattern_hint);
CREATE INDEX IF NOT EXISTS idx_discovery_last_seen   ON upstream_discovery(last_seen);
