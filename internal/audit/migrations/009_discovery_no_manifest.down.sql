-- Narrow the decision CHECK back to the four values migration 006 defined.
--
-- Rows carrying no_manifest or no_namespace cannot survive the narrower
-- constraint. They are DROPPED, not refused: upstream_discovery is a
-- regenerable observation log rather than a system of record, and a down
-- migration that aborts leaves the operator with a schema they cannot roll
-- back without hand-editing SQLite. Re-drive client traffic with
-- discover_mode set to recapture what the DELETE below discards.
ALTER TABLE upstream_discovery RENAME TO upstream_discovery_wide;

DROP INDEX IF EXISTS idx_discovery_type_pattern;
DROP INDEX IF EXISTS idx_discovery_last_seen;

CREATE TABLE upstream_discovery (
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
    upstream_url  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (registry_type, pattern_hint, pkg_name, pkg_version, decision)
);

INSERT INTO upstream_discovery
    (registry_type, host, pattern_hint, pkg_name, pkg_version, decision,
     first_seen, last_seen, last_client, request_count, upstream_url)
SELECT
    registry_type, host, pattern_hint, pkg_name, pkg_version, decision,
    first_seen, last_seen, last_client, request_count, upstream_url
FROM upstream_discovery_wide
WHERE decision NOT IN ('no_manifest','no_namespace');

DROP TABLE upstream_discovery_wide;

CREATE INDEX IF NOT EXISTS idx_discovery_type_pattern ON upstream_discovery(registry_type, pattern_hint);
CREATE INDEX IF NOT EXISTS idx_discovery_last_seen   ON upstream_discovery(last_seen);
