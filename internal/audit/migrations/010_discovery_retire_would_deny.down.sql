-- Widen the decision CHECK back to include would_deny.
--
-- The rewrite in the up migration is not reversible: a would_deny row that
-- merged into a denied row left no marker saying which requests came from
-- which, so rolling back restores the constraint and not the labels. Every row
-- carries forward with the label it has. An operator who needs the original
-- split has to read it out of a backup taken before 010.
ALTER TABLE upstream_discovery RENAME TO upstream_discovery_narrow;

DROP INDEX IF EXISTS idx_discovery_type_pattern;
DROP INDEX IF EXISTS idx_discovery_last_seen;

CREATE TABLE upstream_discovery (
    registry_type TEXT NOT NULL,
    host          TEXT NOT NULL DEFAULT '',
    pattern_hint  TEXT NOT NULL,
    pkg_name      TEXT NOT NULL DEFAULT '',
    pkg_version   TEXT NOT NULL DEFAULT '',
    decision      TEXT NOT NULL CHECK(decision IN ('allowed','denied','would_deny','no_policy','no_manifest','no_namespace')),
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
FROM upstream_discovery_narrow;

DROP TABLE upstream_discovery_narrow;

CREATE INDEX IF NOT EXISTS idx_discovery_type_pattern ON upstream_discovery(registry_type, pattern_hint);
CREATE INDEX IF NOT EXISTS idx_discovery_last_seen   ON upstream_discovery(last_seen);
