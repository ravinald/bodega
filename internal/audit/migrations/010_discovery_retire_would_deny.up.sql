-- Narrow the decision CHECK by dropping would_deny, which only ever came from
-- discover_mode=learn. Enforcement is now unconditional, so nothing writes it.
--
-- Existing would_deny rows become denied rather than being deleted. They are
-- the record of a request the allow-list rejected while learn mode let it
-- through, which is exactly the forensic question this table exists to answer;
-- a discovery log that loses rows on an upgrade is worse than one carrying a
-- retired label. The label changes because "denied" is what the same request
-- gets today, and a reader filtering on decision should find it.
--
-- decision is part of the primary key, so a rewrite can collide with a denied
-- row for the same (registry_type, pattern_hint, pkg_name, pkg_version). The
-- upsert merges instead of failing: counts add, the window widens to cover
-- both, and last_client follows the later last_seen.
--
-- SQLite cannot ALTER a CHECK constraint, so the table is recreated. Same
-- rename-first shape as 009: the copy reads from a table whose indexes have
-- already moved with it, and both indexes are rebuilt below.
ALTER TABLE upstream_discovery RENAME TO upstream_discovery_learn;

DROP INDEX IF EXISTS idx_discovery_type_pattern;
DROP INDEX IF EXISTS idx_discovery_last_seen;

CREATE TABLE upstream_discovery (
    registry_type TEXT NOT NULL,
    host          TEXT NOT NULL DEFAULT '',
    pattern_hint  TEXT NOT NULL,
    pkg_name      TEXT NOT NULL DEFAULT '',
    pkg_version   TEXT NOT NULL DEFAULT '',
    decision      TEXT NOT NULL CHECK(decision IN ('allowed','denied','no_policy','no_manifest','no_namespace')),
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
    registry_type, host, pattern_hint, pkg_name, pkg_version,
    CASE WHEN decision = 'would_deny' THEN 'denied' ELSE decision END,
    first_seen, last_seen, last_client, request_count, upstream_url
FROM upstream_discovery_learn
-- WHERE true is required, not decoration: without it SQLite's parser reads the
-- following ON as a join constraint on the SELECT and rejects the DO.
WHERE true
ON CONFLICT(registry_type, pattern_hint, pkg_name, pkg_version, decision)
DO UPDATE SET
    request_count = upstream_discovery.request_count + excluded.request_count,
    first_seen    = MIN(upstream_discovery.first_seen, excluded.first_seen),
    last_seen     = MAX(upstream_discovery.last_seen, excluded.last_seen),
    last_client   = CASE WHEN excluded.last_seen > upstream_discovery.last_seen
                         THEN excluded.last_client ELSE upstream_discovery.last_client END,
    host          = CASE WHEN upstream_discovery.host = '' THEN excluded.host ELSE upstream_discovery.host END,
    upstream_url  = CASE WHEN upstream_discovery.upstream_url = '' THEN excluded.upstream_url ELSE upstream_discovery.upstream_url END;

DROP TABLE upstream_discovery_learn;

CREATE INDEX IF NOT EXISTS idx_discovery_type_pattern ON upstream_discovery(registry_type, pattern_hint);
CREATE INDEX IF NOT EXISTS idx_discovery_last_seen   ON upstream_discovery(last_seen);
