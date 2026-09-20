-- The postgres sink holds the append-only half of the audit trail and nothing
-- else. The other eight SQLite migrations describe operational state — tokens,
-- ACLs, checksums, the age/OSV/upstream policies — which the request path reads
-- to make decisions and which stays in the embedded store on every host. A sink
-- implements two tables, so this set is two tables rather than a port of ten.
--
-- The decision CHECK is copied from SQLite migration 010 deliberately: a value
-- the embedded store refuses must not be accepted here, or a sink swap would
-- silently widen what the discovery table can hold.

CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type  TEXT        NOT NULL,
    pkg_type    TEXT        NOT NULL DEFAULT '',
    pkg_name    TEXT        NOT NULL DEFAULT '',
    pkg_version TEXT        NOT NULL DEFAULT '',
    client_ip   TEXT        NOT NULL DEFAULT '',
    user_agent  TEXT        NOT NULL DEFAULT '',
    status      TEXT        NOT NULL DEFAULT '',
    duration_ms BIGINT      NOT NULL DEFAULT 0,
    details     TEXT        NOT NULL DEFAULT '',
    actor       TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_pkg       ON events(pkg_type, pkg_name);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_client    ON events(client_ip);
CREATE INDEX IF NOT EXISTS idx_events_actor     ON events(actor);

CREATE TABLE IF NOT EXISTS upstream_discovery (
    registry_type TEXT        NOT NULL,
    host          TEXT        NOT NULL DEFAULT '',
    pattern_hint  TEXT        NOT NULL,
    pkg_name      TEXT        NOT NULL DEFAULT '',
    pkg_version   TEXT        NOT NULL DEFAULT '',
    decision      TEXT        NOT NULL CHECK(decision IN ('allowed','denied','no_policy','no_manifest','no_namespace')),
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_client   TEXT        NOT NULL DEFAULT '',
    request_count BIGINT      NOT NULL DEFAULT 1,
    upstream_url  TEXT        NOT NULL DEFAULT '',
    PRIMARY KEY (registry_type, pattern_hint, pkg_name, pkg_version, decision)
);

CREATE INDEX IF NOT EXISTS idx_discovery_type_pattern ON upstream_discovery(registry_type, pattern_hint);
CREATE INDEX IF NOT EXISTS idx_discovery_last_seen    ON upstream_discovery(last_seen);
