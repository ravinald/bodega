-- Host inventory, as reported by inventory sources (internal/inventory).
--
-- inventory_hosts maps what a source calls a host to the identity bodega
-- calls it. It is keyed by source instance rather than by source type: two
-- Falcon tenants can each have a host 42, and they are different hosts. This
-- table replaces a new identity_bindings kind per tool, which would have
-- needed a table rebuild for every collector.
CREATE TABLE IF NOT EXISTS inventory_hosts (
    source      TEXT NOT NULL,
    external_id TEXT NOT NULL,
    identity    TEXT NOT NULL,
    first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (source, external_id)
);
CREATE INDEX IF NOT EXISTS idx_inventory_hosts_identity ON inventory_hosts(identity);

-- One row per report a source delivered. identity is '' for a report from an
-- external id nothing mapped; it is kept rather than dropped, and binding the
-- id later does not rewrite it.
--
-- seq and prev_sha256 chain the reports of one host under one source, so a
-- gap or a substituted row is visible to a reader without trusting the
-- writer. The chain is keyed on (source, identity), or on (source,
-- external_id) while the host is unbound.
CREATE TABLE IF NOT EXISTS inventory_reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT    NOT NULL,
    external_id TEXT    NOT NULL,
    identity    TEXT    NOT NULL DEFAULT '',
    observed_at TEXT    NOT NULL,
    received_at TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    prev_sha256 TEXT    NOT NULL DEFAULT '',
    sha256      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inventory_reports_chain ON inventory_reports(source, identity, external_id, seq);
CREATE INDEX IF NOT EXISTS idx_inventory_reports_received ON inventory_reports(source, received_at);

CREATE TABLE IF NOT EXISTS inventory_components (
    report_id   INTEGER NOT NULL REFERENCES inventory_reports(id),
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    path        TEXT NOT NULL DEFAULT '',
    digest_alg  TEXT NOT NULL DEFAULT '',
    digest      TEXT NOT NULL DEFAULT '',
    origin      TEXT NOT NULL DEFAULT '',
    purl        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_inventory_components_report ON inventory_components(report_id);
CREATE INDEX IF NOT EXISTS idx_inventory_components_pkg ON inventory_components(ecosystem, name, version);

-- Evidence that a host tried to reach a package registry directly.
CREATE TABLE IF NOT EXISTS inventory_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,
    external_id TEXT NOT NULL,
    identity    TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    destination TEXT NOT NULL,
    ecosystem   TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_inventory_attempts_source ON inventory_attempts(source, received_at);

-- The three tables above are append-only. Retention deletes whole rows by
-- age and is the only writer allowed to remove one; nothing may edit a row in
-- place, and these triggers make that a property of the store rather than a
-- convention every future caller has to know.
CREATE TRIGGER IF NOT EXISTS inventory_reports_append_only BEFORE UPDATE ON inventory_reports
BEGIN SELECT RAISE(ABORT, 'inventory_reports is append-only'); END;
CREATE TRIGGER IF NOT EXISTS inventory_components_append_only BEFORE UPDATE ON inventory_components
BEGIN SELECT RAISE(ABORT, 'inventory_components is append-only'); END;
CREATE TRIGGER IF NOT EXISTS inventory_attempts_append_only BEFORE UPDATE ON inventory_attempts
BEGIN SELECT RAISE(ABORT, 'inventory_attempts is append-only'); END;

-- Per-instance poll state for pull sources: the last attempt, the last
-- success and the error the attempt returned. Mutable on purpose, since it
-- answers "how stale is this source now" and nothing else.
CREATE TABLE IF NOT EXISTS inventory_source_polls (
    source          TEXT PRIMARY KEY,
    last_attempt_at TEXT NOT NULL DEFAULT '',
    last_success_at TEXT NOT NULL DEFAULT '',
    last_error      TEXT NOT NULL DEFAULT ''
);
