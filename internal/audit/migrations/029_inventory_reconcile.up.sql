-- Reconciliation of host inventory against what bodega served (F54).
--
-- inventory_classifications holds the class each component of a report got
-- when the report arrived, and the source-disagreement findings that report
-- produced. One row per report, written once: a component's class in an old
-- report is what bodega knew then, and reclassifying it under today's catalog
-- or baseline would rewrite the record of when a bypass became visible.
--
-- components and disagreements are JSON arrays rather than child tables
-- because every reader wants a report's whole result, and inventory_components
-- has no key of its own a child row could reference.
CREATE TABLE IF NOT EXISTS inventory_classifications (
    report_id     INTEGER PRIMARY KEY REFERENCES inventory_reports(id),
    source        TEXT NOT NULL,
    identity      TEXT NOT NULL,
    classified_at TEXT NOT NULL,
    components    TEXT NOT NULL DEFAULT '[]',
    disagreements TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_inventory_classifications_identity ON inventory_classifications(identity);

CREATE TRIGGER IF NOT EXISTS inventory_classifications_append_only BEFORE UPDATE ON inventory_classifications
BEGIN SELECT RAISE(ABORT, 'inventory_classifications is append-only'); END;

-- An accepted baseline: what an operator said a host (identity) or a class of
-- host (profile) is expected to carry. Exactly one of identity and profile is
-- set. The newest row for an identity or a profile is the one in force; older
-- rows stay as the record of what was accepted before.
--
-- The components are copied in rather than referenced, because retention
-- deletes reports and a baseline must outlive the report it was taken from.
CREATE TABLE IF NOT EXISTS inventory_baselines (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    identity   TEXT NOT NULL DEFAULT '',
    profile    TEXT NOT NULL DEFAULT '',
    report_ids TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT '',
    comment    TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK ((identity = '') <> (profile = ''))
);
CREATE INDEX IF NOT EXISTS idx_inventory_baselines_identity ON inventory_baselines(identity, id);
CREATE INDEX IF NOT EXISTS idx_inventory_baselines_profile ON inventory_baselines(profile, id);

-- version '' covers every version of the name: a profile entry with no pin
-- accepts whichever version the host runs.
CREATE TABLE IF NOT EXISTS inventory_baseline_components (
    baseline_id INTEGER NOT NULL REFERENCES inventory_baselines(id),
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    digest_alg  TEXT NOT NULL DEFAULT '',
    digest      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_inventory_baseline_components ON inventory_baseline_components(baseline_id);
