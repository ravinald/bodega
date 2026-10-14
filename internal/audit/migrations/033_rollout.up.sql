-- The rollout path (F49): how an ecosystem admits names, and whether its
-- gates are in report-only mode.
--
-- admission_mode holds the mode an operator set. An ecosystem with no row
-- takes its mode from the allow-list: listed when it has rules, open when it
-- has none, which is how every ecosystem behaved before the table existed.
CREATE TABLE IF NOT EXISTS admission_mode (
    ecosystem  TEXT PRIMARY KEY,
    mode       TEXT NOT NULL CHECK(mode IN ('listed','open')),
    actor      TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- policy_rollout is an ecosystem in report mode: every gate switched to warn,
-- with the actions it had before. saved is a JSON array of
-- {gate, before, after}, and enforce writes each before back. A row exists
-- only while the ecosystem is in report mode.
CREATE TABLE IF NOT EXISTS policy_rollout (
    ecosystem  TEXT PRIMARY KEY,
    saved      TEXT NOT NULL DEFAULT '[]',
    actor      TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
