-- Whether the proxied indexes for an ecosystem omit the versions the age and
-- OSV gates would refuse. A row per ecosystem an operator has set; absence is
-- off, which is the shipped default.
CREATE TABLE IF NOT EXISTS index_filter (
    ecosystem  TEXT PRIMARY KEY,
    enabled    INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
