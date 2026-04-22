CREATE TABLE IF NOT EXISTS upstream_policies (
    id            TEXT PRIMARY KEY,
    registry_type TEXT NOT NULL,
    rule_kind     TEXT NOT NULL,
    pattern       TEXT NOT NULL,
    comment       TEXT DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    created_by    TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_upstream_policies_type ON upstream_policies(registry_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_upstream_policies_unique ON upstream_policies(registry_type, rule_kind, pattern);
