-- The sink half of SQLite migration 022. Admission decisions are append-only
-- like events, so they go wherever the events go; the decision CHECK is the
-- embedded store's, so a sink swap cannot widen what the column holds.
CREATE TABLE IF NOT EXISTS admissions (
    id            BIGSERIAL   PRIMARY KEY,
    pkg_type      TEXT        NOT NULL,
    pkg_name      TEXT        NOT NULL,
    pkg_version   TEXT        NOT NULL DEFAULT '',
    object_key    TEXT,
    decision      TEXT        NOT NULL CHECK(decision IN ('admitted','policy_blocked','invalid')),
    checks        JSONB       NOT NULL DEFAULT '[]',
    policy_digest TEXT        NOT NULL DEFAULT '',
    actor         TEXT        NOT NULL DEFAULT '',
    identity      TEXT        NOT NULL DEFAULT '',
    decided_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admissions_pkg        ON admissions(pkg_type, pkg_name, pkg_version);
CREATE INDEX IF NOT EXISTS idx_admissions_object_key ON admissions(object_key);
