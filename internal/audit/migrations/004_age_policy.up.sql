CREATE TABLE IF NOT EXISTS age_policy (
    ecosystem       TEXT PRIMARY KEY,
    min_age_seconds INTEGER NOT NULL,
    action          TEXT    NOT NULL CHECK(action IN ('warn','block','ignore')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
