-- Back to one row per pool path. A path two archives recorded keeps the
-- default archive's row, then the archive whose name sorts first: the older
-- schema had no way to hold both, and the age gate on the older binary reads
-- whichever is left.
ALTER TABLE apt_pool_paths RENAME TO apt_pool_paths_archived;

CREATE TABLE apt_pool_paths (
    pool_path   TEXT PRIMARY KEY,
    source      TEXT NOT NULL,
    version     TEXT NOT NULL,
    codename    TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT OR IGNORE INTO apt_pool_paths (pool_path, source, version, codename, recorded_at)
SELECT pool_path, source, version, codename, recorded_at FROM apt_pool_paths_archived
ORDER BY archive;

DROP TABLE apt_pool_paths_archived;
