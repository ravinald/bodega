-- apt_pool_paths keyed by archive as well as pool path (F120). A named apt
-- archive is its own pool namespace, and two distributions publish different
-- builds, from different source versions, at one pool path; keyed on the path
-- alone, the first archive to record it answered for both. The archive is ''
-- for the default archive, which every row written before this migration
-- belongs to: a codename joins a named archive only through apt_archives,
-- and the rows predate the age gate reading one.
ALTER TABLE apt_pool_paths RENAME TO apt_pool_paths_old;

CREATE TABLE apt_pool_paths (
    archive     TEXT NOT NULL DEFAULT '',
    pool_path   TEXT NOT NULL,
    source      TEXT NOT NULL,
    version     TEXT NOT NULL,
    codename    TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (archive, pool_path)
);

INSERT INTO apt_pool_paths (archive, pool_path, source, version, codename, recorded_at)
SELECT '', pool_path, source, version, codename, recorded_at FROM apt_pool_paths_old;

DROP TABLE apt_pool_paths_old;
