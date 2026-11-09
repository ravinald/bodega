-- When a mirrored apt index first listed each source package version, for the
-- age gate (F112). A Packages paragraph carries no date; the Release it belongs
-- to does, and a version first listed under a Release generated at T was
-- published no later than T. Keyed on the source package and its version,
-- epoch included, which is what the OSV gate already reads off a paragraph.
--
-- dated_by is 'release' when published_at is that Release's Date:, and
-- 'predates' when the version was in the first read of its index, so nothing
-- says when it appeared. A row is written once and never updated: a later
-- index listing the version again says nothing new about it.
CREATE TABLE IF NOT EXISTS apt_version_dates (
    source       TEXT NOT NULL,
    version      TEXT NOT NULL,
    codename     TEXT NOT NULL,
    dated_by     TEXT NOT NULL,
    published_at TEXT NOT NULL DEFAULT '',
    recorded_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (source, version)
);

-- The indexes, one (codename, component, architecture) Packages each, that
-- bodega has read at least once. Per index rather than per codename: an index
-- that failed to read while its neighbors succeeded is still the archive's
-- whole history on its own first read, and one that did read is not again.
CREATE TABLE IF NOT EXISTS apt_index_reads (
    codename      TEXT NOT NULL,
    component     TEXT NOT NULL,
    arch          TEXT NOT NULL,
    first_read_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (codename, component, arch)
);

-- The source package and version each pool Filename was listed under, so the
-- age gate can find a version's date once the index stops listing it. A pool
-- path names one build, so a row is written once. The filename alone cannot
-- answer this: the pool drops the epoch the date is keyed on.
CREATE TABLE IF NOT EXISTS apt_pool_paths (
    pool_path   TEXT PRIMARY KEY,
    source      TEXT NOT NULL,
    version     TEXT NOT NULL,
    codename    TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
