-- When a mirrored apt index first listed each source package version, for the
-- age gate (F112). A Packages paragraph carries no date; the Release it belongs
-- to does, and a version first listed under a Release generated at T was
-- published no later than T. Keyed on the source package and its version,
-- epoch included, which is what the OSV gate already reads off a paragraph.
--
-- dated_by is 'release' when published_at is that Release's Date:, and
-- 'predates' when the version was in the first index bodega read for its
-- codename, so nothing says when it appeared. A row is written once and never
-- updated: a later index listing the version again says nothing new about it.
CREATE TABLE IF NOT EXISTS apt_version_dates (
    source       TEXT NOT NULL,
    version      TEXT NOT NULL,
    codename     TEXT NOT NULL,
    dated_by     TEXT NOT NULL,
    published_at TEXT NOT NULL DEFAULT '',
    recorded_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (source, version)
);

-- The codenames bodega has read a complete index for. A codename absent here
-- is one whose next read lists only versions that predate bodega.
CREATE TABLE IF NOT EXISTS apt_codename_reads (
    codename      TEXT PRIMARY KEY,
    first_read_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
