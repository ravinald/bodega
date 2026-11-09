-- When a mirrored apt index first listed each source package version, for the
-- age gate (F112). A Packages paragraph carries no date; the Release it belongs
-- to does, and a version first listed under a Release generated at T was
-- published no later than T. Keyed on the source package and its version,
-- epoch included, which is what the OSV gate already reads off a paragraph.
--
-- dated_by is 'release' when published_at is that Release's Date:, and
-- 'predates' when the version was in an index the codename's first recorded
-- Release published, so nothing says when it appeared. A row is written once and never updated: a later
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

-- The first Release bodega recorded for each mirrored codename. Its indexes
-- are the archive as bodega first found it, so their versions predate bodega;
-- every later Release only dates what it adds. One row per codename, written
-- once: which reader or architecture comes next cannot move the boundary.
CREATE TABLE IF NOT EXISTS apt_codename_first_release (
    codename     TEXT PRIMARY KEY,
    release_date TEXT NOT NULL DEFAULT '',
    recorded_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Every binary Packages file a recorded Release digests, keyed by its SHA256,
-- so an index bodega serves or reads is tied to the Release that published
-- those exact bytes, by-hash and cached copies included. idx is the logical
-- index (component/binary-arch) the three compressions share. initial is 1
-- when the codename's first Release listed it. observed is 1 once the
-- versions of the first Release's copy of idx were recorded, or a later copy
-- of idx was, after which nothing can say what the first one held.
CREATE TABLE IF NOT EXISTS apt_release_indexes (
    codename     TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    path         TEXT NOT NULL,
    idx          TEXT NOT NULL,
    release_date TEXT NOT NULL DEFAULT '',
    initial      INTEGER NOT NULL DEFAULT 0,
    observed     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (codename, sha256, path)
);
CREATE INDEX IF NOT EXISTS apt_release_indexes_idx ON apt_release_indexes (codename, idx);

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
