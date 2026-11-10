-- When mirrored apt indexes listed each source package version, for the age
-- gate (F112). A Packages paragraph carries no date; the Release it belongs to
-- does, and a version listed under a Release generated at T was published no
-- later than T. Keyed on the source package and its version, epoch included,
-- which is what the OSV gate already reads off a paragraph.
--
-- Every date here is a minimum over what bodega has recorded, so the order in
-- which readers record their observations cannot change the result: recording
-- an older snapshot late moves a date earlier, to the Date: of a Release that
-- listed the version, and nothing ever moves one later.

-- Every source version a Packages file bodega read in full has listed.
-- published_at is the earliest Date: among the recorded Releases publishing
-- one of those files, and '' while no recorded Release publishes any of them:
-- the version was read, and is dated when such a Release is. It predates
-- bodega when it is no later than the codename's baseline.
CREATE TABLE IF NOT EXISTS apt_version_dates (
    id           INTEGER PRIMARY KEY,
    source       TEXT NOT NULL,
    version      TEXT NOT NULL,
    codename     TEXT NOT NULL,
    published_at TEXT NOT NULL DEFAULT '',
    recorded_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (source, version, codename)
);

-- The earliest Release Date: recorded for each mirrored codename: the archive
-- as bodega first found it. Debian and Ubuntu regenerate Release daily, so the
-- versions it lists are recorded as predating bodega rather than dated by it.
CREATE TABLE IF NOT EXISTS apt_codename_baseline (
    codename     TEXT PRIMARY KEY,
    release_date TEXT NOT NULL
);

-- Every binary Packages file a recorded Release digests, keyed by its SHA256,
-- so an index bodega serves or reads is tied to the Releases that published
-- those exact bytes, by-hash and cached copies included. idx is the logical
-- index (component/binary-arch) the compressions share. release_date is the
-- earliest Date: of a recorded Release listing the file.
CREATE TABLE IF NOT EXISTS apt_release_indexes (
    codename     TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    path         TEXT NOT NULL,
    idx          TEXT NOT NULL,
    release_date TEXT NOT NULL,
    PRIMARY KEY (codename, sha256, path)
);
CREATE INDEX IF NOT EXISTS apt_release_indexes_idx ON apt_release_indexes (codename, idx);

-- Every Packages file bodega read in full and parsed, by the SHA256 of the
-- bytes as the archive publishes them, whether or not a Release publishing
-- them is recorded yet. A row here is what separates an index bodega read
-- from one a Release only names.
CREATE TABLE IF NOT EXISTS apt_observed_indexes (
    id          INTEGER PRIMARY KEY,
    codename    TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (codename, sha256)
);

-- The source versions each observed Packages file listed. A Release recorded
-- after the read, older or newer, dates them from this relation, so the
-- archive is never asked for bytes bodega already read. Without it a Release
-- that arrives second can move the file's date and not its versions'.
CREATE TABLE IF NOT EXISTS apt_index_members (
    index_id   INTEGER NOT NULL,
    version_id INTEGER NOT NULL,
    PRIMARY KEY (index_id, version_id)
) WITHOUT ROWID;

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
