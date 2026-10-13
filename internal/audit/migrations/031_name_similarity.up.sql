-- The name-similarity check (F39): the action per ecosystem, the popular-name
-- lists an operator loaded over the embedded ones, and the package names in
-- use when the check first ran here.
--
-- An absent policy row means warn, the same default upstream provenance has:
-- a fresh install reports a near-miss name without refusing anything.
CREATE TABLE IF NOT EXISTS name_similarity_policy (
    ecosystem  TEXT PRIMARY KEY,
    action     TEXT NOT NULL CHECK(action IN ('warn','block','ignore')),
    actor      TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- A loaded list replaces the embedded one for its ecosystem, whole. names is
-- newline-separated as loaded; sha256 is over that text, so the policy digest
-- can cite which list a decision was compared against without hashing it on
-- every admission.
CREATE TABLE IF NOT EXISTS name_similarity_lists (
    ecosystem  TEXT PRIMARY KEY,
    names      TEXT NOT NULL,
    name_count INTEGER NOT NULL,
    sha256     TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT '',
    loaded_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Names already in use are exempt, so turning the check on refuses nothing an
-- install already serves. The baseline is taken once, from the manifest store
-- and from the names with an admitted row in admissions (a pass-through proxy
-- fill writes no manifest, so the admission is its only record), by the first
-- process that holds both the store and this database. The single row in
-- name_similarity_baseline_taken says it has been, so an install with nothing
-- in use at that moment still has a baseline rather than a reason to take
-- another one later, after a squat was admitted.
--
-- pkg_key is the safe name under the check's normalization for the type,
-- which is what a lookup computes from the candidate.
CREATE TABLE IF NOT EXISTS name_similarity_baseline (
    pkg_type TEXT NOT NULL,
    pkg_key  TEXT NOT NULL,
    PRIMARY KEY (pkg_type, pkg_key)
);

CREATE TABLE IF NOT EXISTS name_similarity_baseline_taken (
    id              INTEGER PRIMARY KEY CHECK(id = 1),
    package_count   INTEGER NOT NULL,
    admission_count INTEGER NOT NULL DEFAULT 0,
    taken_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
