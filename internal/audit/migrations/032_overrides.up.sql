-- Two-person overrides (F43): a request to admit one version past one check's
-- failure, and the votes cast on it.
--
-- quorum is the override_quorum in force when the request was made, counting
-- the requester, so a later config change neither strands a request already
-- half approved nor lets one through on fewer votes than it was asked under.
-- state moves pending -> approved or pending/approved -> rejected and never
-- back. Expiry is not a state: an override past expires_at stops applying
-- with nobody writing anything, which is the property that makes it safe to
-- forget about.
CREATE TABLE IF NOT EXISTS overrides (
    id           TEXT PRIMARY KEY,
    pkg_type     TEXT NOT NULL,
    pkg_name     TEXT NOT NULL,
    pkg_version  TEXT NOT NULL,
    check_name   TEXT NOT NULL,
    reason       TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    quorum       INTEGER NOT NULL CHECK(quorum >= 2),
    state        TEXT NOT NULL CHECK(state IN ('pending','approved','rejected')),
    decided_at   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_overrides_pkg ON overrides(pkg_type, pkg_name, pkg_version);

-- One vote per identity per request: the primary key is what keeps one
-- person voting twice from counting as two.
CREATE TABLE IF NOT EXISTS override_votes (
    override_id TEXT NOT NULL REFERENCES overrides(id),
    identity    TEXT NOT NULL,
    vote        TEXT NOT NULL CHECK(vote IN ('approve','reject')),
    comment     TEXT NOT NULL DEFAULT '',
    voted_at    TEXT NOT NULL,
    PRIMARY KEY (override_id, identity)
);
