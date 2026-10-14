-- The refusal queue (F50): one row per (type, package, version, check) a
-- client was refused, whichever check refused it, so an operator reviews
-- refusals in one place and resolves each in one step.
--
-- state moves open -> approved or open -> dismissed, and back to open when
-- the same tuple is refused again after the resolution: a row that stays
-- closed while its refusal recurs is a resolution that did not work.
-- pattern is the allow-list rule an allow-list row approves into, and
-- unwaivable says why a row may never be approved (known malware, provenance
-- that failed to verify), recorded at the refusal so approve does not have to
-- re-run the check that decided it.
CREATE TABLE IF NOT EXISTS refusal_queue (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    pkg_type          TEXT NOT NULL,
    pkg_name          TEXT NOT NULL,
    pkg_version       TEXT NOT NULL,
    check_name        TEXT NOT NULL,
    pattern           TEXT NOT NULL DEFAULT '',
    detail            TEXT NOT NULL DEFAULT '',
    unwaivable        TEXT NOT NULL DEFAULT '',
    profiles          TEXT NOT NULL DEFAULT '',
    incident          TEXT NOT NULL DEFAULT '',
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    request_count     INTEGER NOT NULL DEFAULT 1,
    state             TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','approved','dismissed')),
    resolved_at       TEXT NOT NULL DEFAULT '',
    resolved_by       TEXT NOT NULL DEFAULT '',
    resolution        TEXT NOT NULL DEFAULT '',
    resolution_reason TEXT NOT NULL DEFAULT '',
    UNIQUE (pkg_type, pkg_name, pkg_version, check_name)
);

CREATE INDEX IF NOT EXISTS idx_refusal_queue_state ON refusal_queue(state, last_seen);

-- Who asked: one row per (identity, client IP) per queue row, so a refusal
-- hit by a whole fleet names the fleet rather than its last member.
CREATE TABLE IF NOT EXISTS refusal_queue_requesters (
    queue_id      INTEGER NOT NULL REFERENCES refusal_queue(id),
    identity      TEXT NOT NULL,
    client_ip     TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1,
    last_seen     TEXT NOT NULL,
    PRIMARY KEY (queue_id, identity, client_ip)
);
