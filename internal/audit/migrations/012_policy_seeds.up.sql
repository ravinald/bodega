-- Records that bodega has already decided what a policy's default is here, so
-- the shipped default is seeded once and never comes back after an operator
-- clears the table.
--
-- Same reasoning as acl_lists: "no rows in age_policy" is two different
-- answers. An operator who removed every ecosystem chose no gate; an install
-- that has never been seeded has chosen nothing. A policy named here is
-- answered from its own table whatever that table holds, empty included; a
-- policy absent here has never been seeded, and only then does a fresh install
-- get one.
--
-- The row for an install that predates this migration is written by the
-- upgrade path in Go, not here: SQL cannot tell a fresh database from one
-- crossing this version, and seeding a running fleet is the failure to avoid.
CREATE TABLE IF NOT EXISTS policy_seeds (
    policy    TEXT PRIMARY KEY CHECK(policy IN ('age')),
    seeded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
