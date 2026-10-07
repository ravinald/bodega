-- One row per admission decision: the verdict a manifest or a proxy fill got
-- from the allow-list, age and OSV checks, and the policy it was judged
-- against.
--
-- Before this table only a warn or a block left anything behind, as an event
-- row whose details were free text. A version that passed every check left no
-- row at all, so there was nothing an attestation could cite for the bytes
-- bodega went on to serve.
--
-- object_key is NULL from the decision until the digest is pinned. Admission
-- runs on a manifest before any bytes exist, and the key is only known to
-- belong to this decision once a fetch has produced bytes and pinned them.
--
-- checks is a JSON array of {check, action, status, detail}. It is one column
-- rather than a child table because the set of checks grows (upstream
-- provenance and name similarity are each another entry) and every reader
-- wants the whole verdict, never one check.
--
-- policy_digest is the SHA-256 of the allow-list, age_policy and osv_policy
-- rows in force at the decision (policy.Digest). Empty means nothing was
-- evaluated, which is the row a pin with no prior decision writes.
CREATE TABLE IF NOT EXISTS admissions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    pkg_type      TEXT NOT NULL,
    pkg_name      TEXT NOT NULL,
    pkg_version   TEXT NOT NULL DEFAULT '',
    object_key    TEXT,
    decision      TEXT NOT NULL CHECK(decision IN ('admitted','policy_blocked','invalid')),
    checks        TEXT NOT NULL DEFAULT '[]',
    policy_digest TEXT NOT NULL DEFAULT '',
    actor         TEXT NOT NULL DEFAULT '',
    identity      TEXT NOT NULL DEFAULT '',
    decided_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_admissions_pkg        ON admissions(pkg_type, pkg_name, pkg_version);
CREATE INDEX IF NOT EXISTS idx_admissions_object_key ON admissions(object_key);
