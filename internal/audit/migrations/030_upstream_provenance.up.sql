-- The upstream provenance check (F38): the action per ecosystem, and the
-- source repository and builder each package was first verified from.
--
-- An absent policy row means warn, so a fresh install records what every
-- version's publisher signed without refusing anything until an operator
-- chooses block.
CREATE TABLE IF NOT EXISTS upstream_provenance_policy (
    ecosystem  TEXT PRIMARY KEY,
    action     TEXT NOT NULL CHECK(action IN ('warn','block','ignore')),
    actor      TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Trust on first use, the same model as checksum pinning: the first version of
-- a package whose provenance verifies pins the repository it was built from
-- and the builder that built it, and a later version verified from anything
-- else fails the check. One row per package; 'bodega pkg trust reset' deletes
-- it so the next verified version pins afresh.
--
-- builder_id is stored with any "@<ref>" suffix removed. A GitHub Actions
-- builder ID names the workflow at the ref that ran it, and a tag-triggered
-- release workflow runs at a different ref every release, so pinning the ref
-- would fail every version after the first. workflow_ref keeps the full value
-- the pin was taken from, for the person reading it.
CREATE TABLE IF NOT EXISTS upstream_provenance_pins (
    pkg_type              TEXT NOT NULL,
    pkg_name              TEXT NOT NULL,
    source_repository_uri TEXT NOT NULL,
    builder_id            TEXT NOT NULL,
    workflow_ref          TEXT NOT NULL DEFAULT '',
    pinned_version        TEXT NOT NULL DEFAULT '',
    pinned_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (pkg_type, pkg_name)
);
