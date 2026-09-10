-- Host profiles: what one class of host may fetch, and the version rule each
-- package carries for that class.
--
-- A profile is a view over one catalog, never a second catalog. Nothing here
-- touches storage, object keys, the checksum table or the manifests: an
-- artifact reached through two profiles is one artifact. Per-profile storage
-- was the rejected alternative and it fails the way per-backend storage would
-- have, because `checksums` is keyed by object key (011) and the same bytes
-- would acquire two identities that drift on the first refresh touching only
-- one of them.
--
-- Three levels, because two cannot express the ordinary case. Membership and
-- the version default are per (profile, type); a per-entry constraint
-- overrides the default for one package. Collapsed into one level, "everything
-- tracks except postgres, held at 14 because 15 breaks the config" is
-- inexpressible.
CREATE TABLE IF NOT EXISTS profiles (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- A binding attaches a profile to an identity, which is the name migration 013
-- already resolves a request to. Reusing that table is what keeps one
-- resolution path: the serve path answers "which host is this" once, and this
-- says what that host may fetch. A second table keyed by token or CIDR would
-- be a parallel resolver free to disagree with the first about which host a
-- request came from.
--
-- identity is the primary key, so one host resolves to at most one profile.
-- Two profiles for one host is a question with no answer at read time, and
-- picking by row order is not one.
CREATE TABLE IF NOT EXISTS profile_bindings (
    identity   TEXT PRIMARY KEY,
    profile    TEXT NOT NULL,
    comment    TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_profile_bindings_profile ON profile_bindings(profile);

-- profile_types is the marker table, and it exists for the reason acl_lists
-- does (008): "no entries for this type" is two different answers. A type with
-- a row here is answered by the profile even when no entry names a package —
-- closed with nothing listed permits nothing of that type. A type with no row
-- is one the profile states no rule for, and the fleet-wide controls decide it
-- alone. Without the marker those two collapse, and a profile covering apt
-- would silently deny every helm chart or silently permit every one, with
-- nothing in the table saying which the operator meant.
--
-- membership decides the set:  closed = only the packages listed
--                              open   = every package of this type in the catalog
-- version_default decides the version rule for a listed package carrying no
-- constraint of its own:       pinned   = only the version the entry names
--                              floating = any version
CREATE TABLE IF NOT EXISTS profile_types (
    profile         TEXT NOT NULL,
    pkg_type        TEXT NOT NULL,
    membership      TEXT NOT NULL CHECK(membership IN ('closed','open')),
    version_default TEXT NOT NULL CHECK(version_default IN ('pinned','floating')),
    actor           TEXT NOT NULL DEFAULT '',
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (profile, pkg_type)
);

-- constraint_kind holds the four values already on manifest.VersionEntry:
-- exact, compatible, patch, any. A fifth spelling of the same idea is a bug
-- waiting for the two to disagree about what "^" means. Empty is the third
-- level declining to override, which defers to the type's version_default.
--
-- review_after is a date an operator writes when pinning; nothing enforces it
-- here. It is what makes an unexplained pin from two years ago visible in
-- `bodega profile show` rather than permanent by inattention.
--
-- No REFERENCES clause: the connection does not enable foreign_keys, so one
-- would be inert documentation that reads as enforcement. The writer checks
-- the profile exists.
CREATE TABLE IF NOT EXISTS profile_entries (
    profile         TEXT NOT NULL,
    pkg_type        TEXT NOT NULL,
    pkg_name        TEXT NOT NULL,
    constraint_kind TEXT NOT NULL DEFAULT '' CHECK(constraint_kind IN ('','exact','compatible','patch','any')),
    version         TEXT NOT NULL DEFAULT '',
    origin          TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL DEFAULT '',
    review_after    TEXT NOT NULL DEFAULT '',
    actor           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (profile, pkg_type, pkg_name)
);

CREATE INDEX IF NOT EXISTS idx_profile_entries_lookup ON profile_entries(profile, pkg_type);
