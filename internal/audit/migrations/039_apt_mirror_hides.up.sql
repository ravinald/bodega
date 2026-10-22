-- A server-wide hide of one version of a package bodega serves only from a
-- mirrored apt codename (F73). Such a package has no manifest to carry the
-- hidden flag, so the record lives here, where every index rebuild reads it.
-- Keyed on the binary package name and version, which is what a pool path
-- names and what a Packages stanza carries.
CREATE TABLE IF NOT EXISTS apt_mirror_hides (
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    codenames  TEXT NOT NULL DEFAULT '',
    hidden_by  TEXT NOT NULL DEFAULT '',
    hidden_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (name, version)
);
