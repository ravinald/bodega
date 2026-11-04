-- The latest signed tree head the checksum_database admission check (F108)
-- verified, one row per database name. Each lookup checks the tree the
-- database serves against this one, so a log rewritten while bodega was
-- stopped is caught at the first lookup after it starts; held in memory only,
-- every restart would accept whatever tree the database served first.
--
-- note is the signed note exactly as the database served it. It is replaced
-- only by a compare-and-swap on the note it replaces, so two admissions
-- advancing it at once cannot move it backwards.
CREATE TABLE IF NOT EXISTS checksum_database_tree (
    name       TEXT PRIMARY KEY,
    note       BLOB NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
