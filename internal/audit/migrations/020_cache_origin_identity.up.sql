-- Bind a recorded origin to the object it describes, not to the key.
--
-- A key is a name and its bytes get replaced under it: 'bodega pkg upload'
-- writes a locally built .deb over a mirrored one, a delete and a refill put a
-- different @v/list at the same path, and neither fetches anything. With only
-- s3_key to go on, the next hit read back the archive that supplied the bytes
-- that are gone and credited it for bytes it never served.
--
-- So the row carries what the store reports about the object it was written
-- for, and the hit path compares before it believes the row. A mismatch is an
-- object somebody else wrote, which has no recorded origin; it is reported as
-- unrecorded rather than as the previous tenant of the key.
--
-- backend is the store's Label(), which distinguishes two buckets holding the
-- same key: 'bodega pkg move' relocates an object without touching its name.
-- Rows written before this column existed carry the defaults below, match no
-- object, and read as unrecorded.
ALTER TABLE cache_origins ADD COLUMN backend TEXT NOT NULL DEFAULT '';
ALTER TABLE cache_origins ADD COLUMN object_size INTEGER NOT NULL DEFAULT -1;
ALTER TABLE cache_origins ADD COLUMN object_etag TEXT NOT NULL DEFAULT '';
ALTER TABLE cache_origins ADD COLUMN object_modified TEXT NOT NULL DEFAULT '';
