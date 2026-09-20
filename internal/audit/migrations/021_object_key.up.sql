-- One name for the object key, on tables that never held only S3 objects.
--
-- checksums.s3_key has been the key of whatever store answered since the first
-- migration, and on a "storage_backend": "local" install that store is a
-- directory under /var/lib/bodega. cache_origins carried the worse version of
-- the same mistake: migration 020 added a backend column beside s3_key, so one
-- table created to record which backend supplied an object's bytes was keyed on
-- a column named for one of them.
--
-- RENAME COLUMN rather than a rebuild: it keeps the UNIQUE constraint on
-- checksums and the PRIMARY KEY on cache_origins without copying a table that
-- grows with the cache, and it cannot lose a row on the way.
--
-- Earlier migrations still spell the old name in their statements and their
-- comments. They describe the schema at the version they introduced, which is
-- the state a store stepping through them is actually in; rewriting them would
-- make this rename apply twice on a fresh database and once on an upgrade.
ALTER TABLE checksums RENAME COLUMN s3_key TO object_key;
ALTER TABLE cache_origins RENAME COLUMN s3_key TO object_key;
