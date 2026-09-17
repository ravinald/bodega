ALTER TABLE cache_origins RENAME COLUMN object_key TO s3_key;
ALTER TABLE checksums RENAME COLUMN object_key TO s3_key;
