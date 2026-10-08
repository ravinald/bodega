DROP INDEX IF EXISTS idx_events_identity_type;

ALTER TABLE events DROP COLUMN digest;
ALTER TABLE events DROP COLUMN object_key;
