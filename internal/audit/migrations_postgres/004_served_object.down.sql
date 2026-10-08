DROP INDEX IF EXISTS idx_events_identity_type;

ALTER TABLE events DROP COLUMN IF EXISTS digest;
ALTER TABLE events DROP COLUMN IF EXISTS object_key;
