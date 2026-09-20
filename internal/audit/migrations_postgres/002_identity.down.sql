ALTER TABLE upstream_discovery DROP COLUMN IF EXISTS last_identity;

DROP INDEX IF EXISTS idx_events_identity;

ALTER TABLE events DROP COLUMN IF EXISTS identity;
