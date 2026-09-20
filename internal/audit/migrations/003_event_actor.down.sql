DROP INDEX IF EXISTS idx_events_actor;

ALTER TABLE events DROP COLUMN actor;
