ALTER TABLE upstream_discovery DROP COLUMN last_identity;

DROP INDEX IF EXISTS idx_events_identity;

ALTER TABLE events DROP COLUMN identity;

DROP TABLE IF EXISTS identity_bindings;
