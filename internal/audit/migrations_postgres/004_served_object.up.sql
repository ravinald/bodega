-- The sink half of SQLite migration 025.
ALTER TABLE events ADD COLUMN IF NOT EXISTS object_key TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS digest TEXT;

CREATE INDEX IF NOT EXISTS idx_events_identity_type ON events(identity, event_type);
