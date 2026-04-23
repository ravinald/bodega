ALTER TABLE events ADD COLUMN actor TEXT DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor);
