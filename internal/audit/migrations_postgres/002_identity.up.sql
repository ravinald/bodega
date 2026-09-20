-- The sink half of migration 013. identity_bindings is not here: the read path
-- consults it to make a decision, which is operational state, and the postgres
-- sink carries the append-only tables alone.
ALTER TABLE events ADD COLUMN IF NOT EXISTS identity TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_events_identity ON events(identity);

ALTER TABLE upstream_discovery ADD COLUMN IF NOT EXISTS last_identity TEXT NOT NULL DEFAULT '';
