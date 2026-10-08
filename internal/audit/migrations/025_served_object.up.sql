-- What a serve_fetch handed over, not just what it was asked for. Name and
-- version come off the URL and cannot tell two builds of one version apart;
-- the object key names the stored bytes, and the digest is the one a host's
-- package manager can report back for comparison.
--
-- Both are NULL rather than '' on every row that served no stored artifact:
-- indexes, packuments, Release files, and every event that is not a fetch.
-- The digest is NULL as well where bodega recorded none for the key, which is
-- a fact about the record, not a hash of nothing.
ALTER TABLE events ADD COLUMN object_key TEXT;
ALTER TABLE events ADD COLUMN digest TEXT;

-- The served-set query reads one identity's serve_fetch rows.
CREATE INDEX IF NOT EXISTS idx_events_identity_type ON events(identity, event_type);
