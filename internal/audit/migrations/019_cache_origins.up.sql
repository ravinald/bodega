-- Where a cached object's bytes came from, so a cache_hit row names the
-- upstream that answered rather than whatever the config points at now.
--
-- The serving path used to serialize the caller's current candidate. That
-- reads correctly only while the configuration has not moved and the caller
-- holds a URL at all: the pypi wheel route deliberately holds none, because
-- composing one costs a read of the simple index that a hit must not pay for,
-- and a gomod_upstream edit made every subsequent hit credit a host that
-- supplied none of those bytes.
--
-- Separate from checksums, which cover immutable artifacts only. A gomod
-- @v/list, an npm packument and an apt Packages index are cached, served from
-- the cache for the rest of their TTL, and never checksummed.
CREATE TABLE IF NOT EXISTS cache_origins (
    s3_key       TEXT PRIMARY KEY,
    upstream_url TEXT NOT NULL,
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
