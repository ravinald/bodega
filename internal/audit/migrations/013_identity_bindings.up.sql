-- Per-host identity on the read path. A binding maps something the serve path
-- can observe about a request — the token it presented, or the network its
-- address falls in — to a name an operator chose.
--
-- Two kinds because they answer different questions. A token binding is
-- precise and has a bootstrap problem on a host that did not exist an hour
-- ago; a CIDR binding has no bootstrap problem and is the right answer for
-- "everything on this subnet is a devbox". Neither subsumes the other.
--
-- The primary key is what makes "one token or one CIDR resolves to at most one
-- identity" a property of the store rather than a rule the read path has to
-- re-derive. bind_key holds a token id for kind='token' and a masked CIDR for
-- kind='cidr'; the writer masks before inserting, so 10.0.0.5/8 and 10.0.0.0/8
-- are the same row and cannot disagree.
CREATE TABLE IF NOT EXISTS identity_bindings (
    kind       TEXT NOT NULL CHECK(kind IN ('token','cidr')),
    bind_key   TEXT NOT NULL,
    identity   TEXT NOT NULL,
    comment    TEXT DEFAULT '',
    actor      TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (kind, bind_key)
);

-- identity sits alongside client_ip, never in place of it. The deny list still
-- matches on the address, and a row naming only the host would lose which of
-- its addresses asked.
ALTER TABLE events ADD COLUMN identity TEXT DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_events_identity ON events(identity);

-- last_identity follows last_client for the same reason it exists there: the
-- discovery table describes the fleet, and "which host wanted this package"
-- is the question an operator brings to it.
ALTER TABLE upstream_discovery ADD COLUMN last_identity TEXT NOT NULL DEFAULT '';
