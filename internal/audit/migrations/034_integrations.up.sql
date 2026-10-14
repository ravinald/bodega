-- External check integrations (F60): the action each configured instance
-- takes per ecosystem, and the last error each one met.
--
-- One table for every integration, keyed by the instance name the config
-- file gives it, rather than a table per vendor. An absent row means the
-- integration type's own default action, which its descriptor declares.
CREATE TABLE IF NOT EXISTS integration_policy (
    instance   TEXT NOT NULL,
    ecosystem  TEXT NOT NULL,
    action     TEXT NOT NULL CHECK(action IN ('warn','block','ignore')),
    actor      TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (instance, ecosystem)
);

-- The last error an instance met, so `bodega integration list` can answer
-- from a CLI process for the outage a server process saw. One row per
-- instance, overwritten; the admission rows keep the full history.
CREATE TABLE IF NOT EXISTS integration_errors (
    instance   TEXT PRIMARY KEY,
    message    TEXT NOT NULL,
    at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
