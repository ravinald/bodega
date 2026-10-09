-- osquery enrollment, for an osquery inventory source in server mode
-- (internal/inventory/osquery), where bodega is the hosts' osquery server.
--
-- An enroll secret is stored as its peppered HMAC alone, the way api_tokens
-- stores a token: the CLI prints it once and nothing can print it again.
-- identity is who a host enrolling with it becomes, so a secret is minted per
-- host (or per group of hosts that should share an identity).
CREATE TABLE IF NOT EXISTS osquery_enroll_secrets (
    id         TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    label      TEXT NOT NULL,
    identity   TEXT NOT NULL,
    hash       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_osquery_enroll_secrets_source ON osquery_enroll_secrets(source);

-- One row per node_key handed out. Only the key's sha256 is kept: it is also
-- the external id in inventory_hosts, so the key itself never touches disk.
-- Revoking a secret deletes every node enrolled with it, which is what makes
-- a revoked host's next config or log request answer node_invalid.
CREATE TABLE IF NOT EXISTS osquery_nodes (
    source          TEXT NOT NULL,
    key_sha256      TEXT NOT NULL,
    secret_id       TEXT NOT NULL,
    identity        TEXT NOT NULL,
    host_identifier TEXT NOT NULL DEFAULT '',
    enrolled_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (source, key_sha256)
);
CREATE INDEX IF NOT EXISTS idx_osquery_nodes_secret ON osquery_nodes(secret_id);
