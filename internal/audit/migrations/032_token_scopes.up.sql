-- Scopes replace the two-value full/inventory column. A scope list is
-- read, write and admin, each optionally narrowed to package types
-- ("read,write:npm,pypi"); inventory stays a scope of its own.
--
-- A token stored as 'full' was an admin credential and migrates to
-- 'read,write,admin', so nothing in use stops working; bodega doctor names
-- each one still holding all three. subject and issuer are set on a token
-- minted by an OIDC exchange, and name who the token's requests act for.
--
-- SQLite cannot drop a CHECK constraint in place, so the table is rebuilt.
CREATE TABLE api_tokens_scoped (
    id         TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    hash       TEXT NOT NULL,
    comment    TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT,
    last_used  TEXT,
    scope      TEXT NOT NULL CHECK(scope <> ''),
    subject    TEXT NOT NULL DEFAULT '',
    issuer     TEXT NOT NULL DEFAULT ''
);

INSERT INTO api_tokens_scoped (id, label, hash, comment, created_at, expires_at, last_used, scope)
SELECT id, COALESCE(label, ''), COALESCE(hash, ''), comment,
       COALESCE(created_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), expires_at, last_used,
       CASE scope WHEN 'full' THEN 'read,write,admin' ELSE scope END
FROM api_tokens;

DROP TABLE api_tokens;
ALTER TABLE api_tokens_scoped RENAME TO api_tokens;
