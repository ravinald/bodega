-- An older binary knows only full and inventory. A token narrower than
-- read,write,admin is deleted rather than widened to full, and so is every
-- exchanged token: none of them may come back with more than it was issued.
CREATE TABLE api_tokens_legacy (
    id         TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    hash       TEXT NOT NULL,
    comment    TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT,
    last_used  TEXT,
    scope      TEXT NOT NULL DEFAULT 'full' CHECK(scope IN ('full','inventory'))
);

INSERT INTO api_tokens_legacy (id, label, hash, comment, created_at, expires_at, last_used, scope)
SELECT id, COALESCE(label, ''), COALESCE(hash, ''), comment,
       COALESCE(created_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), expires_at, last_used,
       CASE scope WHEN 'inventory' THEN 'inventory' ELSE 'full' END
FROM api_tokens
WHERE issuer = '' AND scope IN ('read,write,admin', 'inventory');

DROP TABLE api_tokens;
ALTER TABLE api_tokens_legacy RENAME TO api_tokens;
