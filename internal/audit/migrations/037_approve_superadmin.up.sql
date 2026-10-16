-- approve and superadmin split the override votes, the refusal queue's
-- resolutions and token management out of admin. Every token holding admin
-- is widened to hold both, so no deployment loses a capability on upgrade;
-- bodega doctor names the ones to narrow. Scopes are stored canonical, so
-- admin is a whole comma-separated field and approve and superadmin follow it.
UPDATE api_tokens SET scope = replace(scope, 'admin', 'admin,approve,superadmin')
WHERE ',' || scope || ',' LIKE '%,admin,%';

-- The identity that minted the token: the caller's override identity on the
-- API, the exchanged principal for an OIDC token, the invoking user on the
-- CLI. A token minted before this column existed has no recorded creator.
ALTER TABLE api_tokens ADD COLUMN created_by TEXT NOT NULL DEFAULT '';
