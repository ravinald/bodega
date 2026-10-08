-- What a token may do, beside who holds it. Before this column every valid
-- token could mutate the catalog, so a credential handed to a host for one
-- narrow job (posting its inventory) was an admin credential on that host.
--
-- 'full' is the default and every existing token migrates as 'full': a token
-- that worked yesterday keeps working. 'inventory' reaches only the push
-- routes inventory sources register; MutationAuthMiddleware refuses it
-- everywhere else.
ALTER TABLE api_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT 'full' CHECK(scope IN ('full','inventory'));
