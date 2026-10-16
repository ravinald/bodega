-- An older binary reads admin as tokens, policy and votes together and does
-- not parse approve or superadmin. A token holding all three goes back to
-- admin. Any other token naming one of them is deleted rather than widened
-- or left unparseable, and so is admin held without both: under the older
-- binary it would vote and mint, which it was not issued to do.
DELETE FROM api_tokens
WHERE (',' || scope || ',' LIKE '%,admin,%'
    OR ',' || scope || ',' LIKE '%,approve,%'
    OR ',' || scope || ',' LIKE '%,superadmin,%')
  AND NOT (',' || scope || ',' LIKE '%,admin,approve,superadmin,%');

UPDATE api_tokens SET scope = replace(scope, 'admin,approve,superadmin', 'admin')
WHERE ',' || scope || ',' LIKE '%,admin,approve,superadmin,%';

ALTER TABLE api_tokens DROP COLUMN created_by;
