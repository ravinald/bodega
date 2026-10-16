-- An older binary counts every requester and every approval. A vote that did
-- not count is deleted rather than left to count, and a pending request whose
-- requester did not count is rejected rather than left to pass on one fewer
-- approver than it was requested under. Both stay in the audit trail.
DELETE FROM override_votes WHERE counted = 0;
UPDATE overrides SET state = 'rejected', decided_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE state = 'pending' AND requester_counts = 0;

ALTER TABLE override_votes DROP COLUMN not_counted;
ALTER TABLE override_votes DROP COLUMN counted;
ALTER TABLE override_votes DROP COLUMN scope;
ALTER TABLE overrides DROP COLUMN requester_counts;
