-- The override quorum counts identities holding approve (F66). A requester
-- counts toward it only when their token held approve at request time, which
-- is recorded here so a later change to the token does not rewrite the
-- request. A request already on file keeps the rule it was made under: its
-- requester counted.
ALTER TABLE overrides ADD COLUMN requester_counts INTEGER NOT NULL DEFAULT 1;

-- Each vote records the scope the voter's token held, and whether the vote
-- counted toward the quorum with the reason when it did not. A vote cast
-- before this column existed counted.
ALTER TABLE override_votes ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE override_votes ADD COLUMN counted INTEGER NOT NULL DEFAULT 1;
ALTER TABLE override_votes ADD COLUMN not_counted TEXT NOT NULL DEFAULT '';
