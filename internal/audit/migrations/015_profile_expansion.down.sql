-- SQLite before 3.35 has no DROP COLUMN, and the driver here is modernc's,
-- which is newer than that. Rebuilding the table would be the portable form
-- and would also drop the CHECK clauses 014 wrote, so the column goes the
-- direct way.
ALTER TABLE profile_types DROP COLUMN expansion;
