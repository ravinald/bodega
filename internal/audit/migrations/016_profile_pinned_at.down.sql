-- Direct, for the reason 015 states: the driver is modernc's, which is past
-- SQLite 3.35, and rebuilding the table would drop 014's CHECK clauses.
ALTER TABLE profile_entries DROP COLUMN pinned_at;
