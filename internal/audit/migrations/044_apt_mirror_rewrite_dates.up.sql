-- The Date of the latest bodega-signed rewrite served for a mirrored codename
-- (B201). apt keeps a stored Release over a fetched one dated earlier, so a
-- codename that goes back to proxying the archive's own Release once its last
-- hide is lifted strands every host that read the rewrite on the filtered
-- Packages, until the archive's Date passes this one. Kept here rather than in
-- memory because a restart would otherwise forget what hosts may hold.
CREATE TABLE IF NOT EXISTS apt_mirror_rewrite_dates (
    codename    TEXT PRIMARY KEY,
    served_date TEXT NOT NULL
);
