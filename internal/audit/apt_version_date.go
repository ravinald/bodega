package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// How an apt version's date was set; see migration 042.
const (
	// AptDatedByRelease is the Date: of the earliest recorded Release whose
	// index listed the version.
	AptDatedByRelease = "release"
	// AptDatedByPredates is a version the codename's earliest recorded
	// Release listed.
	AptDatedByPredates = "predates"
	// AptDatedByNothing is a version an index bodega read listed, while no
	// recorded Release publishes that index: it has no date yet.
	AptDatedByNothing = "no_release"
)

// AptIndexEntry is one Packages paragraph as the age gate keeps it: the pool
// Filename it publishes and the source package version it was built from.
type AptIndexEntry struct {
	Filename, Source, Version string
}

// AptVersionDate is the earliest recorded Release that listed one source
// package version, and whether that Release is the codename's baseline.
type AptVersionDate struct {
	Source, Version, Codename string
	DatedBy                   string
	// PublishedAt is the Release's Date: under AptDatedByRelease, and zero
	// otherwise.
	PublishedAt time.Time
	RecordedAt  time.Time
}

// AptReleaseIndex is one binary Packages file a Release digests: its
// Release-relative Path, the logical Index (component/binary-arch) its
// compressions share, and its SHA256.
type AptReleaseIndex struct {
	Path, Index, SHA256 string
}

// AptIndexSnapshot is what the recorded Releases say about one Packages
// digest: the file it is, the Date: of the earliest recorded Release that
// published it, and whether that Release is the codename's baseline.
type AptIndexSnapshot struct {
	AptReleaseIndex
	ReleaseDate time.Time
	Initial     bool
}

func aptDate(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// The age gate keeps two kinds of evidence and derives every date from their
// join. A Release says which Packages digests it published and when
// (apt_release_indexes); a Packages read says which source versions the bytes
// of one digest listed (apt_observed_indexes, apt_index_members). A version's
// published_at is the minimum release_date over the digests that list it.
// RecordAptRelease and RecordAptIndexMembers each write their half and apply
// that minimum in one transaction, so whichever commits second sees the
// other's rows: no arrival order, restart or pair of concurrent writers leaves
// a date the evidence does not give, and neither needs the other's bytes
// again.

// aptApplyIndexDate lowers the date of every version the observed Packages
// digest sum of codename listed to date, where date is earlier or the version
// has none.
const aptApplyIndexDate = `UPDATE apt_version_dates SET published_at = ?1
	WHERE (published_at = '' OR published_at > ?1) AND id IN (
		SELECT m.version_id FROM apt_index_members m
		JOIN apt_observed_indexes o ON o.id = m.index_id
		WHERE o.codename = ?2 AND o.sha256 = ?3)`

// RecordAptRelease records the Packages files one dated Release of codename
// digests, and dates the versions of each file bodega has already read. Every
// date it keeps is a minimum, so recording Releases in any order leaves the
// same rows: the codename's baseline is the earliest Date: recorded, and each
// file keeps the earliest Date: of a Release listing it.
func (a *DB) RecordAptRelease(ctx context.Context, codename string, releaseDate time.Time, indexes []AptReleaseIndex) error {
	if a.readOnly {
		return errors.New("audit db is read-only")
	}
	if releaseDate.IsZero() {
		return errors.New("a Release with no Date: dates nothing")
	}
	date := aptDate(releaseDate)
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO apt_codename_baseline (codename, release_date) VALUES (?, ?)
		ON CONFLICT (codename) DO UPDATE SET release_date = excluded.release_date
		WHERE excluded.release_date < apt_codename_baseline.release_date`, codename, date); err != nil {
		return fmt.Errorf("record the baseline Release of %s: %w", codename, err)
	}
	ins, err := tx.PrepareContext(ctx, `INSERT INTO apt_release_indexes (codename, sha256, path, idx, release_date)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (codename, sha256, path) DO UPDATE SET release_date = excluded.release_date
		WHERE excluded.release_date < apt_release_indexes.release_date`)
	if err != nil {
		return err
	}
	defer func() { _ = ins.Close() }()
	apply, err := tx.PrepareContext(ctx, aptApplyIndexDate)
	if err != nil {
		return err
	}
	defer func() { _ = apply.Close() }()
	for _, ix := range indexes {
		res, err := ins.ExecContext(ctx, codename, ix.SHA256, ix.Path, ix.Index, date)
		if err != nil {
			return fmt.Errorf("record %s of the %s Release: %w", ix.Path, codename, err)
		}
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			continue
		}
		if _, err := apply.ExecContext(ctx, date, codename, ix.SHA256); err != nil {
			return fmt.Errorf("date the versions %s of the %s Release listed: %w", ix.Path, codename, err)
		}
	}
	return tx.Commit()
}

// LookupAptIndex returns what the recorded Releases of codename say about the
// Packages file whose SHA256 is sum, with ok false when none lists it.
func (a *DB) LookupAptIndex(ctx context.Context, codename, sum string) (AptIndexSnapshot, bool, error) {
	var snap AptIndexSnapshot
	var date, baseline string
	err := a.db.QueryRowContext(ctx, `SELECT i.path, i.idx, i.sha256, i.release_date, b.release_date
		FROM apt_release_indexes i JOIN apt_codename_baseline b ON b.codename = i.codename
		WHERE i.codename = ? AND i.sha256 = ? ORDER BY i.release_date LIMIT 1`, codename, sum).
		Scan(&snap.Path, &snap.Index, &snap.SHA256, &date, &baseline)
	if errors.Is(err, sql.ErrNoRows) {
		return AptIndexSnapshot{}, false, nil
	}
	if err != nil {
		return AptIndexSnapshot{}, false, fmt.Errorf("look up the %s Packages index %s: %w", codename, sum, err)
	}
	if snap.ReleaseDate, err = time.Parse(time.RFC3339, date); err != nil {
		return AptIndexSnapshot{}, false, fmt.Errorf("the Release date recorded for %s index %s does not parse: %w", codename, sum, err)
	}
	snap.Initial = date <= baseline
	return snap, true, nil
}

// AptIndexObserved reports whether the versions the Packages file of codename
// whose SHA256 is sum lists are recorded, with or without a Release
// publishing it.
func (a *DB) AptIndexObserved(ctx context.Context, codename, sum string) (bool, error) {
	var one int
	err := a.db.QueryRowContext(ctx, `SELECT 1 FROM apt_observed_indexes WHERE codename = ? AND sha256 = ?`, codename, sum).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check whether the %s Packages index %s was read: %w", codename, sum, err)
	}
	return true, nil
}

// PendingAptIndexes returns the Packages files of codename the gate still
// needs read, one per logical index, choosing among compressions in the order
// prefer gives: the baseline's copy of a logical index bodega has read some
// other copy of and no baseline copy. Reading it keeps a version the archive
// listed when bodega found it from being dated by whichever later copy of its
// architecture bodega happens to read first.
func (a *DB) PendingAptIndexes(ctx context.Context, codename string, prefer []string) ([]AptReleaseIndex, error) {
	const observed = `SELECT 1 FROM apt_release_indexes o
		JOIN apt_observed_indexes x ON x.codename = o.codename AND x.sha256 = o.sha256
		WHERE o.codename = i.codename AND o.idx = i.idx`
	rows, err := a.db.QueryContext(ctx, `SELECT i.path, i.idx, i.sha256
		FROM apt_release_indexes i JOIN apt_codename_baseline b ON b.codename = i.codename
		WHERE i.codename = ? AND i.release_date <= b.release_date
			AND EXISTS (`+observed+`)
			AND NOT EXISTS (`+observed+` AND o.release_date <= b.release_date)
		ORDER BY i.idx, i.path`, codename)
	if err != nil {
		return nil, fmt.Errorf("read the %s indexes the age gate has not recorded: %w", codename, err)
	}
	defer func() { _ = rows.Close() }()
	var order []string
	byIndex := map[string][]AptReleaseIndex{}
	for rows.Next() {
		var ix AptReleaseIndex
		if err := rows.Scan(&ix.Path, &ix.Index, &ix.SHA256); err != nil {
			return nil, err
		}
		if _, seen := byIndex[ix.Index]; !seen {
			order = append(order, ix.Index)
		}
		byIndex[ix.Index] = append(byIndex[ix.Index], ix)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]AptReleaseIndex, 0, len(order))
	for _, idx := range order {
		out = append(out, preferAptCompression(byIndex[idx], prefer))
	}
	return out, nil
}

func preferAptCompression(found []AptReleaseIndex, prefer []string) AptReleaseIndex {
	for _, suffix := range prefer {
		for _, ix := range found {
			if ix.Path == ix.Index+"/Packages"+suffix {
				return ix
			}
		}
	}
	return found[0]
}

// RecordAptIndexMembers records what the Packages file of codename whose
// SHA256 is sum lists: the digest as read, each source version as one it
// listed, and a source version for each pool Filename with no identity yet.
// It needs no Release. Where a recorded Release publishes sum, each version
// keeps the earlier of that Release's Date: and any date it has; where none
// does, the versions stay undated until RecordAptRelease records one.
//
// A digest names its bytes, so recording one a second time changes nothing.
func (a *DB) RecordAptIndexMembers(ctx context.Context, codename, sum string, entries []AptIndexEntry) error {
	if a.readOnly {
		return errors.New("audit db is read-only")
	}
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO apt_observed_indexes (codename, sha256) VALUES (?, ?)`, codename, sum)
	if err != nil {
		return fmt.Errorf("record the %s Packages index %s as read: %w", codename, sum, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return nil
	}
	var indexID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM apt_observed_indexes WHERE codename = ? AND sha256 = ?`, codename, sum).Scan(&indexID); err != nil {
		return fmt.Errorf("read back the %s Packages index %s: %w", codename, sum, err)
	}
	paths, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO apt_pool_paths
		(pool_path, source, version, codename) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = paths.Close() }()
	versions, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO apt_version_dates (source, version, codename) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = versions.Close() }()
	members, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO apt_index_members (index_id, version_id)
		SELECT ?, id FROM apt_version_dates WHERE source = ? AND version = ? AND codename = ?`)
	if err != nil {
		return err
	}
	defer func() { _ = members.Close() }()
	for _, e := range entries {
		if e.Source == "" || e.Version == "" {
			continue
		}
		if e.Filename != "" {
			if _, err := paths.ExecContext(ctx, e.Filename, e.Source, e.Version, codename); err != nil {
				return fmt.Errorf("record the identity of %s: %w", e.Filename, err)
			}
		}
		if _, err := versions.ExecContext(ctx, e.Source, e.Version, codename); err != nil {
			return fmt.Errorf("record %s %s: %w", e.Source, e.Version, err)
		}
		if _, err := members.ExecContext(ctx, indexID, e.Source, e.Version, codename); err != nil {
			return fmt.Errorf("record %s %s as listed by the %s index %s: %w", e.Source, e.Version, codename, sum, err)
		}
	}
	var date sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT MIN(release_date) FROM apt_release_indexes WHERE codename = ? AND sha256 = ?`, codename, sum).Scan(&date); err != nil {
		return fmt.Errorf("read the Release date of the %s index %s: %w", codename, sum, err)
	}
	if date.Valid {
		if _, err := tx.ExecContext(ctx, aptApplyIndexDate, date.String, codename, sum); err != nil {
			return fmt.Errorf("date the versions the %s index %s listed: %w", codename, sum, err)
		}
	}
	return tx.Commit()
}

// GetAptPoolPath returns the source package version a mirrored index listed
// poolPath under, with ok false when no index bodega read has listed it.
func (a *DB) GetAptPoolPath(ctx context.Context, poolPath string) (AptIndexEntry, bool, error) {
	e := AptIndexEntry{Filename: poolPath}
	err := a.db.QueryRowContext(ctx, `SELECT source, version FROM apt_pool_paths WHERE pool_path = ?`, poolPath).
		Scan(&e.Source, &e.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return AptIndexEntry{}, false, nil
	}
	if err != nil {
		return AptIndexEntry{}, false, fmt.Errorf("read the source version of apt %s: %w", poolPath, err)
	}
	return e, true, nil
}

// GetAptVersionDate returns the date of one source package version, with ok
// false when no index bodega read has listed it. A version listed under
// several codenames predates bodega when any codename's baseline listed it,
// and otherwise takes the earliest Release that did. One that indexes bodega
// read listed, none of them published by a recorded Release, comes back
// AptDatedByNothing.
func (a *DB) GetAptVersionDate(ctx context.Context, source, version string) (AptVersionDate, bool, error) {
	d := AptVersionDate{Source: source, Version: version}
	var published, recorded string
	var predates bool
	err := a.db.QueryRowContext(ctx, `SELECT v.codename, v.published_at, v.recorded_at,
			v.published_at != '' AND v.published_at <= COALESCE(b.release_date, '') AS predates
		FROM apt_version_dates v LEFT JOIN apt_codename_baseline b ON b.codename = v.codename
		WHERE v.source = ? AND v.version = ?
		ORDER BY v.published_at = '', predates DESC, v.published_at LIMIT 1`, source, version).
		Scan(&d.Codename, &published, &recorded, &predates)
	if errors.Is(err, sql.ErrNoRows) {
		return AptVersionDate{}, false, nil
	}
	if err != nil {
		return AptVersionDate{}, false, fmt.Errorf("read the date of apt %s %s: %w", source, version, err)
	}
	d.RecordedAt, _ = time.Parse(time.RFC3339Nano, recorded)
	switch {
	case published == "":
		d.DatedBy = AptDatedByNothing
		return d, true, nil
	case predates:
		d.DatedBy = AptDatedByPredates
		return d, true, nil
	}
	d.DatedBy = AptDatedByRelease
	if d.PublishedAt, err = time.Parse(time.RFC3339, published); err != nil {
		return AptVersionDate{}, false, fmt.Errorf("the date recorded for apt %s %s does not parse: %w", source, version, err)
	}
	return d, true, nil
}
