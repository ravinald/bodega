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
	// PublishedAt is the Release's Date: under AptDatedByRelease, zero under
	// AptDatedByPredates.
	PublishedAt time.Time
	RecordedAt  time.Time
}

// ErrAptIndexUnknown is RecordAptIndexVersions given a Packages digest no
// recorded Release publishes, so nothing says which Release its bytes belong
// to.
var ErrAptIndexUnknown = errors.New("no recorded Release publishes this Packages index")

// AptReleaseIndex is one binary Packages file a Release digests: its
// Release-relative Path, the logical Index (component/binary-arch) its
// compressions share, and its SHA256.
type AptReleaseIndex struct {
	Path, Index, SHA256 string
}

// AptIndexSnapshot is what the recorded Releases say about one Packages
// digest: the file it is, the Date: of the earliest recorded Release that
// published it, whether that Release is the codename's baseline, and whether
// its versions are already recorded at that date.
type AptIndexSnapshot struct {
	AptReleaseIndex
	ReleaseDate time.Time
	Initial     bool
	Observed    bool
}

func aptDate(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// RecordAptRelease records the Packages files one dated Release of codename
// digests. Every date it keeps is a minimum, so recording Releases in any
// order leaves the same rows: the codename's baseline is the earliest Date:
// recorded, and each file keeps the earliest Date: of a Release listing it.
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
	for _, ix := range indexes {
		if _, err := ins.ExecContext(ctx, codename, ix.SHA256, ix.Path, ix.Index, date); err != nil {
			return fmt.Errorf("record %s of the %s Release: %w", ix.Path, codename, err)
		}
	}
	return tx.Commit()
}

// LookupAptIndex returns what the recorded Releases of codename say about the
// Packages file whose SHA256 is sum, with ok false when none lists it.
func (a *DB) LookupAptIndex(ctx context.Context, codename, sum string) (AptIndexSnapshot, bool, error) {
	var snap AptIndexSnapshot
	var date, observed, baseline string
	err := a.db.QueryRowContext(ctx, `SELECT i.path, i.idx, i.sha256, i.release_date, i.observed_date, b.release_date
		FROM apt_release_indexes i JOIN apt_codename_baseline b ON b.codename = i.codename
		WHERE i.codename = ? AND i.sha256 = ? ORDER BY i.release_date LIMIT 1`, codename, sum).
		Scan(&snap.Path, &snap.Index, &snap.SHA256, &date, &observed, &baseline)
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
	snap.Observed = observed == date
	return snap, true, nil
}

// PendingAptIndexes returns the Packages files of codename whose versions the
// gate still needs, one per logical index and Release date, choosing among
// compressions in the order prefer gives: a file whose recorded date moved
// earlier after its versions were recorded, and the baseline's copy of a
// logical index bodega has read some other copy of. The second keeps a
// version the archive listed when bodega found it from being dated by
// whichever later copy of its architecture bodega happens to read first.
func (a *DB) PendingAptIndexes(ctx context.Context, codename string, prefer []string) ([]AptReleaseIndex, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT i.path, i.idx, i.sha256, i.release_date
		FROM apt_release_indexes i JOIN apt_codename_baseline b ON b.codename = i.codename
		WHERE i.codename = ? AND (
			(i.observed_date != '' AND i.observed_date > i.release_date) OR
			(i.observed_date = '' AND i.release_date <= b.release_date AND EXISTS (
				SELECT 1 FROM apt_release_indexes o WHERE o.codename = i.codename AND o.idx = i.idx AND o.observed_date != '')))
		ORDER BY i.idx, i.release_date, i.path`, codename)
	if err != nil {
		return nil, fmt.Errorf("read the %s indexes the age gate has not recorded: %w", codename, err)
	}
	defer func() { _ = rows.Close() }()
	type group struct{ idx, date string }
	var order []group
	byGroup := map[group][]AptReleaseIndex{}
	for rows.Next() {
		var ix AptReleaseIndex
		var date string
		if err := rows.Scan(&ix.Path, &ix.Index, &ix.SHA256, &date); err != nil {
			return nil, err
		}
		g := group{ix.Index, date}
		if _, seen := byGroup[g]; !seen {
			order = append(order, g)
		}
		byGroup[g] = append(byGroup[g], ix)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]AptReleaseIndex, 0, len(order))
	for _, g := range order {
		out = append(out, preferAptCompression(byGroup[g], prefer))
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

// RecordAptIndexVersions records what one Packages file of codename, the one
// whose SHA256 is sum, lists, at the earliest Date: of a recorded Release
// publishing it: each source version keeps the earlier of that and any date
// it already has, and each pool Filename with no identity yet gets one. The
// file and its other compressions under the same Release are marked observed
// at that date in the same transaction.
//
// It returns how the versions were dated as of this write, and
// ErrAptIndexUnknown when no recorded Release publishes sum.
func (a *DB) RecordAptIndexVersions(ctx context.Context, codename, sum string, entries []AptIndexEntry) (string, error) {
	if a.readOnly {
		return "", errors.New("audit db is read-only")
	}
	snap, ok, err := a.LookupAptIndex(ctx, codename, sum)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrAptIndexUnknown
	}
	date := aptDate(snap.ReleaseDate)

	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	paths, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO apt_pool_paths
		(pool_path, source, version, codename) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return "", err
	}
	defer func() { _ = paths.Close() }()
	dates, err := tx.PrepareContext(ctx, `INSERT INTO apt_version_dates (source, version, codename, published_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (source, version, codename) DO UPDATE SET published_at = excluded.published_at
		WHERE excluded.published_at < apt_version_dates.published_at`)
	if err != nil {
		return "", err
	}
	defer func() { _ = dates.Close() }()
	for _, e := range entries {
		if e.Source == "" || e.Version == "" {
			continue
		}
		if e.Filename != "" {
			if _, err := paths.ExecContext(ctx, e.Filename, e.Source, e.Version, codename); err != nil {
				return "", fmt.Errorf("record the identity of %s: %w", e.Filename, err)
			}
		}
		if _, err := dates.ExecContext(ctx, e.Source, e.Version, codename, date); err != nil {
			return "", fmt.Errorf("record %s %s: %w", e.Source, e.Version, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE apt_release_indexes SET observed_date = ?
		WHERE codename = ? AND (sha256 = ? OR (idx = ? AND release_date = ?))`,
		date, codename, sum, snap.Index, date); err != nil {
		return "", fmt.Errorf("mark %s %s observed: %w", codename, snap.Index, err)
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	if snap.Initial {
		return AptDatedByPredates, nil
	}
	return AptDatedByRelease, nil
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
// and otherwise takes the earliest Release that did.
func (a *DB) GetAptVersionDate(ctx context.Context, source, version string) (AptVersionDate, bool, error) {
	d := AptVersionDate{Source: source, Version: version}
	var published, recorded string
	var predates bool
	err := a.db.QueryRowContext(ctx, `SELECT v.codename, v.published_at, v.recorded_at, v.published_at <= b.release_date AS predates
		FROM apt_version_dates v JOIN apt_codename_baseline b ON b.codename = v.codename
		WHERE v.source = ? AND v.version = ? ORDER BY predates DESC, v.published_at LIMIT 1`, source, version).
		Scan(&d.Codename, &published, &recorded, &predates)
	if errors.Is(err, sql.ErrNoRows) {
		return AptVersionDate{}, false, nil
	}
	if err != nil {
		return AptVersionDate{}, false, fmt.Errorf("read the date of apt %s %s: %w", source, version, err)
	}
	d.RecordedAt, _ = time.Parse(time.RFC3339Nano, recorded)
	if predates {
		d.DatedBy = AptDatedByPredates
		return d, true, nil
	}
	d.DatedBy = AptDatedByRelease
	if d.PublishedAt, err = time.Parse(time.RFC3339, published); err != nil {
		return AptVersionDate{}, false, fmt.Errorf("the date recorded for apt %s %s does not parse: %w", source, version, err)
	}
	return d, true, nil
}
