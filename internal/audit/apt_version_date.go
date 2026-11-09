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
	// AptDatedByRelease is the Date: of the Release whose index first listed
	// the version.
	AptDatedByRelease = "release"
	// AptDatedByPredates is a version an index of the codename's first
	// recorded Release listed.
	AptDatedByPredates = "predates"
)

// AptIndexEntry is one Packages paragraph as the age gate keeps it: the pool
// Filename it publishes and the source package version it was built from.
type AptIndexEntry struct {
	Filename, Source, Version string
}

// AptVersionDate is when bodega first saw a mirrored index list one source
// package version, and which index that was.
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
// digest: the file it is, whether the codename's first Release published it,
// and the Date: of the earliest dated Release that did.
type AptIndexSnapshot struct {
	AptReleaseIndex
	Initial     bool
	ReleaseDate time.Time
}

// RecordAptRelease records the Packages files one Release of codename
// digests. The first Release recorded for a codename is its initial snapshot,
// reported by initial true, and every file it lists is marked initial; a later
// Release adds the files it is first to list, dated by releaseDate. A file an
// earlier Release already listed keeps that Release's record, except that a
// date fills one recorded without.
func (a *DB) RecordAptRelease(ctx context.Context, codename string, releaseDate time.Time, indexes []AptReleaseIndex) (initial bool, err error) {
	if a.readOnly {
		return false, errors.New("audit db is read-only")
	}
	date := ""
	if !releaseDate.IsZero() {
		date = releaseDate.UTC().Format(time.RFC3339)
	}
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO apt_codename_first_release (codename, release_date) VALUES (?, ?)`, codename, date)
	if err != nil {
		return false, fmt.Errorf("record the first Release of %s: %w", codename, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	initial = n == 1
	flag := 0
	if initial {
		flag = 1
	}
	ins, err := tx.PrepareContext(ctx, `INSERT INTO apt_release_indexes (codename, sha256, path, idx, release_date, initial)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (codename, sha256, path) DO UPDATE SET release_date = excluded.release_date
		WHERE apt_release_indexes.release_date = '' AND apt_release_indexes.initial = 0`)
	if err != nil {
		return false, err
	}
	defer func() { _ = ins.Close() }()
	for _, ix := range indexes {
		if _, err := ins.ExecContext(ctx, codename, ix.SHA256, ix.Path, ix.Index, date, flag); err != nil {
			return false, fmt.Errorf("record %s of the %s Release: %w", ix.Path, codename, err)
		}
	}
	return initial, tx.Commit()
}

// LookupAptIndex returns what the recorded Releases of codename say about the
// Packages file whose SHA256 is sum, with ok false when none lists it.
func (a *DB) LookupAptIndex(ctx context.Context, codename, sum string) (AptIndexSnapshot, bool, error) {
	var snap AptIndexSnapshot
	var initial int
	var date string
	err := a.db.QueryRowContext(ctx, `SELECT path, idx, sha256, initial, release_date FROM apt_release_indexes
		WHERE codename = ? AND sha256 = ? ORDER BY initial DESC, release_date = '', release_date LIMIT 1`, codename, sum).
		Scan(&snap.Path, &snap.Index, &snap.SHA256, &initial, &date)
	if errors.Is(err, sql.ErrNoRows) {
		return AptIndexSnapshot{}, false, nil
	}
	if err != nil {
		return AptIndexSnapshot{}, false, fmt.Errorf("look up the %s Packages index %s: %w", codename, sum, err)
	}
	snap.Initial = initial == 1
	if date != "" {
		if snap.ReleaseDate, err = time.Parse(time.RFC3339, date); err != nil {
			return AptIndexSnapshot{}, false, fmt.Errorf("the Release date recorded for %s index %s does not parse: %w", codename, sum, err)
		}
	}
	return snap, true, nil
}

// UnobservedAptInitialIndex returns one file of the logical index idx that
// codename's first Release published and whose versions nothing has recorded,
// preferring the compression order given, with ok false when there is none.
func (a *DB) UnobservedAptInitialIndex(ctx context.Context, codename, idx string, prefer []string) (AptReleaseIndex, bool, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT path, idx, sha256 FROM apt_release_indexes
		WHERE codename = ? AND idx = ? AND initial = 1 AND observed = 0`, codename, idx)
	if err != nil {
		return AptReleaseIndex{}, false, fmt.Errorf("read the first %s Release's %s: %w", codename, idx, err)
	}
	defer func() { _ = rows.Close() }()
	var found []AptReleaseIndex
	for rows.Next() {
		var ix AptReleaseIndex
		if err := rows.Scan(&ix.Path, &ix.Index, &ix.SHA256); err != nil {
			return AptReleaseIndex{}, false, err
		}
		found = append(found, ix)
	}
	if err := rows.Err(); err != nil {
		return AptReleaseIndex{}, false, err
	}
	for _, suffix := range prefer {
		for _, ix := range found {
			if ix.Path == idx+"/Packages"+suffix {
				return ix, true, nil
			}
		}
	}
	if len(found) > 0 {
		return found[0], true, nil
	}
	return AptReleaseIndex{}, false, nil
}

// RecordAptIndexVersions records what one Packages file of codename, the one
// whose SHA256 is sum, lists: each source version with no record yet, and each
// pool Filename with no identity yet. A file the codename's first Release
// published dates its versions as predating bodega; any other is dated by the
// earliest recorded Release that published it. The file's logical index is
// marked observed in the same transaction, which settles that the first
// Release's copy of it will not be read for predating versions any more.
//
// It returns how the versions it wrote were dated, and ErrAptIndexUnknown when
// no recorded Release publishes sum. A later index whose Releases carry no
// date dates nothing: there is no date to give them, and leaving them
// unrecorded keeps them for the next read that has one.
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
	datedBy, published := AptDatedByPredates, ""
	if !snap.Initial {
		datedBy = AptDatedByRelease
		if !snap.ReleaseDate.IsZero() {
			published = snap.ReleaseDate.UTC().Format(time.RFC3339)
		}
	}
	undated := !snap.Initial && published == ""

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
	dates, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO apt_version_dates
		(source, version, codename, dated_by, published_at) VALUES (?, ?, ?, ?, ?)`)
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
		if undated {
			continue
		}
		if _, err := dates.ExecContext(ctx, e.Source, e.Version, codename, datedBy, published); err != nil {
			return "", fmt.Errorf("record %s %s: %w", e.Source, e.Version, err)
		}
	}
	if undated {
		return "", tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE apt_release_indexes SET observed = 1
		WHERE codename = ? AND idx = ? AND initial = 1`, codename, snap.Index); err != nil {
		return "", fmt.Errorf("mark %s %s observed: %w", codename, snap.Index, err)
	}
	return datedBy, tx.Commit()
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

// GetAptVersionDate returns the record for one source package version, with ok
// false when no index bodega read has listed it.
func (a *DB) GetAptVersionDate(ctx context.Context, source, version string) (AptVersionDate, bool, error) {
	var d AptVersionDate
	var published, recorded string
	err := a.db.QueryRowContext(ctx, `SELECT source, version, codename, dated_by, published_at, recorded_at
		FROM apt_version_dates WHERE source = ? AND version = ?`, source, version).
		Scan(&d.Source, &d.Version, &d.Codename, &d.DatedBy, &published, &recorded)
	if errors.Is(err, sql.ErrNoRows) {
		return AptVersionDate{}, false, nil
	}
	if err != nil {
		return AptVersionDate{}, false, fmt.Errorf("read the date of apt %s %s: %w", source, version, err)
	}
	if published != "" {
		if d.PublishedAt, err = time.Parse(time.RFC3339, published); err != nil {
			return AptVersionDate{}, false, fmt.Errorf("the date recorded for apt %s %s does not parse: %w", source, version, err)
		}
	}
	d.RecordedAt, _ = time.Parse(time.RFC3339Nano, recorded)
	return d, true, nil
}
