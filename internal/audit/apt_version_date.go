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
	// AptDatedByPredates is a version the first read of its index already
	// listed.
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

// RecordAptIndexVersions records what one read of codename's component/arch
// Packages listed, whose Release says it was generated at releaseDate: each
// source version with no record yet, and each pool Filename with no identity
// yet. On the first read of that index its versions are recorded as predating
// bodega instead, since that index is the archive's whole history and not what
// changed since the last read, and the index is marked read in the same
// transaction.
//
// It returns how the versions it wrote were dated. A releaseDate of zero on an
// index already read dates nothing: there is no date to give them, and leaving
// them unrecorded keeps them for the next read that has one.
func (a *DB) RecordAptIndexVersions(ctx context.Context, codename, component, arch string, releaseDate time.Time, entries []AptIndexEntry) (string, error) {
	if a.readOnly {
		return "", errors.New("audit db is read-only")
	}
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO apt_index_reads (codename, component, arch) VALUES (?, ?, ?)`,
		codename, component, arch)
	if err != nil {
		return "", fmt.Errorf("mark %s/%s/%s read: %w", codename, component, arch, err)
	}
	first, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	datedBy, published := AptDatedByPredates, ""
	if first == 0 {
		datedBy, published = AptDatedByRelease, releaseDate.UTC().Format(time.RFC3339)
	}
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
	undated := first == 0 && releaseDate.IsZero()
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
		datedBy = ""
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
