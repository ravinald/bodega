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
	// AptDatedByPredates is a version the first index bodega read for its
	// codename already listed.
	AptDatedByPredates = "predates"
)

// AptSourceVersion is one source package version a Packages paragraph names.
type AptSourceVersion struct {
	Source, Version string
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

// RecordAptIndexVersions records every version in versions that has no record
// yet, as listed by one read of codename's index whose Release says it was
// generated at releaseDate. When bodega has never completed a read of codename,
// they are recorded as predating it instead, since that index is the archive's
// whole history and not what changed since the last read. complete marks the
// read as covering every component and architecture of codename; only then does
// the codename count as read, so a first read that failed half way leaves the
// rest of the archive to predate bodega at the next read rather than be dated
// by today's Release.
//
// It returns how the versions it wrote were dated. A releaseDate of zero on a
// codename already read records nothing: there is no date to give them, and
// leaving them unrecorded keeps them for the next read that has one.
func (a *DB) RecordAptIndexVersions(ctx context.Context, codename string, releaseDate time.Time, versions []AptSourceVersion, complete bool) (string, error) {
	if a.readOnly {
		return "", errors.New("audit db is read-only")
	}
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var seen int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM apt_codename_reads WHERE codename = ?`, codename).Scan(&seen); err != nil {
		return "", fmt.Errorf("read whether %s was indexed before: %w", codename, err)
	}
	datedBy, published := AptDatedByPredates, ""
	if seen > 0 {
		if releaseDate.IsZero() {
			return "", nil
		}
		datedBy, published = AptDatedByRelease, releaseDate.UTC().Format(time.RFC3339)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO apt_version_dates
		(source, version, codename, dated_by, published_at) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return "", err
	}
	defer func() { _ = stmt.Close() }()
	for _, v := range versions {
		if v.Source == "" || v.Version == "" {
			continue
		}
		if _, err := stmt.ExecContext(ctx, v.Source, v.Version, codename, datedBy, published); err != nil {
			return "", fmt.Errorf("record %s %s: %w", v.Source, v.Version, err)
		}
	}
	if complete && seen == 0 {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO apt_codename_reads (codename) VALUES (?)`, codename); err != nil {
			return "", err
		}
	}
	return datedBy, tx.Commit()
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
