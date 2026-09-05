package audit

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/ravinald/bodega/internal/manifest"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// maxMigrationVersion walks an embedded migrations directory and returns the
// highest NNN prefix seen on a .up.sql file. Used to detect databases that
// have been migrated by a newer binary than the running process. It takes the
// FS and directory because the embedded store and the postgres sink carry
// separate sets, versioned independently.
func maxMigrationVersion(fsys fs.FS, dir string) (uint, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return 0, fmt.Errorf("read embedded migrations %s: %w", dir, err)
	}
	var max uint
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		idx := strings.IndexByte(name, '_')
		if idx <= 0 {
			continue
		}
		n, err := strconv.ParseUint(name[:idx], 10, 32)
		if err != nil {
			continue
		}
		if uint(n) > max {
			max = uint(n)
		}
	}
	if max == 0 {
		return 0, fmt.Errorf("no migrations found in embedded FS under %s", dir)
	}
	return max, nil
}

// runMigrations brings the audit DB up to the latest schema version and
// returns the version it found before doing so, which is what a data backfill
// keyed to a particular migration reads to know whether it has already run. A
// fresh store reports the latest version: it has no rows any backfill could
// correct.
//
// If the DB has been migrated to a version newer than this binary ships, we
// refuse to start. That's the downgrade guardrail — an older binary running
// against a newer schema could silently misread the data.
func runMigrations(db *sql.DB) (from uint, err error) {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return 0, fmt.Errorf("iofs source: %w", err)
	}
	driver, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		return 0, fmt.Errorf("sqlite driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "sqlite", driver)
	if err != nil {
		return 0, fmt.Errorf("migrate instance: %w", err)
	}

	codeMax, err := maxMigrationVersion(migrationsFS, "migrations")
	if err != nil {
		return 0, err
	}

	version, dirty, err := m.Version()
	switch {
	case errors.Is(err, migrate.ErrNilVersion):
		// Fresh database — all migrations will run below.
		version = codeMax
	case err != nil:
		return 0, fmt.Errorf("read schema version: %w", err)
	case dirty:
		return 0, fmt.Errorf("audit db schema is dirty at version %d; manual recovery required", version)
	case version > codeMax:
		return 0, fmt.Errorf("audit db schema version %d exceeds this binary's max (%d); upgrade bodega", version, codeMax)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return 0, fmt.Errorf("apply migrations: %w", err)
	}
	return version, nil
}

// checksumIdentityVersion is migration 011, where checksum rows started
// carrying package identity derived from the object key.
const checksumIdentityVersion = 11

// backfillChecksumIdentity re-derives pkg_type, pkg_name and pkg_version from
// s3_key and writes back every row that disagrees, returning how many it
// touched.
//
// Rows written before migration 011 carry whatever the request-path parser
// made of an object key: nothing at all for apt, gomod, helm and git, and
// ("cargo", "crates") for every crate. s3_key was right the whole time, so the
// correction reads no upstream and no object store.
//
// It is Go rather than SQL because manifest.ParseKey is the derivation the
// write path now uses, and a second one spelled in SQLite string expressions
// would be free to drift from it. Both are pinned together by
// TestBackfillDerivesWhatParseKeyDoes.
func backfillChecksumIdentity(ctx context.Context, db *sql.DB) (int64, error) {
	type correction struct {
		key              string
		typ, name, verzn string
	}

	rows, err := db.QueryContext(ctx, "SELECT s3_key, pkg_type, pkg_name, pkg_version FROM checksums")
	if err != nil {
		return 0, fmt.Errorf("read checksum rows: %w", err)
	}
	var fix []correction
	for rows.Next() {
		var key, typ, name, verzn string
		if err := rows.Scan(&key, &typ, &name, &verzn); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan checksum row: %w", err)
		}
		wantType, wantName, wantVersion := manifest.ParseKey(key)
		if wantType == typ && wantName == name && wantVersion == verzn {
			continue
		}
		fix = append(fix, correction{key: key, typ: wantType, name: wantName, verzn: wantVersion})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("read checksum rows: %w", err)
	}
	// Closed before the updates rather than deferred: SQLite will not write
	// through a connection still streaming the same table.
	rows.Close()
	if len(fix) == 0 {
		return 0, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin checksum backfill: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, c := range fix {
		if _, err := tx.ExecContext(ctx,
			"UPDATE checksums SET pkg_type = ?, pkg_name = ?, pkg_version = ? WHERE s3_key = ?",
			c.typ, c.name, c.verzn, c.key,
		); err != nil {
			return 0, fmt.Errorf("backfill checksum identity for %s: %w", c.key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit checksum backfill: %w", err)
	}
	return int64(len(fix)), nil
}
