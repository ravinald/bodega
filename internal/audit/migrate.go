package audit

import (
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
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// maxMigrationVersion walks the embedded migrations directory and returns
// the highest NNN prefix seen on a .up.sql file. Used to detect databases
// that have been migrated by a newer binary than the running process.
func maxMigrationVersion() (uint, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return 0, fmt.Errorf("read embedded migrations: %w", err)
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
		return 0, errors.New("no migrations found in embedded FS")
	}
	return max, nil
}

// runMigrations brings the audit DB up to the latest schema version.
//
// If the DB has been migrated to a version newer than this binary ships, we
// refuse to start. That's the downgrade guardrail — an older binary running
// against a newer schema could silently misread the data.
func runMigrations(db *sql.DB) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("iofs source: %w", err)
	}
	driver, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		return fmt.Errorf("sqlite driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "sqlite", driver)
	if err != nil {
		return fmt.Errorf("migrate instance: %w", err)
	}

	codeMax, err := maxMigrationVersion()
	if err != nil {
		return err
	}

	version, dirty, err := m.Version()
	switch {
	case errors.Is(err, migrate.ErrNilVersion):
		// Fresh database — all migrations will run below.
	case err != nil:
		return fmt.Errorf("read schema version: %w", err)
	case dirty:
		return fmt.Errorf("audit db schema is dirty at version %d; manual recovery required", version)
	case version > codeMax:
		return fmt.Errorf("audit db schema version %d exceeds this binary's max (%d); upgrade bodega", version, codeMax)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}
