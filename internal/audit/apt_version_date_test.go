package audit

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A Release and the Packages it publishes reach the database from different
// requests, so every interleaving has to leave the dates their join gives.
func TestAptMembershipReconcilesWithReleasesInAnyOrder(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	older, newer := base.Add(24*time.Hour), base.Add(48*time.Hour)
	seed := []AptIndexEntry{{Filename: "pool/main/c/curl/curl_8.5.0-1_amd64.deb", Source: "curl", Version: "8.5.0-1"}}
	added := append([]AptIndexEntry{{Filename: "pool/main/c/curl/curl_8.5.0-2_amd64.deb", Source: "curl", Version: "8.5.0-2"}}, seed...)
	index := func(sum string) []AptReleaseIndex {
		return []AptReleaseIndex{{Path: "main/binary-amd64/Packages.gz", Index: "main/binary-amd64", SHA256: sum}}
	}
	steps := map[string]func(*DB) error{
		"baseline-release": func(db *DB) error { return db.RecordAptRelease(ctx, "noble", base, index("aaa")) },
		"baseline-members": func(db *DB) error { return db.RecordAptIndexMembers(ctx, "", "noble", "aaa", seed) },
		"older-release":    func(db *DB) error { return db.RecordAptRelease(ctx, "noble", older, index("bbb")) },
		"newer-release":    func(db *DB) error { return db.RecordAptRelease(ctx, "noble", newer, index("bbb")) },
		"added-members":    func(db *DB) error { return db.RecordAptIndexMembers(ctx, "", "noble", "bbb", added) },
	}
	check := func(t *testing.T, path string) {
		t.Helper()
		db, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if d, ok, err := db.GetAptVersionDate(ctx, []string{"noble"}, "curl", "8.5.0-1"); err != nil || !ok || d.DatedBy != AptDatedByPredates {
			t.Errorf("version the baseline listed = %+v ok=%v err=%v; want predates", d, ok, err)
		}
		if d, ok, err := db.GetAptVersionDate(ctx, []string{"noble"}, "curl", "8.5.0-2"); err != nil || !ok || d.DatedBy != AptDatedByRelease || !d.PublishedAt.Equal(older) {
			t.Errorf("version added later = %+v ok=%v err=%v; want the earliest Release listing it, %s", d, ok, err, older)
		}
	}
	orders := [][]string{
		{"baseline-release", "baseline-members", "older-release", "added-members", "newer-release"},
		{"baseline-release", "baseline-members", "newer-release", "added-members", "older-release"},
		{"added-members", "baseline-members", "newer-release", "older-release", "baseline-release"},
		{"newer-release", "added-members", "older-release", "baseline-members", "baseline-release"},
		{"added-members", "older-release", "baseline-members", "baseline-release", "newer-release"},
	}
	for i, order := range orders {
		t.Run(fmt.Sprint("order-", i), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.db")
			db, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range order {
				if err := steps[name](db); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
			}
			db.Close()
			check(t, path)
		})
	}
	t.Run("concurrent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.db")
		db, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for round := 0; round < 4; round++ {
			for name, step := range steps {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := step(db); err != nil {
						t.Errorf("%s: %v", name, err)
					}
				}()
			}
		}
		wg.Wait()
		db.Close()
		check(t, path)
	})
}

// A Packages file read before any Release publishing it is recorded is kept,
// and is told apart from one bodega never read.
func TestAptMembersWithNoReleaseAreKeptUndated(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := []AptIndexEntry{{Filename: "pool/main/c/curl/curl_8.5.0-2_amd64.deb", Source: "curl", Version: "8.5.0-2"}}
	if err := db.RecordAptIndexMembers(ctx, "", "noble", "bbb", entries); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if db, err = Open(path); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if seen, err := db.AptIndexObserved(ctx, "noble", "bbb"); err != nil || !seen {
		t.Errorf("index read with no Release: observed=%v err=%v; want it kept across a reopen", seen, err)
	}
	if seen, err := db.AptIndexObserved(ctx, "noble", "ccc"); err != nil || seen {
		t.Errorf("index never read: observed=%v err=%v; want false", seen, err)
	}
	if d, ok, err := db.GetAptVersionDate(ctx, []string{"noble"}, "curl", "8.5.0-2"); err != nil || !ok || d.DatedBy != AptDatedByNothing || !d.PublishedAt.IsZero() {
		t.Errorf("version of an index no Release publishes = %+v ok=%v err=%v; want it listed and undated", d, ok, err)
	}
	if _, ok, err := db.GetAptVersionDate(ctx, []string{"noble"}, "curl", "9.0.0-1"); err != nil || ok {
		t.Errorf("version no index listed: ok=%v err=%v; want no record", ok, err)
	}
	when := time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC)
	if err := db.RecordAptRelease(ctx, "noble", when.Add(-24*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordAptRelease(ctx, "noble", when, []AptReleaseIndex{{Path: "main/binary-amd64/Packages.gz", Index: "main/binary-amd64", SHA256: "bbb"}}); err != nil {
		t.Fatal(err)
	}
	if d, ok, err := db.GetAptVersionDate(ctx, []string{"noble"}, "curl", "8.5.0-2"); err != nil || !ok || d.DatedBy != AptDatedByRelease || !d.PublishedAt.Equal(when) {
		t.Errorf("after its Release is recorded = %+v ok=%v err=%v; want %s", d, ok, err, when)
	}
}

// aptPoolPathArchiveVersion is migration 043, where apt_pool_paths started
// carrying the archive.
const aptPoolPathArchiveVersion = 43

// F120 requirement 2: the rows an age gate recorded before archives existed
// belong to the default archive after the migration, and read back the same
// source versions and dates; the down migration returns them to one row per
// path.
func TestMigration043KeepsPoolPathsInTheDefaultArchive(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	m := migrator(t, raw)
	if err := m.Migrate(aptPoolPathArchiveVersion - 1); err != nil {
		t.Fatalf("migrate to %d: %v", aptPoolPathArchiveVersion-1, err)
	}
	const (
		curlPath = "pool/main/c/curl/curl_8.5.0-2_amd64.deb"
		vimPath  = "pool/main/v/vim/vim_9.1.0016-1ubuntu7_amd64.deb"
	)
	for _, q := range []string{
		`INSERT INTO apt_codename_baseline (codename, release_date) VALUES ('noble', '2026-11-01T06:00:00Z')`,
		`INSERT INTO apt_version_dates (source, version, codename, published_at) VALUES
			('curl', '8.5.0-2', 'noble', '2026-11-03T06:00:00Z'),
			('vim', '2:9.1.0016-1ubuntu7', 'noble', '2026-11-01T06:00:00Z')`,
		`INSERT INTO apt_pool_paths (pool_path, source, version, codename) VALUES
			('` + curlPath + `', 'curl', '8.5.0-2', 'noble'),
			('` + vimPath + `', 'vim', '2:9.1.0016-1ubuntu7', 'noble')`,
	} {
		if _, err := raw.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if err := m.Migrate(aptPoolPathArchiveVersion); err != nil {
		t.Fatalf("migrate to %d: %v", aptPoolPathArchiveVersion, err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		source, version, datedBy string
		published                time.Time
	}{
		curlPath: {"curl", "8.5.0-2", AptDatedByRelease, time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC)},
		vimPath:  {"vim", "2:9.1.0016-1ubuntu7", AptDatedByPredates, time.Time{}},
	}
	for poolPath, w := range want {
		e, ok, err := db.GetAptPoolPath(ctx, "", poolPath)
		if err != nil || !ok || e.Source != w.source || e.Version != w.version {
			t.Errorf("default archive's %s = %+v ok=%v err=%v; want %s %s", poolPath, e, ok, err, w.source, w.version)
			continue
		}
		if _, ok, err := db.GetAptPoolPath(ctx, "ubuntu", poolPath); err != nil || ok {
			t.Errorf("a named archive reads a row the default archive recorded: ok=%v err=%v", ok, err)
		}
		d, ok, err := db.GetAptVersionDate(ctx, []string{"noble"}, e.Source, e.Version)
		if err != nil || !ok || d.DatedBy != w.datedBy || !d.PublishedAt.Equal(w.published) {
			t.Errorf("date of %s %s after the migration = %+v ok=%v err=%v; want %s %s", e.Source, e.Version, d, ok, err, w.datedBy, w.published)
		}
	}
	db.Close()

	if err := m.Migrate(aptPoolPathArchiveVersion - 1); err != nil {
		t.Fatalf("migrate down to %d: %v", aptPoolPathArchiveVersion-1, err)
	}
	var n int
	if err := raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM apt_pool_paths WHERE pool_path IN (?, ?)`, curlPath, vimPath).Scan(&n); err != nil || n != 2 {
		t.Errorf("rows after the down migration = %d err=%v; want 2", n, err)
	}
}

// F120 requirement 2: Debian and Ubuntu publish one pool path under one source
// version, each from its own index on its own date. Each archive reads the
// date its own codenames' Releases give, where a lookup across every codename
// gave both archives the earlier one.
func TestAptOnePoolPathInTwoArchivesHasTwoDates(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const poolPath = "pool/main/c/curl/curl_8.5.0-2_amd64.deb"
	base := time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	dates := map[string]time.Time{"noble": base.Add(48 * time.Hour), "trixie": base.Add(96 * time.Hour)}
	archives := map[string]string{"noble": "ubuntu", "trixie": "debian"}
	sources := map[string]string{"noble": "8.5.0-2", "trixie": "8.5.0-2"}
	for codename, when := range dates {
		sum := codename + "-index"
		if err := db.RecordAptRelease(ctx, codename, base, nil); err != nil {
			t.Fatal(err)
		}
		if err := db.RecordAptRelease(ctx, codename, when, []AptReleaseIndex{{Path: "main/binary-amd64/Packages.gz", Index: "main/binary-amd64", SHA256: sum}}); err != nil {
			t.Fatal(err)
		}
		entries := []AptIndexEntry{{Filename: poolPath, Source: "curl", Version: sources[codename]}}
		if err := db.RecordAptIndexMembers(ctx, archives[codename], codename, sum, entries); err != nil {
			t.Fatal(err)
		}
	}
	for codename, when := range dates {
		e, ok, err := db.GetAptPoolPath(ctx, archives[codename], poolPath)
		if err != nil || !ok || e.Version != sources[codename] {
			t.Errorf("archive %s's %s = %+v ok=%v err=%v; want source version %s", archives[codename], poolPath, e, ok, err, sources[codename])
			continue
		}
		d, ok, err := db.GetAptVersionDate(ctx, []string{codename}, e.Source, e.Version)
		if err != nil || !ok || d.DatedBy != AptDatedByRelease || !d.PublishedAt.Equal(when) || d.Codename != codename {
			t.Errorf("archive %s dates curl %s = %+v ok=%v err=%v; want %s from %s", archives[codename], e.Version, d, ok, err, when, codename)
		}
	}
	if _, ok, _ := db.GetAptVersionDate(ctx, nil, "curl", "8.5.0-2"); ok {
		t.Error("an archive with no codenames read a date")
	}
}
