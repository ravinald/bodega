package audit

import (
	"context"
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
		"baseline-members": func(db *DB) error { return db.RecordAptIndexMembers(ctx, "noble", "aaa", seed) },
		"older-release":    func(db *DB) error { return db.RecordAptRelease(ctx, "noble", older, index("bbb")) },
		"newer-release":    func(db *DB) error { return db.RecordAptRelease(ctx, "noble", newer, index("bbb")) },
		"added-members":    func(db *DB) error { return db.RecordAptIndexMembers(ctx, "noble", "bbb", added) },
	}
	check := func(t *testing.T, path string) {
		t.Helper()
		db, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if d, ok, err := db.GetAptVersionDate(ctx, "curl", "8.5.0-1"); err != nil || !ok || d.DatedBy != AptDatedByPredates {
			t.Errorf("version the baseline listed = %+v ok=%v err=%v; want predates", d, ok, err)
		}
		if d, ok, err := db.GetAptVersionDate(ctx, "curl", "8.5.0-2"); err != nil || !ok || d.DatedBy != AptDatedByRelease || !d.PublishedAt.Equal(older) {
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
	if err := db.RecordAptIndexMembers(ctx, "noble", "bbb", entries); err != nil {
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
	if d, ok, err := db.GetAptVersionDate(ctx, "curl", "8.5.0-2"); err != nil || !ok || d.DatedBy != AptDatedByNothing || !d.PublishedAt.IsZero() {
		t.Errorf("version of an index no Release publishes = %+v ok=%v err=%v; want it listed and undated", d, ok, err)
	}
	if _, ok, err := db.GetAptVersionDate(ctx, "curl", "9.0.0-1"); err != nil || ok {
		t.Errorf("version no index listed: ok=%v err=%v; want no record", ok, err)
	}
	when := time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC)
	if err := db.RecordAptRelease(ctx, "noble", when.Add(-24*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordAptRelease(ctx, "noble", when, []AptReleaseIndex{{Path: "main/binary-amd64/Packages.gz", Index: "main/binary-amd64", SHA256: "bbb"}}); err != nil {
		t.Fatal(err)
	}
	if d, ok, err := db.GetAptVersionDate(ctx, "curl", "8.5.0-2"); err != nil || !ok || d.DatedBy != AptDatedByRelease || !d.PublishedAt.Equal(when) {
		t.Errorf("after its Release is recorded = %+v ok=%v err=%v; want %s", d, ok, err, when)
	}
}
