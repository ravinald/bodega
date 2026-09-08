package main

import (
	"context"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// showStore writes one package's versions to a scratch manifest directory and
// returns a store reading it back.
func showStore(t *testing.T, typ, name string, versions ...manifest.VersionEntry) *manifest.Store {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	for _, ve := range versions {
		if err := store.AddVersion(context.Background(), typ, name, ve); err != nil {
			t.Fatalf("AddVersion %s: %v", ve.Version, err)
		}
	}
	return store
}

// versionRow returns the table row `show pkg` prints for a version.
func versionRow(t *testing.T, out, version string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, version+" ") {
			return line
		}
	}
	t.Fatalf("no row for %s in:\n%s", version, out)
	return ""
}

// TestShowVersionList_FlaggedVersionNamesItsFindings is the R5 rendering leg:
// an operator reading `show pkg` sees the count, the date and the ids.
func TestShowVersionList_FlaggedVersionNamesItsFindings(t *testing.T) {
	store := showStore(t, manifest.TypeNpm, "minimist",
		manifest.VersionEntry{Version: "1.2.5", Metadata: map[string]string{
			policy.OSVMetaVulns:     "GHSA-doomed",
			policy.OSVMetaCheckedAt: "2026-09-08T20:20:20Z",
		}},
		manifest.VersionEntry{Version: "1.2.8", Metadata: map[string]string{
			policy.OSVMetaCheckedAt: "2026-09-08T20:20:20Z",
		}},
		manifest.VersionEntry{Version: "1.2.9"})

	out := captureStdout(t, func() {
		if err := showVersionList(context.Background(), store, manifest.TypeNpm, "minimist", true, false); err != nil {
			t.Errorf("showVersionList: %v", err)
		}
	})

	if row := versionRow(t, out, "1.2.5"); !strings.Contains(row, "1 vuln(s)") || !strings.Contains(row, "2026-09-08") {
		t.Errorf("a flagged version must carry its count and date: %q", row)
	}
	if row := versionRow(t, out, "1.2.8"); !strings.Contains(row, "clean") || !strings.Contains(row, "2026-09-08") {
		t.Errorf("a checked version with no findings must read clean and dated: %q", row)
	}
	if row := versionRow(t, out, "1.2.9"); !strings.Contains(row, "unchecked") || !strings.Contains(row, "never") {
		t.Errorf("a version nobody checked must say so: %q", row)
	}
	if !strings.Contains(out, "Flagged by OSV:") || !strings.Contains(out, "GHSA-doomed") {
		t.Errorf("the flagged block must name the ids:\n%s", out)
	}
}

// TestShowVersionList_UncoveredEcosystemReadsNA pins the distinction R2 exists
// for, one level up: "nobody looked" and "nothing can ever look" must not print
// the same. OSV holds no apt records, and `policy osv rescan --type apt`
// refuses to run, so an apt row saying "unchecked" names a fix that does not
// exist.
func TestShowVersionList_UncoveredEcosystemReadsNA(t *testing.T) {
	for _, typ := range []string{manifest.TypeApt, manifest.TypeGit, manifest.TypeBinary, manifest.TypeHelm} {
		t.Run(typ, func(t *testing.T) {
			store := showStore(t, typ, "hello", manifest.VersionEntry{Version: "1.0.0"})

			out := captureStdout(t, func() {
				if err := showVersionList(context.Background(), store, typ, "hello", true, false); err != nil {
					t.Errorf("showVersionList: %v", err)
				}
			})

			row := versionRow(t, out, "1.0.0")
			if !strings.Contains(row, "n/a") {
				t.Errorf("%s has no OSV answer to give, so the column must read n/a: %q", typ, row)
			}
			if strings.Contains(row, "unchecked") || strings.Contains(row, "never") {
				t.Errorf("%s must not promise a check that can never happen: %q", typ, row)
			}
		})
	}
}
