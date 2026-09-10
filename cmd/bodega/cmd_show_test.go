package main

import (
	"context"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/admit"
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
//
// The stamped version is the case `pkg import` reaches: VersionEntry.Metadata
// is modeled, so an export from one instance carries whatever vetting.osv.*
// keys the source wrote, onto a type bodega's own writers never stamp.
func TestShowVersionList_UncoveredEcosystemReadsNA(t *testing.T) {
	for _, typ := range []string{manifest.TypeApt, manifest.TypeGit, manifest.TypeBinary, manifest.TypeHelm} {
		t.Run(typ, func(t *testing.T) {
			store := showStore(t, typ, "hello",
				manifest.VersionEntry{Version: "1.0.0"},
				manifest.VersionEntry{Version: "1.1.0", Metadata: map[string]string{
					policy.OSVMetaVulns:     "CVE-2024-7347",
					policy.OSVMetaCheckedAt: "2026-09-01T00:00:00Z",
				}})

			out := captureStdout(t, func() {
				if err := showVersionList(context.Background(), store, typ, "hello", true, false); err != nil {
					t.Errorf("showVersionList: %v", err)
				}
			})

			for _, v := range []string{"1.0.0", "1.1.0"} {
				row := versionRow(t, out, v)
				if !strings.Contains(row, "n/a") {
					t.Errorf("%s has no OSV answer to give, so the column must read n/a: %q", typ, row)
				}
				if strings.Contains(row, "unchecked") || strings.Contains(row, "never") {
					t.Errorf("%s must not promise a check that can never happen: %q", typ, row)
				}
			}
			if strings.Contains(out, "Flagged by OSV:") || strings.Contains(out, "CVE-2024-7347") {
				t.Errorf("%s reads n/a in the table, so an imported stamp must not reappear as a finding:\n%s", typ, out)
			}
		})
	}
}

// TestShowVersionList_RangeEntryIsNeverDated is the renderer's half of the
// rule the gate already applies: a non-exact constraint names a range the
// server resolves upstream, so no point lookup dates it. A date on such an
// entry arrived by import or by an edit to the constraint after the check, and
// printing it as a clean verdict asserts an answer for the in-range releases
// nobody queried.
//
// The ids stay. Those are records against the base version and they are real.
func TestShowVersionList_RangeEntryIsNeverDated(t *testing.T) {
	store := showStore(t, manifest.TypeNpm, "minimist",
		manifest.VersionEntry{Version: "1.2.0", VersionConstraint: manifest.ConstraintCompatible,
			Metadata: map[string]string{policy.OSVMetaCheckedAt: "2026-01-01T00:00:00Z"}},
		manifest.VersionEntry{Version: "1.2.9", VersionConstraint: manifest.ConstraintPatch,
			Metadata: map[string]string{
				policy.OSVMetaVulns:     "GHSA-range-hit",
				policy.OSVMetaCheckedAt: "2026-01-01T00:00:00Z",
			}},
		manifest.VersionEntry{Version: "1.3.0", VersionConstraint: manifest.ConstraintExact,
			Metadata: map[string]string{policy.OSVMetaCheckedAt: "2026-01-01T00:00:00Z"}})

	out := captureStdout(t, func() {
		if err := showVersionList(context.Background(), store, manifest.TypeNpm, "minimist", true, false); err != nil {
			t.Errorf("showVersionList: %v", err)
		}
	})

	row := versionRow(t, out, "1.2.0")
	if strings.Contains(row, "clean") || strings.Contains(row, "2026-01-01") {
		t.Errorf("a range entry with no findings is unchecked, not clean and dated: %q", row)
	}
	if !strings.Contains(row, "unchecked") || !strings.Contains(row, "never") {
		t.Errorf("a range entry nothing could date must say so: %q", row)
	}

	row = versionRow(t, out, "1.2.9")
	if !strings.Contains(row, "1 vuln(s)") {
		t.Errorf("a record against the base version is real and stays: %q", row)
	}
	if strings.Contains(row, "2026-01-01") {
		t.Errorf("the finding stays, the date does not: %q", row)
	}
	if !strings.Contains(out, "GHSA-range-hit  (checked never)") {
		t.Errorf("the flagged block must drop the date too:\n%s", out)
	}

	// The control: an exact entry names one version, so its date stands.
	if row := versionRow(t, out, "1.3.0"); !strings.Contains(row, "clean") || !strings.Contains(row, "2026-01-01") {
		t.Errorf("an exact entry keeps the date the gate wrote: %q", row)
	}
}

// A catalog that cannot say which host put a package in it cannot answer the
// first question asked of it, so the origins have to reach the operator's
// screen and not only the manifest file.
func TestShowVersionListDisplaysOrigins(t *testing.T) {
	store := showStore(t, manifest.TypePypi, "requests",
		manifest.VersionEntry{Version: "2.31.0", Metadata: map[string]string{admit.MetaOrigin: "db01,db02"}},
		manifest.VersionEntry{Version: "2.32.0"})

	out := captureStdout(t, func() {
		if err := showVersionList(context.Background(), store, manifest.TypePypi, "requests", true, false); err != nil {
			t.Errorf("showVersionList: %v", err)
		}
	})

	if !strings.Contains(out, "ORIGIN") {
		t.Errorf("the admin table has no ORIGIN column:\n%s", out)
	}
	if row := versionRow(t, out, "2.31.0"); !strings.Contains(row, "db01, db02") {
		t.Errorf("a version cataloged from two hosts must name both: %q", row)
	}
	if row := versionRow(t, out, "2.32.0"); !strings.HasSuffix(strings.TrimRight(row, " "), "-") {
		t.Errorf("a version with no recorded origin must read as a dash: %q", row)
	}
}

// The repo table renders what a client may see. An internal hostname is not
// that, so it withholds the column `show pkg` prints. The --json form of the
// same command is a manifest dump and still carries the key.
func TestShowVersionListWithholdsOriginsFromTheRepoTable(t *testing.T) {
	store := showStore(t, manifest.TypePypi, "requests",
		manifest.VersionEntry{Version: "2.31.0", Metadata: map[string]string{admit.MetaOrigin: "db01"}})

	out := captureStdout(t, func() {
		if err := showVersionList(context.Background(), store, manifest.TypePypi, "requests", false, false); err != nil {
			t.Errorf("showVersionList: %v", err)
		}
	})
	if strings.Contains(out, "db01") {
		t.Errorf("the repo view leaked an origin hostname:\n%s", out)
	}
}
