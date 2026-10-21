package admit

import (
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

func entry(version string, origins ...string) manifest.VersionEntry {
	ve := manifest.VersionEntry{Version: version}
	if len(origins) > 0 {
		ve.Metadata = map[string]string{MetaOrigin: strings.Join(origins, ",")}
	}
	return ve
}

func pkg(name string, versions ...manifest.VersionEntry) *manifest.PackageManifest {
	return &manifest.PackageManifest{Name: name, Type: manifest.TypePypi, Versions: versions}
}

func TestApplyOriginStampsAnUnmarkedEntry(t *testing.T) {
	pm := pkg("requests", entry("2.31.0"))
	if err := ApplyOrigin(pm, "db01"); err != nil {
		t.Fatalf("ApplyOrigin: %v", err)
	}
	if got := Origins(pm.Versions[0]); len(got) != 1 || got[0] != "db01" {
		t.Errorf("origins = %v, want [db01]", got)
	}
}

// A flag and a payload that disagree are two claims about where the row came
// from. Picking either silently is how the field stops being evidence.
func TestApplyOriginRefusesADisagreement(t *testing.T) {
	pm := pkg("requests", entry("2.31.0", "db02"))
	err := ApplyOrigin(pm, "db01")
	if err == nil {
		t.Fatal("--origin db01 over a payload naming db02 must fail")
	}
	for _, want := range []string{"db01", "db02", "2.31.0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must name %q, got: %v", want, err)
		}
	}
}

func TestApplyOriginAcceptsAMatchingPayload(t *testing.T) {
	pm := pkg("requests", entry("2.31.0", "db01"))
	if err := ApplyOrigin(pm, "db01"); err != nil {
		t.Fatalf("a payload that agrees with the flag must pass: %v", err)
	}
}

// A flag naming one of several recorded hosts restates what the payload says.
// Re-importing an export that merged db01 and db02 with --origin db01 has to
// pass, or the same catalog is importable one host earlier and not after.
func TestApplyOriginAcceptsAPayloadThatAlreadyListsTheHost(t *testing.T) {
	pm := pkg("requests", entry("2.31.0", "db01", "db02"))
	if err := ApplyOrigin(pm, "db01"); err != nil {
		t.Fatalf("--origin db01 over a payload naming db01,db02 must pass: %v", err)
	}
	if err := ApplyOrigin(pm, "db03"); err == nil {
		t.Error("--origin db03 over a payload naming db01,db02 must fail")
	} else {
		for _, want := range []string{"db01", "db02", "db03"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %s", err, want)
			}
		}
	}
}

func TestApplyOriginRefusesACommaInTheName(t *testing.T) {
	if err := ApplyOrigin(pkg("requests", entry("2.31.0")), "db01,db02"); err == nil {
		t.Fatal("a comma is the list separator; one name cannot carry it")
	}
}

// The merge is where the field earns the plural. A version already recorded
// from db01 and reported again by db02 is on both machines.
func TestMergeVersionsAccumulatesOrigins(t *testing.T) {
	existing := pkg("requests", entry("2.31.0", "db01"))
	MergeVersions(existing, pkg("requests", entry("2.31.0", "db02"), entry("2.32.0", "db02")))

	if len(existing.Versions) != 2 {
		t.Fatalf("got %d versions, want 2", len(existing.Versions))
	}
	if got := Origins(existing.Versions[0]); len(got) != 2 || got[0] != "db01" || got[1] != "db02" {
		t.Errorf("shared version origins = %v, want [db01 db02] in first-seen order", got)
	}
	if got := Origins(existing.Versions[1]); len(got) != 1 || got[0] != "db02" {
		t.Errorf("new version origins = %v, want [db02]", got)
	}
}

func TestMergeVersionsDoesNotDuplicateAnOrigin(t *testing.T) {
	existing := pkg("requests", entry("2.31.0", "db01"))
	MergeVersions(existing, pkg("requests", entry("2.31.0", "db01")))
	if got := Origins(existing.Versions[0]); len(got) != 1 {
		t.Errorf("re-importing the same host must not repeat it: %v", got)
	}
}

// A merge must not downgrade what is already recorded: the origins union, the
// rest of the entry stays as stored.
func TestMergeVersionsKeepsTheStoredEntry(t *testing.T) {
	existing := pkg("requests", manifest.VersionEntry{Version: "2.31.0", Mode: manifest.ModeHosted})
	MergeVersions(existing, pkg("requests", manifest.VersionEntry{Version: "2.31.0", Mode: manifest.ModeProxy}))
	if existing.Versions[0].Mode != manifest.ModeHosted {
		t.Errorf("mode = %q, want the stored %q", existing.Versions[0].Mode, manifest.ModeHosted)
	}
}

const (
	osqueryAmd64 = "https://pkg.osquery.io/deb/pool/main/o/osquery/osquery_5.23.1-1.linux_amd64.deb"
	osqueryArm64 = "https://pkg.osquery.io/deb/pool/main/o/osquery/osquery_5.23.1-1.linux_arm64.deb"
)

func aptEntry(url, sum string, origins ...string) manifest.VersionEntry {
	ve := entry("5.23.1-1", origins...)
	ve.URL = url
	if sum != "" {
		ve.Checksum = &manifest.Checksum{Algorithm: "sha256", Value: sum}
	}
	return ve
}

func osqueryPkg(versions ...manifest.VersionEntry) *manifest.PackageManifest {
	return &manifest.PackageManifest{Name: "osquery", Type: manifest.TypeApt, Versions: versions}
}

// One apt version ships one .deb per architecture, two entries that differ
// only by URL. Folding the second into the first loses its URL and checksum,
// and the arm64 .deb is never fetched.
func TestMergeVersionsKeepsASecondArchitectureAsItsOwnEntry(t *testing.T) {
	amd := aptEntry(osqueryAmd64, "aaaa", "db01")
	existing := osqueryPkg(amd)

	added, folded := MergeVersions(existing, osqueryPkg(aptEntry(osqueryArm64, "bbbb", "db02")))
	if added != 1 || folded != 0 {
		t.Errorf("MergeVersions = (%d added, %d folded), want (1, 0)", added, folded)
	}
	if len(existing.Versions) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(existing.Versions), existing.Versions)
	}
	if got := existing.Versions[0]; got.URL != osqueryAmd64 || got.Checksum.Value != "aaaa" || !slices.Equal(Origins(got), []string{"db01"}) {
		t.Errorf("amd64 entry changed: %+v", got)
	}
	if got := existing.Versions[1]; got.URL != osqueryArm64 || got.Checksum == nil || got.Checksum.Value != "bbbb" {
		t.Errorf("arm64 entry = %+v, want its own URL and checksum", got)
	}

	added, folded = MergeVersions(existing, osqueryPkg(aptEntry(osqueryAmd64, "", "db03"), aptEntry(osqueryArm64, "", "db03")))
	if added != 0 || folded != 2 {
		t.Errorf("second merge = (%d added, %d folded), want (0, 2)", added, folded)
	}
	if len(existing.Versions) != 2 {
		t.Fatalf("second merge left %d entries, want 2", len(existing.Versions))
	}
	for i, want := range [][]string{{"db01", "db03"}, {"db02", "db03"}} {
		if got := Origins(existing.Versions[i]); !slices.Equal(got, want) {
			t.Errorf("entry %d origins = %v, want %v", i, got, want)
		}
	}
}

// A host capture records an apt row with no URL, so it names the version and
// nothing more: it folds into whichever entry holds that version. An npm URL
// names a registry, not an artifact, so a different one is the same version.
func TestMergeVersionsFoldsAURLlessAptEntryAndANonAptURL(t *testing.T) {
	existing := osqueryPkg(aptEntry(osqueryAmd64, "aaaa", "db01"))
	if added, folded := MergeVersions(existing, osqueryPkg(aptEntry("", "", "db02"))); added != 0 || folded != 1 {
		t.Errorf("URL-less apt merge = (%d added, %d folded), want (0, 1)", added, folded)
	}
	if len(existing.Versions) != 1 || !slices.Equal(Origins(existing.Versions[0]), []string{"db01", "db02"}) {
		t.Errorf("URL-less apt entry did not fold: %+v", existing.Versions)
	}

	npm := func(url, origin string) *manifest.PackageManifest {
		ve := entry("1.3.0", origin)
		ve.URL = url
		return &manifest.PackageManifest{Name: "left-pad", Type: manifest.TypeNpm, Versions: []manifest.VersionEntry{ve}}
	}
	stored := npm("https://registry.npmjs.org/left-pad", "db01")
	if added, folded := MergeVersions(stored, npm("https://npm.mirror.example/left-pad", "db02")); added != 0 || folded != 1 {
		t.Errorf("npm merge = (%d added, %d folded), want (0, 1)", added, folded)
	}
	if len(stored.Versions) != 1 || stored.Versions[0].URL != "https://registry.npmjs.org/left-pad" {
		t.Errorf("npm entry from a second registry did not fold onto the stored one: %+v", stored.Versions)
	}
}
