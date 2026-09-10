package admit

import (
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
