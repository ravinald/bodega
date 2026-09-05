package builder

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// TestStampedEntryCarriesTheBuildVersion drives the path an artifact takes
// rather than the assignment: NewConfig reads the package variable main sets,
// GetBuildEnv stamps it, stampVersion writes the entry to disk, and the entry
// is read back and marshaled.
//
// The marshal is the half that matters. BuildEnv.Bodega is omitempty, so an
// unset version produced no wrong value anywhere along this path; the field
// left the JSON entirely, which is why nobody noticed it had never been set.
func TestStampedEntryCarriesTheBuildVersion(t *testing.T) {
	const want = "v9.9.9-test"
	prev := Version
	Version = want
	t.Cleanup(func() { Version = prev })

	root := t.TempDir()
	store := manifest.NewLocalStore(root)
	ve := manifest.VersionEntry{Version: "1.2.3"}
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "hello", ve); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	NewConfig(&config.Config{BuildRoot: root, ManifestDir: root}).
		StampBinaryEntry(store, "hello", ve)

	pm, err := store.GetPackage(t.Context(), manifest.TypeBinary, "hello")
	if err != nil || pm == nil {
		t.Fatalf("GetPackage: %v", err)
	}
	if len(pm.Versions) != 1 || pm.Versions[0].BuildEnv == nil {
		t.Fatalf("stamped entry carries no build_env: %+v", pm.Versions)
	}
	if got := pm.Versions[0].BuildEnv.Bodega; got != want {
		t.Errorf("build_env.bodega = %q, want %q", got, want)
	}

	b, err := json.Marshal(pm.Versions[0].BuildEnv)
	if err != nil {
		t.Fatalf("marshal build_env: %v", err)
	}
	if !strings.Contains(string(b), `"bodega":"`+want+`"`) {
		t.Errorf("marshaled build_env = %s, want a bodega field", b)
	}
}

// TestNewConfigDefaultsTheVersion pins the fallback nothing overwrites.
// "unknown" is a value the manifest keeps and a reader can act on; "" is one
// omitempty deletes, which is the state that hid this for as long as it did.
func TestNewConfigDefaultsTheVersion(t *testing.T) {
	if Version != "unknown" {
		t.Fatalf("package default Version = %q, want \"unknown\"", Version)
	}
	if got := NewConfig(&config.Config{}).BodegaVersion; got != "unknown" {
		t.Errorf("NewConfig().BodegaVersion = %q, want \"unknown\"", got)
	}
}
