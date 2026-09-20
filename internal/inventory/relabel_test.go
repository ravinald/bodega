package inventory

import (
	"context"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

const binaryKey = "binaries/example-tool-v2/2.15.0/example-tool.zip"

// twoBackends returns a resolver over the default backend plus "bulk", both
// local and both empty.
func twoBackends(t *testing.T) storage.Resolver {
	t.Helper()
	stores, err := storage.NewResolver(t.Context(), &config.Config{
		StorageBackend:  "local",
		StoragePath:     t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local", Path: t.TempDir()}},
	})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return stores
}

func put(t *testing.T, stores storage.Resolver, backend, key string) {
	t.Helper()
	st, err := stores.ByName(backend)
	if err != nil {
		t.Fatalf("ByName(%q): %v", backend, err)
	}
	if err := st.Put(t.Context(), key, []byte("artifact")); err != nil {
		t.Fatalf("Put %s on %q: %v", key, backend, err)
	}
}

// binaryPair returns the same package before and after an edit that repoints
// its one version from was to now.
func binaryPair(was, now string) (*manifest.PackageManifest, *manifest.PackageManifest) {
	entry := func(backend string) *manifest.PackageManifest {
		return &manifest.PackageManifest{
			Type: manifest.TypeBinary,
			Name: "example-tool-v2",
			Versions: []manifest.VersionEntry{{
				Version:  "2.15.0",
				Filename: "example-tool.zip",
				Storage:  backend,
			}},
		}
	}
	return entry(was), entry(now)
}

// TestCheckRelabelRefusesWhenTheObjectIsOnlyOnTheOldBackend is the defect:
// reads resolve by the recorded name, so relabeling the record turns an
// artifact that exists into a 404 with nothing reporting it.
func TestCheckRelabelRefusesWhenTheObjectIsOnlyOnTheOldBackend(t *testing.T) {
	stores := twoBackends(t)
	put(t, stores, storage.DefaultName, binaryKey)
	before, after := binaryPair("", "bulk")

	err := CheckRelabel(t.Context(), stores, before, after)
	if err == nil {
		t.Fatal("CheckRelabel accepted a relabel that strands the artifact")
	}
	for _, want := range []string{binaryKey, "default", "bulk", "bodega pkg move binary example-tool-v2@2.15.0 --to bulk"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %s", err, want)
		}
	}
}

// TestCheckRelabelAcceptsACorrectedRecord: the other edit this cannot tell
// apart from the manifest alone. The object is on the backend being named, so
// the record was wrong and is now right.
func TestCheckRelabelAcceptsACorrectedRecord(t *testing.T) {
	stores := twoBackends(t)
	put(t, stores, "bulk", binaryKey)
	before, after := binaryPair("", "bulk")

	if err := CheckRelabel(t.Context(), stores, before, after); err != nil {
		t.Errorf("CheckRelabel refused a correction: %v", err)
	}
}

// TestCheckRelabelAcceptsAVersionWithNoBytesAnywhere: 'pkg create' then
// 'pkg edit' is a normal order, and a version that was never uploaded strands
// nothing.
func TestCheckRelabelAcceptsAVersionWithNoBytesAnywhere(t *testing.T) {
	stores := twoBackends(t)
	before, after := binaryPair("", "bulk")

	if err := CheckRelabel(t.Context(), stores, before, after); err != nil {
		t.Errorf("CheckRelabel refused an entry with no object at either end: %v", err)
	}
}

// TestCheckRelabelIgnoresAnEditThatLeavesStorageAlone keeps the probe off the
// common edit. A description or a URL change must not open a backend.
func TestCheckRelabelIgnoresAnEditThatLeavesStorageAlone(t *testing.T) {
	stores := twoBackends(t)
	put(t, stores, storage.DefaultName, binaryKey)
	before, after := binaryPair("", "")
	after.Description = "edited"

	if err := CheckRelabel(t.Context(), stores, before, after); err != nil {
		t.Errorf("CheckRelabel refused an edit that did not touch storage: %v", err)
	}
}

// TestCheckRelabelReadsEmptyAndDefaultAsOneBackend. Spelling the reserved name
// out is not a move, and refusing it would fail an edit that changed nothing.
func TestCheckRelabelReadsEmptyAndDefaultAsOneBackend(t *testing.T) {
	stores := twoBackends(t)
	put(t, stores, storage.DefaultName, binaryKey)
	before, after := binaryPair("", storage.DefaultName)

	if err := CheckRelabel(t.Context(), stores, before, after); err != nil {
		t.Errorf("CheckRelabel read %q as a move away from the default: %v", storage.DefaultName, err)
	}
}

// unreachable answers every probe with an error, standing in for a backend
// that is down rather than empty.
type unreachable struct{ storage.ObjectStore }

func (unreachable) Head(context.Context, string) (*storage.ObjectInfo, error) {
	return nil, context.DeadlineExceeded
}

// downResolver hands out an unreachable store for one name.
type downResolver struct {
	storage.Resolver
	down string
}

func (d *downResolver) ByName(name string) (storage.ObjectStore, error) {
	inner, err := d.Resolver.ByName(name)
	if err != nil {
		return nil, err
	}
	if EffectiveBackend(name) == d.down {
		return unreachable{inner}, nil
	}
	return inner, nil
}

// TestCheckRelabelRefusesWhenABackendCannotAnswer. An unreachable backend has
// not said the object is there, and waving the edit through on a timeout is
// the same stranding with an excuse attached.
func TestCheckRelabelRefusesWhenABackendCannotAnswer(t *testing.T) {
	stores := &downResolver{Resolver: twoBackends(t), down: "bulk"}
	before, after := binaryPair("", "bulk")

	err := CheckRelabel(t.Context(), stores, before, after)
	if err == nil {
		t.Fatal("CheckRelabel accepted a relabel no backend confirmed")
	}
	if !strings.Contains(err.Error(), "bulk") {
		t.Errorf("error = %q, want it to name the backend that could not answer", err)
	}
}

// TestCheckRelabelProbesThePypiSentinel. pypi has no per-version object key, so
// the wheel tree stands in for it — and the remedy is the type-wide one,
// because 'pkg move' refuses pypi.
func TestCheckRelabelProbesThePypiSentinel(t *testing.T) {
	stores := twoBackends(t)
	put(t, stores, storage.DefaultName, pypiSentinel)

	before := &manifest.PackageManifest{
		Type:     manifest.TypePypi,
		Name:     "examplesdk",
		Versions: []manifest.VersionEntry{{Version: "1.26.0"}},
	}
	after := &manifest.PackageManifest{
		Type:     manifest.TypePypi,
		Name:     "examplesdk",
		Versions: []manifest.VersionEntry{{Version: "1.26.0", Storage: "bulk"}},
	}

	err := CheckRelabel(t.Context(), stores, before, after)
	if err == nil {
		t.Fatal("CheckRelabel accepted a pypi relabel that leaves the wheel tree behind")
	}
	if strings.Contains(err.Error(), "pkg move") {
		t.Errorf("error = %q, but 'pkg move' refuses pypi", err)
	}
	if !strings.Contains(err.Error(), "storage_by_type.pypi") {
		t.Errorf("error = %q, want the remedy that moves a whole type", err)
	}
}
