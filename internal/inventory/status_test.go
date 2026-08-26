package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// recorder wraps a real Memory store and keeps every key it was asked to Head,
// so a test can assert on what was probed as well as what came back.
type recorder struct {
	storage.ObjectStore
	heads []string
}

func (r *recorder) Head(ctx context.Context, key string) (*storage.ObjectInfo, error) {
	r.heads = append(r.heads, key)
	return r.ObjectStore.Head(ctx, key)
}

// failing answers every call with an error, standing in for a backend that is
// down rather than empty.
type failing struct{ storage.ObjectStore }

func (f failing) Head(context.Context, string) (*storage.ObjectInfo, error) {
	return nil, errBackendDown
}

func (f failing) List(context.Context, string) ([]string, error) {
	return nil, errBackendDown
}

var errBackendDown = errors.New("backend down")

// TestCheckAptStatusPoolOnly pins the fix for the dead dists/ probe: a store
// holding only pool objects must report its apt entries present. Both the
// _pool_path path and the pool-listing fallback are covered.
func TestCheckAptStatusPoolOnly(t *testing.T) {
	ctx := t.Context()
	store := manifest.NewLocalStore(t.TempDir())

	if err := store.AddVersion(ctx, manifest.TypeApt, "amazon-efs-utils", manifest.VersionEntry{
		Version:    "2.4.2",
		SourceName: "amazon-efs-utils",
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   "pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb",
		},
	}); err != nil {
		t.Fatalf("add amazon-efs-utils: %v", err)
	}
	// No _pool_path: predates the metadata key, so status must fall back to a
	// pool listing rather than report a false negative.
	if err := store.AddVersion(ctx, manifest.TypeApt, "linux-headers", manifest.VersionEntry{
		Version:    "5.15.0",
		SourceName: "linux-headers",
		Metadata:   map[string]string{"Architecture": "arm64"},
	}); err != nil {
		t.Fatalf("add linux-headers: %v", err)
	}
	// Nothing in the pool backs this one.
	if err := store.AddVersion(ctx, manifest.TypeApt, "nginx", manifest.VersionEntry{
		Version:    "1.24.0",
		SourceName: "nginx",
		Metadata:   map[string]string{"Architecture": "amd64"},
	}); err != nil {
		t.Fatalf("add nginx: %v", err)
	}

	// A healthy install: pool objects, no dists/ tree anywhere.
	mem := storage.NewMemory()
	mem.Seed("packages/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb", strings.Repeat("x", 12345))
	mem.Seed("packages/apt/pool/main/l/linux-headers/linux-headers_5.15.0_arm64.deb", strings.Repeat("y", 678))
	rec := &recorder{ObjectStore: mem}

	statuses, err := inventory.CheckStatus(ctx, storage.NewSingle(rec), store, []string{manifest.TypeApt})
	if err != nil {
		t.Fatalf("CheckStatus: %v", err)
	}

	byName := make(map[string]inventory.EntryStatus, len(statuses))
	for _, s := range statuses {
		byName[s.Name] = s
	}
	if len(byName) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(byName), statuses)
	}

	want := []struct {
		name    string
		key     string
		present bool
		size    int64
	}{
		{"amazon-efs-utils@2.4.2", "packages/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb", true, 12345},
		{"linux-headers@5.15.0", "packages/apt/pool/main/l/linux-headers/linux-headers_5.15.0_arm64.deb", true, 678},
		{"nginx@1.24.0", "", false, 0},
	}
	for _, w := range want {
		got, ok := byName[w.name]
		if !ok {
			t.Errorf("%s: missing from status output", w.name)
			continue
		}
		if got.Present != w.present {
			t.Errorf("%s: Present = %v, want %v", w.name, got.Present, w.present)
		}
		if got.Key != w.key {
			t.Errorf("%s: Key = %q, want %q", w.name, got.Key, w.key)
		}
		if got.Size != w.size {
			t.Errorf("%s: Size = %d, want %d", w.name, got.Size, w.size)
		}
		if got.Backend != storage.DefaultName {
			t.Errorf("%s: Backend = %q, want %q", w.name, got.Backend, storage.DefaultName)
		}
	}

	for _, key := range rec.heads {
		if strings.Contains(key, "/dists/") {
			t.Errorf("probed a generated path that is never stored: %s", key)
		}
	}
}

// TestStatusProbesTheRecordedBackend is the reason this package exists. Two
// backends hold the same package name; the entry records one of them, and a
// status walk that consulted the config hierarchy instead would report the
// artifact missing the moment a placement rule pointed elsewhere.
func TestStatusProbesTheRecordedBackend(t *testing.T) {
	ctx := t.Context()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(ctx, manifest.TypeBinary, "awscli", manifest.VersionEntry{
		Version: "2.1.0",
		URL:     "https://example.com/awscli.zip",
		Storage: "bulk",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	def, bulk := storage.NewMemory(), storage.NewMemory()
	bulk.Seed("binaries/awscli/2.1.0/awscli.zip", "payload")

	statuses, err := inventory.CheckStatus(ctx, twoBackends(def, bulk), store, []string{manifest.TypeBinary})
	if err != nil {
		t.Fatalf("CheckStatus: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("got %d rows, want 1", len(statuses))
	}
	if !statuses[0].Present {
		t.Fatalf("probed %q on %q and found nothing — the recorded backend was not consulted",
			statuses[0].Key, statuses[0].Backend)
	}
	if statuses[0].Backend != "bulk" {
		t.Fatalf("Backend = %q, want bulk", statuses[0].Backend)
	}
}

// TestOneFailingBackendDoesNotHideTheOthers pins the diagnostic policy, which
// is the deliberate inverse of the package indexes': an index fails the whole
// request, a diagnostic reports every backend it could reach and marks the one
// it could not.
func TestOneFailingBackendDoesNotHideTheOthers(t *testing.T) {
	ctx := t.Context()
	store := manifest.NewLocalStore(t.TempDir())
	for _, tc := range []struct{ name, backend string }{{"good", ""}, {"bad", "bulk"}} {
		if err := store.AddVersion(ctx, manifest.TypeBinary, tc.name, manifest.VersionEntry{
			Version: "1.0",
			URL:     "https://example.com/" + tc.name + ".zip",
			Storage: tc.backend,
		}); err != nil {
			t.Fatalf("AddVersion %s: %v", tc.name, err)
		}
	}

	def := storage.NewMemory()
	def.Seed("binaries/good/1.0/good.zip", "payload")

	statuses, err := inventory.CheckStatus(ctx,
		twoBackends(def, failing{storage.NewMemory()}), store, []string{manifest.TypeBinary})
	if err != nil {
		t.Fatalf("CheckStatus returned a fatal error for one unreachable backend: %v", err)
	}
	if len(statuses) != 2 {
		t.Fatalf("got %d rows, want 2 — a failing backend swallowed the other's rows", len(statuses))
	}
	if n := inventory.Failures(statuses); n != 1 {
		t.Fatalf("Failures = %d, want 1", n)
	}
	for _, s := range statuses {
		switch s.Backend {
		case storage.DefaultName:
			if !s.Present || s.Error != "" {
				t.Errorf("default row = %+v, want present with no error", s)
			}
		case "bulk":
			if s.Error == "" {
				t.Errorf("bulk row = %+v, want the backend's error attributed to it", s)
			}
		}
	}
}

// twoBackends builds a Resolver over "default" and "bulk" without going
// through config, so a test can substitute a store that fails on demand.
func twoBackends(def, bulk storage.ObjectStore) storage.Resolver {
	return &pair{def: def, bulk: bulk}
}

type pair struct {
	def  storage.ObjectStore
	bulk storage.ObjectStore
}

func (p *pair) Default() storage.ObjectStore { return p.def }

func (p *pair) ByName(name string) (storage.ObjectStore, error) {
	switch name {
	case "", storage.DefaultName:
		return p.def, nil
	case "bulk":
		return p.bulk, nil
	}
	return nil, fmt.Errorf("unknown storage backend %q", name)
}

func (p *pair) Placement(string, string) storage.Decision {
	return storage.Decision{Name: storage.DefaultName}
}

func (p *pair) ForType(string) storage.ObjectStore { return p.def }

func (p *pair) Fanout(context.Context, string, []string) []storage.NamedStore { return p.All() }

func (p *pair) All() []storage.NamedStore {
	return []storage.NamedStore{
		{Name: storage.DefaultName, Store: p.def},
		{Name: "bulk", Store: p.bulk},
	}
}
