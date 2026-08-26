package storage

import (
	"context"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
)

// TestDriverRegistryIsWiredIntoConfig proves the hook config.Load reads is
// actually installed. Without it the reserved-name check is vacuous and a
// backend called "s3" loads clean.
func TestDriverRegistryIsWiredIntoConfig(t *testing.T) {
	got := config.StorageDrivers()
	want := map[string]bool{"local": true, "s3": true}
	for _, name := range got {
		delete(want, name)
	}
	if len(want) != 0 {
		t.Errorf("config.StorageDrivers() = %v, missing %v", got, want)
	}
}

// TestNewResolverWithoutNamedBackendsIsSingle pins the back-compat shape: a
// config with none of the new keys produces exactly the resolver it produced
// before they existed.
func TestNewResolverWithoutNamedBackendsIsSingle(t *testing.T) {
	cfg := &config.Config{StorageBackend: "local", StoragePath: t.TempDir()}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if all := r.All(); len(all) != 1 || all[0].Name != DefaultName {
		t.Fatalf("All() = %v, want one backend named %q", all, DefaultName)
	}
	for _, typ := range []string{"apt", "pypi", "binary", "git"} {
		if got := r.Placement(typ, "anything"); got != DefaultName {
			t.Errorf("Placement(%q) = %q, want %q", typ, got, DefaultName)
		}
	}
}

func TestPlacementFollowsStorageByType(t *testing.T) {
	r := twoBackendResolver(t, t.TempDir(), t.TempDir(), map[string]string{"apt": "bulk"})
	if got := r.Placement("apt", "nginx"); got != "bulk" {
		t.Errorf("Placement(apt) = %q, want bulk", got)
	}
	if got := r.Placement("pypi", "boto3"); got != DefaultName {
		t.Errorf("Placement(pypi) = %q, want %q", got, DefaultName)
	}
}

// TestByNameRejectsUnknownRatherThanFallingBack pins that resolution has no
// fallback. Serving from another backend would publish bytes under a digest
// recorded against the one named.
func TestByNameRejectsUnknownRatherThanFallingBack(t *testing.T) {
	r := twoBackendResolver(t, t.TempDir(), t.TempDir(), nil)
	if _, err := r.ByName("ghost"); err == nil {
		t.Fatal("ByName(ghost) succeeded, want an error")
	} else if !strings.Contains(err.Error(), "default, bulk") {
		t.Errorf("error = %q, want it to list the configured backends", err)
	}
	if _, err := r.ByName(""); err != nil {
		t.Errorf(`ByName("") = %v, want the default backend`, err)
	}
}

// TestFanoutDedupsBackendsAtOneLocation covers the staged-migration config:
// two names for one directory. Listing it twice doubles every fan-out and
// hands the union a duplicate of every key.
func TestFanoutDedupsBackendsAtOneLocation(t *testing.T) {
	shared := t.TempDir()
	r := twoBackendResolver(t, shared, shared, nil)

	if all := r.All(); len(all) != 2 {
		t.Fatalf("All() = %d backends, want 2 — dedup belongs to Fanout, not All", len(all))
	}
	fan := r.Fanout(context.Background(), "apt")
	if len(fan) != 1 {
		t.Fatalf("Fanout() = %d backends, want 1: %v", len(fan), fan)
	}
	if fan[0].Name != DefaultName {
		t.Errorf("Fanout kept %q, want the default to win the tie", fan[0].Name)
	}
}

func TestPrefixScopesKeysAndStripsThemBack(t *testing.T) {
	root := t.TempDir()
	store, err := NewFromSpec(context.Background(), Spec{Driver: "local", Path: root, Prefix: "cold/"})
	if err != nil {
		t.Fatalf("NewFromSpec: %v", err)
	}
	ctx := context.Background()
	if err := store.Put(ctx, "packages/apt/pool/x.deb", []byte("bytes")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	keys, err := store.List(ctx, "packages/apt/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != "packages/apt/pool/x.deb" {
		t.Fatalf("List = %v, want the prefix stripped back off", keys)
	}

	// The prefix has to be real on disk, or it is decoration.
	unprefixed := NewLocal(root)
	if got, err := unprefixed.Get(ctx, "cold/packages/apt/pool/x.deb"); err != nil || string(got) != "bytes" {
		t.Fatalf("underlying key = %q (err %v), want the object under cold/", got, err)
	}
}

// twoBackendResolver builds a real resolver over "default" and "bulk", both
// local, so tests exercise NewResolver rather than a hand-written double.
func twoBackendResolver(t *testing.T, defaultPath, bulkPath string, byType map[string]string) Resolver {
	t.Helper()
	cfg := &config.Config{
		StorageBackend: "local",
		StoragePath:    defaultPath,
		StorageBackends: map[string]config.StorageSpec{
			"bulk": {Driver: "local", Path: bulkPath},
		},
		StorageByType: byType,
	}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}
