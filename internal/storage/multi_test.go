package storage

import (
	"context"
	"sort"
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
		if got := r.Placement(typ, "", nil); got.Name != DefaultName {
			t.Errorf("Placement(%q) = %q, want %q", typ, got.Name, DefaultName)
		}
	}
}

func TestPlacementFollowsStorageByType(t *testing.T) {
	r := twoBackendResolver(t, t.TempDir(), t.TempDir(), map[string]string{"apt": "bulk"})
	if got := r.Placement("apt", "", nil); got.Name != "bulk" || got.Level != LevelType {
		t.Errorf("Placement(apt) = %+v, want bulk at LevelType", got)
	}
	if got := r.Placement("pypi", "", nil); got.Name != DefaultName || got.Level != LevelDefault {
		t.Errorf("Placement(pypi) = %+v, want %q at LevelDefault", got, DefaultName)
	}
}

// TestPackagePolicyBeatsTheTypeRule is the whole reason the package level
// exists. The motivating case is a package whose bytes must live in a specific
// bucket under a specific KMS key while its type is shared with packages that
// must not; a package policy that lost to the type rule could not express it,
// and would silently move that package the day someone added a type rule.
func TestPackagePolicyBeatsTheTypeRule(t *testing.T) {
	r := twoBackendResolver(t, t.TempDir(), t.TempDir(), map[string]string{"git": "bulk"})

	// git's type rule says bulk. This one package says otherwise and must win.
	if got := r.Placement("git", DefaultName, nil); got.Name != DefaultName || got.Level != LevelPackage {
		t.Errorf("Placement(git, %q) = %+v, want %q at LevelPackage", DefaultName, got, DefaultName)
	}
	if got := r.Placement("git", "", nil); got.Name != "bulk" || got.Level != LevelType {
		t.Errorf("Placement(git, no policy) = %+v, want bulk at LevelType", got)
	}
	// A type with no rule of its own still honors the package policy.
	if got := r.Placement("npm", "bulk", nil); got.Name != "bulk" || got.Level != LevelPackage {
		t.Errorf("Placement(npm, bulk) = %+v, want bulk at LevelPackage", got)
	}
}

// TestDecisionReasonNamesTheDecidingRule: printing the winning level is what
// makes a three-level hierarchy debuggable, and the type level names the config
// key so an operator can find and change it.
func TestDecisionReasonNamesTheDecidingRule(t *testing.T) {
	for _, tc := range []struct {
		d    Decision
		want string
	}{
		{Decision{Name: "bulk", Level: LevelPackage}, "package policy"},
		{Decision{Name: "bulk", Level: LevelType}, "type rule: storage_by_type.apt"},
		{Decision{Name: DefaultName, Level: LevelDefault}, "global default; no type, group or package rule"},
	} {
		if got := tc.d.Reason("apt"); got != tc.want {
			t.Errorf("Reason() = %q, want %q", got, tc.want)
		}
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
	fan := r.Fanout(context.Background(), "apt", []string{"bulk"})
	if len(fan) != 1 {
		t.Fatalf("Fanout() = %d backends, want 1: %v", len(fan), fan)
	}
	if fan[0].Name != DefaultName {
		t.Errorf("Fanout kept %q, want the default to win the tie", fan[0].Name)
	}
}

// TestFanoutNarrowsToWhatAReadCanReach: a backend that holds nothing for this
// type must not join its fan-out. A per-backend error fails the whole index,
// so an unrelated backend being down would otherwise 502 every type.
func TestFanoutNarrowsToWhatAReadCanReach(t *testing.T) {
	r := twoBackendResolver(t, t.TempDir(), t.TempDir(), map[string]string{"apt": "bulk"})

	names := func(in []NamedStore) []string {
		out := make([]string, 0, len(in))
		for _, ns := range in {
			out = append(out, ns.Name)
		}
		sort.Strings(out)
		return out
	}

	if got := names(r.Fanout(context.Background(), "pypi", nil)); len(got) != 1 || got[0] != DefaultName {
		t.Errorf("Fanout(pypi) = %v, want only %q — bulk holds no pypi", got, DefaultName)
	}
	if got := names(r.Fanout(context.Background(), "apt", nil)); len(got) != 2 {
		t.Errorf("Fanout(apt) = %v, want both — storage_by_type sends apt to bulk", got)
	}
	// A pypi package moved to bulk puts bulk back in pypi's fan-out, which
	// config alone cannot say.
	if got := names(r.Fanout(context.Background(), "pypi", []string{"bulk"})); len(got) != 2 {
		t.Errorf("Fanout(pypi, [bulk]) = %v, want both — a moved artifact was dropped from the index", got)
	}
	// An empty recorded name is the default, not a third backend.
	if got := names(r.Fanout(context.Background(), "pypi", []string{""})); len(got) != 1 {
		t.Errorf("Fanout(pypi, [\"\"]) = %v, want only the default", got)
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

// groupResolver builds a real resolver over "default", "bulk" and "cold" with
// both maps populated, so the group level is exercised against NewResolver
// rather than a hand-written double.
func groupResolver(t *testing.T, byType, byGroup map[string]string) Resolver {
	t.Helper()
	cfg := &config.Config{
		StorageBackend: "local",
		StoragePath:    t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{
			"bulk": {Driver: "local", Path: t.TempDir()},
			"cold": {Driver: "local", Path: t.TempDir()},
		},
		StorageByType:  byType,
		StorageByGroup: byGroup,
	}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

// TestGroupSitsBetweenTypeAndPackage pins the one property the level was added
// for. A group that lost to the type rule would place nothing an operator
// could not already place, and one that beat the package policy would move the
// single package that must not move.
func TestGroupSitsBetweenTypeAndPackage(t *testing.T) {
	r := groupResolver(t,
		map[string]string{"apt": "bulk"},
		map[string]string{"mirror-set": "cold"})

	if got := r.Placement("apt", "", []string{"mirror-set"}); got.Name != "cold" || got.Level != LevelGroup {
		t.Errorf("Placement(apt, no policy, mirror-set) = %+v, want cold at LevelGroup", got)
	}
	if got := r.Placement("apt", DefaultName, []string{"mirror-set"}); got.Name != DefaultName || got.Level != LevelPackage {
		t.Errorf("Placement(apt, policy, mirror-set) = %+v, want %q at LevelPackage", got, DefaultName)
	}
	if got := r.Placement("apt", "", []string{"unmapped"}); got.Name != "bulk" || got.Level != LevelType {
		t.Errorf("Placement(apt, group with no rule) = %+v, want bulk at LevelType", got)
	}
	if got := r.Placement("npm", "", []string{"unmapped"}); got.Name != DefaultName || got.Level != LevelDefault {
		t.Errorf("Placement(npm, group with no rule) = %+v, want %q at LevelDefault", got, DefaultName)
	}
}

// TestTwoGroupsResolveByNameNotByOrder is the answer to "what does a package in
// two groups get". Both orderings are driven because manifest order is exactly
// what the rule must not depend on: a rewrite that reorders the list would
// otherwise move the next upload's bytes.
func TestTwoGroupsResolveByNameNotByOrder(t *testing.T) {
	r := groupResolver(t, nil, map[string]string{"alpha": "bulk", "omega": "cold"})

	for _, groups := range [][]string{{"alpha", "omega"}, {"omega", "alpha"}} {
		got := r.Placement("apt", "", groups)
		if got.Name != "bulk" || got.Group != "alpha" {
			t.Errorf("Placement(apt, %v) = %+v, want bulk decided by alpha", groups, got)
		}
	}

	// The caller's slice is its manifest's field; sorting it in place would
	// rewrite the manifest on the next save.
	groups := []string{"omega", "alpha"}
	r.Placement("apt", "", groups)
	if groups[0] != "omega" {
		t.Errorf("groups = %v after Placement, want the caller's order untouched", groups)
	}
}

// TestGroupReasonNamesBothEdits keeps the level debuggable: a reason saying
// only "group rule" leaves the operator hunting for which of the two files to
// change.
func TestGroupReasonNamesBothEdits(t *testing.T) {
	r := groupResolver(t, nil, map[string]string{"mirror-set": "cold"})
	got := r.Placement("apt", "", []string{"mirror-set"}).Reason("apt")
	for _, want := range []string{"storage_by_group.mirror-set", "storage_groups"} {
		if !strings.Contains(got, want) {
			t.Errorf("Reason() = %q, want it to name %q", got, want)
		}
	}
}

// TestStorageByGroupAloneStillBuildsMulti guards the reporting path: with only
// the default backend every group resolves to it, so the answer is the same
// either way and a single resolver would report LevelDefault for a package the
// operator did place by group.
func TestStorageByGroupAloneStillBuildsMulti(t *testing.T) {
	cfg := &config.Config{
		StorageBackend: "local",
		StoragePath:    t.TempDir(),
		StorageByGroup: map[string]string{"mirror-set": DefaultName},
	}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if got := r.Placement("apt", "", []string{"mirror-set"}); got.Level != LevelGroup || got.Name != DefaultName {
		t.Errorf("Placement(apt, mirror-set) = %+v, want %q at LevelGroup", got, DefaultName)
	}
}
