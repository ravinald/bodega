package placement

import (
	"context"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// resolveOnly answers Placement and fails the test on every method that
// resolves. Drift reads the config hierarchy on one side and the manifest
// record on the other, and the moment it asks a Resolver where something lives
// it has become the second resolver the layer is built to not have.
type resolveOnly struct {
	t      *testing.T
	byType map[string]string
}

func (r *resolveOnly) Placement(typ, policy string) storage.Decision {
	if policy != "" {
		return storage.Decision{Name: policy, Level: storage.LevelPackage}
	}
	if name := r.byType[typ]; name != "" {
		return storage.Decision{Name: name, Level: storage.LevelType}
	}
	return storage.Decision{Name: storage.DefaultName, Level: storage.LevelDefault}
}

func (r *resolveOnly) Default() storage.ObjectStore {
	r.t.Fatal("Drift called Default: it must not resolve where an artifact lives")
	return nil
}

func (r *resolveOnly) ByName(name string) (storage.ObjectStore, error) {
	r.t.Fatalf("Drift called ByName(%q): it must not resolve where an artifact lives", name)
	return nil, nil
}

func (r *resolveOnly) ForType(typ string) storage.ObjectStore {
	r.t.Fatalf("Drift called ForType(%q): it must not resolve where an artifact lives", typ)
	return nil
}

func (r *resolveOnly) Fanout(context.Context, string, []string) []storage.NamedStore {
	r.t.Fatal("Drift called Fanout: it must not resolve where an artifact lives")
	return nil
}

func (r *resolveOnly) All() []storage.NamedStore {
	r.t.Fatal("Drift called All: it must not resolve where an artifact lives")
	return nil
}

// driftStore seeds one version per (type, package, recorded backend) triple.
func driftStore(t *testing.T, entries ...[4]string) *manifest.Store {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	for _, e := range entries {
		typ, name, version, recorded := e[0], e[1], e[2], e[3]
		if err := store.AddVersion(t.Context(), typ, name, manifest.VersionEntry{
			Version: version,
			Storage: recorded,
		}); err != nil {
			t.Fatalf("AddVersion %s/%s: %v", typ, name, err)
		}
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	return store
}

// TestDriftResolvesNothing is requirement 4 as an assertion. A report that
// reads both sides is useful; one that reaches a backend to decide what a row
// says is a second answer to "where does this artifact live?", and the first
// rule change would make the two disagree.
func TestDriftResolvesNothing(t *testing.T) {
	store := driftStore(t,
		[4]string{manifest.TypeBinary, "awscli-v2", "2.15.0", ""},
		[4]string{manifest.TypeNpm, "left-pad", "1.3.0", "archive"},
		[4]string{manifest.TypePypi, "boto3", "1.26.0", ""},
	)
	stores := &resolveOnly{t: t, byType: map[string]string{
		manifest.TypeBinary: "bulk",
		manifest.TypePypi:   "archive",
	}}

	rows, err := Drift(t.Context(), stores, store, manifest.AllTypes)
	if err != nil {
		t.Fatalf("Drift: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("Drift found nothing; the fixture drifts on three types")
	}
}

// TestDriftReportsEveryTypeNotOnlyThePypiOne is the finding itself: ForType
// refuses a stranded upload for pypi and every other type wrote on in silence.
func TestDriftReportsEveryTypeNotOnlyThePypiOne(t *testing.T) {
	store := driftStore(t,
		[4]string{manifest.TypeBinary, "awscli-v2", "2.15.0", ""},  // drifts: type rule names bulk
		[4]string{manifest.TypeNpm, "left-pad", "1.3.0", "bulk"},   // agrees: the type rule names bulk
		[4]string{manifest.TypeGit, "netbox", "v4.5.5", "archive"}, // drifts: no rule, so default
		[4]string{manifest.TypePypi, "boto3", "1.26.0", ""},        // drifts: type rule names archive
	)
	stores := &resolveOnly{t: t, byType: map[string]string{
		manifest.TypeBinary: "bulk",
		manifest.TypeNpm:    "bulk",
		manifest.TypePypi:   "archive",
	}}

	rows, err := Drift(t.Context(), stores, store, manifest.AllTypes)
	if err != nil {
		t.Fatalf("Drift: %v", err)
	}

	got := map[string]DriftRow{}
	for _, r := range rows {
		got[r.Type] = r
	}
	for _, typ := range []string{manifest.TypeBinary, manifest.TypeGit, manifest.TypePypi} {
		if _, ok := got[typ]; !ok {
			t.Errorf("no drift row for %s; rows: %+v", typ, rows)
		}
	}
	if _, ok := got[manifest.TypeNpm]; ok {
		t.Errorf("npm/left-pad is on the backend its rule names; it must not be a row")
	}
	if r := got[manifest.TypeBinary]; r.On != storage.DefaultName || r.Rule != "bulk" {
		t.Errorf("binary row = on %q, rule %q; want default -> bulk", r.On, r.Rule)
	}
	if r := got[manifest.TypeGit]; r.On != "archive" || r.Rule != storage.DefaultName {
		t.Errorf("git row = on %q, rule %q; want archive -> default", r.On, r.Rule)
	}
}

// TestDriftReadsARecordedNothingAsTheDefaultBackend covers the case that made a
// forgotten storage_by_type invisible: every artifact uploaded before named
// backends existed records "", and "" is the default backend, not "recompute".
func TestDriftReadsARecordedNothingAsTheDefaultBackend(t *testing.T) {
	store := driftStore(t, [4]string{manifest.TypeHelm, "cilium", "1.15.0", ""})
	stores := &resolveOnly{t: t, byType: map[string]string{manifest.TypeHelm: storage.DefaultName}}

	rows, err := Drift(t.Context(), stores, store, []string{manifest.TypeHelm})
	if err != nil {
		t.Fatalf("Drift: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("an unrecorded version under a rule naming the default drifted: %+v", rows)
	}
}

func TestDriftRowRemedyNamesTheMoveWithItsArguments(t *testing.T) {
	r := DriftRow{Type: manifest.TypeNpm, Package: "@bitwarden/cli", Version: "2026.4.0", On: "default", Rule: "archive"}
	want := "bodega pkg move npm @bitwarden/cli@2026.4.0 --to archive"
	if got := r.Remedy(); got != want {
		t.Errorf("Remedy() = %q, want %q", got, want)
	}
}

// TestDriftRowRemedyForPypiDoesNotNameACommandThatRefuses: 'pkg move' refuses
// pypi outright, so printing it would hand the operator a command that exits
// non-zero and leave the row undischarged.
func TestDriftRowRemedyForPypiDoesNotNameACommandThatRefuses(t *testing.T) {
	r := DriftRow{Type: manifest.TypePypi, Package: "boto3", Version: "1.26.0", On: "default", Rule: "archive"}
	got := r.Remedy()
	if strings.Contains(got, "pkg move") {
		t.Errorf("Remedy() = %q, but 'pkg move' refuses pypi", got)
	}
	for _, want := range []string{"storage_by_type.pypi", "--replace-placement"} {
		if !strings.Contains(got, want) {
			t.Errorf("Remedy() = %q, want it to name %s", got, want)
		}
	}
}

// TestDriftRowRemedyNamesTheUnfreezeFirst: selectForMove refuses the whole
// command when any selected version is frozen.
func TestDriftRowRemedyNamesTheUnfreezeFirst(t *testing.T) {
	r := DriftRow{Type: manifest.TypeBinary, Package: "awscli-v2", Version: "2.15.0", On: "default", Rule: "bulk", Frozen: true}
	got := r.Remedy()
	if !strings.Contains(got, "bodega pkg freeze binary awscli-v2") {
		t.Errorf("Remedy() = %q, want it to name the unfreeze", got)
	}
	if !strings.Contains(got, "bodega pkg move binary awscli-v2@2.15.0 --to bulk") {
		t.Errorf("Remedy() = %q, want it to name the move too", got)
	}
}

// TestDriftCarriesTheIgnoredPolicyForADirectoryPlacedType: WritePlacement drops
// the package level for pypi, so a storage_policy on a drifted pypi package is
// a second thing wrong with it that repointing the type rule does not fix.
func TestDriftCarriesTheIgnoredPolicyForADirectoryPlacedType(t *testing.T) {
	store := driftStore(t, [4]string{manifest.TypePypi, "boto3", "1.26.0", ""})
	pm, err := store.GetPackage(t.Context(), manifest.TypePypi, "boto3")
	if err != nil || pm == nil {
		t.Fatalf("GetPackage: %v", err)
	}
	pm.StoragePolicy = "bulk"
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	stores := &resolveOnly{t: t, byType: map[string]string{manifest.TypePypi: "archive"}}
	rows, err := Drift(t.Context(), stores, store, []string{manifest.TypePypi})
	if err != nil {
		t.Fatalf("Drift: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want one", rows)
	}
	if rows[0].Rule != "archive" {
		t.Errorf("Rule = %q; the package level is not consulted for pypi, so the type rule decides", rows[0].Rule)
	}
	if rows[0].IgnoredPolicy != "bulk" {
		t.Errorf("IgnoredPolicy = %q, want the storage_policy the write path drops", rows[0].IgnoredPolicy)
	}
}

// TestDriftOverARealResolverAgreesWithWritePlacement holds the scan to the
// resolver the uploads actually run against, not only to the stub above.
func TestDriftOverARealResolverAgreesWithWritePlacement(t *testing.T) {
	cfg := &config.Config{
		StorageBackend: "local",
		StoragePath:    t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{
			"bulk": {Driver: "local", Path: t.TempDir()},
		},
		StorageByType: map[string]string{manifest.TypeBinary: "bulk"},
	}
	stores, err := storage.NewResolver(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	store := driftStore(t, [4]string{manifest.TypeBinary, "awscli-v2", "2.15.0", ""})

	rows, err := Drift(t.Context(), stores, store, []string{manifest.TypeBinary})
	if err != nil {
		t.Fatalf("Drift: %v", err)
	}
	if len(rows) != 1 || rows[0].Rule != "bulk" || rows[0].On != storage.DefaultName {
		t.Fatalf("rows = %+v, want one row default -> bulk", rows)
	}
}
