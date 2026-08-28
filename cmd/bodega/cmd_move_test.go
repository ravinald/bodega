package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

const awscliKey = "binaries/awscli/2.1.0/awscli.zip"

// undeletable is a Memory store whose Delete always fails, standing in for a
// backend that lost write permission or went read-only mid-migration.
type undeletable struct {
	storage.ObjectStore
}

func (undeletable) Delete(context.Context, string) error {
	return errors.New("access denied")
}

// blackhole accepts every write and holds nothing, which is what a
// silently-failing destination looks like from the caller's side.
type blackhole struct {
	storage.ObjectStore
}

func (blackhole) PutFile(context.Context, string, string) error { return nil }

// testResolver is a Resolver over exactly two named backends.
type testResolver struct {
	def  storage.ObjectStore
	bulk storage.ObjectStore
}

func (r *testResolver) Default() storage.ObjectStore { return r.def }

func (r *testResolver) ByName(name string) (storage.ObjectStore, error) {
	switch name {
	case "", storage.DefaultName:
		return r.def, nil
	case "bulk":
		return r.bulk, nil
	}
	return nil, fmt.Errorf("unknown storage backend %q", name)
}

func (r *testResolver) Placement(string, string) storage.Decision {
	return storage.Decision{Name: storage.DefaultName}
}

func (r *testResolver) ForType(string) storage.ObjectStore { return r.def }

func (r *testResolver) Fanout(context.Context, string, []string) []storage.NamedStore {
	return r.All()
}

func (r *testResolver) All() []storage.NamedStore {
	return []storage.NamedStore{
		{Name: storage.DefaultName, Store: r.def},
		{Name: "bulk", Store: r.bulk},
	}
}

// moveFixture seeds one binary entry on the default backend and returns a
// mover pointed at "bulk".
func moveFixture(t *testing.T, src, dst storage.ObjectStore, del bool) (*mover, *manifest.Store, *manifest.PackageManifest, *bytes.Buffer) {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "awscli", manifest.VersionEntry{
		Version: "2.1.0",
		URL:     "https://example.com/awscli.zip",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	pm, err := store.GetPackage(t.Context(), manifest.TypeBinary, "awscli")
	if err != nil || pm == nil {
		t.Fatalf("GetPackage: %v", err)
	}
	out := &bytes.Buffer{}
	return &mover{
		stores:  &testResolver{def: src, bulk: dst},
		dst:     dst,
		dstName: "bulk",
		store:   store,
		spool:   t.TempDir(),
		out:     out,
		del:     del,
	}, store, pm, out
}

func recordedBackend(t *testing.T, store *manifest.Store) string {
	t.Helper()
	pm, err := store.GetPackage(t.Context(), manifest.TypeBinary, "awscli")
	if err != nil || pm == nil {
		t.Fatalf("GetPackage: %v", err)
	}
	return effectiveStorage(pm.Versions[0].Storage)
}

// TestMoveSurvivesAFailingDelete is the ordering guarantee, and the reason
// --delete-source runs last and never fails the command.
//
// Local.Get and the S3 client both answer a missing object with (nil, nil), so
// a caller cannot tell "lost during the move" from "never uploaded". The
// manifest is therefore written before anything touches the source, and a
// delete that fails afterwards costs disk space rather than the artifact.
func TestMoveSurvivesAFailingDelete(t *testing.T) {
	src := storage.NewMemory()
	src.Seed(awscliKey, "payload")
	dst := storage.NewMemory()

	m, store, pm, out := moveFixture(t, undeletable{src}, dst, true)
	if err := m.moveVersion(t.Context(), pm, 0); err != nil {
		t.Fatalf("moveVersion returned an error for a delete failure: %v", err)
	}

	if got := recordedBackend(t, store); got != "bulk" {
		t.Fatalf("manifest records %q, want bulk — a failed delete rolled the move back", got)
	}
	if info, _ := dst.Head(t.Context(), awscliKey); info == nil || !info.Exists {
		t.Fatal("destination has no copy")
	}
	if info, _ := src.Head(t.Context(), awscliKey); info == nil || !info.Exists {
		t.Fatal("source copy vanished despite Delete failing")
	}
	if !strings.Contains(out.String(), "could not delete") {
		t.Errorf("delete failure was not reported to the operator:\n%s", out)
	}
}

// TestMoveLeavesTheSourceWithoutTheFlag pins the default. Deletion is opt-in.
func TestMoveLeavesTheSourceWithoutTheFlag(t *testing.T) {
	src := storage.NewMemory()
	src.Seed(awscliKey, "payload")
	dst := storage.NewMemory()

	m, store, pm, _ := moveFixture(t, src, dst, false)
	if err := m.moveVersion(t.Context(), pm, 0); err != nil {
		t.Fatalf("moveVersion: %v", err)
	}
	if got := recordedBackend(t, store); got != "bulk" {
		t.Fatalf("manifest records %q, want bulk", got)
	}
	if info, _ := src.Head(t.Context(), awscliKey); info == nil || !info.Exists {
		t.Fatal("source deleted without --delete-source")
	}
}

// TestMoveRefusesToRecordAnUnverifiedCopy is the other half of the ordering
// guarantee: a destination that reports a successful write but holds nothing
// must not be recorded, or every read of that version 404s afterwards.
func TestMoveRefusesToRecordAnUnverifiedCopy(t *testing.T) {
	src := storage.NewMemory()
	src.Seed(awscliKey, "payload")

	m, store, pm, _ := moveFixture(t, src, blackhole{storage.NewMemory()}, true)
	err := m.moveVersion(t.Context(), pm, 0)
	if err == nil {
		t.Fatal("move succeeded against a destination holding nothing")
	}
	if !strings.Contains(err.Error(), "not there after the write reported success") {
		t.Fatalf("error %q does not say the verification failed", err)
	}
	if got := recordedBackend(t, store); got != storage.DefaultName {
		t.Fatalf("manifest records %q after a failed verify, want %q", got, storage.DefaultName)
	}
	if info, _ := src.Head(t.Context(), awscliKey); info == nil || !info.Exists {
		t.Fatal("source was deleted despite the move failing")
	}
}

// TestMoveVerifiesTheRecordedChecksum: a copy that lands with different bytes
// is caught at the destination, not assumed correct because the write returned
// nil.
func TestMoveVerifiesTheRecordedChecksum(t *testing.T) {
	src := storage.NewMemory()
	src.Seed(awscliKey, "payload")
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "awscli", manifest.VersionEntry{
		Version:  "2.1.0",
		URL:      "https://example.com/awscli.zip",
		Checksum: &manifest.Checksum{Algorithm: "sha256", Value: strings.Repeat("0", 64)},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	pm, _ := store.GetPackage(t.Context(), manifest.TypeBinary, "awscli")

	dst := storage.NewMemory()
	m := &mover{
		stores: &testResolver{def: src, bulk: dst}, dst: dst, dstName: "bulk",
		store: store, spool: t.TempDir(), out: &bytes.Buffer{},
	}
	err := m.moveVersion(t.Context(), pm, 0)
	if err == nil || !strings.Contains(err.Error(), "sha256 is") {
		t.Fatalf("move accepted a copy whose digest does not match the manifest: %v", err)
	}
	if got := recordedBackend(t, store); got != storage.DefaultName {
		t.Fatalf("manifest records %q after a checksum failure, want %q", got, storage.DefaultName)
	}
}

func TestSelectForMoveGuards(t *testing.T) {
	base := func(ves ...manifest.VersionEntry) *manifest.PackageManifest {
		return &manifest.PackageManifest{Type: manifest.TypeBinary, Name: "awscli", Versions: ves}
	}
	for _, tc := range []struct {
		name    string
		pm      *manifest.PackageManifest
		version string
		want    string
	}{
		{
			name: "frozen refuses outright, mirroring delete",
			pm:   base(manifest.VersionEntry{Version: "2.1.0", Frozen: true}),
			want: "frozen",
		},
		{
			name: "a version already on the destination is not a move",
			pm:   base(manifest.VersionEntry{Version: "2.1.0", Storage: "bulk"}),
			want: "already recorded",
		},
		{
			name: "pypi has no per-version object to move",
			pm:   &manifest.PackageManifest{Type: manifest.TypePypi, Name: "requests"},
			want: "no per-version object key",
		},
		{
			name: "git uploads a whole directory, so one package cannot leave it",
			pm:   &manifest.PackageManifest{Type: manifest.TypeGit, Name: "netbox", Versions: []manifest.VersionEntry{{Ref: "v4.5.5"}}},
			want: "git is not movable",
		},
		{
			name: "apt uploads a whole directory too",
			pm:   &manifest.PackageManifest{Type: manifest.TypeApt, Name: "nginx", Versions: []manifest.VersionEntry{{Version: "1.24.0"}}},
			want: "apt is not movable",
		},
		{
			name:    "an unknown version names the ones that exist",
			pm:      base(manifest.VersionEntry{Version: "2.1.0"}),
			version: "9.9.9",
			want:    "not found",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &testResolver{def: storage.NewMemory(), bulk: storage.NewMemory()}
			dst, err := r.ByName("bulk")
			if err != nil {
				t.Fatalf("ByName: %v", err)
			}
			_, err = selectForMove(r, dst, tc.pm, tc.version, "bulk")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("selectForMove = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// TestSelectForMoveSkipsWhatIsAlreadyThere: an interrupted move must be
// re-runnable, so a version already on the destination is skipped rather than
// failing the versions that still need to travel.
func TestSelectForMoveSkipsWhatIsAlreadyThere(t *testing.T) {
	pm := &manifest.PackageManifest{
		Type: manifest.TypeBinary, Name: "awscli",
		Versions: []manifest.VersionEntry{
			{Version: "2.0.0", Storage: "bulk"},
			{Version: "2.1.0"},
		},
	}
	r := &testResolver{def: storage.NewMemory(), bulk: storage.NewMemory()}
	dst, err := r.ByName("bulk")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	got, err := selectForMove(r, dst, pm, "", "bulk")
	if err != nil {
		t.Fatalf("selectForMove: %v", err)
	}
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("selected %v, want only index 1", got)
	}
}

func TestSplitVersionArg(t *testing.T) {
	for _, tc := range []struct{ in, name, version string }{
		{"awscli", "awscli", ""},
		{"awscli@2.1.0", "awscli", "2.1.0"},
		{"@bitwarden/cli", "@bitwarden/cli", ""},
		{"@bitwarden/cli@2026.4.0", "@bitwarden/cli", "2026.4.0"},
	} {
		name, version := splitVersionArg(tc.in)
		if name != tc.name || version != tc.version {
			t.Errorf("splitVersionArg(%q) = (%q, %q), want (%q, %q)", tc.in, name, version, tc.name, tc.version)
		}
	}
}

// TestSelectForMoveRefusesOneLocationUnderTwoNames is the artifact-destroying
// case, and the reason the check sits in selectForMove rather than in
// moveVersion.
//
// Two names for one bucket is documented as a normal way to stage a migration,
// and config.Load rejects a colliding name but not a colliding path. Copying
// then reads and writes one object: the verify re-reads what it overwrote and
// passes, the manifest is repointed at a backend it was already on, and
// --delete-source removes the only copy. Exit 0, three lines of success, no
// artifact.
func TestSelectForMoveRefusesOneLocationUnderTwoNames(t *testing.T) {
	one := storage.NewMemory()
	one.Seed(awscliKey, "the only copy")
	r := &testResolver{def: one, bulk: one}
	dst, err := r.ByName("bulk")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	pm := &manifest.PackageManifest{
		Type: manifest.TypeBinary, Name: "awscli",
		Versions: []manifest.VersionEntry{{Version: "2.1.0"}},
	}

	_, err = selectForMove(r, dst, pm, "", "bulk")
	if err == nil {
		t.Fatal("selectForMove accepted a move whose source and destination are one location")
	}
	if !strings.Contains(err.Error(), "same location") {
		t.Fatalf("error %q does not name the collision", err)
	}
	// The refusal is the whole command, not only --delete-source: a move that
	// copied every object onto itself and reported success would teach the
	// operator that the placement changed.
	if !strings.Contains(err.Error(), "--delete-source") {
		t.Errorf("error %q does not say what --delete-source would have cost", err)
	}
}

// TestSelectForMoveReportsAnUnresolvableSource pins that a recorded backend no
// config defines fails at selection, beside the other preconditions, rather
// than after the first version has already travelled.
func TestSelectForMoveReportsAnUnresolvableSource(t *testing.T) {
	r := &testResolver{def: storage.NewMemory(), bulk: storage.NewMemory()}
	dst, err := r.ByName("bulk")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	pm := &manifest.PackageManifest{
		Type: manifest.TypeBinary, Name: "awscli",
		Versions: []manifest.VersionEntry{{Version: "2.1.0", Storage: "ghost"}},
	}
	if _, err := selectForMove(r, dst, pm, "", "bulk"); err == nil ||
		!strings.Contains(err.Error(), "unknown storage backend") {
		t.Fatalf("selectForMove = %v, want an unknown-backend error", err)
	}
}
