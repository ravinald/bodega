package placement

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// placerFixture builds a placer over a default backend plus "bulk", with
// storage_by_type.binary pointing at "archive" so the rule, the record and the
// flag are three distinguishable answers.
func placerFixture(t *testing.T, recorded string) (*Placer, *manifest.Store) {
	t.Helper()
	cfg := &config.Config{
		StorageBackend: "local",
		StoragePath:    t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{
			"bulk":    {Driver: "local", Path: t.TempDir()},
			"archive": {Driver: "local", Path: t.TempDir()},
		},
		StorageByType: map[string]string{manifest.TypeBinary: "archive"},
	}
	stores, err := storage.NewResolver(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "awscli-v2", manifest.VersionEntry{
		Version: "2.15.0",
		Storage: recorded,
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	return NewWith(stores, store, io.Discard, false), store
}

func recordedStorage(t *testing.T, store *manifest.Store) string {
	t.Helper()
	pm, err := store.GetPackage(t.Context(), manifest.TypeBinary, "awscli-v2")
	if err != nil || pm == nil {
		t.Fatalf("GetPackage: %v", err)
	}
	return EffectiveStorage(pm.Versions[0].Storage)
}

// TestPlaceVersionBeatsTheRecordedNameAndTheRule is what the flag is for: the
// one artifact an operator has to direct somewhere has neither a rule that can
// name it nor a record worth keeping.
func TestPlaceVersionBeatsTheRecordedNameAndTheRule(t *testing.T) {
	pl, store := placerFixture(t, "archive")
	pl.PlaceVersion("awscli-v2", "2.15.0", "bulk")

	st, err := pl.ForVersion(t.Context(), manifest.TypeBinary, "awscli-v2", "2.15.0", "binaries/awscli-v2/2.15.0/awscli")
	if err != nil {
		t.Fatalf("ForVersion: %v", err)
	}
	if st == nil {
		t.Fatal("ForVersion returned no store")
	}
	if got := recordedStorage(t, store); got != "bulk" {
		t.Errorf("recorded storage = %q, want bulk", got)
	}
	if !pl.PlacedVersion() {
		t.Error("PlacedVersion() = false after the pinned version was placed")
	}
}

// TestPlaceVersionRecordsSoTheNextUploadFollowsWithoutTheFlag is the half of
// requirement 1 that separates a flag from a fourth level. The name is recorded
// once; from there ForVersion's "a recorded name wins over the rule" carries
// it, with nothing still deciding.
func TestPlaceVersionRecordsSoTheNextUploadFollowsWithoutTheFlag(t *testing.T) {
	pl, store := placerFixture(t, "")
	pl.PlaceVersion("awscli-v2", "2.15.0", "bulk")
	if _, err := pl.ForVersion(t.Context(), manifest.TypeBinary, "awscli-v2", "2.15.0", "k"); err != nil {
		t.Fatalf("ForVersion: %v", err)
	}

	next := NewWith(pl.Stores(), store, io.Discard, false)
	if _, err := next.ForVersion(t.Context(), manifest.TypeBinary, "awscli-v2", "2.15.0", "k"); err != nil {
		t.Fatalf("ForVersion (second run, no flag): %v", err)
	}
	if got := recordedStorage(t, store); got != "bulk" {
		t.Errorf("recorded storage = %q after an unflagged upload, want bulk: the flag records, it does not keep deciding", got)
	}
}

// TestPlacedVersionIsFalseWhenTheVersionWasNeverReached is the guard against
// the quiet failure: a mistyped version leaves the rule in charge, the upload
// succeeds, and the operator believes an artifact is on a backend nothing ever
// wrote to.
func TestPlacedVersionIsFalseWhenTheVersionWasNeverReached(t *testing.T) {
	pl, store := placerFixture(t, "")
	pl.PlaceVersion("awscli-v2", "2.15.1", "bulk") // one digit off

	if _, err := pl.ForVersion(t.Context(), manifest.TypeBinary, "awscli-v2", "2.15.0", "k"); err != nil {
		t.Fatalf("ForVersion: %v", err)
	}
	if pl.PlacedVersion() {
		t.Error("PlacedVersion() = true for a version this run never reached")
	}
	if got := recordedStorage(t, store); got != "archive" {
		t.Errorf("recorded storage = %q, want the type rule's archive", got)
	}
}

// TestPlaceVersionMatchesARefAsWellAsAVersion mirrors VersionIndex: a git entry
// is addressed by its ref, and a pin that matched only Version would silently
// miss every one of them.
func TestPlaceVersionMatchesARefAsWellAsAVersion(t *testing.T) {
	cfg := &config.Config{
		StorageBackend:  "local",
		StoragePath:     t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local", Path: t.TempDir()}},
	}
	stores, err := storage.NewResolver(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeGit, "netbox", manifest.VersionEntry{Ref: "v4.5.5"}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	pl := NewWith(stores, store, io.Discard, false)
	pl.PlaceVersion("netbox", "v4.5.5", "bulk")

	if _, err := pl.ForVersion(t.Context(), manifest.TypeGit, "netbox", "v4.5.5", "repos/netbox/v4.5.5.bundle"); err != nil {
		t.Fatalf("ForVersion: %v", err)
	}
	if !pl.PlacedVersion() {
		t.Error("PlacedVersion() = false for an entry addressed by its ref")
	}
}

// TestOnlySkipsTheDirectoryPlacedType: one pypi package cannot be pushed apart
// from the rest of its type, and uploading every package the operator did not
// name is the wrong answer to that.
func TestOnlySkipsTheDirectoryPlacedType(t *testing.T) {
	cfg := &config.Config{
		BuildRoot:      t.TempDir(),
		StorageBackend: "local",
		StoragePath:    t.TempDir(),
	}
	stores, err := storage.NewResolver(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	out := &bytes.Buffer{}
	pl := NewWith(stores, manifest.NewLocalStore(t.TempDir()), out, false)
	pl.Only("boto3")

	n, err := pl.UploadType(t.Context(), builder.NewConfig(cfg, nil), manifest.TypePypi)
	if err != nil {
		t.Fatalf("UploadType(pypi): %v", err)
	}
	if n != 0 {
		t.Errorf("uploaded %d object(s) for a filtered pypi run, want 0", n)
	}
	if !strings.Contains(out.String(), "skipping") {
		t.Errorf("pypi was skipped silently; output was %q", out.String())
	}
}
