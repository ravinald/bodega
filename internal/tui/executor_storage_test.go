package tui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// twoBackendTUI builds the config and resolver an install with storage_by_type
// has, plus a build root the uploaders can find artifacts in.
func twoBackendTUI(t *testing.T, byType map[string]string) (*config.Config, storage.Resolver, *manifest.Store, string, string) {
	t.Helper()
	defaultRoot, bulkRoot, buildRoot := t.TempDir(), t.TempDir(), t.TempDir()
	cfg := &config.Config{
		BuildRoot:       buildRoot,
		ManifestDir:     "manifests",
		StorageBackend:  "local",
		StoragePath:     defaultRoot,
		StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local", Path: bulkRoot}},
		StorageByType:   byType,
	}
	stores, err := storage.NewResolver(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return cfg, stores, manifest.NewLocalStore(t.TempDir()), defaultRoot, bulkRoot
}

func seedLocal(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// TestTUIUploadReachesTheNamedBackend is the defect #85 named: the TUI wrote
// through a bare S3 client on the default bucket, so an install with
// storage_by_type uploaded to the wrong backend and said nothing about it.
//
// It asserts on the destination rather than on the log line, because the log
// line was already right while the bytes were going elsewhere.
func TestTUIUploadReachesTheNamedBackend(t *testing.T) {
	cfg, stores, store, defaultRoot, bulkRoot := twoBackendTUI(t,
		map[string]string{manifest.TypeBinary: "bulk"})
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "awscli", manifest.VersionEntry{
		Version: "2.0.0", URL: "https://example.com/awscli.zip",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	seedLocal(t, cfg.BuildRoot, "binaries/awscli/2.0.0/awscli.zip", "binary-bytes")

	var buf bytes.Buffer
	if err := runUpload(&buf, cfg, store, stores, []string{manifest.TypeBinary}); err != nil {
		t.Fatalf("runUpload: %v", err)
	}

	key := manifest.BinaryKey("awscli", "2.0.0", "awscli.zip")
	if _, err := os.Stat(filepath.Join(bulkRoot, filepath.FromSlash(key))); err != nil {
		t.Errorf("%s is not on the backend storage_by_type names: %v", key, err)
	}
	if _, err := os.Stat(filepath.Join(defaultRoot, filepath.FromSlash(key))); err == nil {
		t.Errorf("%s landed on the default backend as well", key)
	}
}

// TestTUIUploadCoversEveryType pins the four cases the old switch had no arm
// for. Each reported "No artifacts at  — skipping" against an empty localDir,
// which reads as "nothing to do" rather than as "this type is not wired up".
func TestTUIUploadCoversEveryType(t *testing.T) {
	cfg, stores, store, defaultRoot, _ := twoBackendTUI(t, nil)
	ctx := t.Context()

	seeds := []struct {
		typ, pkg, rel string
		ve            manifest.VersionEntry
		key           string
	}{
		{manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2", "gomod/github.com--aws--aws-sdk-go-v2/@v/v1.30.0.zip",
			manifest.VersionEntry{Version: "v1.30.0"}, manifest.GomodKey("github.com/aws/aws-sdk-go-v2", "v1.30.0", ".zip")},
		{manifest.TypeHelm, "ingress-nginx", "charts/ingress-nginx/4.11.0/ingress-nginx-4.11.0.tgz",
			manifest.VersionEntry{Version: "4.11.0"}, manifest.HelmChartKey("ingress-nginx", "4.11.0")},
		{manifest.TypeNpm, "@bitwarden/cli", "npm/@bitwarden--cli/2026.4.0/@bitwarden--cli-2026.4.0.tgz",
			manifest.VersionEntry{Version: "2026.4.0"}, manifest.NpmTarballKey("@bitwarden/cli", "2026.4.0")},
		{manifest.TypeCargo, "serde", "cargo/serde/1.0.200/serde-1.0.200.crate",
			manifest.VersionEntry{Version: "1.0.200"}, manifest.CargoCrateKey("serde", "1.0.200")},
	}
	for _, s := range seeds {
		if err := store.AddVersion(ctx, s.typ, s.pkg, s.ve); err != nil {
			t.Fatalf("AddVersion %s: %v", s.typ, err)
		}
		seedLocal(t, cfg.BuildRoot, s.rel, s.typ+"-bytes")
	}

	var buf bytes.Buffer
	types := make([]string, 0, len(seeds))
	for _, s := range seeds {
		types = append(types, s.typ)
	}
	if err := runUpload(&buf, cfg, store, stores, types); err != nil {
		t.Fatalf("runUpload: %v", err)
	}
	for _, s := range seeds {
		if _, err := os.Stat(filepath.Join(defaultRoot, filepath.FromSlash(s.key))); err != nil {
			t.Errorf("%s uploaded nothing for %s: %v\n%s", s.typ, s.key, err, buf.String())
		}
	}
}

// TestTUIRemoveReachesTheRecordedBackend: runRemove refused any version
// recording a named backend, which was honest and left the TUI unable to do
// the operation at all.
func TestTUIRemoveReachesTheRecordedBackend(t *testing.T) {
	_, stores, store, _, bulkRoot := twoBackendTUI(t, nil)
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "awscli", manifest.VersionEntry{
		Version: "2.0.0", URL: "https://example.com/awscli.zip", Storage: "bulk",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	key := manifest.BinaryKey("awscli", "2.0.0", "awscli.zip")
	seedLocal(t, bulkRoot, key, "binary-bytes")

	var buf bytes.Buffer
	if err := runRemove(&buf, store, stores, manifest.TypeBinary, "awscli"); err != nil {
		t.Fatalf("runRemove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bulkRoot, filepath.FromSlash(key))); err == nil {
		t.Errorf("%s survived a remove that reported success", key)
	}
	if !strings.Contains(buf.String(), key) {
		t.Errorf("the report does not name what it deleted: %q", buf.String())
	}
}

// TestTUIRemoveRefusesWhenNoKeyResolves: every Delete in bodega is idempotent,
// so a delete aimed at a key nothing wrote reports the same success as one
// that worked. pypi is the type with no per-version key, and this is the last
// place the two can be told apart.
func TestTUIRemoveRefusesWhenNoKeyResolves(t *testing.T) {
	_, stores, store, _, _ := twoBackendTUI(t, nil)
	if err := store.AddVersion(t.Context(), manifest.TypePypi, "boto3", manifest.VersionEntry{
		Version: "1.35.0",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	var buf bytes.Buffer
	err := runRemove(&buf, store, stores, manifest.TypePypi, "boto3")
	if err == nil {
		t.Fatal("runRemove reported a delete for a version with no object key")
	}
	if !strings.Contains(err.Error(), "no per-version object key") {
		t.Errorf("error %q does not say why nothing resolved", err)
	}
}
