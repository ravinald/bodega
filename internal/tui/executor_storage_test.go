package tui

import (
	"bytes"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

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
	if err := runRemove(&buf, nil, store, stores, manifest.TypeBinary, "awscli"); err != nil {
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
	err := runRemove(&buf, nil, store, stores, manifest.TypePypi, "boto3")
	if err == nil {
		t.Fatal("runRemove reported a delete for a version with no object key")
	}
	if !strings.Contains(err.Error(), "no per-version object key") {
		t.Errorf("error %q does not say why nothing resolved", err)
	}
}

// TestTUIMutationsSignalTheServer is #52 by its second route. The CLI
// classifies each verb where it is registered and one cobra hook signals;
// nothing in the TUI passes through cobra, so a freeze or a delete here left
// the withdrawn entry published while the TUI reported success. The hourly
// tick swept it up within an hour, which is what made it survivable and hard
// to see.
//
// Driven through the run helpers rather than the tea.Cmd wrappers: they are
// the level a future non-cobra caller lands on, and the level the signal now
// lives at.
func TestTUIMutationsSignalTheServer(t *testing.T) {
	cfg, stores, store, _, bulkRoot := twoBackendTUI(t, nil)
	cfg.LogDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg.LogDir, "bodega.pid"),
		[]byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "awscli", manifest.VersionEntry{
		Version: "2.0.0", URL: "https://example.com/awscli.zip", Storage: "bulk",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	seedLocal(t, bulkRoot, manifest.BinaryKey("awscli", "2.0.0", "awscli.zip"), "binary-bytes")

	sighup := make(chan os.Signal, 8)
	signal.Notify(sighup, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(sighup) })

	// Order matters: remove takes the object, freeze flips the flag and flips
	// it back (delete refuses a frozen entry), delete takes what is left.
	verbs := []struct {
		name string
		run  func(*bytes.Buffer) error
	}{
		{"remove", func(b *bytes.Buffer) error {
			return runRemove(b, cfg, store, stores, manifest.TypeBinary, "awscli")
		}},
		{"freeze", func(b *bytes.Buffer) error {
			return runFreeze(b, cfg, store, manifest.TypeBinary, "awscli", nil)
		}},
		{"unfreeze", func(b *bytes.Buffer) error {
			return runFreeze(b, cfg, store, manifest.TypeBinary, "awscli", nil)
		}},
		{"delete", func(b *bytes.Buffer) error {
			return runDelete(b, cfg, store, manifest.TypeBinary, "awscli", nil)
		}},
	}
	for _, v := range verbs {
		var buf bytes.Buffer
		if err := v.run(&buf); err != nil {
			t.Fatalf("%s: %v\n%s", v.name, err, buf.String())
		}
		select {
		case <-sighup:
		case <-time.After(5 * time.Second):
			t.Errorf("%s reported success and sent no reload signal; the entry stays published until the hourly tick", v.name)
		}
	}
}
