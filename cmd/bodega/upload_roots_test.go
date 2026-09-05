package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// aptPoolRel is the path a built .deb occupies relative to the apt-repo
// directory, which is the form _pool_path and the published Filename take.
const aptPoolRel = "pool/main/n/nginx/nginx_1.24.0_amd64.deb"

// syncFixture points the process at a config that sets apt_root away from
// build_root, seeds one apt entry, and writes its .deb under the per-type root
// and nowhere else. It returns the storage path the upload has to reach.
func syncFixture(t *testing.T) string {
	t.Helper()
	aptRoot, buildRoot := t.TempDir(), t.TempDir()
	storagePath, manifestDir := t.TempDir(), t.TempDir()

	body, err := json.Marshal(map[string]string{
		"build_root":      buildRoot,
		"apt_root":        aptRoot,
		"storage_backend": "local",
		"storage_path":    storagePath,
		"manifest_dir":    manifestDir,
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, body, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// The file is the whole input: an inherited env var for any of these would
	// decide the test's outcome instead of the config under test.
	t.Setenv(config.EnvConfigFile, cfgPath)
	t.Setenv(config.EnvBuildRoot, "")
	t.Setenv(config.EnvManifestDir, "")
	t.Setenv(config.EnvBucket, "")

	deb := filepath.Join(aptRoot, "apt-repo", filepath.FromSlash(aptPoolRel))
	if err := os.MkdirAll(filepath.Dir(deb), 0o755); err != nil {
		t.Fatalf("mkdir pool: %v", err)
	}
	if err := os.WriteFile(deb, []byte("!<arch>\nbuilt under apt_root"), 0o644); err != nil {
		t.Fatalf("write .deb: %v", err)
	}

	store := manifest.NewLocalStore(manifestDir)
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "nginx", manifest.VersionEntry{
		Version:    "1.24.0",
		SourceName: "nginx",
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   aptPoolRel,
		},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	// The command loads its own store off disk, and ListPackages answers from
	// the index rather than a directory walk.
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	return storagePath
}

// TestSyncUploadsFromThePerTypeRoot pins the direction the roots travel. sync
// built its builder.Config without them, so an install setting apt_root walked
// build_root, found an empty tree and exited 0 reporting nothing to do — the
// artifact it was asked to push sitting untouched one directory over.
func TestSyncUploadsFromThePerTypeRoot(t *testing.T) {
	storagePath := syncFixture(t)

	cmd := newSyncCmd(&globalFlags{})
	cmd.SetArgs([]string{manifest.TypeApt})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("bodega build sync apt: %v", err)
	}

	landed := filepath.Join(storagePath, filepath.FromSlash(manifest.AptKey(aptPoolRel)))
	if _, err := os.Stat(landed); err != nil {
		t.Fatalf("sync uploaded nothing from apt_root: %v", err)
	}
}

// TestUploadNamesTheDirectoryItWalked covers the report, not the walk. A skip
// line that named no path is why the dropped roots survived: an empty build
// and a build under a root this command never read printed the same sentence.
func TestUploadNamesTheDirectoryItWalked(t *testing.T) {
	aptRoot := t.TempDir()
	cfg := &config.Config{
		BuildRoot:      t.TempDir(),
		AptRoot:        aptRoot,
		StorageBackend: "local",
		StoragePath:    t.TempDir(),
	}
	out := &bytes.Buffer{}
	pl, err := newPlacer(t.Context(), cfg, manifest.NewLocalStore(t.TempDir()), out, false)
	if err != nil {
		t.Fatalf("newPlacer: %v", err)
	}

	if _, err := pl.UploadType(t.Context(), builder.NewConfig(cfg), manifest.TypeApt); err != nil {
		t.Fatalf("UploadType(apt): %v", err)
	}
	want := filepath.Join(aptRoot, "apt-repo")
	if !strings.Contains(out.String(), want) {
		t.Errorf("skip line = %q, want it to name %s", out.String(), want)
	}
}

// TestEveryTypeHasAnUploadCascade is the guard ensureUploadable had none of.
// It declares a nil *builder.Summary, assigns it in a switch over
// manifest.AllTypes and calls HasFailures unconditionally, so a ninth type
// joining that list without an arm panics `bodega build upload` rather than
// skipping the type.
func TestEveryTypeHasAnUploadCascade(t *testing.T) {
	cfg := &config.Config{BuildRoot: t.TempDir(), ManifestDir: t.TempDir()}
	bcfg := builder.NewConfig(cfg)
	bcfg.Stdout = io.Discard
	store := manifest.NewLocalStore(cfg.ManifestDir)

	for _, typ := range manifest.AllTypes {
		if err := ensureUploadable(typ, bcfg, store); err != nil {
			t.Errorf("ensureUploadable(%q) on an empty store = %v, want nil", typ, err)
		}
	}
	if err := ensureUploadable("conda", bcfg, store); err == nil {
		t.Error("ensureUploadable on a type the switch does not cover returned nil, want an error naming it")
	}
}
