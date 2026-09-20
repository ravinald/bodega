package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
)

func TestEnsureMutable_Writable(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		ManifestDir:    dir,
		AuditDB:        filepath.Join(dir, "audit.db"),
		StorageBackend: "local",
	}
	if err := ensureMutable(cfg); err != nil {
		t.Errorf("fresh tempdir should be writable, got %v", err)
	}
}

func TestEnsureMutable_ReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod semantics differ on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses unix file perms; probe would succeed")
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	cfg := &config.Config{
		ManifestDir:    dir,
		StorageBackend: "local",
	}
	err := ensureMutable(cfg)
	if err == nil {
		t.Fatal("expected error on 0555 manifest dir, got nil")
	}
}

func TestEnsureMutable_MissingDirIsOK(t *testing.T) {
	// First run / fresh install: ManifestDir may not exist yet. MkdirAll
	// will create it on real write; preflight should not block.
	cfg := &config.Config{
		ManifestDir:    filepath.Join(t.TempDir(), "does-not-exist"),
		StorageBackend: "local",
	}
	if err := ensureMutable(cfg); err != nil {
		t.Errorf("missing dir should pass preflight, got %v", err)
	}
}

// TestEnsureManifestRoot walks the cases that separate a legal empty
// repository from the one that shipped an empty Release over a root nothing
// could read.
func TestEnsureManifestRoot(t *testing.T) {
	t.Run("existing dir passes", func(t *testing.T) {
		cfg := &config.Config{ManifestDir: t.TempDir(), StorageBackend: "local"}
		if err := ensureManifestRoot(cfg); err != nil {
			t.Errorf("existing dir: %v", err)
		}
	})

	t.Run("absent dir is created", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "manifests")
		cfg := &config.Config{ManifestDir: dir, StorageBackend: "local"}
		if err := ensureManifestRoot(cfg); err != nil {
			t.Fatalf("fresh install should not be refused: %v", err)
		}
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			t.Fatalf("stat %s = %v, %v; want a directory", dir, fi, err)
		}
	})

	t.Run("uncreatable dir refuses", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("chmod semantics differ on Windows")
		}
		if os.Geteuid() == 0 {
			t.Skip("root bypasses unix file perms; MkdirAll would succeed")
		}
		parent := t.TempDir()
		if err := os.Chmod(parent, 0o555); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

		cfg := &config.Config{ManifestDir: filepath.Join(parent, "manifests"), StorageBackend: "local"}
		err := ensureManifestRoot(cfg)
		if err == nil {
			t.Fatal("expected a refusal on a manifest root that cannot be created")
		}
		if !strings.Contains(err.Error(), "manifest_dir") {
			t.Errorf("error %q does not name manifest_dir", err)
		}
	})

	t.Run("unlistable dir refuses", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("chmod semantics differ on Windows")
		}
		if os.Geteuid() == 0 {
			t.Skip("root bypasses unix file perms; the open would succeed")
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		cfg := &config.Config{ManifestDir: dir, StorageBackend: "local"}
		if err := ensureManifestRoot(cfg); err == nil {
			t.Fatal("expected a refusal on a manifest root that cannot be opened")
		}
	})

	t.Run("file where a directory belongs refuses", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "manifests")
		if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		cfg := &config.Config{ManifestDir: path, StorageBackend: "local"}
		err := ensureManifestRoot(cfg)
		if err == nil {
			t.Fatal("expected a refusal on a manifest root that is a file")
		}
		if !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("error %q does not say what is wrong", err)
		}
	})

	t.Run("s3 manifests are not probed", func(t *testing.T) {
		cfg := &config.Config{ManifestDir: "/nonexistent/manifests", StorageBackend: "s3"}
		if err := ensureManifestRoot(cfg); err != nil {
			t.Errorf("an s3 store has no local root to check: %v", err)
		}
	})
}
