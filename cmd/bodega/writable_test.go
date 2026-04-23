package main

import (
	"os"
	"path/filepath"
	"runtime"
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
