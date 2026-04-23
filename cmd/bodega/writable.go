package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ravinald/bodega/internal/config"
)

// ensureMutable fails early when the current process can't write to the
// directories a mutation command will touch. Without this check, commands
// like `bodega pkg edit` launch $EDITOR, let the user craft a change, and
// only then discover that /var/lib/bodega/manifests/ is owned by root. The
// buffer is preserved on failure anyway, but it's a worse UX than failing
// up front with a "try: sudo bodega ..." hint.
//
// Probe targets:
//   - Manifest directory, when the store is local (--local-config or default).
//     S3-backed manifests go through a different path and we can't easily
//     preflight S3 perms.
//   - Audit DB parent directory — audit.Open degrades gracefully on a
//     read-only DB, but the directory still needs to be reachable.
//
// Returns nil when we're confident the save path will succeed, or a
// human-readable error otherwise.
func ensureMutable(cfg *config.Config) error {
	var probes []string

	// Local manifest storage. An explicit empty string and the default
	// ("local") both point at the local filesystem backend.
	if cfg.LocalConfig || cfg.StorageBackend == "" || cfg.StorageBackend == "local" {
		if cfg.ManifestDir != "" {
			probes = append(probes, cfg.ManifestDir)
		}
	}

	// Audit DB directory is always local regardless of manifest backend.
	if cfg.AuditDB != "" {
		probes = append(probes, filepath.Dir(cfg.AuditDB))
	} else if cfg.LogDir != "" {
		probes = append(probes, cfg.LogDir)
	}

	for _, p := range probes {
		if err := dirIsWritable(p); err != nil {
			return fmt.Errorf("%s: %w (try running with sudo)", p, err)
		}
	}
	return nil
}

// dirIsWritable probes a directory with a best-effort temp-file creation. A
// missing directory is treated as writable — MkdirAll will create it on
// first real write, and we don't want preflight to refuse a fresh install.
func dirIsWritable(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory")
	}
	f, err := os.CreateTemp(dir, ".bodega-writetest-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}
