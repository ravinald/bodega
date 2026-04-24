package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ravinald/bodega/internal/config"
)

// ensureMutable fails a mutation command early when its target dirs aren't
// writable, so the operator sees "try sudo" before investing time in an
// $EDITOR buffer. Only probes local paths; S3 perms aren't checkable here.
func ensureMutable(cfg *config.Config) error {
	var probes []string

	if cfg.LocalConfig || cfg.StorageBackend == "" || cfg.StorageBackend == "local" {
		if cfg.ManifestDir != "" {
			probes = append(probes, cfg.ManifestDir)
		}
	}
	if cfg.AuditDB != "" {
		probes = append(probes, filepath.Dir(cfg.AuditDB))
	} else if cfg.LogDir != "" {
		probes = append(probes, cfg.LogDir)
	}

	for _, p := range probes {
		if err := dirIsWritable(p); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

// Missing dir is OK; MkdirAll will create it on first real write. Don't
// refuse fresh installs in preflight.
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
