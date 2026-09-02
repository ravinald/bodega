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

	if usesLocalManifests(cfg) {
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

// ensureManifestRoot refuses to let a local-manifest server start over a root
// it cannot read, and creates one that is merely absent.
//
// The alternative was a journal warning, which the empty-index Error in serve
// already provides and which was not enough: on angus the unit reached active
// (running), /healthz answered 200, and apt clients got a syntactically valid
// Release whose Packages digest was the SHA-256 of the empty string. A
// repository server that publishes an empty index over a root that does not
// exist has told every client the packages were withdrawn. Refusing is the
// same posture bodega already takes on a missing TLS pair.
//
// Creating the absent case rather than refusing it keeps first boot working:
// on a fresh host neither storage_path nor its manifests/ exists yet, and
// systemctl enable --now has to survive that. The class that produced the
// silent empty repository is what cannot be created: /manifests under
// ProtectSystem=strict, a path owned by another user, a file where a
// directory belongs.
func ensureManifestRoot(cfg *config.Config) error {
	if !usesLocalManifests(cfg) || cfg.ManifestDir == "" {
		return nil
	}

	info, err := os.Stat(cfg.ManifestDir)
	switch {
	case err == nil && !info.IsDir():
		return fmt.Errorf("manifest_dir %s is not a directory (config: %s)", cfg.ManifestDir, config.ConfigPath())
	case err != nil && !os.IsNotExist(err):
		return fmt.Errorf("manifest_dir %s is unreadable: %w (config: %s)", cfg.ManifestDir, err, config.ConfigPath())
	case err != nil:
		if mkErr := os.MkdirAll(cfg.ManifestDir, 0o755); mkErr != nil {
			return fmt.Errorf(
				"manifest_dir %s does not exist and cannot be created: %w (config: %s)",
				cfg.ManifestDir, mkErr, config.ConfigPath(),
			)
		}
	}

	// Stat says the inode is there; only an open proves the process can list
	// it. A root owned by another user stats fine and reads back empty, which
	// is the failure this whole function exists to make loud.
	f, err := os.Open(cfg.ManifestDir)
	if err != nil {
		return fmt.Errorf("manifest_dir %s cannot be opened: %w (config: %s)", cfg.ManifestDir, err, config.ConfigPath())
	}
	_ = f.Close()
	return nil
}
