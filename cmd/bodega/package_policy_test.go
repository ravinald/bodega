package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// TestPackageRefusesBlockedCrate covers the second command that reached a
// fetcher with no allow-list. `bodega build package cargo` cascades into
// ensureFetchedCargo, so a rule that refuses a crate under `bodega build
// fetch` did not refuse it here: builder.NewConfig left Policy to the caller
// and this one wired only AuditDB.
//
// The crate is absent from the build root and no upstream is configured, so a
// fetch that got as far as the network would fail differently than a refusal.
func TestPackageRefusesBlockedCrate(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	manifestDir := filepath.Join(dir, "manifests")

	body, err := json.Marshal(map[string]string{
		"build_root":      filepath.Join(dir, "build"),
		"manifest_dir":    manifestDir,
		"log_dir":         dir,
		"audit_db":        dbPath,
		"storage_backend": "local",
		"storage_path":    filepath.Join(dir, "storage"),
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, body, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, cfgPath)
	t.Setenv(config.EnvBuildRoot, "")
	t.Setenv(config.EnvManifestDir, "")
	t.Setenv(config.EnvBucket, "")

	db, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	if err := db.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID:           "cargo-anyhow",
		RegistryType: manifest.TypeCargo,
		RuleKind:     policy.KindPackage,
		Pattern:      "anyhow",
	}); err != nil {
		t.Fatalf("InsertPolicy: %v", err)
	}
	// The command opens the same file, so this handle closes before it runs.
	if err := db.Close(); err != nil {
		t.Fatalf("close audit db: %v", err)
	}

	store := manifest.NewLocalStore(manifestDir)
	if err := store.AddVersion(t.Context(), manifest.TypeCargo, "serde", manifest.VersionEntry{
		Version: "1.0.210",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	out := captureStdout(t, func() {
		cmd := newPackageCmd(&globalFlags{})
		cmd.SetArgs([]string{manifest.TypeCargo})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil {
			t.Errorf("bodega build package cargo packaged a blocked crate")
		}
	})
	if !strings.Contains(out, "BLOCKED by policy") {
		t.Errorf("command output = %q, want the refusal in it", out)
	}

	db, err = audit.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen audit db: %v", err)
	}
	defer db.Close()
	events, err := db.Query(t.Context(), audit.Filter{
		EventType: audit.EventFetch,
		PkgType:   manifest.TypeCargo,
		PkgName:   "serde",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("a refused package run wrote %d audit rows, want 1\n%s", len(events), out)
	}
	if events[0].Status != "policy_violation" {
		t.Errorf("audit row status = %q, want policy_violation", events[0].Status)
	}
}
