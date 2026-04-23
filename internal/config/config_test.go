package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/config"
)

// isolateConfig points loadFileConfig at a path in t.TempDir() that does not
// exist, so a host-level /etc/bodega/config.json cannot leak into the test.
func isolateConfig(t *testing.T) {
	t.Helper()
	t.Setenv(config.EnvConfigFile, filepath.Join(t.TempDir(), "no-such-config.json"))
	t.Setenv(config.EnvBucket, "")
	t.Setenv(config.EnvRegion, "")
	t.Setenv(config.EnvBuildRoot, "")
}

func TestLoad_Defaults(t *testing.T) {
	isolateConfig(t)

	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Region != config.DefaultRegion {
		t.Errorf("Region = %q, want %q", cfg.Region, config.DefaultRegion)
	}
	if cfg.BuildRoot != config.DefaultBuildRoot {
		t.Errorf("BuildRoot = %q, want %q", cfg.BuildRoot, config.DefaultBuildRoot)
	}
	if cfg.Bucket != "" {
		t.Errorf("Bucket = %q, want empty", cfg.Bucket)
	}
}

func TestLoad_FlagOverridesEnv(t *testing.T) {
	isolateConfig(t)
	t.Setenv(config.EnvBucket, "env-bucket")

	cfg, err := config.Load(t.TempDir(), "flag-bucket", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Bucket != "flag-bucket" {
		t.Errorf("Bucket = %q, want flag-bucket (flag should override env)", cfg.Bucket)
	}
}

func TestLoad_EnvOverridesDefault(t *testing.T) {
	isolateConfig(t)
	t.Setenv(config.EnvRegion, "eu-west-1")

	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Region != "eu-west-1" {
		t.Errorf("Region = %q, want eu-west-1", cfg.Region)
	}
}

// TestLoad_ConfigFileOverride verifies that BODEGA_CONFIG_FILE points the
// loader at a specific file, bypassing /etc/bodega/config.json.
func TestLoad_ConfigFileOverride(t *testing.T) {
	t.Setenv(config.EnvBucket, "")
	t.Setenv(config.EnvRegion, "")
	t.Setenv(config.EnvBuildRoot, "")

	path := filepath.Join(t.TempDir(), "bodega.json")
	body := []byte(`{"bucket": "override-bucket", "region": "ap-southeast-2"}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write override config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)

	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Bucket != "override-bucket" {
		t.Errorf("Bucket = %q, want override-bucket (from %s)", cfg.Bucket, path)
	}
	if cfg.Region != "ap-southeast-2" {
		t.Errorf("Region = %q, want ap-southeast-2", cfg.Region)
	}
}
