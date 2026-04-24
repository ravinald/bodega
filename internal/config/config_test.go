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
	t.Setenv(config.EnvListenAddr, "")
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

// TestResolveListenAddr walks the full precedence chain: flag > env >
// config-file > built-in default.
func TestResolveListenAddr(t *testing.T) {
	isolateConfig(t)

	// 1. Built-in default when nothing is set.
	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.ResolveListenAddr(""); got != config.DefaultListenAddr {
		t.Errorf("no overrides: got %q, want %q", got, config.DefaultListenAddr)
	}

	// 2. Config file wins over default.
	cfgFile := filepath.Join(t.TempDir(), "bodega.json")
	if err := os.WriteFile(cfgFile, []byte(`{"listen_addr": ":9090"}`), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	t.Setenv(config.EnvConfigFile, cfgFile)
	cfg, err = config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.ResolveListenAddr(""); got != ":9090" {
		t.Errorf("config-file only: got %q, want :9090", got)
	}

	// 3. Env var wins over config file.
	t.Setenv(config.EnvListenAddr, ":9091")
	if got := cfg.ResolveListenAddr(""); got != ":9091" {
		t.Errorf("env over config: got %q, want :9091", got)
	}

	// 4. Flag wins over env.
	if got := cfg.ResolveListenAddr("127.0.0.1:9092"); got != "127.0.0.1:9092" {
		t.Errorf("flag over env: got %q, want 127.0.0.1:9092", got)
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
