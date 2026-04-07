package config_test

import (
	"os"
	"testing"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/config"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear env vars that might be set in the environment.
	if err := os.Unsetenv(config.EnvBucket); err != nil {
		t.Fatalf("unsetenv %s: %v", config.EnvBucket, err)
	}
	if err := os.Unsetenv(config.EnvRegion); err != nil {
		t.Fatalf("unsetenv %s: %v", config.EnvRegion, err)
	}
	if err := os.Unsetenv(config.EnvBuildRoot); err != nil {
		t.Fatalf("unsetenv %s: %v", config.EnvBuildRoot, err)
	}

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
	if err := os.Setenv(config.EnvBucket, "env-bucket"); err != nil {
		t.Fatalf("setenv %s: %v", config.EnvBucket, err)
	}
	defer func() {
		if err := os.Unsetenv(config.EnvBucket); err != nil {
			t.Errorf("unsetenv %s: %v", config.EnvBucket, err)
		}
	}()

	cfg, err := config.Load(t.TempDir(), "flag-bucket", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Bucket != "flag-bucket" {
		t.Errorf("Bucket = %q, want flag-bucket (flag should override env)", cfg.Bucket)
	}
}

func TestLoad_EnvOverridesDefault(t *testing.T) {
	if err := os.Setenv(config.EnvRegion, "eu-west-1"); err != nil {
		t.Fatalf("setenv %s: %v", config.EnvRegion, err)
	}
	defer func() {
		if err := os.Unsetenv(config.EnvRegion); err != nil {
			t.Errorf("unsetenv %s: %v", config.EnvRegion, err)
		}
	}()

	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Region != "eu-west-1" {
		t.Errorf("Region = %q, want eu-west-1", cfg.Region)
	}
}
