package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

// fillConfig sets every settable (JSON-visible) field on cfg to a distinct
// non-zero value. It fails the test on a field whose kind it does not know how
// to fill, so adding a field to Config without teaching this helper is a test
// failure rather than a silently uncovered key.
func fillConfig(t *testing.T, cfg *config.Config) {
	t.Helper()

	// discover_mode is validated by Load, so it cannot take a generated value.
	overrides := map[string]any{"discover_mode": "observe"}

	v := reflect.ValueOf(cfg).Elem()
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "-" {
			continue
		}
		if over, ok := overrides[tag]; ok {
			v.Field(i).Set(reflect.ValueOf(over))
			continue
		}
		switch f.Type.Kind() {
		case reflect.String:
			v.Field(i).SetString("value-" + tag)
		case reflect.Int:
			v.Field(i).SetInt(int64(i + 1))
		case reflect.Bool:
			v.Field(i).SetBool(true)
		case reflect.Slice:
			if f.Type.Elem().Kind() != reflect.String {
				t.Fatalf("fillConfig: unhandled slice element type %s for field %s — extend fillConfig", f.Type.Elem(), f.Name)
			}
			v.Field(i).Set(reflect.ValueOf([]string{tag + "-one", tag + "-two"}))
		default:
			t.Fatalf("fillConfig: unhandled kind %s for field %s — extend fillConfig", f.Type.Kind(), f.Name)
		}
	}
}

// TestSaveLoadRoundTrip is the guard against Config.Save() dropping keys. It
// walks Config by reflection rather than naming fields, so a key added to the
// struct and forgotten in the persistence path fails here instead of vanishing
// from an operator's config file on the next TUI edit.
func TestSaveLoadRoundTrip(t *testing.T) {
	isolateConfig(t)
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv(config.EnvConfigFile, path)

	var want config.Config
	fillConfig(t, &want)
	// json:"-" fields come from Load's arguments, never from the file.
	want.LocalConfig = true
	want.Verbose = true

	if err := want.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.LocalConfig || got.Verbose {
		t.Errorf("LocalConfig=%v Verbose=%v after Load(false,false) — json:\"-\" fields leaked through the file", got.LocalConfig, got.Verbose)
	}
	want.LocalConfig = false
	want.Verbose = false

	wv, gv := reflect.ValueOf(want), reflect.ValueOf(*got)
	typ := wv.Type()
	for i := 0; i < typ.NumField(); i++ {
		if !reflect.DeepEqual(wv.Field(i).Interface(), gv.Field(i).Interface()) {
			t.Errorf("%s (json %q): saved %#v, loaded %#v",
				typ.Field(i).Name, typ.Field(i).Tag.Get("json"),
				wv.Field(i).Interface(), gv.Field(i).Interface())
		}
	}
}

// TestSave_OmitsRuntimeAndUnsetFields pins the two properties Save relies on
// now that Config is itself the on-disk shape: json:"-" keeps runtime-only
// fields out of the file, and omitempty keeps unset optional keys out.
func TestSave_OmitsRuntimeAndUnsetFields(t *testing.T) {
	isolateConfig(t)
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv(config.EnvConfigFile, path)

	cfg, err := config.Load("", "", "", "", true, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("unmarshal saved config: %v", err)
	}

	for _, k := range []string{"LocalConfig", "Verbose", "local_config", "verbose", "-"} {
		if _, ok := keys[k]; ok {
			t.Errorf("saved config contains runtime-only key %q", k)
		}
	}
	for _, k := range []string{"apt_root", "git_root", "tls_cert", "tls_domain", "timezone", "audit_events"} {
		if _, ok := keys[k]; ok {
			t.Errorf("saved config contains %q, which is unset and omitempty", k)
		}
	}
	for _, k := range []string{"bucket", "region", "build_root", "log_dir", "logwindow_height", "custom_paths", "proxy_cache_enabled"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("saved config is missing non-omitempty key %q", k)
		}
	}
}

// TestLoad_TimezoneAndAuditEvents covers the keys openAuditDB reads: they were
// absent from the on-disk struct, so the audit DB's timezone and event filter
// silently did nothing.
func TestLoad_TimezoneAndAuditEvents(t *testing.T) {
	isolateConfig(t)
	path := filepath.Join(t.TempDir(), "config.json")
	body := []byte(`{"timezone": "America/Los_Angeles", "audit_events": ["fetch", "mutate"]}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)

	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Timezone != "America/Los_Angeles" {
		t.Errorf("Timezone = %q, want America/Los_Angeles", cfg.Timezone)
	}
	if !reflect.DeepEqual(cfg.AuditEvents, []string{"fetch", "mutate"}) {
		t.Errorf("AuditEvents = %#v, want [fetch mutate]", cfg.AuditEvents)
	}
}

// TestLoad_LegacyShellHeight pins the alias that outlived fileConfig:
// shell_height is still read when logwindow_height is absent, and is never
// written back.
func TestLoad_LegacyShellHeight(t *testing.T) {
	isolateConfig(t)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"shell_height": 27}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)

	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LogWindowHeight != 27 {
		t.Errorf("LogWindowHeight = %d, want 27 (from legacy shell_height)", cfg.LogWindowHeight)
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("unmarshal saved config: %v", err)
	}
	if _, ok := keys["shell_height"]; ok {
		t.Error("saved config wrote shell_height; the legacy alias is read-only")
	}
	if got := string(keys["logwindow_height"]); got != "27" {
		t.Errorf("logwindow_height = %s, want 27 (legacy value promoted on save)", got)
	}
}
