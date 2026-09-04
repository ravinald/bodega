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
	// apt_suites is normalized by Load — apt_codename first, then the rest, no
	// duplicates — so it has to be filled in the shape Load would produce.
	// storage_backends keys and storage_by_type values are validated against
	// each other, so a generated value would fail Load: the name has to exist
	// and the driver has to be non-empty.
	overrides := map[string]any{
		"discover_mode": "observe",
		// Load validates this one, so the reflective "value-<tag>" filler
		// cannot reach it. 1.2 rather than the 1.3 default, so the round trip
		// would still catch a Save that dropped the key and let the default
		// stand in for a persisted value.
		"tls_min_version": "1.2",
		// audit_sink and audit_sink_dsn are cross-validated: sqlite refuses a
		// dsn, postgres and jsonl require one. jsonl with an absolute path is
		// a real combination and is not the default, so a Save that dropped
		// either key still fails here.
		"audit_sink":     "jsonl",
		"audit_sink_dsn": "/var/log/bodega/audit.jsonl",
		"apt_suites":     []string{"value-apt_codename", "apt_suites-one"},
		"storage_backends": map[string]config.StorageSpec{
			"bulk": {Driver: "local", Path: "/mnt/bulk", Prefix: "cold/"},
		},
		"storage_by_type": map[string]string{"apt": "bulk"},
		// git_upstreams and binary_upstreams keys and values are both
		// validated, and an empty mode is defaulted by Load, so the round trip
		// only measures Save when the filled value is already the shape Load
		// would produce.
		"git_upstreams": map[string]config.GitUpstream{
			"corp": {URL: "https://git.corp.example/", Mode: config.UpstreamModeOpen},
		},
		"binary_upstreams": map[string]config.BinaryUpstream{
			"hashicorp": {URL: "https://releases.hashicorp.com/", Mode: config.UpstreamModeOpen},
		},
		// The codename is deliberately not one the slice filler produces for
		// apt_suites: Load refuses a codename in both, so a collision here
		// would fail the round trip for the right reason and the wrong test.
		// The URL carries no trailing slash because Load trims one.
		"apt_upstreams": map[string][]config.AptUpstream{
			"mirrored-noble": {{URL: "https://archive.ubuntu.com/ubuntu"}},
		},
	}

	v := reflect.ValueOf(cfg).Elem()
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "-" || f.PkgPath != "" {
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
		case reflect.Map:
			t.Fatalf("fillConfig: map field %s has no override — a map's values are usually cross-validated, so give it an explicit one", f.Name)
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

	if _, err := want.Save(); err != nil {
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
		if typ.Field(i).PkgPath != "" {
			continue
		}
		if !reflect.DeepEqual(wv.Field(i).Interface(), gv.Field(i).Interface()) {
			t.Errorf("%s (json %q): saved %#v, loaded %#v",
				typ.Field(i).Name, typ.Field(i).Tag.Get("json"),
				wv.Field(i).Interface(), gv.Field(i).Interface())
		}
	}
}

// TestSave_OmitsRuntimeAndResolvedValues pins what a save writes on a host
// with no config file yet: the shipped default as its baseline, runtime-only
// fields kept out by json:"-", and no key rewritten to the value Load resolved
// for it. audit_db is the one to watch — the file says "", Load turns that
// into {log_dir}/audit.db, and writing the resolved path back would pin one
// host to a default a later release could no longer change.
func TestSave_OmitsRuntimeAndResolvedValues(t *testing.T) {
	isolateConfig(t)
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv(config.EnvConfigFile, path)

	cfg, err := config.Load("", "", "", "", true, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.Save(); err != nil {
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
	for k, want := range map[string]string{
		"audit_db":     `""`,
		"manifest_dir": `""`,
		"apt_codename": `"noble"`,
		"metadata_ttl": `"1h"`,
	} {
		if got := string(keys[k]); got != want {
			t.Errorf("saved config %q = %s, want %s — Save wrote a resolved value as though the operator had set it", k, got, want)
		}
	}
	for _, k := range []string{"bucket", "region", "build_root", "log_dir", "logwindow_height", "custom_paths", "proxy_cache_enabled"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("saved config is missing non-omitempty key %q", k)
		}
	}
	if _, ok := keys["_comment_allow_plaintext"]; !ok {
		t.Error("saved config dropped the shipped comment blocks")
	}
}

// discover_mode "learn" was accepted through the previous release, so an
// operator meets this error on a config file they did not touch. The message
// has to say where the capability went, not that a value is invalid: the test
// pins both halves of the redirection, and that "observe" still loads.
func TestDiscoverModeLearnIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		wants      []string
	}{
		{name: "observe still loads", mode: "observe"},
		{name: "learn names its replacement", mode: "learn", wants: []string{"observe", "bodega pkg convert"}},
		{name: "typo still fails", mode: "obsrve", wants: []string{`invalid discover_mode "obsrve"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfig(t)
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(`{"discover_mode": "`+tc.mode+`"}`), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			t.Setenv(config.EnvConfigFile, path)

			cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
			if len(tc.wants) == 0 {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				if cfg.DiscoverMode != tc.mode {
					t.Errorf("DiscoverMode = %q, want %q", cfg.DiscoverMode, tc.mode)
				}
				return
			}
			if err == nil {
				t.Fatalf("Load accepted discover_mode %q", tc.mode)
			}
			for _, want := range tc.wants {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Load error = %v, want mention of %q", err, want)
				}
			}
		})
	}
}

// TestLoad_TLSPair covers the half-configured pair. Load refuses it rather
// than handing the server a Config whose only distinguishable state is "no
// TLS", which is the same state as an operator who wanted none.
func TestLoad_TLSPair(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		err  string
	}{
		{name: "neither", body: `{}`},
		{name: "both", body: `{"tls_cert": "/c.pem", "tls_key": "/k.pem"}`},
		{name: "cert alone", body: `{"tls_cert": "/c.pem"}`, err: "tls_key is empty"},
		{name: "key alone", body: `{"tls_key": "/k.pem"}`, err: "tls_cert is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfig(t)
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			t.Setenv(config.EnvConfigFile, path)

			_, err := config.Load(t.TempDir(), "", "", "", false, false)
			if tc.err == "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Load accepted half a certificate pair, want error mentioning %q", tc.err)
			}
			for _, want := range []string{tc.err, "allow_plaintext"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Load error = %v, want mention of %q", err, want)
				}
			}
		})
	}
}

func TestLoad_AptSuites(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
		err  string
	}{
		{name: "default", body: `{}`, want: []string{"noble"}},
		{
			name: "codename is prepended when apt_suites omits it",
			body: `{"apt_codename": "noble", "apt_suites": ["jammy"]}`,
			want: []string{"noble", "jammy"},
		},
		{
			name: "codename listed twice is served once",
			body: `{"apt_codename": "jammy", "apt_suites": ["jammy", "noble"]}`,
			want: []string{"jammy", "noble"},
		},
		{
			name: "slash in a suite name is rejected",
			body: `{"apt_suites": ["stable/updates"]}`,
			err:  "stable/updates",
		},
		{
			name: "slash in the default suite is rejected",
			body: `{"apt_codename": "a/b"}`,
			err:  "a/b",
		},
		{
			name: "empty suite name is rejected",
			body: `{"apt_suites": [""]}`,
			err:  "empty name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfig(t)
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			t.Setenv(config.EnvConfigFile, path)

			cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
			if tc.err != "" {
				if err == nil {
					t.Fatalf("Load succeeded, want error mentioning %q", tc.err)
				}
				if !strings.Contains(err.Error(), tc.err) {
					t.Errorf("Load error = %v, want mention of %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !reflect.DeepEqual(cfg.AptSuites, tc.want) {
				t.Errorf("AptSuites = %v, want %v", cfg.AptSuites, tc.want)
			}
			if !cfg.ServesAptSuite(cfg.AptCodename) {
				t.Errorf("ServesAptSuite(%q) = false — the default suite must always be served", cfg.AptCodename)
			}
			if cfg.ServesAptSuite("not-a-suite") {
				t.Error("ServesAptSuite(\"not-a-suite\") = true")
			}
		})
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
	if _, err := cfg.Save(); err != nil {
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

// audit_sink is refused at load rather than at the first write. Half of these
// cases are not the enum: a postgres with no DSN, a relative jsonl path and a
// sqlite carrying a DSN each produce a running server whose audit trail goes
// somewhere the operator did not intend, which is the failure the sink design
// exists to prevent.
func TestAuditSinkValidation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wants      []string
		wantSink   string
	}{
		{
			name:     "unset defaults to sqlite",
			body:     `{}`,
			wantSink: "sqlite",
		},
		{
			name:     "sqlite loads",
			body:     `{"audit_sink": "sqlite"}`,
			wantSink: "sqlite",
		},
		{
			name:     "syslog with no dsn is the local daemon",
			body:     `{"audit_sink": "syslog"}`,
			wantSink: "syslog",
		},
		{
			name:     "jsonl with an absolute path loads",
			body:     `{"audit_sink": "jsonl", "audit_sink_dsn": "/var/log/bodega/audit.jsonl"}`,
			wantSink: "jsonl",
		},
		{
			name:  "unknown sink names the four",
			body:  `{"audit_sink": "mysql"}`,
			wants: []string{`invalid audit_sink "mysql"`, "sqlite, postgres, syslog, jsonl"},
		},
		{
			name:  "postgres needs a dsn",
			body:  `{"audit_sink": "postgres"}`,
			wants: []string{"needs audit_sink_dsn", "postgres://"},
		},
		{
			name:  "jsonl needs a dsn",
			body:  `{"audit_sink": "jsonl"}`,
			wants: []string{"needs audit_sink_dsn", ".jsonl"},
		},
		{
			name:  "a relative jsonl path is refused",
			body:  `{"audit_sink": "jsonl", "audit_sink_dsn": "audit.jsonl"}`,
			wants: []string{"must be absolute", "working directory"},
		},
		{
			name:  "sqlite refuses a dsn rather than ignoring it",
			body:  `{"audit_sink": "sqlite", "audit_sink_dsn": "/tmp/x.jsonl"}`,
			wants: []string{"takes no audit_sink_dsn", "audit_db"},
		},
		{
			name:  "an unknown syslog network is refused",
			body:  `{"audit_sink": "syslog", "audit_sink_dsn": "smtp://logs.internal:514"}`,
			wants: []string{"unknown network", "tcp, udp, unix"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfig(t)
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			t.Setenv(config.EnvConfigFile, path)

			cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
			if len(tc.wants) == 0 {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				if cfg.AuditSink != tc.wantSink {
					t.Errorf("AuditSink = %q, want %q", cfg.AuditSink, tc.wantSink)
				}
				return
			}
			if err == nil {
				t.Fatalf("Load accepted %s", tc.body)
			}
			for _, want := range tc.wants {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Load error = %v, want mention of %q", err, want)
				}
			}
		})
	}
}
