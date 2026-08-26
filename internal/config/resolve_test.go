package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fileState is one cell of the config-path matrix: whether a candidate file
// exists on the host and whether this process can read it.
type fileState int

const (
	absent        fileState = iota
	pointsNowhere           // the path is named but nothing is there
	readable
	unreadable
)

// place writes (or does not write) a config file in the requested state and
// returns its path.
func place(t *testing.T, path string, state fileState, body string) {
	t.Helper()
	if state == absent || state == pointsNowhere {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if state == unreadable {
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatalf("chmod %s: %v", path, err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	}
}

// TestConfigPathMatrix is the regression this item exists for. Load, Save,
// ConfigPath and EnsureConfigFile each used to walk the candidate list under a
// different predicate — first that reads, first that can be written, first
// that stats, and one that consulted the list and then ignored it. On a host
// with a root-owned /etc/bodega/config.json a non-root operator got all four
// answers at once and the setting they edited never took effect.
//
// Every row asserts one file, named by all four.
func TestConfigPathMatrix(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file, so the unreadable rows cannot be set up")
	}

	cases := []struct {
		name     string
		override fileState // absent means $BODEGA_CONFIG_FILE unset
		system   fileState
		user     fileState
		asRoot   bool
		want     string // "override", "system" or "user"
	}{
		{name: "override wins over both", override: readable, system: readable, user: readable, want: "override"},
		{name: "override wins when it does not exist yet", override: pointsNowhere, system: readable, user: readable, want: "override"},
		{name: "override with nothing else present", override: pointsNowhere, system: absent, user: absent, want: "override"},
		{name: "system readable beats user", system: readable, user: readable, want: "system"},
		{name: "system readable, no user", system: readable, user: absent, want: "system"},
		{name: "system absent falls to user", system: absent, user: readable, want: "user"},
		{name: "system unreadable still wins: it exists", system: unreadable, user: readable, want: "system"},
		{name: "system unreadable, no user", system: unreadable, user: absent, want: "system"},
		{name: "neither present, non-root picks user", system: absent, user: absent, want: "user"},
		{name: "neither present, root picks system", system: absent, user: absent, asRoot: true, want: "system"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			sysPath := filepath.Join(root, "etc", "bodega", "config.json")
			usrPath := filepath.Join(root, "home", ".config", "bodega", "config.json")
			ovrPath := filepath.Join(root, "scratch", "config.json")

			swap(t, &systemConfigFile, sysPath)
			swapFn(t, &userConfigFile, func() string { return usrPath })
			swapFn(t, &runningAsRoot, func() bool { return tc.asRoot })

			place(t, sysPath, tc.system, `{"bucket":"from-system"}`)
			place(t, usrPath, tc.user, `{"bucket":"from-user"}`)
			place(t, ovrPath, tc.override, `{"bucket":"from-override"}`)
			t.Setenv(EnvConfigFile, "")
			if tc.override != absent {
				t.Setenv(EnvConfigFile, ovrPath)
			}
			t.Setenv(EnvBucket, "")
			t.Setenv(EnvRegion, "")
			t.Setenv(EnvBuildRoot, "")
			t.Setenv(EnvManifestDir, "")

			want := map[string]string{"override": ovrPath, "system": sysPath, "user": usrPath}[tc.want]
			state := map[string]fileState{"override": tc.override, "system": tc.system, "user": tc.user}[tc.want]

			if got := ConfigPath(); got != want {
				t.Fatalf("ConfigPath() = %s, want %s", got, want)
			}

			// Load names the same file: by reading it, or by an error that
			// says which file it could not read.
			cfg, err := Load("", "", "", "", false, false)
			switch state {
			case readable:
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				if want := "from-" + tc.want; cfg.Bucket != want {
					t.Errorf("Load read bucket %q, want %q", cfg.Bucket, want)
				}
			case unreadable:
				if err == nil {
					t.Fatal("Load returned no error on an unreadable config; built-in defaults bind plaintext and deny nothing")
				}
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Load error does not name %s: %v", want, err)
				}
			default:
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				if cfg.Bucket != "" {
					t.Errorf("Load read bucket %q from a file that is not in force", cfg.Bucket)
				}
			}

			if got, err := EnsureConfigFile(); err != nil {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("EnsureConfigFile error does not name %s: %v", want, err)
				}
			} else if got != want {
				t.Errorf("EnsureConfigFile() = %s, want %s", got, want)
			}

			got, err := (&Config{Bucket: "written"}).Save()
			if err != nil {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Save error does not name %s: %v", want, err)
				}
			} else if got != want {
				t.Errorf("Save() = %s, want %s", got, want)
			}
		})
	}
}

// TestEnsureConfigFileHonorsOverride pins requirement 2 on its own: the
// generated default lands at $BODEGA_CONFIG_FILE, not in the location the
// override was set to avoid.
func TestEnsureConfigFileHonorsOverride(t *testing.T) {
	root := t.TempDir()
	sysPath := filepath.Join(root, "etc", "config.json")
	usrPath := filepath.Join(root, "home", "config.json")
	ovrPath := filepath.Join(root, "scratch", "nested", "config.json")

	swap(t, &systemConfigFile, sysPath)
	swapFn(t, &userConfigFile, func() string { return usrPath })
	t.Setenv(EnvConfigFile, ovrPath)

	got, err := EnsureConfigFile()
	if err != nil {
		t.Fatalf("EnsureConfigFile: %v", err)
	}
	if got != ovrPath {
		t.Fatalf("EnsureConfigFile() = %s, want %s", got, ovrPath)
	}
	for _, p := range []string{sysPath, usrPath} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("wrote %s despite the override", p)
		}
	}
}

// TestLoadRejectsUnparsableConfig covers requirement 4. The mistyped
// audit_events is the shape item 4 made reachable: a single-value list written
// as a bare string.
func TestLoadRejectsUnparsableConfig(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"typed key", `{"audit_events":"upload"}`, []string{"audit_events", "[]string"}},
		{"typed key, deny_list", `{"deny_list":"10.0.0.0/8"}`, []string{"deny_list", "[]string"}},
		{"syntax error", `{"bucket": "b",}`, []string{"byte offset"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			t.Setenv(EnvConfigFile, path)

			_, err := Load("", "", "", "", false, false)
			if err == nil {
				t.Fatal("Load returned no error; the process would fall back to built-in defaults")
			}
			for _, want := range append(tc.want, path) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// TestPrecedenceMatrix walks flag x env x config key for the two settings that
// disagreed: --build-root was registered with an empty default and worked,
// --manifest-dir was registered with a non-empty one and never reached its
// config key.
func TestPrecedenceMatrix(t *testing.T) {
	settings := []struct {
		name    string
		jsonKey string
		env     string
		load    func(flag string) (*Config, error)
		get     func(*Config) string
		builtin func(storagePath string) string
	}{
		{
			name:    "manifest_dir",
			jsonKey: "manifest_dir",
			env:     EnvManifestDir,
			load:    func(flag string) (*Config, error) { return Load(flag, "", "", "", false, false) },
			get:     func(c *Config) string { return c.ManifestDir },
			builtin: defaultManifestDir,
		},
		{
			name:    "build_root",
			jsonKey: "build_root",
			env:     EnvBuildRoot,
			load:    func(flag string) (*Config, error) { return Load("", "", "", flag, false, false) },
			get:     func(c *Config) string { return c.BuildRoot },
			builtin: func(string) string { return DefaultBuildRoot },
		},
	}

	for _, s := range settings {
		t.Run(s.name, func(t *testing.T) {
			for _, flag := range []bool{true, false} {
				for _, key := range []bool{true, false} {
					for _, env := range []bool{true, false} {
						name := label("flag", flag) + "-" + label("key", key) + "-" + label("env", env)
						t.Run(name, func(t *testing.T) {
							storagePath := t.TempDir()
							body := `{"storage_path":` + quote(storagePath)
							if key {
								body += `,` + quote(s.jsonKey) + `:"/from-key"`
							}
							body += `}`

							path := filepath.Join(t.TempDir(), "config.json")
							if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
								t.Fatalf("write: %v", err)
							}
							t.Setenv(EnvConfigFile, path)
							t.Setenv(s.env, "")
							if env {
								t.Setenv(s.env, "/from-env")
							}
							flagVal := ""
							if flag {
								flagVal = "/from-flag"
							}

							want := s.builtin(storagePath)
							switch {
							case flag:
								want = "/from-flag"
							case env:
								want = "/from-env"
							case key:
								want = "/from-key"
							}

							cfg, err := s.load(flagVal)
							if err != nil {
								t.Fatalf("Load: %v", err)
							}
							if got := s.get(cfg); got != want {
								t.Errorf("%s = %q, want %q", s.jsonKey, got, want)
							}
						})
					}
				}
			}
		})
	}
}

// TestDefaultManifestDirIsAbsolute pins requirement 7. A relative "manifests"
// under a unit with no WorkingDirectory= resolved to /manifests, which
// ProtectSystem=strict makes unreadable, and the server published an empty
// repository over it without a word in the journal.
func TestDefaultManifestDirIsAbsolute(t *testing.T) {
	for _, storagePath := range []string{"", "/srv/bodega"} {
		got := defaultManifestDir(storagePath)
		if !filepath.IsAbs(got) {
			t.Errorf("defaultManifestDir(%q) = %q, want an absolute path", storagePath, got)
		}
	}
	if got, want := defaultManifestDir("/srv/bodega"), "/srv/bodega/manifests"; got != want {
		t.Errorf("defaultManifestDir(/srv/bodega) = %q, want %q", got, want)
	}
}

func swap(t *testing.T, target *string, val string) {
	t.Helper()
	prev := *target
	*target = val
	t.Cleanup(func() { *target = prev })
}

func swapFn[T any](t *testing.T, target *T, val T) {
	t.Helper()
	prev := *target
	*target = val
	t.Cleanup(func() { *target = prev })
}

func label(prefix string, set bool) string {
	if set {
		return prefix
	}
	return "no" + prefix
}

func quote(s string) string { return `"` + s + `"` }
