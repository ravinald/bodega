package config_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
)

// loadedFrom writes body to a scratch config file, puts it in force, and
// returns the path. Every test here drives config.Load and (*Config).Save
// against a real file: the defects they cover live in the seam between the two
// and are invisible to a test that marshals a Config directly.
func loadedFrom(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}
	t.Setenv(config.EnvConfigFile, path)
	t.Setenv(config.EnvBucket, "")
	t.Setenv(config.EnvRegion, "")
	t.Setenv(config.EnvBuildRoot, "")
	t.Setenv(config.EnvManifestDir, "")
	t.Setenv(config.EnvListenAddr, "")
	return path
}

func savedKeys(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("unmarshal saved config: %v", err)
	}
	return keys
}

// TestManifestDirPrecedence walks the whole chain rather than the one cell
// that was broken. manifest_dir in the file was unreachable for as long as
// --manifest-dir was registered with a non-empty default, and the file value
// is the rung nothing else can substitute for: a flag and an env var are set
// per invocation, so a server started by systemd has only the file.
func TestManifestDirPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, flag, env, want string
	}{
		{name: "file alone", want: "/srv/from-file"},
		{name: "env beats file", env: "/srv/from-env", want: "/srv/from-env"},
		{name: "flag beats env", flag: "/srv/from-flag", env: "/srv/from-env", want: "/srv/from-flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loadedFrom(t, `{"manifest_dir": "/srv/from-file"}`)
			t.Setenv(config.EnvManifestDir, tc.env)

			cfg, err := config.Load(tc.flag, "", "", "", false, false)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.ManifestDir != tc.want {
				t.Errorf("ManifestDir = %q, want %q", cfg.ManifestDir, tc.want)
			}
		})
	}
}

// TestSaveKeepsGeneratedComments pins the guidance bodega ships in the
// generated config against a TUI save. The comment F2 was required to write —
// that "mode": "open" on a public forge lets any client make bodega fetch
// arbitrary upstream repositories — lived only in that file, and Save used to
// delete all twenty blocks on the first write.
func TestSaveKeepsGeneratedComments(t *testing.T) {
	path := loadedFrom(t, "")

	created, err := config.EnsureConfigFile()
	if err != nil {
		t.Fatalf("EnsureConfigFile: %v", err)
	}
	if created != path {
		t.Fatalf("EnsureConfigFile() = %s, want %s", created, path)
	}
	before := savedKeys(t, path)
	generated, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	cfg, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	after := savedKeys(t, path)

	comments := 0
	for k, want := range before {
		if !strings.HasPrefix(k, "_comment") {
			continue
		}
		comments++
		got, ok := after[k]
		if !ok {
			t.Errorf("Save dropped %q", k)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("Save rewrote %q:\n got %s\nwant %s", k, got, want)
		}
	}
	if comments != 27 {
		t.Errorf("generated config carries %d comment blocks, want 27 — update this count with the guidance, not around it", comments)
	}

	// Key by key is not enough. The comments are only useful beside what they
	// document and set off from the block above, and neither the order nor the
	// blank lines survive a map: marshalling one sorts every _comment_ key
	// ahead of every real key, and JSON has no blank line to carry.
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if !bytes.Equal(generated, saved) {
		t.Errorf("a save with nothing changed rewrote the generated config:\n--- generated\n%s\n--- saved\n%s", generated, saved)
	}
}

// TestSaveRewritesOnlyTheChangedLine is the byte-level form of the same
// contract, on the file bodega itself generates: one operator edit changes one
// line, and a 5-kilobyte commented config does not come back as the handful of
// keys the save happened to touch.
func TestSaveRewritesOnlyTheChangedLine(t *testing.T) {
	path := loadedFrom(t, "")
	if _, err := config.EnsureConfigFile(); err != nil {
		t.Fatalf("EnsureConfigFile: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	cfg, err := config.Load("/tmp/flagged", "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Bucket = "operator-typed-this"
	if _, err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}

	var changed []string
	beforeLines, afterLines := strings.Split(string(before), "\n"), strings.Split(string(after), "\n")
	if len(beforeLines) != len(afterLines) {
		t.Fatalf("saved config has %d lines, generated has %d", len(afterLines), len(beforeLines))
	}
	for i := range beforeLines {
		if beforeLines[i] != afterLines[i] {
			changed = append(changed, afterLines[i])
		}
	}
	if len(changed) != 1 || strings.TrimSpace(changed[0]) != `"bucket": "operator-typed-this",` {
		t.Errorf("save changed %d lines, want the one bucket line: %q", len(changed), changed)
	}
}

// TestSaveDoesNotPinResolvedValues covers the other half of the same rewrite.
// `bodega --manifest-dir /tmp/x shell` plus one config save used to write the
// flag into the file, along with every built-in default Load had filled in, so
// a later change to any of those defaults could never reach that host again.
func TestSaveDoesNotPinResolvedValues(t *testing.T) {
	path := loadedFrom(t, `{
  "_comment_keep": "unrecognized keys survive a save",
  "manifest_dir": "",
  "log_dir": "/var/log/bodega",
  "future_key": {"written_by": "a newer release"}
}`)

	cfg, err := config.Load("/tmp/x", "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ManifestDir != "/tmp/x" {
		t.Fatalf("ManifestDir = %q, want /tmp/x", cfg.ManifestDir)
	}
	if _, err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	keys := savedKeys(t, path)
	for k, want := range map[string]string{
		"manifest_dir":  `""`,
		"log_dir":       `"/var/log/bodega"`,
		"_comment_keep": `"unrecognized keys survive a save"`,
		"future_key":    `{"written_by":"a newer release"}`,
	} {
		var got bytes.Buffer
		if err := json.Compact(&got, keys[k]); err != nil {
			t.Fatalf("compact %q: %v", k, err)
		}
		if got.String() != want {
			t.Errorf("saved config %q = %s, want %s", k, got.String(), want)
		}
	}
	for _, k := range []string{"audit_db", "metadata_ttl", "apt_codename", "apt_suites", "admin_permit_cidr", "tls_min_version", "storage_backend"} {
		if _, ok := keys[k]; ok {
			t.Errorf("saved config gained %q, which Load resolved and the operator never set", k)
		}
	}
}

// TestSaveWritesOperatorEdits is the guard on the guard: a Save that preserved
// the file by writing nothing at all would pass every assertion above.
func TestSaveWritesOperatorEdits(t *testing.T) {
	path := loadedFrom(t, `{"manifest_dir": "", "deny_list": ["10.0.0.5/32"]}`)

	cfg, err := config.Load("/tmp/x", "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.ManifestDir = "/srv/manifests"
	cfg.DenyList = nil
	if _, err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	keys := savedKeys(t, path)
	if got := string(keys["manifest_dir"]); got != `"/srv/manifests"` {
		t.Errorf("manifest_dir = %s, want \"/srv/manifests\"", got)
	}
	if _, ok := keys["deny_list"]; ok {
		t.Error("saved config kept deny_list; clearing a list in the TUI has to reach the file")
	}

	reloaded, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if reloaded.ManifestDir != "/srv/manifests" {
		t.Errorf("reloaded ManifestDir = %q, want /srv/manifests", reloaded.ManifestDir)
	}
}
