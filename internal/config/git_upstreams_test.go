package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
)

// TestLoad_GitUpstreamsDefaultsToCatalog asserts the default against the
// loaded struct rather than against a handler. Every reader of Mode — the git
// proxy, the binary proxy that lifts this shape, anything rendering the config
// — has to see "catalog" for a namespace whose mode nobody wrote, and a
// default applied in one caller is a default the next one does not share.
func TestLoad_GitUpstreamsDefaultsToCatalog(t *testing.T) {
	writeConfig(t, `{
	  "git_upstreams": {
	    "absent":   {"url": "https://github.com/"},
	    "empty":    {"url": "https://github.com/", "mode": ""},
	    "explicit": {"url": "https://git.corp.example/", "mode": "open"}
	  }
	}`)

	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, ns := range []string{"absent", "empty"} {
		if got := cfg.GitUpstreams[ns].Mode; got != config.GitModeCatalog {
			t.Errorf("git_upstreams[%q].Mode = %q, want %q — an unwritten mode must not resolve to the posture that fetches anything asked for", ns, got, config.GitModeCatalog)
		}
	}
	if got := cfg.GitUpstreams["explicit"].Mode; got != config.GitModeOpen {
		t.Errorf("git_upstreams[\"explicit\"].Mode = %q, want %q", got, config.GitModeOpen)
	}
	if got := cfg.GitUpstreams["explicit"].URL; got != "https://git.corp.example/" {
		t.Errorf("git_upstreams[\"explicit\"].URL = %q, want the configured URL", got)
	}
}

// TestLoad_GitUpstreamsInvalid pins that a bad value is refused at load rather
// than corrected in place, following discover_mode. Every message has to name
// the offending namespace key: an operator with six forges configured cannot
// act on "invalid url".
func TestLoad_GitUpstreamsInvalid(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantIn string
	}{
		{"key with slash", `{"git_upstreams":{"corp/git":{"url":"https://git.corp.example/"}}}`, "corp/git"},
		{"key with dots", `{"git_upstreams":{"..":{"url":"https://git.corp.example/"}}}`, `".."`},
		{"key leading digit", `{"git_upstreams":{"2fa":{"url":"https://git.corp.example/"}}}`, "2fa"},
		{"key empty", `{"git_upstreams":{"":{"url":"https://git.corp.example/"}}}`, "git_upstreams"},
		{"key shadows a route", `{"git_upstreams":{"api":{"url":"https://git.corp.example/"}}}`, "api"},
		{"key shadows storage", `{"git_upstreams":{"repos":{"url":"https://git.corp.example/"}}}`, "repos"},
		{"url empty", `{"git_upstreams":{"corp":{"url":""}}}`, "corp"},
		{"url not https", `{"git_upstreams":{"corp":{"url":"http://git.corp.example/"}}}`, "corp"},
		{"url is ssh", `{"git_upstreams":{"corp":{"url":"ssh://git@git.corp.example/"}}}`, "corp"},
		{"url has no host", `{"git_upstreams":{"corp":{"url":"https:///path/"}}}`, "corp"},
		{"url has no trailing slash", `{"git_upstreams":{"corp":{"url":"https://git.corp.example"}}}`, "corp"},
		{"mode unknown", `{"git_upstreams":{"corp":{"url":"https://git.corp.example/","mode":"wide-open"}}}`, "corp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeConfig(t, tc.body)
			cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
			if err == nil {
				t.Fatalf("Load accepted %s: %+v", tc.body, cfg.GitUpstreams)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("Load error %q does not name %s", err, tc.wantIn)
			}
		})
	}
}

// TestGitUpstreamsRoundTrip is the same guard TestSaveLoadRoundTrip applies to
// the whole struct, aimed at this key so the failure names it. A key that
// loads but does not save is destroyed by the next TUI edit, which is the
// defect the Save rewrite fixed for four other keys.
func TestGitUpstreamsRoundTrip(t *testing.T) {
	isolateConfig(t)
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv(config.EnvConfigFile, path)

	want := map[string]config.GitUpstream{
		"corp":   {URL: "https://git.corp.example/", Mode: config.GitModeOpen},
		"github": {URL: "https://github.com/", Mode: config.GitModeCatalog},
	}
	cfg := &config.Config{GitUpstreams: want}
	if _, err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var raw map[string]json.RawMessage
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal saved config: %v", err)
	}
	if _, ok := raw["git_upstreams"]; !ok {
		t.Fatalf("Save dropped git_upstreams; the file it wrote is %s", data)
	}

	got, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for ns, w := range want {
		if got.GitUpstreams[ns] != w {
			t.Errorf("git_upstreams[%q] = %+v after a save/load cycle, want %+v", ns, got.GitUpstreams[ns], w)
		}
	}
}
