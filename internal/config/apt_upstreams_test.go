package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
)

// writeAptConfig lands a config.json holding exactly the given keys and points
// the loader at it.
func writeAptConfig(t *testing.T, body map[string]any) {
	t.Helper()
	isolateConfig(t)
	path := filepath.Join(t.TempDir(), "config.json")
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)
}

func loadApt(t *testing.T) (*config.Config, error) {
	t.Helper()
	return config.Load("", "", "", "", false, false)
}

// TestAptUpstreamsRejected walks every way the block can be wrong. Each of
// these reaches the operator as a refused start rather than as an apt client
// failing later with a message about the archive.
func TestAptUpstreamsRejected(t *testing.T) {
	for _, tc := range []struct {
		name      string
		upstreams map[string]any
		suites    []string
		wantIn    string
	}{
		{
			name:      "uppercase codename",
			upstreams: map[string]any{"Noble": []any{map[string]string{"url": "https://archive.ubuntu.com/ubuntu"}}},
			wantIn:    "invalid apt_upstreams key",
		},
		{
			name:      "codename with a slash would misroute the dists path",
			upstreams: map[string]any{"noble/updates": []any{map[string]string{"url": "https://archive.ubuntu.com/ubuntu"}}},
			wantIn:    "invalid apt_upstreams key",
		},
		{
			name:      "leading digit",
			upstreams: map[string]any{"24noble": []any{map[string]string{"url": "https://archive.ubuntu.com/ubuntu"}}},
			wantIn:    "invalid apt_upstreams key",
		},
		{
			name:      "empty list",
			upstreams: map[string]any{"noble": []any{}},
			wantIn:    "names no upstream",
		},
		{
			name:      "empty url",
			upstreams: map[string]any{"noble": []any{map[string]string{"url": ""}}},
			wantIn:    "url is required",
		},
		{
			name:      "plaintext upstream",
			upstreams: map[string]any{"noble": []any{map[string]string{"url": "http://archive.ubuntu.com/ubuntu"}}},
			wantIn:    "must use the https scheme",
		},
		{
			name:      "no host",
			upstreams: map[string]any{"noble": []any{map[string]string{"url": "https:///ubuntu"}}},
			wantIn:    "names no host",
		},
		{
			name:      "query would land after the appended path",
			upstreams: map[string]any{"noble": []any{map[string]string{"url": "https://archive.ubuntu.com/ubuntu?mirror=1"}}},
			wantIn:    "query or fragment",
		},
		{
			name: "second entry is checked too",
			upstreams: map[string]any{"noble": []any{
				map[string]string{"url": "https://archive.ubuntu.com/ubuntu"},
				map[string]string{"url": "ftp://security.ubuntu.com/ubuntu"},
			}},
			wantIn: "must use the https scheme",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{"apt_codename": "jammy", "apt_upstreams": tc.upstreams}
			if tc.suites != nil {
				body["apt_suites"] = tc.suites
			}
			writeAptConfig(t, body)
			_, err := loadApt(t)
			if err == nil {
				t.Fatalf("Load accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("error = %q, want it to name %q", err, tc.wantIn)
			}
		})
	}
}

// A codename in both sets is the one combination that cannot be given a
// meaning: bodega signs an index it generated and forwards upstream's for one
// it mirrors, and one URL serves one of them. Refusing at load is the only
// place the hazard is impossible rather than unlikely.
func TestAptCodenameInBothSetsIsRefused(t *testing.T) {
	writeAptConfig(t, map[string]any{
		"apt_codename": "jammy",
		"apt_suites":   []string{"noble"},
		"apt_upstreams": map[string]any{
			"noble": []any{map[string]string{"url": "https://archive.ubuntu.com/ubuntu"}},
		},
	})
	_, err := loadApt(t)
	if err == nil {
		t.Fatal("Load accepted a codename in both apt_suites and apt_upstreams")
	}
	for _, want := range []string{"noble", "apt_suites", "apt_upstreams"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %q", err, want)
		}
	}
}

// apt_codename is implicitly a served suite, so it collides the same way even
// when apt_suites is empty. Missing this would let the default install mirror
// the codename it also generates.
func TestAptCodenameDefaultCollidesToo(t *testing.T) {
	writeAptConfig(t, map[string]any{
		"apt_codename": "noble",
		"apt_upstreams": map[string]any{
			"noble": []any{map[string]string{"url": "https://archive.ubuntu.com/ubuntu"}},
		},
	})
	if _, err := loadApt(t); err == nil {
		t.Fatal("Load accepted apt_codename as a mirrored codename")
	}
}

func TestAptUpstreamsAccepted(t *testing.T) {
	writeAptConfig(t, map[string]any{
		"apt_codename": "local",
		"apt_upstreams": map[string]any{
			"noble":         []any{map[string]string{"url": "https://archive.ubuntu.com/ubuntu/"}, map[string]string{"url": "https://security.ubuntu.com/ubuntu"}},
			"noble-updates": []any{map[string]string{"url": "https://archive.ubuntu.com/ubuntu"}},
			"bookworm":      []any{map[string]string{"url": "https://deb.debian.org/debian"}},
		},
	})
	cfg, err := loadApt(t)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// The trailing slash is trimmed at load so every composition site appends
	// "/dists/..." the same way. Left in, the fetch URL carries "//dists".
	if got := cfg.AptUpstreams["noble"][0].URL; got != "https://archive.ubuntu.com/ubuntu" {
		t.Errorf("url = %q, want the trailing slash trimmed", got)
	}
	if !cfg.MirrorsAptCodename("noble-updates") || cfg.MirrorsAptCodename("local") {
		t.Errorf("MirrorsAptCodename disagrees with the loaded map")
	}
	if got := cfg.MirroredAptCodenames(); strings.Join(got, ",") != "bookworm,noble,noble-updates" {
		t.Errorf("MirroredAptCodenames = %v, want them sorted", got)
	}

	// The pool candidate list is the deduplicated union across codenames,
	// sorted: a pool path carries no codename, so the probe order has to be
	// the same on every server running this config.
	want := "https://archive.ubuntu.com/ubuntu,https://deb.debian.org/debian,https://security.ubuntu.com/ubuntu"
	if got := strings.Join(cfg.AptPoolUpstreams(), ","); got != want {
		t.Errorf("AptPoolUpstreams() = %q, want %q", got, want)
	}
}

// The empty map is what every existing install runs, and it has to keep
// producing exactly today's behavior.
func TestNoAptUpstreamsIsUnchanged(t *testing.T) {
	writeAptConfig(t, map[string]any{"apt_codename": "noble", "apt_suites": []string{"noble", "jammy"}})
	cfg, err := loadApt(t)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.AptUpstreams) != 0 {
		t.Errorf("AptUpstreams = %v, want empty", cfg.AptUpstreams)
	}
	if cfg.MirrorsAptCodename("noble") || len(cfg.AptPoolUpstreams()) != 0 {
		t.Error("an install with no apt_upstreams reports mirrored state")
	}
	if got := strings.Join(cfg.ServedAptSuites(), ","); got != "noble,jammy" {
		t.Errorf("ServedAptSuites() = %q, want the generated suites untouched", got)
	}
}
