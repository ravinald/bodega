package config_test

import (
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
)

// binary_upstreams runs through the validator git_upstreams runs through, so
// what this pins is the wiring and the message: the shared rules are already
// covered by TestLoad_GitUpstreamsInvalid, and a message naming the wrong key
// sends an operator with both blocks set to edit the wrong one.
func TestLoad_BinaryUpstreamsInvalid(t *testing.T) {
	for _, tc := range []struct{ name, body, wantIn string }{
		{"key with slash", `{"binary_upstreams":{"vendor/dl":{"url":"https://dl.vendor.example/"}}}`, "vendor/dl"},
		{"key shadows a route", `{"binary_upstreams":{"binaries":{"url":"https://dl.vendor.example/"}}}`, "binaries"},
		{"url not https", `{"binary_upstreams":{"vendor":{"url":"http://dl.vendor.example/"}}}`, "vendor"},
		{"url has no trailing slash", `{"binary_upstreams":{"vendor":{"url":"https://dl.vendor.example"}}}`, "vendor"},
		{"mode unknown", `{"binary_upstreams":{"vendor":{"url":"https://dl.vendor.example/","mode":"wide-open"}}}`, "vendor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeConfig(t, tc.body)
			cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
			if err == nil {
				t.Fatalf("Load accepted %s: %+v", tc.body, cfg.BinaryUpstreams)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q does not name %q, so the operator cannot tell which entry to fix", err, tc.wantIn)
			}
			if !strings.Contains(err.Error(), "binary_upstreams") {
				t.Errorf("error %q does not name binary_upstreams; an install with both blocks set cannot tell which one it is", err)
			}
		})
	}
}

// An absent mode has to land as catalog on the loaded struct, not as the empty
// string a handler might read as "whatever the caller meant". The default is
// applied by the shared validator, so this also proves the second map reaches
// it rather than being copied into the config unchecked.
func TestLoad_BinaryUpstreamsDefaultsToCatalog(t *testing.T) {
	writeConfig(t, `{
	  "binary_upstreams": {
	    "absent":   {"url": "https://dl.vendor.example/"},
	    "empty":    {"url": "https://dl.vendor.example/", "mode": ""},
	    "explicit": {"url": "https://releases.hashicorp.example/", "mode": "open"}
	  }
	}`)

	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, ns := range []string{"absent", "empty"} {
		if got := cfg.BinaryUpstreams[ns].Mode; got != config.UpstreamModeCatalog {
			t.Errorf("binary_upstreams[%q].Mode = %q, want %q — an unwritten mode must not resolve to the posture that fetches anything asked for", ns, got, config.UpstreamModeCatalog)
		}
	}
	if got := cfg.BinaryUpstreams["explicit"].Mode; got != config.UpstreamModeOpen {
		t.Errorf("binary_upstreams[\"explicit\"].Mode = %q, want %q", got, config.UpstreamModeOpen)
	}
}
