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
		{"revalidate pattern malformed", `{"binary_upstreams":{"vendor":{"url":"https://dl.vendor.example/","revalidate":["dist/["]}}}`, "vendor"},
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
	    "explicit": {"url": "https://downloads.example.com/", "mode": "open"}
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

func TestLoad_GomodSumdbURL(t *testing.T) {
	writeConfig(t, `{}`)
	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GomodSumdbURL != "https://sum.golang.org" {
		t.Errorf("gomod_sumdb_url default = %q, want https://sum.golang.org", cfg.GomodSumdbURL)
	}

	for _, bad := range []string{"http://sum.golang.org", "sum.golang.org", "https://", "https://u:p@sum.example/"} {
		writeConfig(t, `{"gomod_sumdb_url":"`+bad+`"}`)
		if _, err := config.Load(t.TempDir(), "", "", "", false, false); err == nil {
			t.Errorf("Load accepted gomod_sumdb_url %q", bad)
		} else if !strings.Contains(err.Error(), "gomod_sumdb_url") {
			t.Errorf("error %q does not name gomod_sumdb_url", err)
		}
	}
}

func TestLoad_MavenUpstream(t *testing.T) {
	writeConfig(t, `{}`)
	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MavenUpstream != config.DefaultMavenUpstream {
		t.Errorf("maven_upstream default = %q, want %s", cfg.MavenUpstream, config.DefaultMavenUpstream)
	}

	writeConfig(t, `{"maven_upstream":"https://maven.example/repo/"}`)
	if cfg, err = config.Load(t.TempDir(), "", "", "", false, false); err != nil || cfg.MavenUpstream != "https://maven.example/repo" {
		t.Errorf("maven_upstream with a trailing slash = %q, %v; want it trimmed", cfg.MavenUpstream, err)
	}

	for _, bad := range []string{"http://repo.maven.apache.org/maven2", "repo.maven.apache.org", "https://", "https://u:p@maven.example/", "https://maven.example/?x=1"} {
		writeConfig(t, `{"maven_upstream":"`+bad+`"}`)
		if _, err := config.Load(t.TempDir(), "", "", "", false, false); err == nil {
			t.Errorf("Load accepted maven_upstream %q", bad)
		} else if !strings.Contains(err.Error(), "maven_upstream") {
			t.Errorf("error %q does not name maven_upstream", err)
		}
	}
}

func TestLoad_RubygemsUpstream(t *testing.T) {
	writeConfig(t, `{}`)
	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RubygemsUpstream != config.DefaultRubygemsUpstream {
		t.Errorf("rubygems_upstream default = %q, want %s", cfg.RubygemsUpstream, config.DefaultRubygemsUpstream)
	}

	writeConfig(t, `{"rubygems_upstream":"https://gems.example.com/"}`)
	cfg, err = config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RubygemsUpstream != "https://gems.example.com" {
		t.Errorf("rubygems_upstream = %q, want the trailing slash trimmed", cfg.RubygemsUpstream)
	}

	for _, bad := range []string{"http://rubygems.org", "rubygems.org", "https://", "https://u:p@gems.example/", "https://gems.example/?x=1"} {
		writeConfig(t, `{"rubygems_upstream":"`+bad+`"}`)
		if _, err := config.Load(t.TempDir(), "", "", "", false, false); err == nil {
			t.Errorf("Load accepted rubygems_upstream %q", bad)
		} else if !strings.Contains(err.Error(), "rubygems_upstream") {
			t.Errorf("error %q does not name rubygems_upstream", err)
		}
	}
}

func TestLoad_ProxyUpstreamsRequireHTTPS(t *testing.T) {
	defaults := map[string]string{
		"gomod_upstream":    "https://proxy.golang.org",
		"npm_upstream":      "https://registry.npmjs.org",
		"pypi_upstream":     "https://pypi.org",
		"cargo_upstream":    "https://index.crates.io",
		"cargo_dl_upstream": "https://static.crates.io/crates",
	}
	for key, def := range defaults {
		for _, bad := range []string{"http://registry.example.com", "registry.example.com", "https://", "https://registry.example.com/?x=1", "https://registry.example.com/#f"} {
			writeConfig(t, `{"`+key+`":"`+bad+`"}`)
			_, err := config.Load(t.TempDir(), "", "", "", false, false)
			if err == nil {
				t.Errorf("Load accepted %s %q", key, bad)
				continue
			}
			for _, want := range []string{key + ` "` + bad + `"`, "(default " + def + ")"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s %q: error %q does not contain %q", key, bad, err, want)
				}
			}
		}
	}

	writeConfig(t, `{"distfiles_upstream":"http://distfiles.example.com/"}`)
	if _, err := config.Load(t.TempDir(), "", "", "", false, false); err != nil {
		t.Errorf("Load refused an http distfiles_upstream: %v", err)
	}
}

func TestLoad_ProxyUpstreamsAdmitCredentials(t *testing.T) {
	for _, key := range []string{"gomod_upstream", "npm_upstream", "pypi_upstream", "cargo_upstream", "cargo_dl_upstream"} {
		good := "https://ci:s3cret@registry.corp.example/repository/" + key
		writeConfig(t, `{"`+key+`":"`+good+`"}`)
		if _, err := config.Load(t.TempDir(), "", "", "", false, false); err != nil {
			t.Errorf("Load refused a credentialed %s: %v", key, err)
		}

		for _, bad := range []string{"http://ci:s3cret@registry.corp.example/", "https://ci:s3cret@", "https://ci:s3cret@registry.corp.example/?x=1", "https://ci:s3cret@registry.corp.example:bad/"} {
			writeConfig(t, `{"`+key+`":"`+bad+`"}`)
			_, err := config.Load(t.TempDir(), "", "", "", false, false)
			if err == nil {
				t.Errorf("Load accepted %s %q", key, bad)
				continue
			}
			if !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "ci:") {
				t.Errorf("%s %q: error %q does not name the key and the value", key, bad, err)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Errorf("%s %q: error %q prints the password", key, bad, err)
			}
		}
	}
}

func TestLoad_PrivateUpstreamHosts(t *testing.T) {
	writeConfig(t, `{"private_upstream_hosts":["Registry.Corp.Example","10.0.0.5","FD00:0::5"]}`)
	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"registry.corp.example", "10.0.0.5", "fd00::5"}
	if strings.Join(cfg.PrivateUpstreamHosts, ",") != strings.Join(want, ",") {
		t.Errorf("private_upstream_hosts = %q, want %q", cfg.PrivateUpstreamHosts, want)
	}

	for _, bad := range []string{"", "https://registry.corp.example", "registry.corp.example:4873", "registry.corp.example/npm", "[fd00::5]", "fe80::1%eth0", "bad host", "-lead.example"} {
		writeConfig(t, `{"private_upstream_hosts":["`+bad+`"]}`)
		if _, err := config.Load(t.TempDir(), "", "", "", false, false); err == nil {
			t.Errorf("Load accepted private_upstream_hosts entry %q", bad)
		} else if !strings.Contains(err.Error(), "private_upstream_hosts") || !strings.Contains(err.Error(), `"`+bad+`"`) {
			t.Errorf("entry %q: error %q does not name the entry", bad, err)
		}
	}
}
