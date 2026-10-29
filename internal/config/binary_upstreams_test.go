package config_test

import (
	"encoding/json"
	"maps"
	"slices"
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
	want := []string{config.DefaultMavenUpstream, "https://plugins.gradle.org/m2"}
	if strings.Join(cfg.MavenUpstreams, " ") != strings.Join(want, " ") || cfg.MavenUpstream != "" {
		t.Errorf("unset: maven_upstreams = %q, maven_upstream = %q; want %q and the single key folded away", cfg.MavenUpstreams, cfg.MavenUpstream, want)
	}

	writeConfig(t, `{"maven_upstream":"https://maven.example/repo/"}`)
	if cfg, err = config.Load(t.TempDir(), "", "", "", false, false); err != nil ||
		len(cfg.MavenUpstreams) != 1 || cfg.MavenUpstreams[0] != "https://maven.example/repo" || cfg.MavenUpstream != "" {
		t.Errorf("maven_upstream alone = %q (single key %q), %v; want the one trimmed entry", cfg.MavenUpstreams, cfg.MavenUpstream, err)
	}

	writeConfig(t, `{"maven_upstreams":["https://maven.google.com/","https://repo.maven.apache.org/maven2"]}`)
	if cfg, err = config.Load(t.TempDir(), "", "", "", false, false); err != nil ||
		strings.Join(cfg.MavenUpstreams, " ") != "https://maven.google.com https://repo.maven.apache.org/maven2" {
		t.Errorf("maven_upstreams = %q, %v; want the operator's order, trimmed", cfg.MavenUpstreams, err)
	}

	writeConfig(t, `{"maven_upstream":"https://maven.example/repo","maven_upstreams":["https://maven.google.com"]}`)
	if _, err := config.Load(t.TempDir(), "", "", "", false, false); err == nil {
		t.Error("Load accepted maven_upstream and maven_upstreams together")
	} else if !strings.Contains(err.Error(), "maven_upstream and maven_upstreams") {
		t.Errorf("both-keys error %q does not name both keys", err)
	}

	for _, body := range []string{`{"maven_upstreams":[]}`, `{"maven_upstreams":["https://a.example","https://a.example/"]}`} {
		writeConfig(t, body)
		if _, err := config.Load(t.TempDir(), "", "", "", false, false); err == nil || !strings.Contains(err.Error(), "maven_upstreams") {
			t.Errorf("Load(%s) = %v; want an error naming maven_upstreams", body, err)
		}
	}

	for _, bad := range []string{"http://repo.maven.apache.org/maven2", "repo.maven.apache.org", "https://", "https://u:p@maven.example/", "https://maven.example/?x=1"} {
		for _, body := range []string{`{"maven_upstream":"` + bad + `"}`, `{"maven_upstreams":["https://maven.google.com","` + bad + `"]}`} {
			writeConfig(t, body)
			if _, err := config.Load(t.TempDir(), "", "", "", false, false); err == nil {
				t.Errorf("Load accepted %s", body)
			} else if key := body[2 : strings.Index(body[2:], `"`)+2]; !strings.Contains(err.Error(), key) {
				t.Errorf("error %q does not name %s", err, key)
			}
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

func TestLoad_ComposerUpstreamAndDistHosts(t *testing.T) {
	writeConfig(t, `{}`)
	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ComposerUpstream != config.DefaultComposerUpstream {
		t.Errorf("composer_upstream default = %q, want %s", cfg.ComposerUpstream, config.DefaultComposerUpstream)
	}
	if !slices.Equal(cfg.ComposerDistHosts, config.DefaultComposerDistHosts) {
		t.Errorf("composer_dist_hosts default = %v, want %v", cfg.ComposerDistHosts, config.DefaultComposerDistHosts)
	}

	writeConfig(t, `{"composer_upstream":"https://packagist.example.com/","composer_dist_hosts":["Git.Example.com"]}`)
	cfg, err = config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ComposerUpstream != "https://packagist.example.com" {
		t.Errorf("composer_upstream = %q, want the trailing slash trimmed", cfg.ComposerUpstream)
	}
	if !slices.Equal(cfg.ComposerDistHosts, []string{"git.example.com"}) {
		t.Errorf("composer_dist_hosts = %v, want the host lowercased", cfg.ComposerDistHosts)
	}

	// An empty list is kept: it refuses every archive, which is the
	// operator's to choose.
	writeConfig(t, `{"composer_dist_hosts":[]}`)
	if cfg, err = config.Load(t.TempDir(), "", "", "", false, false); err != nil || len(cfg.ComposerDistHosts) != 0 {
		t.Errorf("composer_dist_hosts [] loaded as %v (err %v), want it kept empty", cfg.ComposerDistHosts, err)
	}

	for _, bad := range []string{"http://repo.packagist.org", "repo.packagist.org", "https://", "https://u:p@packagist.example/", "https://packagist.example/?x=1"} {
		writeConfig(t, `{"composer_upstream":"`+bad+`"}`)
		if _, err := config.Load(t.TempDir(), "", "", "", false, false); err == nil {
			t.Errorf("Load accepted composer_upstream %q", bad)
		} else if !strings.Contains(err.Error(), "composer_upstream") {
			t.Errorf("error %q does not name composer_upstream", err)
		}
	}
	for _, bad := range []string{"https://github.com", "github.com:443", "github.com/x"} {
		writeConfig(t, `{"composer_dist_hosts":["`+bad+`"]}`)
		if _, err := config.Load(t.TempDir(), "", "", "", false, false); err == nil {
			t.Errorf("Load accepted composer_dist_hosts entry %q", bad)
		} else if !strings.Contains(err.Error(), "composer_dist_hosts") {
			t.Errorf("error %q does not name composer_dist_hosts", err)
		}
	}
}

func TestLoad_OCIUpstreamsAndTokenHosts(t *testing.T) {
	writeConfig(t, `{}`)
	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !maps.Equal(cfg.OCIUpstreams, config.DefaultOCIUpstreams) {
		t.Errorf("oci_upstreams default = %v, want %v", cfg.OCIUpstreams, config.DefaultOCIUpstreams)
	}
	if !slices.Equal(cfg.OCITokenHosts, config.DefaultOCITokenHosts) {
		t.Errorf("oci_token_hosts default = %v, want %v", cfg.OCITokenHosts, config.DefaultOCITokenHosts)
	}

	// A given map is used as written, a credential in userinfo is kept, and
	// the key is folded to lower case.
	writeConfig(t, `{"oci_upstreams":{"Registry.Example.com":"https://robot:s3cret@registry.example.com/"},"oci_token_hosts":["Auth.Example.com"]}`)
	if cfg, err = config.Load(t.TempDir(), "", "", "", false, false); err != nil {
		t.Fatalf("Load: %v", err)
	}
	//nolint:gosec // G101: a fixture credential, asserted to survive Load.
	if want := map[string]string{"registry.example.com": "https://robot:s3cret@registry.example.com"}; !maps.Equal(cfg.OCIUpstreams, want) {
		t.Errorf("oci_upstreams = %v, want %v", cfg.OCIUpstreams, want)
	}
	if !slices.Equal(cfg.OCITokenHosts, []string{"auth.example.com"}) {
		t.Errorf("oci_token_hosts = %v, want the host lowercased", cfg.OCITokenHosts)
	}

	for _, tc := range []struct{ doc, key string }{
		{`{"oci_upstreams":{"docker.io":"http://robot:s3cret@registry-1.docker.io"}}`, `oci_upstreams["docker.io"]`},
		{`{"oci_upstreams":{"docker.io":"https://robot:s3cret@registry-1.docker.io/?x=1"}}`, `oci_upstreams["docker.io"]`},
		{`{"oci_upstreams":{"localhost":"https://registry.example.com"}}`, "oci_upstreams key"},
		{`{"oci_upstreams":{"https://ghcr.io":"https://ghcr.io"}}`, "oci_upstreams key"},
		{`{"oci_token_hosts":["https://auth.docker.io"]}`, "oci_token_hosts"},
	} {
		writeConfig(t, tc.doc)
		_, err := config.Load(t.TempDir(), "", "", "", false, false)
		switch {
		case err == nil:
			t.Errorf("Load accepted %s", tc.doc)
		case !strings.Contains(err.Error(), tc.key):
			t.Errorf("error %q does not name %s", err, tc.key)
		case strings.Contains(err.Error(), "s3cret"):
			t.Errorf("error %q prints the credential", err)
		}
	}
}

func TestLoad_RpmUpstreams(t *testing.T) {
	writeConfig(t, `{}`)
	cfg, err := config.Load(t.TempDir(), "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.RpmUpstreams) != 0 {
		t.Errorf("rpm_upstreams default = %v, want empty: an operator names what bodega serves", cfg.RpmUpstreams)
	}

	writeConfig(t, `{"rpm_upstreams":{"rocky-baseos":"https://dl.rockylinux.org/pub/rocky/$releasever/BaseOS/$basearch/os","epel":"https://dl.fedoraproject.org/pub/epel/$releasever/Everything/$basearch/"}}`)
	if cfg, err = config.Load(t.TempDir(), "", "", "", false, false); err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]config.RpmUpstream{
		"rocky-baseos": {URL: "https://dl.rockylinux.org/pub/rocky/$releasever/BaseOS/$basearch/os/"},
		"epel":         {URL: "https://dl.fedoraproject.org/pub/epel/$releasever/Everything/$basearch/"},
	}
	if !maps.Equal(cfg.RpmUpstreams, want) {
		t.Errorf("rpm_upstreams = %v, want %v with one trailing slash each", cfg.RpmUpstreams, want)
	}

	writeConfig(t, `{"rpm_upstreams":{
		"rocky-baseos":"https://dl.rockylinux.org/pub/rocky/$releasever/BaseOS/$basearch/os/",
		"alma-appstream":"https://repo.almalinux.org/almalinux/$releasever/AppStream/$basearch/os/",
		"rhel-baseos":"https://cdn.redhat.com/content/dist/rhel9/$releasever/$basearch/baseos/os/",
		"epel":"https://dl.fedoraproject.org/pub/epel/$releasever/Everything/$basearch/",
		"rocky-mirror":{"url":"https://mirror.example.com/rocky/$releasever/BaseOS/$basearch/os/","osv_ecosystem":"Rocky Linux"},
		"alma-at-rocky":{"url":"https://dl.rockylinux.org/x/","osv_ecosystem":"AlmaLinux"}}}`)
	if cfg, err = config.Load(t.TempDir(), "", "", "", false, false); err != nil {
		t.Fatalf("Load: %v", err)
	}
	for repo, eco := range map[string]string{
		"rocky-baseos": "Rocky Linux", "alma-appstream": "AlmaLinux", "rhel-baseos": "Red Hat",
		"epel": "", "rocky-mirror": "Rocky Linux", "alma-at-rocky": "AlmaLinux", "absent": "",
	} {
		if got := cfg.RpmOSVEcosystem(repo); got != eco {
			t.Errorf("RpmOSVEcosystem(%s) = %q, want %q", repo, got, eco)
		}
	}
	if got := cfg.RpmOSVEcosystemsServed(); !slices.Equal(got, []string{"AlmaLinux", "Red Hat", "Rocky Linux"}) {
		t.Errorf("RpmOSVEcosystemsServed = %v", got)
	}
	// The short form survives a write: only an entry naming an ecosystem is
	// written as an object.
	out, err := json.Marshal(cfg.RpmUpstreams)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"epel":"https://dl.fedoraproject.org/`) ||
		!strings.Contains(string(out), `"rocky-mirror":{"url":"https://mirror.example.com/rocky/$releasever/BaseOS/$basearch/os/","osv_ecosystem":"Rocky Linux"}`) {
		t.Errorf("rpm_upstreams marshals as %s", out)
	}

	for _, tc := range []struct{ doc, key string }{
		{`{"rpm_upstreams":{"rocky":"http://robot:s3cret@dl.rockylinux.org/$releasever/"}}`, `rpm_upstreams["rocky"]`},
		{`{"rpm_upstreams":{"rocky":"https://robot:s3cret@dl.rockylinux.org/$releasever/?x=1"}}`, `rpm_upstreams["rocky"]`},
		{`{"rpm_upstreams":{"rocky":"https://dl.rockylinux.org/$contentdir/$releasever/"}}`, `rpm_upstreams["rocky"]`},
		{`{"rpm_upstreams":{"../x":"https://dl.rockylinux.org/"}}`, "rpm_upstreams key"},
		{`{"rpm_upstreams":{"a/b":"https://dl.rockylinux.org/"}}`, "rpm_upstreams key"},
		{`{"rpm_upstreams":{"epel":{"url":"https://dl.fedoraproject.org/pub/epel/","osv_ecosystem":"EPEL"}}}`, `rpm_upstreams["epel"] osv_ecosystem "EPEL"`},
		{`{"rpm_upstreams":{"epel":{"url":"https://dl.fedoraproject.org/pub/epel/","osv":"Rocky Linux"}}}`, "osv_ecosystem"},
	} {
		writeConfig(t, tc.doc)
		_, err := config.Load(t.TempDir(), "", "", "", false, false)
		switch {
		case err == nil:
			t.Errorf("Load accepted %s", tc.doc)
		case !strings.Contains(err.Error(), tc.key):
			t.Errorf("error %q does not name %s", err, tc.key)
		case strings.Contains(err.Error(), "s3cret"):
			t.Errorf("error %q prints the credential", err)
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
