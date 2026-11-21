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

const grafanaFingerprint = "B53AE77BADB630A683046005963FA27710458545"

func grafanaUpstream(keyURL, fpr string) map[string]any {
	up := map[string]any{"url": "https://apt.grafana.com", "components": []string{"main"}}
	if keyURL != "" {
		up["signing_key_url"] = keyURL
	}
	if fpr != "" {
		up["signing_key_fingerprint"] = fpr
	}
	return map[string]any{"stable": []any{up}}
}

// E22 R1: a vendor key is a URL and a fingerprint together, and each refusal
// names the codename and the key at fault.
func TestAptUpstreamSigningKeyRejected(t *testing.T) {
	for _, tc := range []struct {
		name      string
		upstreams map[string]any
		wantIn    string
	}{
		{"url without fingerprint", grafanaUpstream("https://apt.grafana.com/gpg.key", ""), "signing_key_url and signing_key_fingerprint go together"},
		{"fingerprint without url", grafanaUpstream("", grafanaFingerprint), "signing_key_url and signing_key_fingerprint go together"},
		{"plain http url", grafanaUpstream("http://apt.grafana.com/gpg.key", grafanaFingerprint), `signing_key_url "http://apt.grafana.com/gpg.key" must use the https scheme`},
		{"url with no host", grafanaUpstream("https:///gpg.key", grafanaFingerprint), "names no host"},
		{"short fingerprint", grafanaUpstream("https://apt.grafana.com/gpg.key", "963FA27710458545"), `signing_key_fingerprint "963FA27710458545" is not an OpenPGP primary key fingerprint`},
		{"non-hex fingerprint", grafanaUpstream("https://apt.grafana.com/gpg.key", "Z53AE77BADB630A683046005963FA27710458545"), "is not an OpenPGP primary key fingerprint"},
		{
			name: "two entries, two fingerprints",
			upstreams: map[string]any{"stable": []any{
				map[string]string{"url": "https://apt.grafana.com", "signing_key_url": "https://apt.grafana.com/gpg.key", "signing_key_fingerprint": grafanaFingerprint},
				map[string]string{"url": "https://mirror.example.com/grafana", "signing_key_url": "https://mirror.example.com/gpg.key", "signing_key_fingerprint": strings.Repeat("A", 40)},
			}},
			wantIn: "differs from " + grafanaFingerprint,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeAptConfig(t, map[string]any{"apt_codename": "local", "apt_upstreams": tc.upstreams})
			_, err := loadApt(t)
			if err == nil {
				t.Fatal("Load accepted it")
			}
			if !strings.Contains(err.Error(), tc.wantIn) || !strings.Contains(err.Error(), `apt_upstreams["stable"]`) {
				t.Errorf("error = %q, want it to name the codename and contain %q", err, tc.wantIn)
			}
		})
	}
}

// E22 R1: a fingerprint as gpg prints it, spaced and in either case, loads
// normalized, and a codename with no key reports none.
func TestAptUpstreamSigningKeyAccepted(t *testing.T) {
	spaced := "b53a e77b adb6 30a6 8304  6005 963f a277 1045 8545"
	up := grafanaUpstream("https://apt.grafana.com/gpg.key", spaced)
	up["noble"] = []any{map[string]string{"url": "https://archive.ubuntu.com/ubuntu"}}
	writeAptConfig(t, map[string]any{"apt_codename": "local", "apt_upstreams": up})
	cfg, err := loadApt(t)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	key, ok := cfg.AptSigningKeyFor("stable")
	if !ok || key.URL != "https://apt.grafana.com/gpg.key" || key.Fingerprint != grafanaFingerprint {
		t.Errorf("AptSigningKeyFor(stable) = %+v, %v; want the URL and %s", key, ok, grafanaFingerprint)
	}
	if _, ok := cfg.AptSigningKeyFor("noble"); ok {
		t.Error("noble names no key and reports one")
	}
	if got := cfg.AptKeyedCodenames(); strings.Join(got, ",") != "stable" {
		t.Errorf("AptKeyedCodenames = %v, want [stable]", got)
	}
}

// aptTwoDistros is the apt_upstreams block the archive tests group: two
// distributions, each with a pocket.
func aptTwoDistros() map[string]any {
	up := func(u string) []any { return []any{map[string]string{"url": u}} }
	return map[string]any{
		"resolute":         up("https://archive.ubuntu.com/ubuntu"),
		"resolute-updates": up("https://archive.ubuntu.com/ubuntu"),
		"trixie":           up("https://deb.debian.org/debian"),
		"trixie-security":  up("https://security.debian.org/debian-security"),
	}
}

// TestAptArchivesRejected walks each refusal. Every message has to name the
// key, the offending value and the reason, because the operator reads it on a
// server that would not start.
func TestAptArchivesRejected(t *testing.T) {
	for _, tc := range []struct {
		name     string
		archives map[string][]string
		wantIn   []string
	}{
		{
			name:     "name with a dot is not a URL segment and a directory",
			archives: map[string][]string{"ubuntu.com": {"resolute"}},
			wantIn:   []string{`invalid apt_archives key "ubuntu.com"`, "must match"},
		},
		{
			name:     "reserved path element",
			archives: map[string][]string{"pool": {"resolute"}},
			wantIn:   []string{`invalid apt_archives key "pool"`, "reserved", "apt pool storage element"},
		},
		{
			name:     "dists would shadow the default route",
			archives: map[string][]string{"dists": {"resolute"}},
			wantIn:   []string{`invalid apt_archives key "dists"`, "reserved"},
		},
		{
			name:     "keys is the vendor key route",
			archives: map[string][]string{"keys": {"resolute"}},
			wantIn:   []string{`invalid apt_archives key "keys"`, "reserved", "/apt/keys/"},
		},
		{
			name:     "codename apt_upstreams does not mirror",
			archives: map[string][]string{"ubuntu": {"resolute", "noble"}},
			wantIn:   []string{`apt_archives["ubuntu"]`, `"noble"`, "not mirrored"},
		},
		{
			name:     "codename in two archives",
			archives: map[string][]string{"debian": {"trixie"}, "ubuntu": {"resolute", "trixie"}},
			wantIn:   []string{`apt_archives["ubuntu"]`, `"trixie"`, `already in archive "debian"`},
		},
		{
			name:     "generated suite",
			archives: map[string][]string{"ubuntu": {"resolute", "local"}},
			wantIn:   []string{`apt_archives["ubuntu"]`, `"local"`, "generated suite from apt_suites"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeAptConfig(t, map[string]any{
				"apt_codename":  "local",
				"apt_upstreams": aptTwoDistros(),
				"apt_archives":  tc.archives,
			})
			_, err := loadApt(t)
			if err == nil {
				t.Fatal("Load accepted the block")
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// TestAptArchivesAccepted loads the two-distribution form and checks the
// three questions the server asks of it: which archive a codename is in,
// which roots an archive's pool asks, and what is left in the default.
func TestAptArchivesAccepted(t *testing.T) {
	writeAptConfig(t, map[string]any{
		"apt_codename":  "local",
		"apt_upstreams": aptTwoDistros(),
		"apt_archives": map[string][]string{
			"ubuntu": {"resolute", "resolute-updates"},
			"debian": {"trixie"},
		},
	})
	cfg, err := loadApt(t)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := strings.Join(cfg.AptArchiveNames(), ","); got != "debian,ubuntu" {
		t.Errorf("AptArchiveNames() = %q, want them sorted", got)
	}
	for codename, want := range map[string]string{
		"resolute": "ubuntu", "resolute-updates": "ubuntu", "trixie": "debian",
		"trixie-security": "", "local": "", "unknown": "",
	} {
		if got := cfg.AptArchiveOf(codename); got != want {
			t.Errorf("AptArchiveOf(%q) = %q, want %q", codename, got, want)
		}
	}
	for archive, want := range map[string]string{
		"ubuntu": "https://archive.ubuntu.com/ubuntu",
		"debian": "https://deb.debian.org/debian",
		"":       "https://security.debian.org/debian-security",
	} {
		if got := strings.Join(cfg.AptPoolUpstreamsIn(archive), ","); got != want {
			t.Errorf("AptPoolUpstreamsIn(%q) = %q, want %q", archive, got, want)
		}
	}
}

// TestNoAptArchivesIsUnchanged pins the absent key: every mirrored codename is
// in the default archive, whose pool asks every configured root as it did
// before the key existed.
func TestNoAptArchivesIsUnchanged(t *testing.T) {
	writeAptConfig(t, map[string]any{"apt_codename": "local", "apt_upstreams": aptTwoDistros()})
	cfg, err := loadApt(t)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.AptArchives) != 0 || len(cfg.AptArchiveNames()) != 0 {
		t.Errorf("AptArchives = %v, want none", cfg.AptArchives)
	}
	for _, codename := range cfg.MirroredAptCodenames() {
		if got := cfg.AptArchiveOf(codename); got != "" {
			t.Errorf("AptArchiveOf(%q) = %q, want the default archive", codename, got)
		}
	}
	if got, want := strings.Join(cfg.AptPoolUpstreamsIn(""), ","), strings.Join(cfg.AptPoolUpstreams(), ","); got != want {
		t.Errorf("AptPoolUpstreamsIn(\"\") = %q, want every configured root %q", got, want)
	}
}

// B198 requirement 1: apt_architectures limits the architectures the pool
// index reads, defaults to amd64 and arm64, and refuses a list that would
// read nothing or names no Debian architecture.
func TestAptArchitectures(t *testing.T) {
	writeAptConfig(t, map[string]any{"apt_codename": "local", "apt_upstreams": aptTwoDistros()})
	cfg, err := loadApt(t)
	if err != nil {
		t.Fatalf("Load without apt_architectures: %v", err)
	}
	if got := strings.Join(cfg.AptIndexArchitectures(), " "); got != "amd64 arm64" {
		t.Errorf("AptIndexArchitectures() unset = %q, want %q", got, "amd64 arm64")
	}

	writeAptConfig(t, map[string]any{"apt_codename": "local", "apt_upstreams": aptTwoDistros(), "apt_architectures": []string{"amd64", "i386"}})
	if cfg, err = loadApt(t); err != nil {
		t.Fatalf("Load with apt_architectures: %v", err)
	}
	if got := strings.Join(cfg.AptIndexArchitectures(), " "); got != "amd64 i386" {
		t.Errorf("AptIndexArchitectures() = %q, want the configured list", got)
	}

	for _, tc := range []struct {
		name   string
		arches []string
		wantIn []string
	}{
		{"empty list indexes nothing", []string{}, []string{"apt_architectures", "[]"}},
		{"upper case", []string{"amd64", "ARM64"}, []string{"apt_architectures", `"ARM64"`}},
		{"punctuation", []string{"x86_64"}, []string{"apt_architectures", `"x86_64"`}},
		{"blank entry", []string{""}, []string{"apt_architectures", `""`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeAptConfig(t, map[string]any{"apt_codename": "local", "apt_upstreams": aptTwoDistros(), "apt_architectures": tc.arches})
			_, err := loadApt(t)
			if err == nil {
				t.Fatalf("Load accepted apt_architectures %q", tc.arches)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}
