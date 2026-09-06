package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

func TestNpmVersionFromTarball(t *testing.T) {
	cases := []struct {
		pkg, tarball, want string
	}{
		{"@bitwarden/cli", "cli-2026.4.0.tgz", "2026.4.0"},
		{"@bitwarden/cli", "cli-2026.4.0-beta.1.tgz", "2026.4.0-beta.1"},
		{"lodash", "lodash-4.17.21.tgz", "4.17.21"},
		// Mismatched basename — refuse to guess.
		{"@bitwarden/cli", "other-1.0.0.tgz", ""},
		// No .tgz suffix — still strips the prefix cleanly.
		{"lodash", "lodash-4.17.21", "4.17.21"},
	}
	for _, c := range cases {
		if got := npmVersionFromTarball(c.pkg, c.tarball); got != c.want {
			t.Errorf("npmVersionFromTarball(%q, %q) = %q, want %q",
				c.pkg, c.tarball, got, c.want)
		}
	}
}

func TestIsVersionHidden(t *testing.T) {
	pm := &manifest.PackageManifest{
		Versions: []manifest.VersionEntry{
			{Version: "1.0.0"},
			{Version: "2026.4.0", Hidden: true},
			{Version: "2026.4.1"},
		},
	}
	if !isVersionHidden(pm, "2026.4.0") {
		t.Error("2026.4.0 should be hidden")
	}
	if isVersionHidden(pm, "1.0.0") {
		t.Error("1.0.0 is not hidden")
	}
	if isVersionHidden(pm, "nonexistent") {
		t.Error("unknown version must not report hidden (false-positive risk)")
	}
}

func TestHasHiddenVersion(t *testing.T) {
	cases := []struct {
		name string
		pm   *manifest.PackageManifest
		want bool
	}{
		{"none hidden", &manifest.PackageManifest{Versions: []manifest.VersionEntry{
			{Version: "1.0.0"}, {Version: "2.0.0"},
		}}, false},
		{"one hidden", &manifest.PackageManifest{Versions: []manifest.VersionEntry{
			{Version: "1.0.0"}, {Version: "2.0.0", Hidden: true},
		}}, true},
		{"empty", &manifest.PackageManifest{}, false},
	}
	for _, c := range cases {
		if got := hasHiddenVersion(c.pm); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFilterPackumentByManifest_Hidden(t *testing.T) {
	raw := []byte(`{
		"name": "@bitwarden/cli",
		"dist-tags": {"latest": "2026.4.0", "next": "2026.4.1"},
		"versions": {
			"2026.3.0": {"name": "@bitwarden/cli", "version": "2026.3.0"},
			"2026.4.0": {"name": "@bitwarden/cli", "version": "2026.4.0"},
			"2026.4.1": {"name": "@bitwarden/cli", "version": "2026.4.1"}
		},
		"time": {
			"created": "2026-04-02T00:00:00Z",
			"2026.3.0": "2026-04-02T00:00:00Z",
			"2026.4.0": "2026-04-22T21:22:59Z",
			"2026.4.1": "2026-04-23T15:54:37Z"
		}
	}`)

	pm := &manifest.PackageManifest{
		Name: "@bitwarden/cli",
		Type: manifest.TypeNpm,
		Versions: []manifest.VersionEntry{
			{Version: "2026.3.0"},
			{Version: "2026.4.0", Hidden: true},
			{Version: "2026.4.1"},
		},
	}

	out, err := filterPackumentByManifest(raw, pm)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}

	// Hidden version must be gone from the versions map.
	if v, ok := doc["versions"].(map[string]any); ok {
		if _, present := v["2026.4.0"]; present {
			t.Error("filtered packument still lists 2026.4.0 in versions")
		}
		if _, present := v["2026.4.1"]; !present {
			t.Error("filtered packument dropped visible 2026.4.1")
		}
	} else {
		t.Fatal("versions key missing from filtered output")
	}

	// dist-tags pointing at hidden versions should be dropped entirely.
	// `latest` pointed at 2026.4.0 → gone. `next` pointed at 2026.4.1 → kept.
	if t_, ok := doc["dist-tags"].(map[string]any); ok {
		if _, present := t_["latest"]; present {
			t.Error(`dist-tag "latest" pointed at hidden 2026.4.0 but wasn't removed`)
		}
		if _, present := t_["next"]; !present {
			t.Error(`dist-tag "next" pointed at visible 2026.4.1 and should be kept`)
		}
	} else {
		t.Fatal("dist-tags key missing from filtered output")
	}

	// time entry for the hidden version should be gone.
	if tm, ok := doc["time"].(map[string]any); ok {
		if _, present := tm["2026.4.0"]; present {
			t.Error("filtered packument still has time entry for 2026.4.0")
		}
		if _, present := tm["2026.4.1"]; !present {
			t.Error("filtered packument dropped time entry for visible 2026.4.1")
		}
	}
}

func TestFilterPackumentByManifest_NoOp(t *testing.T) {
	raw := []byte(`{"name":"lodash","versions":{"4.17.21":{"version":"4.17.21"}}}`)
	pm := &manifest.PackageManifest{
		Versions: []manifest.VersionEntry{{Version: "4.17.21"}},
	}
	out, err := filterPackumentByManifest(raw, pm)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if string(out) != string(raw) {
		t.Errorf("expected passthrough; got rewritten bytes")
	}
}

// TestHasVersionConstraint exercises the detection helper used to decide
// whether the handler needs to run the packument through the filter.
func TestHasVersionConstraint(t *testing.T) {
	cases := []struct {
		name string
		pm   *manifest.PackageManifest
		want bool
	}{
		{"no versions", &manifest.PackageManifest{}, false},
		{"no constraint", &manifest.PackageManifest{Versions: []manifest.VersionEntry{{Version: "1.0.0"}}}, false},
		{"any constraint is trivial",
			&manifest.PackageManifest{Versions: []manifest.VersionEntry{{Version: "1.0.0", VersionConstraint: manifest.ConstraintAny}}},
			false},
		{"compatible is non-trivial",
			&manifest.PackageManifest{Versions: []manifest.VersionEntry{{Version: "2026.4.1", VersionConstraint: manifest.ConstraintCompatible}}},
			true},
		{"exact is non-trivial",
			&manifest.PackageManifest{Versions: []manifest.VersionEntry{{Version: "2026.4.1", VersionConstraint: manifest.ConstraintExact}}},
			true},
	}
	for _, c := range cases {
		if got := hasVersionConstraint(c.pm); got != c.want {
			t.Errorf("%s: hasVersionConstraint = %v, want %v", c.name, got, c.want)
		}
	}
}

// Mirrors the Bitwarden case study shape: pin 2026.4.1 via compatible
// constraint + keep 2026.4.0 as a hidden tombstone.
func TestFilterPackumentByManifest_Constraint(t *testing.T) {
	raw := []byte(`{
		"name": "@bitwarden/cli",
		"dist-tags": {"latest": "2026.4.1", "legacy": "2026.3.0"},
		"versions": {
			"2026.3.0": {"name": "@bitwarden/cli", "version": "2026.3.0"},
			"2026.4.0": {"name": "@bitwarden/cli", "version": "2026.4.0"},
			"2026.4.1": {"name": "@bitwarden/cli", "version": "2026.4.1"},
			"2026.5.0": {"name": "@bitwarden/cli", "version": "2026.5.0"}
		},
		"time": {
			"created": "2026-04-02T00:00:00Z",
			"2026.3.0": "2026-04-02T00:00:00Z",
			"2026.4.0": "2026-04-22T21:22:59Z",
			"2026.4.1": "2026-04-23T15:54:37Z",
			"2026.5.0": "2026-05-03T00:00:00Z"
		}
	}`)

	pm := &manifest.PackageManifest{
		Name: "@bitwarden/cli",
		Type: manifest.TypeNpm,
		Versions: []manifest.VersionEntry{
			{Version: "2026.4.1", VersionConstraint: manifest.ConstraintCompatible},
			{Version: "2026.4.0", Hidden: true, Frozen: true},
		},
	}

	out, err := filterPackumentByManifest(raw, pm)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}

	versions := doc["versions"].(map[string]any)
	// Below constraint: stripped.
	if _, has := versions["2026.3.0"]; has {
		t.Error("2026.3.0 should be stripped (below 2026.4.1 constraint)")
	}
	// Hidden: stripped (tombstone; also below constraint, so doubly stripped).
	if _, has := versions["2026.4.0"]; has {
		t.Error("2026.4.0 should be stripped (hidden)")
	}
	// At or above constraint, not hidden: kept.
	if _, has := versions["2026.4.1"]; !has {
		t.Error("2026.4.1 should be kept (at constraint boundary)")
	}
	if _, has := versions["2026.5.0"]; !has {
		t.Error("2026.5.0 should be kept (above constraint)")
	}

	tags := doc["dist-tags"].(map[string]any)
	if _, has := tags["latest"]; !has {
		t.Error("dist-tag latest → 2026.4.1 should survive")
	}
	if _, has := tags["legacy"]; has {
		t.Error(`dist-tag "legacy" pointed at 2026.3.0 (out-of-constraint) and should be stripped`)
	}

	times := doc["time"].(map[string]any)
	if _, has := times["created"]; !has {
		t.Error(`"created" is metadata, not a version; it should survive`)
	}
	if _, has := times["2026.3.0"]; has {
		t.Error("time entry for 2026.3.0 should be stripped")
	}
	if _, has := times["2026.4.0"]; has {
		t.Error("time entry for hidden 2026.4.0 should be stripped")
	}
	if _, has := times["2026.4.1"]; !has {
		t.Error("time entry for in-constraint 2026.4.1 should survive")
	}
}

// tarballOf pulls one version's dist.tarball out of a packument body.
func tarballOf(t *testing.T, body []byte, version string) string {
	t.Helper()
	var doc struct {
		Versions map[string]struct {
			Dist struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal packument: %v (body %s)", err, truncateForTest(body))
	}
	v, ok := doc.Versions[version]
	if !ok {
		t.Fatalf("packument has no version %s (body %s)", version, truncateForTest(body))
	}
	return v.Dist.Tarball
}

func truncateForTest(b []byte) string {
	if len(b) > 400 {
		return string(b[:400]) + "…"
	}
	return string(b)
}

// A scoped package carries the scope in its tarball path, and bodega's own
// route splits it back out on "/-/". Composed wrong, the scope lands in the
// filename half and every scoped install 404s.
func TestRewriteNpmPackumentScoped(t *testing.T) {
	raw := []byte(`{
		"name": "@scope/pkg",
		"versions": {
			"1.0.0": {"name":"@scope/pkg","version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz","integrity":"sha512-aaa"}}
		}
	}`)
	out, err := rewriteNpmPackument(raw, "https://bodega.example.com/npm", "@scope/pkg")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	const want = "https://bodega.example.com/npm/@scope/pkg/-/pkg-1.0.0.tgz"
	if got := tarballOf(t, out, "1.0.0"); got != want {
		t.Errorf("dist.tarball = %q, want %q", got, want)
	}
	// The integrity hash is the client's check on the bytes; a rewrite that
	// drops it has clients install what they cannot verify.
	if !strings.Contains(string(out), "sha512-aaa") {
		t.Errorf("rewrite dropped dist.integrity: %s", truncateForTest(out))
	}
}

// The upstream host is not what the rewrite keys on. A packument whose
// tarballs already live on a private registry or a CDN has to land on bodega
// the same way registry.npmjs.org's does — which is what separates a rewrite
// from a strings.Replace of the default hostname.
func TestRewriteNpmPackumentNonDefaultHost(t *testing.T) {
	raw := []byte(`{
		"name": "widget",
		"dist": {"tarball": "https://npm.corp.internal/artifacts/widget-3.0.0.tgz"},
		"versions": {
			"1.0.0": {"version":"1.0.0","dist":{"tarball":"https://npm.corp.internal/deep/nested/path/widget-1.0.0.tgz"}},
			"2.0.0": {"version":"2.0.0","dist":{"tarball":"https://cdn.example.net/t/widget-2.0.0.tgz?sig=abc"}}
		}
	}`)
	out, err := rewriteNpmPackument(raw, "https://bodega.example.com/npm", "widget")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	for version, want := range map[string]string{
		"1.0.0": "https://bodega.example.com/npm/widget/-/widget-1.0.0.tgz",
		"2.0.0": "https://bodega.example.com/npm/widget/-/widget-2.0.0.tgz",
	} {
		if got := tarballOf(t, out, version); got != want {
			t.Errorf("version %s: dist.tarball = %q, want %q", version, got, want)
		}
	}
	for _, host := range []string{"npm.corp.internal", "cdn.example.net"} {
		if strings.Contains(string(out), host) {
			t.Errorf("rewritten packument still names %s: %s", host, truncateForTest(out))
		}
	}
	// The version-manifest route (/npm/{pkg}/{version}) answers with a
	// top-level dist and no versions map. Left alone it is the same bypass.
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	dist, _ := doc["dist"].(map[string]any)
	if got := dist["tarball"]; got != "https://bodega.example.com/npm/widget/-/widget-3.0.0.tgz" {
		t.Errorf("top-level dist.tarball = %v, want the bodega route", got)
	}
}

// A packument too large to buffer is refused, not relayed: served unrewritten
// it points the client straight past bodega, which is the defect. The cap is
// the one the filtered path already imposes through fetchUpstream, so neither
// packument path is bounded by the spool.
func TestNpmPackumentOverTheBufferIsRefused(t *testing.T) {
	saved := maxUpstreamBody
	maxUpstreamBody = 64
	t.Cleanup(func() { maxUpstreamBody = saved })

	rec := httptest.NewRecorder()
	w := &npmPackumentWriter{ResponseWriter: rec, base: "https://bodega.example.com/npm", pkg: "big"}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(strings.Repeat("x", 128))); err == nil {
		t.Error("Write past the cap returned nil; the copy would read a body nothing can use")
	}
	if err := w.flush(); err == nil {
		t.Error("flush returned nil for a body it could not rewrite")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

const npmFixturePackument = `{
	"name": "@scope/pkg",
	"dist-tags": {"latest": "1.1.0"},
	"versions": {
		"1.0.0": {"name":"@scope/pkg","version":"1.0.0","dist":{"tarball":"%[1]s/@scope/pkg/-/pkg-1.0.0.tgz"}},
		"1.1.0": {"name":"@scope/pkg","version":"1.1.0","dist":{"tarball":"%[1]s/@scope/pkg/-/pkg-1.1.0.tgz"}}
	},
	"time": {"created":"2026-01-01T00:00:00Z","1.0.0":"2026-01-01T00:00:00Z","1.1.0":"2026-02-01T00:00:00Z"}
}`

// The filtered and unfiltered packument paths are two functions serving one
// document, and a client that trips the filter must not be told a different
// URL from one that does not. The cache hit is the third answer to the same
// question: the rewrite runs on the way out, so it applies to a stored copy
// that still carries the upstream URL.
func TestNpmPackumentRewriteIsTheSameOnEveryPath(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/@scope/pkg", fmt.Sprintf(npmFixturePackument, up.ts.URL))
	s.cfg.NpmUpstream = up.ts.URL

	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	get := func() []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/npm/@scope/pkg", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET packument: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read packument: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, truncateForTest(body))
		}
		return body
	}

	want := ts.URL + "/npm/@scope/pkg/-/pkg-1.1.0.tgz"
	miss := tarballOf(t, get(), "1.1.0")
	if miss != want {
		t.Errorf("cache miss: dist.tarball = %q, want %q", miss, want)
	}
	hit := tarballOf(t, get(), "1.1.0")
	if hit != want {
		t.Errorf("cache hit: dist.tarball = %q, want %q", hit, want)
	}
	// Without this the second request could have been another miss, and the
	// assertion above would say nothing about the path that serves from
	// storage.
	var fetches int
	for _, p := range up.paths() {
		if p == "/@scope/pkg" {
			fetches++
		}
	}
	if fetches != 1 {
		t.Errorf("upstream saw %d packument fetches for two requests, want 1: the second must be a cache hit", fetches)
	}

	// The stored object stays the document the registry served. Rewritten
	// before the cache write it would carry this instance's public_url, which
	// is wrong the moment that key changes or a second instance shares the
	// store.
	cached, err := s.typeStore(manifest.TypeNpm).GetStream(t.Context(), manifest.NpmPackumentKey("@scope/pkg"))
	if err != nil || cached == nil {
		t.Fatalf("read the cached packument: %v", err)
	}
	defer func() { _ = cached.Body.Close() }()
	stored, err := io.ReadAll(cached.Body)
	if err != nil {
		t.Fatalf("read the cached packument body: %v", err)
	}
	if got := tarballOf(t, stored, "1.1.0"); got != up.ts.URL+"/@scope/pkg/-/pkg-1.1.0.tgz" {
		t.Errorf("cached dist.tarball = %q, want the upstream URL untouched", got)
	}

	// Hiding 1.0.0 sends the same package down serveFilteredPackument.
	pm := &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          "@scope/pkg",
		Type:          manifest.TypeNpm,
		Versions: []manifest.VersionEntry{
			{Version: "1.1.0", Mode: manifest.ModeProxy},
			{Version: "1.0.0", Hidden: true},
		},
	}
	if err := s.store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("seed npm/@scope/pkg: %v", err)
	}
	filtered := get()
	if got := tarballOf(t, filtered, "1.1.0"); got != want {
		t.Errorf("filtered path: dist.tarball = %q, want %q", got, want)
	}
	if strings.Contains(string(filtered), `"1.0.0"`) {
		t.Errorf("filtered packument still lists the hidden 1.0.0: %s", truncateForTest(filtered))
	}
}
