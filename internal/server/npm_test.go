package server

import (
	"encoding/json"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

func TestNpmSafeName(t *testing.T) {
	cases := map[string]string{
		"@bitwarden/cli": "@bitwarden--cli",
		"@aws-sdk/s3":    "@aws-sdk--s3",
		"lodash":         "lodash",
		"":               "",
	}
	for in, want := range cases {
		if got := npmSafeName(in); got != want {
			t.Errorf("npmSafeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNpmStorageKeyForTarball(t *testing.T) {
	cases := []struct {
		pkg, tarball, want string
	}{
		// Scoped: URL form → safe-encoded path + safe-encoded filename.
		{"@bitwarden/cli", "cli-2026.3.0.tgz", "npm/@bitwarden--cli/@bitwarden--cli-2026.3.0.tgz"},
		{"@aws-sdk/client-s3", "client-s3-3.500.0.tgz", "npm/@aws-sdk--client-s3/@aws-sdk--client-s3-3.500.0.tgz"},
		// Unscoped: URL and storage forms identical.
		{"lodash", "lodash-4.17.21.tgz", "npm/lodash/lodash-4.17.21.tgz"},
		// Unparseable URL-form tarball: fall through to the URL filename so
		// we still 404 cleanly rather than constructing a garbage key.
		{"@bitwarden/cli", "not-matching-prefix.tgz", "npm/@bitwarden--cli/not-matching-prefix.tgz"},
	}
	for _, c := range cases {
		if got := npmStorageKeyForTarball(c.pkg, c.tarball); got != c.want {
			t.Errorf("npmStorageKeyForTarball(%q, %q) = %q, want %q",
				c.pkg, c.tarball, got, c.want)
		}
	}
}

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

func TestFilterHiddenFromPackument(t *testing.T) {
	// A trimmed-down packument resembling what npmjs.org returns.
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

	out, err := filterHiddenFromPackument(raw, pm)
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

// No hidden versions → passthrough (same bytes).
func TestFilterHiddenFromPackument_NoOp(t *testing.T) {
	raw := []byte(`{"name":"lodash","versions":{"4.17.21":{"version":"4.17.21"}}}`)
	pm := &manifest.PackageManifest{
		Versions: []manifest.VersionEntry{{Version: "4.17.21"}},
	}
	out, err := filterHiddenFromPackument(raw, pm)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if string(out) != string(raw) {
		t.Errorf("expected passthrough; got rewritten bytes")
	}
}
