package builder

import (
	"net/url"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// crates.io serves the sparse index and the crate tarballs from separate
// hosts, and the index host answers /download with 404. The builder composed
// its download URL from the index root, so no hosted crate could be staged;
// B14 fixed the server half and nothing here asserted either host.
func TestCargoDownloadURLUsesTheDownloadRootNotTheIndex(t *testing.T) {
	ve := manifest.VersionEntry{Version: "0.3.36"}

	cases := []struct {
		name     string
		cfg      *Config
		entry    manifest.VersionEntry
		wantHost string
		wantPath string
	}{
		{
			name:     "configured download root",
			cfg:      &Config{CargoDLUpstream: "https://static.crates.io/crates"},
			entry:    ve,
			wantHost: "static.crates.io",
			wantPath: "/crates/time/0.3.36/download",
		},
		{
			name:     "no config falls back to the download root, never the index",
			cfg:      &Config{},
			entry:    ve,
			wantHost: "static.crates.io",
			wantPath: "/crates/time/0.3.36/download",
		},
		{
			name:     "per-entry URL still overrides",
			cfg:      &Config{CargoDLUpstream: "https://static.crates.io/crates"},
			entry:    manifest.VersionEntry{Version: "0.3.36", URL: "https://mirror.example.com/crates/"},
			wantHost: "mirror.example.com",
			wantPath: "/crates/time/0.3.36/download",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cargoDownloadURL(tc.cfg, "time", tc.entry)
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("parse %q: %v", got, err)
			}
			if u.Host != tc.wantHost {
				t.Errorf("host = %q, want %q (full URL %s)", u.Host, tc.wantHost, got)
			}
			if u.Host == "index.crates.io" {
				t.Errorf("composed a download URL against the sparse index host, which serves no downloads: %s", got)
			}
			if u.Path != tc.wantPath {
				t.Errorf("path = %q, want %q", u.Path, tc.wantPath)
			}
		})
	}
}
