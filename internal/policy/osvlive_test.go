package policy

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestOSVLiveAgreement compares the local matcher against api.osv.dev itself
// rather than against captured fixtures. It is opt-in because it downloads
// OSV's real exports (a few hundred megabytes, npm most of it) and because a
// new advisory changes the expected answer between runs:
//
//	BODEGA_OSV_LIVE=1 go test ./internal/policy -run OSVLiveAgreement
//
// Set BODEGA_OSV_LIVE_DIR to reuse a directory an earlier sync wrote.
func TestOSVLiveAgreement(t *testing.T) {
	if os.Getenv("BODEGA_OSV_LIVE") == "" {
		t.Skip("set BODEGA_OSV_LIVE=1 to compare against api.osv.dev")
	}
	dir := os.Getenv("BODEGA_OSV_LIVE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	db := NewOSVDatabase(dir)
	ctx := context.Background()

	for _, tc := range osvAgreementCases {
		if _, err := db.Meta(tc.ecosystem); err != nil {
			if _, err := db.Sync(ctx, tc.ecosystem); err != nil {
				t.Fatalf("sync %s: %v", tc.ecosystem, err)
			}
		}
		ck := NewOSVChecker(nil)
		for _, version := range []string{tc.vulnerable, tc.clean} {
			local, _, err := db.Match(tc.ecosystem, tc.pkg, version)
			if err != nil {
				t.Fatalf("%s match: %v", tc.ecosystem, err)
			}
			remote, err := ck.query(ctx, tc.ecosystem, tc.pkg, version)
			if err != nil {
				t.Fatalf("%s query: %v", tc.ecosystem, err)
			}
			if got, want := strings.Join(vulnIDs(local), ","), strings.Join(vulnIDs(remote), ","); got != want {
				t.Errorf("%s %s@%s: local %q, api.osv.dev %q", tc.ecosystem, tc.pkg, version, got, want)
			}
		}
	}
}

// osvLiveDistroCases are the Ubuntu and Debian lookups compared against
// api.osv.dev. Each pair is one source package at two revisions of the same
// upstream release: the fix moved the revision and nothing else, which is the
// case a semver or string comparison gets wrong.
//
// Neither revision is asserted clean. Every distro package carries advisories
// nobody has fixed yet, so the claim here is agreement with the live service,
// not an empty result.
var osvLiveDistroCases = []struct {
	ecosystem string
	pkg       string
	versions  []string
}{
	{"Ubuntu:22.04:LTS", "expat", []string{"2.4.7-1ubuntu0.2", "2.4.7-1ubuntu0.6"}},
	// An epoch, and a dfsg-repacked upstream version.
	{"Ubuntu:22.04:LTS", "zlib", []string{"1:1.2.11.dfsg-2ubuntu9", "1:1.2.11.dfsg-2ubuntu9.2"}},
	{"Ubuntu:24.04:LTS", "expat", []string{"2.6.1-2build1", "2.6.1-2ubuntu0.1"}},
	// "+deb12u1" is the shape semver discards as a build tag, making the two
	// revisions compare equal and the unpatched one report clean.
	{"Debian:12", "expat", []string{"2.5.0-1", "2.5.0-1+deb12u1"}},
}

// TestOSVLiveDistroAgreement is the apt half of TestOSVLiveAgreement, kept
// apart because it downloads the aggregate Ubuntu and Debian archives (681 MB
// and 330 MB) rather than a per-ecosystem export:
//
//	BODEGA_OSV_LIVE=1 go test ./internal/policy -run OSVLiveDistroAgreement
func TestOSVLiveDistroAgreement(t *testing.T) {
	if os.Getenv("BODEGA_OSV_LIVE") == "" {
		t.Skip("set BODEGA_OSV_LIVE=1 to compare against api.osv.dev")
	}
	dir := os.Getenv("BODEGA_OSV_LIVE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	db := NewOSVDatabase(dir)
	ctx := context.Background()

	var missing []string
	for _, tc := range osvLiveDistroCases {
		if _, err := db.Meta(tc.ecosystem); err != nil {
			missing = append(missing, tc.ecosystem)
		}
	}
	for _, res := range db.SyncGroup(ctx, missing) {
		if res.Err != nil {
			t.Fatalf("sync %s: %v", res.Ecosystem, res.Err)
		}
	}

	ck := NewOSVChecker(nil)
	for _, tc := range osvLiveDistroCases {
		for _, version := range tc.versions {
			local, skipped, err := db.Match(tc.ecosystem, tc.pkg, version)
			if err != nil {
				t.Fatalf("%s match: %v", tc.ecosystem, err)
			}
			if len(skipped) > 0 {
				t.Errorf("%s %s@%s: %d record(s) no ordering could place: %v",
					tc.ecosystem, tc.pkg, version, len(skipped), skipped)
			}
			remote, err := ck.query(ctx, tc.ecosystem, tc.pkg, version)
			if err != nil {
				t.Fatalf("%s query: %v", tc.ecosystem, err)
			}
			if got, want := strings.Join(vulnIDs(local), ","), strings.Join(vulnIDs(remote), ","); got != want {
				t.Errorf("%s %s@%s:\n local %q\n   api %q", tc.ecosystem, tc.pkg, version, got, want)
			}
		}
	}
}
