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
			local, err := db.Match(tc.ecosystem, tc.pkg, version)
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
