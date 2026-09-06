package server

import (
	"context"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

// The seeded gate has to reach the operator's terminal. A default nobody is
// told about is a default nobody can reason about when a build starts warning.
func TestBannerNamesTheSeededAgePolicy(t *testing.T) {
	s := newACLServer(t, &config.Config{})
	got := s.agePolicyBanner()
	for _, want := range []string{"npm 7d (warn)", "pypi 7d (warn)"} {
		if !strings.Contains(got, want) {
			t.Errorf("startup banner %q does not name %q", got, want)
		}
	}
}

// An install enforcing nothing says so. Printing the line only when a gate
// exists makes "no gate" and "banner not reached" the same output.
func TestBannerReportsNoAgePolicy(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{})
	for _, eco := range audit.DefaultAgeEcosystems() {
		if _, err := s.auditDB.DeleteAgePolicy(ctx, eco); err != nil {
			t.Fatalf("delete %s: %v", eco, err)
		}
	}
	if got := s.agePolicyBanner(); !strings.Contains(got, "none enforced") {
		t.Errorf("banner with no age policy = %q, want it to say none is enforced", got)
	}
}

// An ecosystem set to ignore is a row that enforces nothing, so the banner
// must not count it as coverage.
func TestBannerSkipsIgnoredEcosystems(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{})
	for _, eco := range audit.DefaultAgeEcosystems() {
		if err := s.auditDB.SetAgePolicy(ctx, audit.AgePolicy{
			Ecosystem: eco, MinAgeSeconds: audit.DefaultAgeMinSeconds, Action: "ignore",
		}); err != nil {
			t.Fatalf("set %s to ignore: %v", eco, err)
		}
	}
	if got := s.agePolicyBanner(); !strings.Contains(got, "none enforced") {
		t.Errorf("banner with every ecosystem ignored = %q, want it to say none is enforced", got)
	}
}

// A stored row for an ecosystem the age gate cannot date is what an install
// carries after writing one before the CLI refused it. Counting it as
// enforcement made the banner print "helm 7d (block)" on an install where
// every gate that runs sat on ignore.
func TestBannerSkipsEcosystemsNoGateCanDate(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{})
	for _, eco := range audit.DefaultAgeEcosystems() {
		if err := s.auditDB.SetAgePolicy(ctx, audit.AgePolicy{
			Ecosystem: eco, MinAgeSeconds: audit.DefaultAgeMinSeconds, Action: "ignore",
		}); err != nil {
			t.Fatalf("set %s to ignore: %v", eco, err)
		}
	}
	if err := s.auditDB.SetAgePolicy(ctx, audit.AgePolicy{
		Ecosystem: "helm", MinAgeSeconds: audit.DefaultAgeMinSeconds, Action: "block",
	}); err != nil {
		t.Fatalf("store an uncovered helm row: %v", err)
	}
	got := s.agePolicyBanner()
	if !strings.Contains(got, "none enforced") {
		t.Errorf("banner with only a dead helm row = %q, want it to say none is enforced", got)
	}
	if strings.Contains(got, "helm") {
		t.Errorf("banner %q names helm, which no age gate reads", got)
	}
}
