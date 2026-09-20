package policy_test

import (
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/policy"
)

// The profile expansion action reuses the triple `policy age` and `policy osv`
// already carry. internal/policy imports internal/audit, so the strings are
// spelled twice; this is what stops the two spellings drifting into a day when
// a profile's "warn" and an age policy's "warn" mean different things.
//
// It lives here rather than in internal/audit because this is the side that
// can see both packages.
func TestExpansionMatchesPolicyActions(t *testing.T) {
	for _, pair := range []struct{ expansion, action string }{
		{audit.ExpansionWarn, policy.ActionWarn},
		{audit.ExpansionBlock, policy.ActionBlock},
		{audit.ExpansionIgnore, policy.ActionIgnore},
	} {
		if pair.expansion != pair.action {
			t.Errorf("profile expansion %q and policy action %q are two spellings of one idea",
				pair.expansion, pair.action)
		}
	}
	if len(audit.Expansions()) != 3 {
		t.Errorf("Expansions() returns %d values; the triple is warn, block, ignore", len(audit.Expansions()))
	}
}
