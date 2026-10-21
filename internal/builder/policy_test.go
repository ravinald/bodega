package builder

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

type staticStore struct{ rules map[string][]policy.Rule }

func (s staticStore) GetPoliciesByType(_ context.Context, t string) ([]policy.Rule, error) {
	return s.rules[t], nil
}

func TestEnforcePolicyAllowsWhenNoChecker(t *testing.T) {
	c := &Config{}
	if err := c.EnforcePolicy(context.Background(), manifest.TypePypi, "django", manifest.VersionEntry{Version: "4.2"}); err != nil {
		t.Errorf("nil checker should pass: %v", err)
	}
}

func TestEnforcePolicyAllowsWhenMatch(t *testing.T) {
	store := staticStore{rules: map[string][]policy.Rule{
		manifest.TypePypi: {audit.PolicyInfo{RegistryType: manifest.TypePypi, RuleKind: policy.KindPackage, Pattern: "django"}},
	}}
	c := &Config{policyChecker: policy.NewChecker(store)}
	if err := c.EnforcePolicy(context.Background(), manifest.TypePypi, "django", manifest.VersionEntry{Version: "4.2"}); err != nil {
		t.Errorf("django should match: %v", err)
	}
}

func TestEnforcePolicyBlocksWhenNoMatch(t *testing.T) {
	store := staticStore{rules: map[string][]policy.Rule{
		manifest.TypePypi: {audit.PolicyInfo{RegistryType: manifest.TypePypi, RuleKind: policy.KindPackage, Pattern: "django"}},
	}}
	c := &Config{policyChecker: policy.NewChecker(store)}
	err := c.EnforcePolicy(context.Background(), manifest.TypePypi, "requests", manifest.VersionEntry{Version: "2.31"})
	if !policy.IsViolation(err) {
		t.Fatalf("requests should be blocked, got %v", err)
	}
}

// approvedOverride records an allow-list override on minimist@version,
// requested at at by alice and approved by bob a minute later.
func approvedOverride(t *testing.T, adb *audit.DB, version, expires string, at time.Time) audit.Override {
	t.Helper()
	o, err := admit.RequestOverride(t.Context(), adb, &config.Config{}, admit.OverrideRequest{
		Type: manifest.TypeNpm, Name: "minimist", Version: version, Check: audit.CheckAllowList,
		Reason: "vendored mirror pending review, INC-2", Expires: expires,
	}, audit.LocalOverrideCaller("alice"), at)
	if err != nil {
		t.Fatalf("RequestOverride: %v", err)
	}
	if _, err := admit.VoteOverride(t.Context(), adb, o.ID, audit.LocalOverrideCaller("bob"), true, "", at.Add(time.Minute)); err != nil {
		t.Fatalf("VoteOverride: %v", err)
	}
	return o
}

func fetchViolations(t *testing.T, adb *audit.DB, version string) int {
	t.Helper()
	rows, err := adb.Query(t.Context(), audit.Filter{EventType: audit.EventFetch})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	n := 0
	for _, row := range rows {
		if row.Status == "policy_violation" && row.PkgVersion == version {
			n++
		}
	}
	return n
}

// An approved allow-list override admits the fetch the list refuses: the row
// records the refusal overridden and names the override, and no
// policy_violation is written, since nobody was refused. Past its expiry the
// same entry is refused and the event is written.
func TestEnforcePolicyAdmitsPastAnAllowListOverride(t *testing.T) {
	for _, tc := range []struct {
		name    string
		age     time.Duration
		expires string
		admit   bool
	}{
		{"active", 0, "7d", true},
		{"expired", 2 * time.Hour, "1h", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, out := admissionConfig(t, true)
			if err := c.AuditDB.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeNpm,
				RuleKind: policy.KindPackage, Pattern: "lodash"}); err != nil {
				t.Fatalf("InsertPolicy: %v", err)
			}
			o := approvedOverride(t, c.AuditDB, "1.2.8", tc.expires, time.Now().Add(-tc.age))

			err := c.EnforcePolicy(t.Context(), manifest.TypeNpm, "minimist", manifest.VersionEntry{Version: "1.2.8"})
			row := onlyAdmission(t, c, manifest.TypeNpm, "minimist", "1.2.8")
			allow := audit.AdmissionCheck{}
			for _, ck := range row.Checks {
				if ck.Check == audit.CheckAllowList {
					allow = ck
				}
			}
			violations := fetchViolations(t, c.AuditDB, "1.2.8")
			if !tc.admit {
				if !policy.IsViolation(err) || allow.Status != audit.CheckBlock || violations != 1 {
					t.Errorf("expired override: err %v, allowlist %+v, %d policy_violation events; want refused with one", err, allow, violations)
				}
				return
			}
			if err != nil {
				t.Fatalf("EnforcePolicy = %v, want the override to admit it", err)
			}
			if allow.Status != audit.CheckOverridden || allow.Override != o.ID || row.Decision != audit.AdmissionAdmitted {
				t.Errorf("row = %s with allowlist %+v, want admitted and overridden by %s", row.Decision, allow, o.ID)
			}
			if violations != 0 {
				t.Errorf("an overridden refusal wrote %d policy_violation events, want none", violations)
			}
			if !strings.Contains(out.String(), o.ID) {
				t.Errorf("the build output does not name override %s: %q", o.ID, out.String())
			}
		})
	}
}
