package main

import (
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/policy"
)

// blockedCreate is the Result admit.Create returns when r refuses version
// 1.0.0, with the admission row recording r the way admission does: its
// Unwaivable comes from the same classifier that writes the row.
func blockedCreate(r policy.Result) admit.Result {
	c := audit.AdmissionCheck{Check: r.Check, Action: policy.ActionBlock, Status: audit.CheckBlock,
		Detail: r.Reason, Provenance: r.Provenance, Unwaivable: admit.Unwaivable(r)}
	return admit.Result{
		Decision: admit.PolicyBlocked,
		Reason:   r.Reason,
		Admissions: []audit.Admission{{PkgType: "npm", PkgName: "minimist", PkgVersion: "1.0.0",
			Decision: audit.AdmissionPolicyBlocked, Checks: []audit.AdmissionCheck{c}}},
		Check:    r.Check,
		Version:  "1.0.0",
		Incident: "inc-test",
		Details:  r.Details,
	}
}

// A check no override can lift gets no override command; the hint says why in
// the row's words and names the incident. An age refusal keeps the command.
func TestOverrideHintOmitsUnwaivableChecks(t *testing.T) {
	const cmd = "bodega override request"
	for _, tc := range []struct {
		name string
		r    policy.Result
		why  string
	}{
		{"osv malware", policy.Result{Check: audit.CheckOSV, Action: policy.ActionBlock, Reason: "known malware: MAL-2026-1",
			Details: map[string]any{"malware": []string{"MAL-2026-1"}}}, "known malware is never overridden"},
		{"invalid provenance", policy.Result{Check: audit.CheckUpstreamProvenance, Action: policy.ActionBlock, Reason: "signature did not verify",
			Provenance: &audit.UpstreamProvenance{Outcome: audit.ProvenanceInvalid}}, "invalid upstream provenance is never overridden"},
		{"malware-list integration", policy.Result{Check: "integration:aikido", Action: policy.ActionBlock, Reason: "flagged as malware",
			Details: map[string]any{"malware": true}}, "known malware is never overridden"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := blockedCreate(tc.r)
			if res.Admissions[0].Checks[0].Unwaivable == "" {
				t.Fatalf("fixture: admission does not classify %+v as unwaivable", tc.r)
			}
			got := overrideHint("npm", "minimist", res)
			if strings.Contains(got, cmd) {
				t.Errorf("hint names an override no override can lift:\n%s", got)
			}
			if !strings.Contains(got, tc.why) || !strings.Contains(got, "inc-test") {
				t.Errorf("hint does not give the row's reason %q and the incident:\n%s", tc.why, got)
			}
		})
	}

	t.Run("age", func(t *testing.T) {
		res := blockedCreate(policy.Result{Check: audit.CheckAge, Action: policy.ActionBlock, Reason: "published 2h ago"})
		want := "To admit it anyway, request an override for a second identity to approve:\n" +
			"  bodega override request npm minimist 1.0.0 --check age --reason \"<why>\" --expires 7d"
		if got := overrideHint("npm", "minimist", res); got != want {
			t.Errorf("age hint =\n%s\nwant\n%s", got, want)
		}
	})

	t.Run("no audit rows", func(t *testing.T) {
		res := blockedCreate(policy.Result{Check: audit.CheckOSV, Action: policy.ActionBlock, Reason: "known malware: MAL-2026-1",
			Details: map[string]any{"malware": []string{"MAL-2026-1"}}})
		res.Admissions = nil
		if got := overrideHint("npm", "minimist", res); !strings.Contains(got, cmd+" npm minimist 1.0.0 --check osv") {
			t.Errorf("without admission rows the hint changed:\n%s", got)
		}
	})
}
