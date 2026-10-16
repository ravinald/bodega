package admit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/integration"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// verdictDouble answers from its "verdict" setting and reaches nothing.
type verdictDouble struct{ inst *integration.Instance }

func (d verdictDouble) Lookup(_ context.Context, q integration.Query) (integration.Answer, error) {
	switch d.inst.String("verdict") {
	case "flagged":
		return integration.Answer{Flagged: true, Reason: q.Name + " is on the test list"}, nil
	case "error":
		return integration.Answer{}, errors.New("429 Too Many Requests")
	}
	return integration.Answer{}, nil
}

func init() {
	integration.Register(integration.Descriptor{
		Type: "admit-double", DisplayName: "Admit double", VendorURL: "https://example.test/", Cost: integration.CostFree,
		Ecosystems: []string{manifest.TypeCargo}, DataSent: "Nothing.", DefaultAction: policy.ActionWarn, Flags: integration.FlagRisk,
		Fields: []integration.Field{{Key: "verdict", Label: "Verdict", Kind: integration.KindEnum, Default: "clean",
			Options: []string{"clean", "flagged", "error"}}},
		New: func(inst *integration.Instance) (integration.Checker, error) { return verdictDouble{inst}, nil },
	})
	integration.Register(integration.Descriptor{
		Type: "admit-malware-double", DisplayName: "Admit malware double", VendorURL: "https://example.test/", Cost: integration.CostFree,
		Ecosystems: []string{manifest.TypeCargo}, DataSent: "Nothing.", DefaultAction: policy.ActionBlock, Flags: integration.FlagMalware,
		Fields: []integration.Field{{Key: "verdict", Label: "Verdict", Kind: integration.KindEnum, Default: "clean",
			Options: []string{"clean", "flagged", "error"}}},
		New: func(inst *integration.Instance) (integration.Checker, error) { return verdictDouble{inst}, nil },
	})
}

func withIntegrations(cfg *config.Config) *config.Config {
	c := *cfg
	c.Integrations = map[string]config.Integration{
		"flagger": {"type": "admit-double", "enabled": true, "verdict": "flagged"},
		"off":     {"type": "admit-double", "enabled": false, "verdict": "flagged"},
		"outage":  {"type": "admit-double", "enabled": true, "verdict": "error"},
	}
	return &c
}

// An enabled instance records its verdict in the admission row under the
// action in force; a disabled one runs nothing and is not in the row; an
// erroring one records the error under the action, so block refuses.
func TestAdmitRunsIntegrationsUnderEachAction(t *testing.T) {
	for _, action := range []string{"", policy.ActionWarn, policy.ActionBlock, policy.ActionIgnore} {
		t.Run("action="+action, func(t *testing.T) {
			f := newAdmissionFixture(t)
			ctx := t.Context()
			want := action
			if action == "" {
				want = policy.ActionWarn // the descriptor default
			} else {
				for _, inst := range []string{"flagger", "outage"} {
					if err := f.adb.SetIntegrationPolicy(ctx, audit.IntegrationPolicy{Instance: inst, Ecosystem: manifest.TypeCargo, Action: action}); err != nil {
						t.Fatal(err)
					}
				}
			}
			name := "zq-integration-" + strings.ReplaceAll(want+action, "_", "")
			res := Admit(ctx, policy.NewChecker(f.adb), f.adb, withIntegrations(f.unsynced), crate(name), "ravi")
			row := cargoRow(t, f, name)
			for _, c := range row.Checks {
				if c.Check == "integration:off" {
					t.Errorf("the disabled instance is in the row: %+v", c)
				}
			}
			flag, outage := checkOf(t, row, "integration:flagger"), checkOf(t, row, "integration:outage")
			if flag.Action != want || outage.Action != want {
				t.Errorf("recorded actions %s, %s; want %s", flag.Action, outage.Action, want)
			}
			if !strings.Contains(flag.Detail, "on the test list") || !strings.HasPrefix(outage.Detail, "error: 429") {
				t.Errorf("details: %q, %q", flag.Detail, outage.Detail)
			}
			switch want {
			case policy.ActionWarn:
				if res.Decision != Admitted || flag.Status != audit.CheckWarn || outage.Status != audit.CheckWarn {
					t.Errorf("warn: %v, %s, %s", res.Decision, flag.Status, outage.Status)
				}
				if !strings.Contains(strings.Join(res.Warnings, "\n"), "integration:outage: error: 429") {
					t.Errorf("warn: the outage is not reported: %v", res.Warnings)
				}
			case policy.ActionBlock:
				if res.Decision != PolicyBlocked || res.Check != "integration:flagger" ||
					flag.Status != audit.CheckBlock || outage.Status != audit.CheckBlock {
					t.Errorf("block: %v %q, %s, %s", res.Decision, res.Check, flag.Status, outage.Status)
				}
			case policy.ActionIgnore:
				if res.Decision != Admitted || flag.Status != audit.CheckPass || outage.Status != audit.CheckPass {
					t.Errorf("ignore: %v, %s, %s", res.Decision, flag.Status, outage.Status)
				}
			}
			// The statement copies the row, so it names the integration too.
			found := false
			for _, e := range attest.Evaluations(row.Checks) {
				found = found || e.Check == "integration:flagger"
			}
			if !found {
				t.Error("the attestation evaluations omit the integration check")
			}
		})
	}
}

// Only the erroring instance under block: an outage refuses, it does not
// admit.
func TestAdmitOutageUnderBlockRefuses(t *testing.T) {
	f := newAdmissionFixture(t)
	ctx := t.Context()
	if err := f.adb.SetIntegrationPolicy(ctx, audit.IntegrationPolicy{Instance: "outage", Ecosystem: manifest.TypeCargo, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	cfg := *f.unsynced
	cfg.Integrations = map[string]config.Integration{"outage": {"type": "admit-double", "enabled": true, "verdict": "error"}}
	res := Admit(ctx, policy.NewChecker(f.adb), f.adb, &cfg, crate("zq-outage-crate"), "ravi")
	if res.Decision != PolicyBlocked || res.Check != "integration:outage" {
		t.Fatalf("Decision = %v, Check = %q (%s)", res.Decision, res.Check, res.Reason)
	}
	last, err := f.adb.IntegrationErrors(ctx)
	if err != nil || !strings.Contains(last["outage"].Message, "429") {
		t.Errorf("last error = %+v, %v", last, err)
	}
}

// A version never reached because an earlier one was refused still names
// every enabled integration, as not evaluated.
func TestRefusedManifestNamesIntegrationsNotRun(t *testing.T) {
	f := newAdmissionFixture(t)
	ctx := t.Context()
	if err := f.adb.SetIntegrationPolicy(ctx, audit.IntegrationPolicy{Instance: "flagger", Ecosystem: manifest.TypeCargo, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	pm := crate("zq-two-versions")
	pm.Versions = append(pm.Versions, manifest.VersionEntry{Version: "2.0.0"})
	cfg := *f.unsynced
	cfg.Integrations = map[string]config.Integration{"flagger": {"type": "admit-double", "enabled": true, "verdict": "flagged"}}
	res := Admit(ctx, policy.NewChecker(f.adb), f.adb, &cfg, pm, "ravi")
	if res.Decision != PolicyBlocked {
		t.Fatalf("Decision = %v", res.Decision)
	}
	rows, err := f.adb.Admissions(ctx, audit.AdmissionFilter{PkgType: manifest.TypeCargo, PkgName: "zq-two-versions", PkgVersion: "2.0.0"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows for 2.0.0: %d, %v", len(rows), err)
	}
	if c := checkOf(t, rows[0], "integration:flagger"); c.Status != audit.CheckNotEvaluated || c.Action != policy.ActionBlock {
		t.Errorf("2.0.0's integration check = %+v", c)
	}
}

// An override request may name an integration check by its instance.
func TestOverrideNamesIntegrationCheck(t *testing.T) {
	if !isIntegrationCheck("integration:aikido") || isIntegrationCheck("integration:") || isIntegrationCheck("integration:Bad.Name") {
		t.Error("isIntegrationCheck accepts or refuses the wrong names")
	}
}

// Evaluate runs the integrations Admit runs, under the same actions, and
// leaves no last error behind: a preview that skipped them would admit what
// the admission it previews refuses.
func TestEvaluateRunsIntegrationsLikeAdmit(t *testing.T) {
	for _, action := range []string{policy.ActionWarn, policy.ActionBlock, policy.ActionIgnore} {
		t.Run("action="+action, func(t *testing.T) {
			f := newAdmissionFixture(t)
			ctx := t.Context()
			for _, inst := range []string{"flagger", "outage"} {
				if err := f.adb.SetIntegrationPolicy(ctx, audit.IntegrationPolicy{Instance: inst, Ecosystem: manifest.TypeCargo, Action: action}); err != nil {
					t.Fatal(err)
				}
			}
			cfg := withIntegrations(f.unsynced)
			name := "zq-evaluate-" + action
			v := Evaluate(ctx, cfg, policy.NewChecker(f.adb), f.adb, nil, crate(name), time.Now())
			if last, err := f.adb.IntegrationErrors(ctx); err != nil || len(last) != 0 {
				t.Fatalf("Evaluate recorded integration errors: %+v, %v", last, err)
			}
			var flag, outage audit.AdmissionCheck
			for _, c := range v.Checks {
				switch c.Check {
				case "integration:flagger":
					flag = c
				case "integration:outage":
					outage = c
				case "integration:off":
					t.Errorf("the disabled instance ran: %+v", c)
				}
			}
			if flag.Action != action || outage.Action != action {
				t.Errorf("Evaluate actions %q, %q; want %s (%+v)", flag.Action, outage.Action, action, v.Checks)
			}
			res := Admit(ctx, policy.NewChecker(f.adb), f.adb, cfg, crate(name), "ravi")
			if res.Decision != v.Decision {
				t.Errorf("Evaluate = %v, Admit = %v (%s)", v.Decision, res.Decision, res.Reason)
			}
			if want := action == policy.ActionBlock; (v.Decision == PolicyBlocked) != want {
				t.Errorf("Evaluate = %v under %s", v.Decision, action)
			}
		})
	}
}

// A hit from a type whose flags mean malware is recorded unwaivable on the
// admission row, and an override request naming it is refused with the check
// named. A risk type's hit on the same version is recorded waivable, but a
// request naming it is refused too: the malware hit still refuses the version.
func TestOverrideRequestRefusesMalwareListHit(t *testing.T) {
	f := newAdmissionFixture(t)
	ctx := t.Context()
	if err := f.adb.SetIntegrationPolicy(ctx, audit.IntegrationPolicy{Instance: "flagger", Ecosystem: manifest.TypeCargo, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	cfg := *f.unsynced
	cfg.Integrations = map[string]config.Integration{
		"aikido":  {"type": "admit-malware-double", "enabled": true, "verdict": "flagged"},
		"flagger": {"type": "admit-double", "enabled": true, "verdict": "flagged"},
	}
	if res := Admit(ctx, policy.NewChecker(f.adb), f.adb, &cfg, crate("zq-malware-hit"), "ravi"); res.Decision != PolicyBlocked {
		t.Fatalf("Decision = %v", res.Decision)
	}
	row := cargoRow(t, f, "zq-malware-hit")
	if c := checkOf(t, row, "integration:aikido"); c.Status != audit.CheckBlock || c.Unwaivable != "known malware is never overridden" {
		t.Errorf("malware-list check = %+v", c)
	}
	if c := checkOf(t, row, "integration:flagger"); c.Unwaivable != "" {
		t.Errorf("risk check recorded unwaivable: %+v", c)
	}

	req := OverrideRequest{Type: manifest.TypeCargo, Name: "zq-malware-hit", Version: row.PkgVersion,
		Check: "integration:aikido", Reason: "vendor says false positive", Expires: "1d"}
	_, err := RequestOverride(ctx, f.adb, &cfg, req, audit.LocalOverrideCaller("alice"), time.Now())
	if !errors.Is(err, ErrInvalidOverride) || !strings.Contains(err.Error(), "integration:aikido") ||
		!strings.Contains(err.Error(), "known malware is never overridden") {
		t.Errorf("override request for a malware-list hit: %v", err)
	}
	req.Check = "integration:flagger"
	if _, err := RequestOverride(ctx, f.adb, &cfg, req, audit.LocalOverrideCaller("alice"), time.Now()); !errors.Is(err, ErrInvalidOverride) ||
		!strings.Contains(err.Error(), "also refused by integration:aikido") {
		t.Errorf("override request for a risk hit beside a malware-list hit: %v", err)
	}
}
