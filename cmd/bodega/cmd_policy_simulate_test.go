package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// simulateFixture stores minimist 1.2.0 (named by the OSV database) and lodash
// 4.17.21 in the manifest store, and records left-pad 1.3.0 as a version the
// proxy admitted that the store does not list.
func simulateFixture(t *testing.T, osvAction string) *prefetchFixture {
	t.Helper()
	f := newPrefetchFixture(t, osvAction)
	store := manifest.NewLocalStore(f.manifests)
	for name, version := range map[string]string{"minimist": "1.2.0", "lodash": "4.17.21"} {
		pm := &manifest.PackageManifest{ConfigVersion: manifest.CurrentConfigVersion, Type: manifest.TypeNpm, Name: name,
			Versions: []manifest.VersionEntry{{Version: version, Mode: manifest.ModeProxy}}}
		if err := store.SavePackage(t.Context(), pm); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatal(err)
	}
	adb := f.open(t)
	defer adb.Close()
	if err := adb.RecordAdmission(t.Context(), audit.Admission{PkgType: manifest.TypeNpm, PkgName: "left-pad", PkgVersion: "1.3.0",
		Decision: audit.AdmissionAdmitted, DecidedAt: time.Now(),
		Checks: []audit.AdmissionCheck{{Check: audit.CheckAllowList, Action: audit.ActionNone, Status: audit.CheckPass}}}); err != nil {
		t.Fatal(err)
	}
	return f
}

func runSimulate(t *testing.T, args ...string) simulation {
	t.Helper()
	cmd := newPolicySimulateCmd(&globalFlags{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(append(args, "--json"))
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err != nil {
		t.Fatalf("policy simulate %v: %v", args, err)
	}
	var sim simulation
	if err := json.Unmarshal(out.Bytes(), &sim); err != nil {
		t.Fatalf("parse %q: %v", out.String(), err)
	}
	return sim
}

func policyState(t *testing.T, f *prefetchFixture) string {
	t.Helper()
	adb := f.open(t)
	defer adb.Close()
	osv, _ := adb.ListOSVPolicies(t.Context())
	rules, _ := adb.ListPolicies(t.Context())
	digest, err := policy.Digest(t.Context(), adb)
	if err != nil {
		t.Fatal(err)
	}
	return installState(t, f) + " osv=" + strings.Repeat("x", len(osv)) + " rules=" + strings.Repeat("x", len(rules)) + " digest=" + digest
}

func TestPolicySimulateNewlyBlocks(t *testing.T) {
	f := simulateFixture(t, policy.ActionWarn)
	before := policyState(t, f)

	sim := runSimulate(t, "--osv", "npm=block")
	if sim.Evaluated != 3 {
		t.Errorf("evaluated %d versions; want the two stored and the one the proxy admitted", sim.Evaluated)
	}
	if len(sim.Changes) != 1 {
		t.Fatalf("changes = %+v; want minimist alone", sim.Changes)
	}
	c := sim.Changes[0]
	if c.Name != "minimist" || c.Before != audit.AdmissionAdmitted || c.After != audit.AdmissionPolicyBlocked ||
		len(c.Checks) != 1 || c.Checks[0].Check != audit.CheckOSV || c.Checks[0].After != audit.CheckBlock ||
		!strings.Contains(c.Checks[0].Detail, "GHSA-test-0001") {
		t.Fatalf("change = %+v; want minimist newly blocked by osv, naming the advisory", c)
	}
	if after := policyState(t, f); after != before {
		t.Fatalf("simulate wrote something:\nbefore %s\nafter  %s", before, after)
	}
}

func TestPolicySimulateNewlyAdmits(t *testing.T) {
	f := simulateFixture(t, policy.ActionWarn)
	adb := f.open(t)
	if err := adb.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeNpm,
		RuleKind: policy.RuleKindForType(manifest.TypeNpm), Pattern: "lodash"}); err != nil {
		t.Fatal(err)
	}
	adb.Close()
	rules := f.write(t, "rules.json", `{"npm": ["lodash", "minimist", "left-pad"]}`)
	before := policyState(t, f)

	sim := runSimulate(t, "--allow-file", rules)
	got := map[string]simulatedChange{}
	for _, c := range sim.Changes {
		got[c.Name] = c
	}
	for _, name := range []string{"minimist", "left-pad"} {
		c, ok := got[name]
		if !ok || c.Before != audit.AdmissionPolicyBlocked || c.After != audit.AdmissionAdmitted ||
			len(c.Checks) == 0 || c.Checks[0].Check != audit.CheckAllowList || c.Checks[0].Before != audit.CheckBlock {
			t.Errorf("%s change = %+v (present %v); want newly admitted by the allow-list", name, c, ok)
		}
	}
	if _, ok := got["lodash"]; ok || len(sim.Changes) != 2 {
		t.Errorf("changes = %+v; lodash is allowed either way", sim.Changes)
	}
	if after := policyState(t, f); after != before {
		t.Fatalf("simulate wrote something:\nbefore %s\nafter  %s", before, after)
	}
}

func TestPolicySimulateRefusesWhatSetRefuses(t *testing.T) {
	newPrefetchFixture(t, policy.ActionWarn)
	for _, args := range [][]string{
		{},
		{"--osv", "helm=block"},
		{"--osv", "npm=deny"},
		{"--age", "npm=block"},
		{"--age", "apt=7d:block"},
	} {
		cmd := newPolicySimulateCmd(&globalFlags{})
		cmd.SetArgs(args)
		cmd.SetOut(&bytes.Buffer{})
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		if err := cmd.Execute(); err == nil {
			t.Errorf("policy simulate %v succeeded; want a refusal", args)
		}
	}
}
