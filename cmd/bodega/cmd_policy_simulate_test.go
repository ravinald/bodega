package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/integration/malwarelist"
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

func TestPolicySimulateEmptyListUnderListedMode(t *testing.T) {
	f := simulateFixture(t, policy.ActionWarn)
	adb := f.open(t)
	for i, name := range []string{"lodash", "minimist", "left-pad"} {
		if err := adb.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r" + strings.Repeat("x", i), RegistryType: manifest.TypeNpm,
			RuleKind: policy.RuleKindForType(manifest.TypeNpm), Pattern: name}); err != nil {
			t.Fatal(err)
		}
	}
	if err := adb.SetAdmissionMode(t.Context(), audit.AdmissionMode{Ecosystem: manifest.TypeNpm, Mode: audit.ModeListed, Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	adb.Close()
	rules := f.write(t, "rules.json", `{"npm": []}`)
	before := policyState(t, f)

	sim := runSimulate(t, "--allow-file", rules)
	if len(sim.Changes) != 3 {
		t.Fatalf("changes = %+v; want every admitted npm version, since listed mode with no rules refuses every name", sim.Changes)
	}
	for _, c := range sim.Changes {
		if c.Before != audit.AdmissionAdmitted || c.After != audit.AdmissionPolicyBlocked ||
			len(c.Checks) == 0 || c.Checks[0].Check != audit.CheckAllowList || c.Checks[0].After != audit.CheckBlock {
			t.Errorf("%s change = %+v; want newly blocked by the allow-list", c.Name, c)
		}
	}
	if after := policyState(t, f); after != before {
		t.Fatalf("simulate wrote something:\nbefore %s\nafter  %s", before, after)
	}
}

// simulateAgrees checks a simulation's verdict on minimist against what
// admission decides once the change is made for real.
func simulateAgrees(t *testing.T, f *prefetchFixture, sim simulation) {
	t.Helper()
	for _, c := range sim.Changes {
		if c.Name == "minimist" {
			t.Fatalf("changes = %+v; minimist stays admitted", sim.Changes)
		}
	}
	adb := f.open(t)
	defer adb.Close()
	if err := adb.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(&globalFlags{})
	if err != nil {
		t.Fatal(err)
	}
	pm, err := manifest.NewLocalStore(f.manifests).GetPackage(t.Context(), manifest.TypeNpm, "minimist")
	if err != nil || pm == nil {
		t.Fatalf("load minimist: %v", err)
	}
	if res := admit.Admit(t.Context(), policy.NewChecker(adb), adb, cfg, pm, "test"); !res.OK() {
		t.Fatalf("admission under npm=block = %s (%s); the simulation said it would stay admitted", res.Decision, res.Reason)
	}
}

func TestPolicySimulateHonorsBaseline(t *testing.T) {
	f := simulateFixture(t, policy.ActionWarn)
	storeBaseline(t, f, "minimist", "1.2.0")
	sim := runSimulate(t, "--osv", "npm=block")
	simulateAgrees(t, f, sim)
}

func TestPolicySimulateHonorsOverride(t *testing.T) {
	f := simulateFixture(t, policy.ActionWarn)
	adb := f.open(t)
	now := time.Now()
	o := audit.Override{ID: "o1", PkgType: manifest.TypeNpm, PkgName: "minimist", PkgVersion: "1.2.0", Check: audit.CheckOSV,
		Reason: "patched in the vendored build", RequestedBy: "alice", RequestedAt: now, ExpiresAt: now.Add(24 * time.Hour), Quorum: 2}
	if err := adb.InsertOverride(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	if got, err := adb.VoteOverride(t.Context(), o.ID, "bob", audit.VoteApprove, "", now); err != nil || got.State != audit.OverrideApproved {
		t.Fatalf("vote = %+v, %v; want the override approved", got, err)
	}
	adb.Close()
	sim := runSimulate(t, "--osv", "npm=block")
	simulateAgrees(t, f, sim)
}

func TestPolicySimulateBaselineDoesNotCoverMalware(t *testing.T) {
	f := simulateFixture(t, policy.ActionWarn)
	storeBaseline(t, f, "evil-pkg", "1.0.0")
	adb := f.open(t)
	if err := adb.SetOSVMalwarePolicy(t.Context(), audit.OSVMalwarePolicy{Ecosystem: manifest.TypeNpm, Action: policy.ActionWarn}); err != nil {
		t.Fatal(err)
	}
	adb.Close()

	sim := runSimulate(t, "--osv", "npm=block")
	for _, c := range sim.Changes {
		if c.Name == "evil-pkg" {
			if c.Before != audit.AdmissionAdmitted || c.After != audit.AdmissionPolicyBlocked ||
				len(c.Checks) != 1 || c.Checks[0].Check != audit.CheckOSV || !strings.Contains(c.Checks[0].Detail, "baseline mark does not apply") {
				t.Fatalf("change = %+v; want evil-pkg newly blocked by osv, the mark refused for malware", c)
			}
			return
		}
	}
	t.Fatalf("changes = %+v; want evil-pkg newly blocked: a baseline mark never admits known malware", sim.Changes)
}

// A proposal equal to current policy moves nothing, even when an integration
// under block fails its first lookup and answers the next: the malware list
// below answers 503 to its first download and serves a list after that.
func TestPolicySimulateIgnoresTransientIntegrationError(t *testing.T) {
	var fetches atomic.Int32
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fetches.Add(1) == 1 {
			http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`[{"package_name":"evil-pkg","version":"1.0.0","reason":"test"}]`))
	}))
	t.Cleanup(list.Close)
	f := simulateFixture(t, policy.ActionWarn)
	adb := f.open(t)
	defer adb.Close()
	if err := adb.SetIntegrationPolicy(t.Context(), audit.IntegrationPolicy{Instance: "flaky", Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	gf := &globalFlags{}
	cfg, err := loadConfig(gf)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Integrations = map[string]config.Integration{"flaky": {"type": malwarelist.Type, "enabled": true, "url": list.URL}}
	store, err := loadStore(gf)
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := parsePolicyChange(adb, []string{"npm=warn"}, nil, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	sim, err := simulatePolicy(t.Context(), cfg, adb, store, proposed)
	if err != nil {
		t.Fatal(err)
	}
	if fetches.Load() < 2 {
		t.Fatalf("the list was fetched %d time(s); the test needs the failure and an answer", fetches.Load())
	}
	if sim.Evaluated != 3 || len(sim.Changes) != 0 {
		t.Fatalf("evaluated=%d changes=%+v; a no-op proposal moves nothing", sim.Evaluated, sim.Changes)
	}
}
