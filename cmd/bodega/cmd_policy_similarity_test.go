package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

func runPolicy(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var errb bytes.Buffer
	stdout = captureStdout(t, func() {
		cmd := newPolicyCmd(&globalFlags{})
		cmd.SetArgs(args)
		cmd.SetIn(strings.NewReader(stdin))
		cmd.SetErr(&errb)
		cmd.SetOut(os.Stdout)
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		err = cmd.Execute()
	})
	return stdout, errb.String(), err
}

func pypiRules(t *testing.T, adbPath string) []string {
	t.Helper()
	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	rules, err := adb.GetPoliciesByType(t.Context(), manifest.TypePypi)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rules {
		out = append(out, r.Pattern)
	}
	return out
}

// An exact rule near a popular name is asked about, naming both, and only a
// yes writes it.
func TestPolicyAddConfirmsANearPopularName(t *testing.T) {
	adbPath := admissionInstall(t, false)

	_, stderr, err := runPolicy(t, "n\n", "add", "pypi", "reqeusts")
	if err == nil {
		t.Fatal("a no added the rule")
	}
	for _, want := range []string{"reqeusts", "requests", "distance 1"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("prompt does not name %q:\n%s", want, stderr)
		}
	}
	if _, _, err := runPolicy(t, "", "add", "pypi", "reqeusts"); err == nil {
		t.Error("a stdin that ended before an answer added the rule")
	}
	if got := pypiRules(t, adbPath); len(got) != 0 {
		t.Fatalf("rules after refusals = %v", got)
	}

	if _, _, err := runPolicy(t, "y\n", "add", "pypi", "reqeusts"); err != nil {
		t.Fatalf("a yes: %v", err)
	}
	_, stderr, err = runPolicy(t, "", "add", "pypi", "requests")
	if err != nil || strings.Contains(stderr, "WARNING") {
		t.Fatalf("a popular name prompted or failed: %v\n%s", err, stderr)
	}
	if got := strings.Join(pypiRules(t, adbPath), ","); got != "reqeusts,requests" && got != "requests,reqeusts" {
		t.Errorf("rules = %s", got)
	}
}

func TestPolicySimilaritySetListLoad(t *testing.T) {
	adbPath := admissionInstall(t, false)

	if _, _, err := runPolicy(t, "", "similarity", "set", "gomod", "block"); err == nil {
		t.Error("set accepted gomod, which has no popular list")
	}
	if _, _, err := runPolicy(t, "", "similarity", "set", "pypi", "block"); err != nil {
		t.Fatalf("set: %v", err)
	}
	file := filepath.Join(t.TempDir(), "top.txt")
	if err := os.WriteFile(file, []byte("# source: internal mirror\n# date: 2026-10-12\nacme-core\nacme-cli\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runPolicy(t, "", "similarity", "load", "npm", file); err != nil {
		t.Fatalf("load: %v", err)
	}
	out, _, err := runPolicy(t, "", "similarity", "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, want := range []string{"pypi", "block", "warn (default)", "loaded list of 2, 2026-10-12", "internal mirror", "embedded list of 1000", "Exempt as in use before the check: 0 package names"} {
		if !strings.Contains(out, want) {
			t.Errorf("list does not show %q:\n%s", want, out)
		}
	}

	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	if p, err := adb.GetSimilarityPolicy(t.Context(), manifest.TypePypi); err != nil || p.Action != "block" || p.Actor == "" {
		t.Errorf("stored policy = %+v, %v", p, err)
	}
}

func runDiscoverStdin(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var errb bytes.Buffer
	stdout = captureStdout(t, func() {
		cmd := newDiscoverCmd(&globalFlags{})
		cmd.SetArgs(args)
		cmd.SetIn(strings.NewReader(stdin))
		cmd.SetErr(&errb)
		cmd.SetOut(os.Stdout)
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		err = cmd.Execute()
	})
	return stdout, errb.String(), err
}

func pypiDenial(name string) audit.DiscoveryRow {
	return audit.DiscoveryRow{RegistryType: manifest.TypePypi, Host: "pypi.org", PatternHint: name, PkgName: name,
		PkgVersion: "1.0.0", Decision: audit.DecisionDenied, LastClient: "10.0.0.5"}
}

func policyCreateEvents(t *testing.T, adbPath string) []audit.StoredEvent {
	t.Helper()
	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	events, err := adb.Query(t.Context(), audit.Filter{EventType: audit.EventCreate})
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// discover promote asks about a near-popular name the way policy add does,
// and the rule it writes leaves a create event.
func TestDiscoverPromoteConfirmsANearPopularName(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, pypiDenial("reqeusts"))

	_, stderr, err := runDiscoverStdin(t, "n\n", "promote", "pypi", "reqeusts")
	if err == nil {
		t.Fatal("a no promoted the rule")
	}
	if !strings.Contains(stderr, "requests") || !strings.Contains(stderr, "distance 1") {
		t.Errorf("prompt does not name the popular package:\n%s", stderr)
	}
	if _, _, err := runDiscoverStdin(t, "", "promote", "pypi", "reqeusts"); err == nil {
		t.Error("a stdin that ended before an answer promoted the rule")
	}
	if got := pypiRules(t, env.auditDB); len(got) != 0 {
		t.Fatalf("rules after refusals = %v", got)
	}

	if _, _, err := runDiscoverStdin(t, "y\n", "promote", "pypi", "reqeusts"); err != nil {
		t.Fatalf("a yes: %v", err)
	}
	if got := pypiRules(t, env.auditDB); len(got) != 1 || got[0] != "reqeusts" {
		t.Fatalf("rules = %v", got)
	}
	events := policyCreateEvents(t, env.auditDB)
	if len(events) != 1 || events[0].PkgName != "pypi:reqeusts" || events[0].PkgType != "policy" ||
		!strings.Contains(events[0].Details, "near_popular=requests") || !strings.Contains(events[0].Details, "confirmed=yes") {
		t.Errorf("create events = %+v", events)
	}
}

// promote-all writes nothing near a popular name, names each one with the
// command that confirms it, and still promotes the rest.
func TestDiscoverPromoteAllHoldsBackANearPopularName(t *testing.T) {
	env := newDiscoverEnv(t)
	env.seedDiscovery(t, pypiDenial("reqeusts"), pypiDenial("flask"))

	stdout, _, err := runDiscoverStdin(t, "", "promote-all", "pypi")
	if err != nil {
		t.Fatalf("promote-all: %v", err)
	}
	if got := pypiRules(t, env.auditDB); len(got) != 1 || got[0] != "flask" {
		t.Errorf("rules = %v, want flask alone", got)
	}
	for _, want := range []string{"reqeusts", "requests", "bodega discover promote pypi reqeusts", "held back 1"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output does not name %q:\n%s", want, stdout)
		}
	}
	if events := policyCreateEvents(t, env.auditDB); len(events) != 1 || events[0].PkgName != "pypi:flask" {
		t.Errorf("create events = %+v", events)
	}
}
