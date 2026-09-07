package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/policy"
)

// A policy row for an ecosystem its gate cannot evaluate is written, listed,
// and never read. Both set commands refuse one before they reach the config or
// the audit DB, so these drive RunE with no store behind it.

func TestPolicyOSVSet_RefusesUnmappedEcosystem(t *testing.T) {
	cmd := newPolicyOSVSetCmd(&globalFlags{})
	err := cmd.RunE(cmd, []string{"helm", "block"})
	if err == nil {
		t.Fatal("helm has no OSV identifier; set must refuse it")
	}
	for _, want := range []string{"helm", "OSV gate", "never read", "cargo", "npm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q, got: %v", want, err)
		}
	}
}

func TestPolicyAgeSet_RefusesUnmappedEcosystem(t *testing.T) {
	cmd := newPolicyAgeSetCmd(&globalFlags{})
	err := cmd.RunE(cmd, []string{"apt", "7d", "warn"})
	if err == nil {
		t.Fatal("apt has no upstream timestamp source; set must refuse it")
	}
	for _, want := range []string{"apt", "age gate", "every version would warn", "cargo", "gomod"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q, got: %v", want, err)
		}
	}
}

func TestRequireEcosystem_AcceptsCovered(t *testing.T) {
	for _, eco := range policy.OSVEcosystems() {
		if err := requireEcosystem(eco, policy.OSVEcosystems(), "OSV gate", "x"); err != nil {
			t.Errorf("%s is mapped but was refused: %v", eco, err)
		}
	}
	for _, eco := range policy.AgeEcosystems() {
		if err := requireEcosystem(eco, policy.AgeEcosystems(), "age gate", "x"); err != nil {
			t.Errorf("%s is dated but was refused: %v", eco, err)
		}
	}
	if err := requireEcosystem("NPM", policy.OSVEcosystems(), "OSV gate", "x"); err == nil {
		t.Error("registry types are lowercase; NPM must be refused, not silently accepted")
	}
}

// The rows that predate the refusal above are the ones nobody is told about:
// `list` prints them beside the enforced rows with nothing to tell them apart.
func TestReportUncoveredNamesTheStoredRowsNoGateReads(t *testing.T) {
	out := captureStdout(t, func() {
		reportUncovered("age gate", []string{"npm", "helm", "apt"}, policy.AgeEcosystems(), "bodega policy age remove")
	})
	for _, want := range []string{"helm", "apt", "never read", "bodega policy age remove"} {
		if !strings.Contains(out, want) {
			t.Errorf("note does not mention %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "npm") {
		t.Errorf("npm is covered by the age gate and must not be flagged:\n%s", out)
	}

	if quiet := captureStdout(t, func() {
		reportUncovered("age gate", policy.AgeEcosystems(), policy.AgeEcosystems(), "bodega policy age remove")
	}); quiet != "" {
		t.Errorf("a fully covered policy set printed a note:\n%s", quiet)
	}
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	fn()
	os.Stdout = orig
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}
