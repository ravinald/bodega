package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// A policy row for an ecosystem its gate cannot evaluate is written, listed,
// and never read. Both set commands refuse one before they reach the config or
// the audit DB, so these drive RunE with no store behind it.

func TestPolicyOSVSet_RefusesUnmappedEcosystem(t *testing.T) {
	loadFrom(t, "{}")
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
	loadFrom(t, "{}")
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

// An ecosystem set open ignores its allow-list; unset is the way back to the
// default, where one rule makes it listed.
func TestPolicyModeUnsetReturnsToDefault(t *testing.T) {
	dir := t.TempDir()
	adbPath := filepath.Join(dir, "audit.db")
	loadFrom(t, fmt.Sprintf(`{"audit_db": %q, "log_dir": %q, "manifest_dir": %q}`, adbPath, dir, filepath.Join(dir, "manifests")))
	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if err := adb.InsertPolicy(ctx, audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeNpm, RuleKind: policy.KindPackage, Pattern: "lodash"}); err != nil {
		t.Fatal(err)
	}
	adb.Close()

	run := func(c *cobra.Command, args ...string) string {
		t.Helper()
		var runErr error
		out := captureStdout(t, func() { runErr = c.RunE(c, args) })
		if runErr != nil {
			t.Fatalf("%s %v: %v", c.Name(), args, runErr)
		}
		return out
	}
	run(newPolicyModeSetCmd(&globalFlags{}), "npm", "open")
	out := run(newPolicyModeUnsetCmd(&globalFlags{}), "npm")
	if want := "Unset npm admission mode: now listed by default (was open, set)\n"; out != want {
		t.Errorf("unset printed %q, want %q", out, want)
	}
	out = run(newPolicyModeUnsetCmd(&globalFlags{}), "npm")
	if want := "npm has no admission mode set; it is listed by default\n"; out != want {
		t.Errorf("second unset printed %q, want %q", out, want)
	}

	adb, err = audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	m, err := policy.NewChecker(adb).ModeFor(ctx, manifest.TypeNpm)
	if err != nil {
		t.Fatal(err)
	}
	if m.Mode != audit.ModeListed || m.Set {
		t.Errorf("ModeFor after unset = %+v, want listed and not set", m)
	}
	events, err := adb.Query(ctx, audit.Filter{EventType: audit.EventPolicy, PkgType: manifest.TypeNpm})
	if err != nil {
		t.Fatal(err)
	}
	var unsets []map[string]any
	for _, e := range events {
		var d map[string]any
		if err := json.Unmarshal([]byte(e.Details), &d); err != nil {
			t.Fatalf("details %q: %v", e.Details, err)
		}
		if d["admission_mode"] == "default" {
			if e.Status != "success" || e.Actor == "" {
				t.Errorf("unset event status=%q actor=%q", e.Status, e.Actor)
			}
			unsets = append(unsets, d)
		}
	}
	if len(unsets) != 1 {
		t.Fatalf("want exactly one unset event (the second unset records none), got %d: %v", len(unsets), unsets)
	}
	want := map[string]any{"admission_mode": "default", "before": "open", "before_set": true, "after": "listed"}
	for k, v := range want {
		if unsets[0][k] != v {
			t.Errorf("details[%q] = %v, want %v", k, unsets[0][k], v)
		}
	}
}
