package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// F15 wired ValidateReviewDate to the two flag paths and not to the third
// writer of review_after. A baseline document carrying "next quarter" stored
// verbatim is a pin that is never overdue, so --stale — the CI gate R2 exists
// for — passes on it forever, and the row renders with the string under REVIEW
// AFTER and a dash under OVERDUE, which reads as not yet due.
func TestProfileCreateFromFileRefusesAnUnparsableReviewDate(t *testing.T) {
	env := newDiscoverEnv(t)
	seedVersions(t, env, manifest.TypePypi, "django",
		[]manifest.VersionEntry{{Version: "4.2.11"}})

	doc := `{"config_version":1,"name":"imported",
	  "types":[{"type":"pypi","membership":"closed","version_default":"pinned"}],
	  "entries":[{"type":"pypi","name":"django","constraint_kind":"exact","version":"4.2.11",
	              "reason":"held","review_after":"next quarter"}]}`
	path := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write doc: %v", err)
	}

	out, err := runProfile(t, "create", "imported", "--from-file", path)
	if err == nil {
		t.Fatalf("create accepted an unparsable review date:\n%s", out)
	}
	for _, want := range []string{"entries[0]", "pypi/django", "review_after", "YYYY-MM-DD"} {
		if !strings.Contains(out+err.Error(), want) {
			t.Errorf("refusal does not name %q: %s / %v", want, out, err)
		}
	}

	// The refusal happens before the write, because createFromDoc reaches
	// CreateProfileWith as one transaction.
	if shown, sErr := runProfile(t, "show", "imported"); sErr == nil && strings.Contains(shown, "django") {
		t.Errorf("the document landed anyway:\n%s", shown)
	}
}

// No code path writes an edge whose parent is a pypi, gomod, npm or cargo
// package, so pins.Of returns nothing for one and reportPinClosure printed
// nothing. Silence and "this pin holds nothing still" were the same output,
// which is R4's stated failure landing where the graph is blind.
func TestPinningAPackageNothingRecordsAsAParentSaysSo(t *testing.T) {
	env := newDiscoverEnv(t)
	seedVersions(t, env, manifest.TypePypi, "django",
		[]manifest.VersionEntry{{Version: "4.2.11"}})
	seedEdges(t, env,
		manifest.DepEdge{Parent: "git/netbox@v4.5.7", Child: "pypi/django@4.2.11", RawSpec: "Django==4.2.11"},
		manifest.DepEdge{Parent: "git/netbox@v4.5.7", Child: "pypi/asgiref@3.7.2", RawSpec: "asgiref==3.7.2"},
	)
	mustRunProfile(t, "create", "real")

	out := mustRunProfile(t, "pin", "real", "pypi", "django", "4.2.11",
		"--reason", "5.x drops the auth backend")

	if !strings.Contains(out, "pypi") || !strings.Contains(out, "git") {
		t.Errorf("the report does not say which types appear as a parent:\n%s", out)
	}
	if !strings.Contains(out, "Nothing records what a pypi package depends on") {
		t.Errorf("an empty closure on a blind type reads as a pin that holds nothing still:\n%s", out)
	}
}

// The other empty case: the graph does record this type as a parent, and
// nothing in it depends on this package. That is a real answer and must not
// read like the blind one.
func TestPinningAPackageWithNoDependentsSaysThatInstead(t *testing.T) {
	env := newDiscoverEnv(t)
	seedVersions(t, env, manifest.TypeApt, "nginx",
		[]manifest.VersionEntry{{Version: "1.24.0"}})
	seedEdges(t, env,
		manifest.DepEdge{Parent: "apt/postgresql-14", Child: "apt/libpq5@14.9"},
	)
	mustRunProfile(t, "create", "web")

	out := mustRunProfile(t, "pin", "web", "apt", "nginx", "1.24.0", "--reason", "1.25 changes the config")
	if !strings.Contains(out, "holds nothing else still") {
		t.Errorf("a pin with no dependents does not say so:\n%s", out)
	}
	if strings.Contains(out, "Nothing records what") {
		t.Errorf("a type the graph does have parents for was reported as blind:\n%s", out)
	}
}

// pinned_at stopped an edit re-dating the decision; actor got no such
// treatment, so a second operator correcting a typo took the byline and the
// row paired one person's name with another person's date.
func TestPinBylineSurvivesAnEditToTheReason(t *testing.T) {
	env := newDiscoverEnv(t)
	seedVersions(t, env, manifest.TypePypi, "django",
		[]manifest.VersionEntry{{Version: "4.2.11"}})
	mustRunProfile(t, "create", "act")

	t.Setenv("SUDO_USER", "ravi")
	mustRunProfile(t, "pin", "act", "pypi", "django", "4.2.11",
		"--reason", "original decision", "--review-after", "2027-01-01")

	byline := func() string {
		t.Helper()
		got := decodePins(t, mustRunProfile(t, "pins", "--json"))
		if len(got) != 1 {
			t.Fatalf("pins = %+v, want one", got)
		}
		return got[0].Actor
	}
	if first := byline(); first != "ravi" {
		t.Fatalf("the pin byline is %q, want ravi", first)
	}

	t.Setenv("SUDO_USER", "colleague")
	mustRunProfile(t, "add", "act", "pypi", "django", "--reason", "original decision, reworded")
	if after := byline(); after != "ravi" {
		t.Errorf("editing the reason reassigned the pin to %q; the row now names one person beside another's date", after)
	}

	// Moving the pin is a new decision, and the byline moves with it.
	mustRunProfile(t, "pin", "act", "pypi", "django", "4.2.11", "--reason", "still held")
	if after := byline(); after != "colleague" {
		t.Errorf("re-pinning left the byline at %q rather than the person who decided it", after)
	}
}

// A row written before `set` learned to refuse an uncovered ecosystem survives
// untouched, and the table rendered it exactly like an enforcing one.
func TestPolicyListMarksARowItsGateCannotEvaluate(t *testing.T) {
	env := newDiscoverEnv(t)
	adb, err := audit.Open(env.auditDB)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	ctx := context.Background()
	// Written directly, the way a build predating the refusal would have.
	if err := adb.SetAgePolicy(ctx, audit.AgePolicy{
		Ecosystem: manifest.TypeApt, MinAgeSeconds: 604800, Action: "block",
	}); err != nil {
		t.Fatalf("seed age policy: %v", err)
	}
	_ = adb.Close()

	out := mustRunPolicy(t, "age", "list")
	if !strings.Contains(out, "not enforced") {
		t.Errorf("the row for an ecosystem the gate cannot date renders as an active control:\n%s", out)
	}
}

// mustRunPolicy drives the policy command tree the way runProfile drives the
// profile one, capturing os.Stdout because the tables are printed rather than
// written to the command's own writer.
func mustRunPolicy(t *testing.T, args ...string) string {
	t.Helper()
	cmd := newPolicyCmd(&globalFlags{})
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true

	stdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	execErr := cmd.Execute()
	_ = w.Close()
	os.Stdout = stdout
	var printed bytes.Buffer
	_, _ = printed.ReadFrom(r)

	got := printed.String() + out.String()
	if execErr != nil {
		t.Fatalf("bodega policy %s: %v\n%s", strings.Join(args, " "), execErr, got)
	}
	return got
}
