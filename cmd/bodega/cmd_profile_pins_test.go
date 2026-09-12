package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pins"
	"github.com/ravinald/bodega/internal/policy"
)

// seedVersions writes one package with the metadata each version carries, so a
// test can put a version in the exact OSV state the report has to tell apart.
func seedVersions(t *testing.T, env *discoverEnv, typ, name string, versions []manifest.VersionEntry) {
	t.Helper()
	ctx := context.Background()
	store := manifest.NewLocalStore(env.manifestDir)
	if err := store.LoadIndex(ctx); err != nil {
		t.Fatalf("load index: %v", err)
	}
	pm := &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          name,
		Type:          typ,
		Versions:      versions,
	}
	if err := store.SavePackage(ctx, pm); err != nil {
		t.Fatalf("save %s/%s: %v", typ, name, err)
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("save index: %v", err)
	}
}

// seedEdges writes the dependency graph through the store, so the closure walk
// reads the same graph.json the discoverers write.
func seedEdges(t *testing.T, env *discoverEnv, edges ...manifest.DepEdge) {
	t.Helper()
	ctx := context.Background()
	store := manifest.NewLocalStore(env.manifestDir)
	if err := store.LoadGraph(ctx); err != nil {
		t.Fatalf("load graph: %v", err)
	}
	for _, e := range edges {
		store.AddEdge(e)
	}
	if err := store.SaveGraph(ctx); err != nil {
		t.Fatalf("save graph: %v", err)
	}
}

func decodePins(t *testing.T, out string) []pins.Pin {
	t.Helper()
	start := strings.Index(out, "[")
	if start < 0 {
		t.Fatalf("no JSON array in the output:\n%s", out)
	}
	var got []pins.Pin
	if err := json.Unmarshal([]byte(out[start:]), &got); err != nil {
		t.Fatalf("decode pins: %v\n%s", err, out)
	}
	return got
}

// --stale is a CI gate, so it has to exit non-zero and name the pin. A pin
// whose review date is still ahead of it is not stale and must not be counted,
// or the gate fails on every profile forever and stops being read.
func TestProfilePinsStaleExitsNonZeroAndNamesOnlyTheOverdueOnes(t *testing.T) {
	env := newDiscoverEnv(t)
	seedVersions(t, env, manifest.TypeApt, "postgresql-14",
		[]manifest.VersionEntry{{Version: "14.9"}})
	seedVersions(t, env, manifest.TypeApt, "nginx",
		[]manifest.VersionEntry{{Version: "1.24.0"}})
	mustRunProfile(t, "create", "db")

	past := time.Now().UTC().AddDate(0, 0, -30).Format(pins.ReviewDateLayout)
	future := time.Now().UTC().AddDate(1, 0, 0).Format(pins.ReviewDateLayout)
	mustRunProfile(t, "pin", "db", "apt", "postgresql-14", "14.9",
		"--reason", "15 breaks the config", "--review-after", past)
	mustRunProfile(t, "pin", "db", "apt", "nginx", "1.24.0",
		"--reason", "waiting on the module rebuild", "--review-after", future)

	all := mustRunProfile(t, "pins")
	for _, want := range []string{"postgresql-14", "nginx", "15 breaks the config"} {
		if !strings.Contains(all, want) {
			t.Errorf("the full report does not mention %q:\n%s", want, all)
		}
	}

	out, err := runProfile(t, "pins", "--stale")
	if err == nil {
		t.Fatalf("--stale exited zero with a pin 30 days overdue, so it is no gate:\n%s", out)
	}
	if !strings.Contains(out, "postgresql-14") {
		t.Errorf("--stale does not name the overdue pin:\n%s", out)
	}
	if strings.Contains(out, "nginx") {
		t.Errorf("--stale reported a pin whose review date has not arrived:\n%s", out)
	}
	if !strings.Contains(out, "30d") {
		t.Errorf("--stale does not say how far past the review date the pin is:\n%s", out)
	}
}

// A pin with no review date never comes due, and a review date nothing can
// parse is the same thing while looking like a date. The gate would pass on it
// forever, which is the one failure the review date exists to prevent.
func TestProfilePinRefusesAReviewDateNothingCanParse(t *testing.T) {
	newDiscoverEnv(t)
	mustRunProfile(t, "create", "db")

	_, err := runProfile(t, "pin", "db", "apt", "postgresql-14", "14.9",
		"--reason", "15 breaks the config", "--review-after", "next quarter")
	if err == nil {
		t.Fatal("a review date nothing can parse was stored, so --stale would pass on it forever")
	}
	for _, want := range []string{"YYYY-MM-DD", "never overdue"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, err)
		}
	}
}

// The report is the one document that holds both halves: the decision an
// operator recorded and what OSV says about the version they held. A version
// that became vulnerable after it was pinned has to show the advisory and its
// score, and a version nobody ever queried has to read unchecked rather than
// clean — an empty advisory list means nobody looked as often as it means
// there is nothing to find.
func TestProfilePinsSeparateAnUncheckedVersionFromACleanOne(t *testing.T) {
	env := newDiscoverEnv(t)
	checked := time.Now().UTC().AddDate(0, 0, -2).Format(time.RFC3339)
	seedVersions(t, env, manifest.TypePypi, "django", []manifest.VersionEntry{
		{
			// Pinned while clean, flagged by a later rescan. The stamp is
			// what E6 writes and B34 scores.
			Version: "4.2.11",
			Metadata: map[string]string{
				policy.OSVMetaVulns:     "GHSA-xxxx-yyyy-zzzz",
				policy.OSVMetaSeverity:  `{"GHSA-xxxx-yyyy-zzzz":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`,
				policy.OSVMetaCheckedAt: checked,
			},
		},
		// No stamp at all: never queried.
		{Version: "4.2.12"},
		// Answered, nothing found.
		{Version: "5.0.1", Metadata: map[string]string{policy.OSVMetaCheckedAt: checked}},
	})
	mustRunProfile(t, "create", "web")
	mustRunProfile(t, "pin", "web", "pypi", "django", "4.2.11", "--reason", "5 drops the middleware")
	mustRunProfile(t, "create", "ci")
	mustRunProfile(t, "pin", "ci", "pypi", "django", "4.2.12", "--reason", "reproducing a build")
	mustRunProfile(t, "create", "ops")
	mustRunProfile(t, "pin", "ops", "pypi", "django", "5.0.1", "--reason", "certified release")

	byProfile := map[string]pins.Pin{}
	for _, p := range decodePins(t, mustRunProfile(t, "pins", "--json")) {
		byProfile[p.Profile] = p
	}
	if got := byProfile["web"].OSV.State; got != pins.OSVFlagged {
		t.Errorf("a version flagged after it was pinned reports %q, not flagged", got)
	}
	if got := byProfile["ci"].OSV.State; got != pins.OSVUnchecked {
		t.Errorf("a version no run has ever answered for reports %q; unchecked and clean are different facts", got)
	}
	if got := byProfile["ops"].OSV.State; got != pins.OSVClean {
		t.Errorf("a version answered with no findings reports %q, not clean", got)
	}

	sev := byProfile["web"].OSV.Severity["GHSA-xxxx-yyyy-zzzz"]
	if len(sev) != 1 || !strings.HasPrefix(sev[0].Score, "CVSS:3.1/") {
		t.Errorf("the severity B34 recorded did not survive into the report: %+v", sev)
	}
	if byProfile["web"].OSV.Checked == nil {
		t.Error("a flagged pin carries no refresh date, so nobody can tell how current the answer is")
	}
	if byProfile["ci"].OSV.Checked != nil {
		t.Error("an unchecked pin carries a refresh date, which dates an answer nobody has")
	}

	table := mustRunProfile(t, "pins")
	for _, want := range []string{"GHSA-xxxx-yyyy-zzzz", "accepts 1 known advisory", "CVSS_V3"} {
		if !strings.Contains(table, want) {
			t.Errorf("the table does not carry %q, so the advisory is only in --json:\n%s", want, table)
		}
	}
}

// An operator who does not know a pin implies eleven others finds out during
// an upgrade. The closure is reported before the write, and it names the
// packages the pinned version depends on rather than the ones that depend on
// it.
func TestProfilePinReportsTheDependencyClosureBeforeItCommits(t *testing.T) {
	env := newDiscoverEnv(t)
	seedVersions(t, env, manifest.TypeApt, "postgresql-14",
		[]manifest.VersionEntry{{Version: "14.9"}})
	seedEdges(t, env,
		manifest.DepEdge{Parent: "apt/postgresql-14", Child: "apt/libpq5@14.9", RawSpec: "libpq5 (= 14.9)"},
		manifest.DepEdge{Parent: "apt/libpq5", Child: "apt/libssl3@3.0.2", RawSpec: "libssl3 (>= 3.0.0)"},
		// A package that depends on the pinned one, which the closure must not
		// claim: pinning postgres does not hold pgbouncer still.
		manifest.DepEdge{Parent: "apt/pgbouncer", Child: "apt/postgresql-14"},
		// Another package's subtree entirely.
		manifest.DepEdge{Parent: "apt/nginx", Child: "apt/libpcre3@2.0.0"},
	)
	mustRunProfile(t, "create", "db")

	out := mustRunProfile(t, "pin", "db", "apt", "postgresql-14", "14.9",
		"--reason", "15 breaks the config")
	for _, want := range []string{"holds 2 other package(s) still", "apt/libpq5", "apt/libssl3", "--strict-closure"} {
		if !strings.Contains(out, want) {
			t.Errorf("the closure report does not mention %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"apt/pgbouncer", "apt/libpcre3"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the closure claims %q, which this pin does not hold still:\n%s", unwanted, out)
		}
	}

	// Reporting is the default: nothing beyond the named package is pinned.
	shown := mustRunProfile(t, "show", "db")
	if strings.Contains(shown, "libpq5") {
		t.Errorf("the default extended the pin across the closure, freezing a growing set:\n%s", shown)
	}

	mustRunProfile(t, "pin", "db", "apt", "postgresql-14", "14.9",
		"--reason", "15 breaks the config", "--strict-closure")
	shown = mustRunProfile(t, "show", "db")
	for _, want := range []string{"libpq5", "14.9", "libssl3", "3.0.2"} {
		if !strings.Contains(shown, want) {
			t.Errorf("--strict-closure did not write %q, so the implication stays unrecorded:\n%s", want, shown)
		}
	}
	if !strings.Contains(shown, "implied by the apt/postgresql-14 pin") {
		t.Errorf("a closure pin does not say what implied it:\n%s", shown)
	}
}

// The report measures a review date against the decision, so the decision
// needs its own date. created_at is the entry's, and it does not move when the
// version does: a pin moved yesterday under an entry written two years ago
// would read as two years stale and be reviewed by somebody who had just
// reviewed it.
func TestProfilePinDateMovesWithTheVersionAndNotWithAnEdit(t *testing.T) {
	env := newDiscoverEnv(t)
	seedVersions(t, env, manifest.TypeApt, "postgresql-14",
		[]manifest.VersionEntry{{Version: "14.9"}, {Version: "14.11"}})
	mustRunProfile(t, "create", "db")

	long := time.Now().UTC().AddDate(-2, 0, 0)
	adb, err := audit.Open(env.auditDB)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	if _, err := adb.PutProfileEntry(context.Background(), audit.ProfileEntry{
		Profile: "db", Type: manifest.TypeApt, Name: "postgresql-14",
		Constraint: manifest.ConstraintExact, Version: "14.9",
		Reason: "15 breaks the config", PinnedAt: long,
	}); err != nil {
		t.Fatalf("seed pin: %v", err)
	}
	_ = adb.Close()

	pinnedAt := func() time.Time {
		t.Helper()
		got := decodePins(t, mustRunProfile(t, "pins", "--json"))
		if len(got) != 1 || got[0].PinnedAt == nil {
			t.Fatalf("pins = %+v, want one pin carrying a date", got)
		}
		return *got[0].PinnedAt
	}
	if first := pinnedAt(); first.Year() != long.Year() {
		t.Fatalf("the stored pin date did not survive the read: %s", first)
	}

	mustRunProfile(t, "add", "db", "apt", "postgresql-14", "--reason", "15 still breaks the config")
	if after := pinnedAt(); after.Year() != long.Year() {
		t.Errorf("correcting the reason re-dated the decision to %s, resetting the review clock", after)
	}

	mustRunProfile(t, "pin", "db", "apt", "postgresql-14", "14.11", "--reason", "15 still breaks the config")
	if after := pinnedAt(); after.Year() == long.Year() {
		t.Errorf("moving the pin to a new version left the decision dated %s", after)
	}
}
