package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// osvExport serves OSV's per-ecosystem export shape: <base>/<eco>/all.zip,
// one JSON file per record.
func osvExport(t *testing.T, records ...map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, rec := range records {
			f, err := zw.Create(rec["id"].(string) + ".json")
			if err != nil {
				t.Errorf("zip create: %v", err)
				return
			}
			if err := json.NewEncoder(f).Encode(rec); err != nil {
				t.Errorf("zip write: %v", err)
				return
			}
		}
		if err := zw.Close(); err != nil {
			t.Errorf("zip close: %v", err)
			return
		}
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func advisory(id, pkg, introduced, fixed string) map[string]any {
	return map[string]any{
		"id":       id,
		"modified": "2026-09-01T00:00:00Z",
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "npm", "name": pkg},
			"ranges": []any{map[string]any{
				"type":   "SEMVER",
				"events": []any{map[string]any{"introduced": introduced}, map[string]any{"fixed": fixed}},
			}},
		}},
	}
}

// rescanInstall writes a config whose manifest directory holds one npm package
// at the given versions, and returns the install root.
func rescanInstall(t *testing.T, versions ...manifest.VersionEntry) (root string) {
	t.Helper()
	root = t.TempDir()
	manifests := filepath.Join(root, "manifests")
	osvDir := filepath.Join(root, "osv")
	cfg := map[string]any{
		"manifest_dir": manifests,
		"storage_path": filepath.Join(root, "storage"),
		"log_dir":      filepath.Join(root, "logs"),
		"osv_db_dir":   osvDir,
		"bucket":       "",
	}
	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(cfgPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BODEGA_CONFIG_FILE", cfgPath)

	store := manifest.NewLocalStore(manifests)
	for _, ve := range versions {
		if err := store.AddVersion(context.Background(), manifest.TypeNpm, "minimist", ve); err != nil {
			t.Fatalf("AddVersion %s: %v", ve.Version, err)
		}
	}
	// The walk lists packages out of the index, not off the filesystem.
	if err := store.SaveIndex(context.Background()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	return root
}

// syncInto fills the install's OSV directory from a stand-in for OSV's bucket.
func syncInto(t *testing.T, root string, records ...map[string]any) {
	t.Helper()
	db := policy.NewOSVDatabase(filepath.Join(root, "osv"))
	db.ExportBase = osvExport(t, records...).URL
	if _, err := db.Sync(context.Background(), "npm"); err != nil {
		t.Fatalf("sync npm: %v", err)
	}
}

func runRescan(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	cmd := newPolicyOSVRescanCmd(&globalFlags{})
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	err = cmd.Execute()

	os.Stdout, os.Stderr = oldOut, oldErr
	_ = outW.Close()
	_ = errW.Close()
	o, _ := io.ReadAll(outR)
	e, _ := io.ReadAll(errR)
	return string(o), string(e), err
}

// stampOf reads the version's stamp back off disk. Reading through a store the
// command never touched is the point: asserting on the in-process manifest
// would pass even if SavePackage was never called.
func stampOf(t *testing.T, root, version string) policy.OSVStamp {
	t.Helper()
	fresh := manifest.NewLocalStore(filepath.Join(root, "manifests"))
	pm, err := fresh.GetPackage(context.Background(), manifest.TypeNpm, "minimist")
	if err != nil || pm == nil {
		t.Fatalf("reload minimist: %v", err)
	}
	for _, ve := range pm.Versions {
		if ve.Version == version {
			return policy.OSVStampOf(ve)
		}
	}
	t.Fatalf("version %s not in the reloaded manifest", version)
	return policy.OSVStamp{}
}

// TestRescanCommand_WalksStampsAndPersists is the composed path: the walk, the
// stamp and the write to disk. A Rescan that returns the right struct and
// never reaches SavePackage satisfies every unit test in internal/policy.
func TestRescanCommand_WalksStampsAndPersists(t *testing.T) {
	root := rescanInstall(t,
		manifest.VersionEntry{Version: "1.2.5"},
		manifest.VersionEntry{Version: "1.2.8"})
	syncInto(t, root, advisory("GHSA-doomed", "minimist", "1.2.4", "1.2.6"))

	stdout, stderr, err := runRescan(t)
	if err != nil {
		t.Fatalf("rescan: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "2 answered") || !strings.Contains(stderr, "1 newly flagged") {
		t.Errorf("summary should answer for both and flag only 1.2.5: %q", stderr)
	}
	if !strings.Contains(stdout, "GHSA-doomed") {
		t.Errorf("the report must name the finding: %q", stdout)
	}

	for _, v := range []string{"1.2.5", "1.2.8"} {
		st := stampOf(t, root, v)
		if st.Checked.IsZero() {
			t.Errorf("%s: check date was not written to disk", v)
		}
		if v == "1.2.5" && !st.Flagged() {
			t.Errorf("%s should be flagged on disk: %+v", v, st)
		}
		if v == "1.2.8" && st.Flagged() {
			t.Errorf("%s is outside the advisory: %+v", v, st)
		}
	}
}

// TestRescanCommand_BlindRunFailsLoudly is requirement 3's second sentence at
// the exit code: a rescan against a directory nothing ever synced answered for
// nothing, and exiting 0 with an empty report is how that becomes "no
// vulnerabilities found" in a pipeline.
func TestRescanCommand_BlindRunFailsLoudly(t *testing.T) {
	root := rescanInstall(t, manifest.VersionEntry{
		Version:  "1.2.5",
		Metadata: map[string]string{policy.OSVMetaVulns: "GHSA-doomed"},
	})

	stdout, stderr, err := runRescan(t)
	if err == nil {
		t.Fatal("a run that answered for nothing must not exit 0")
	}
	if !strings.Contains(stderr, "0 answered") || !strings.Contains(stderr, "1 version(s) unanswered") {
		t.Errorf("summary must separate silence from success: %q", stderr)
	}
	if !strings.Contains(stderr, "policy osv sync") {
		t.Errorf("the reason must name the next step: %q", stderr)
	}
	if !strings.Contains(stdout, "unanswered") {
		t.Errorf("the report must name the version it could not answer for: %q", stdout)
	}
	if st := stampOf(t, root, "1.2.5"); !st.Flagged() {
		t.Errorf("a blind run overwrote a real finding: %+v", st)
	}
}

// TestRescanCommand_ClearsAndFiltersByName covers the withdrawal transition
// through the command, and pins --name to the package it names.
func TestRescanCommand_ClearsAndFiltersByName(t *testing.T) {
	root := rescanInstall(t, manifest.VersionEntry{
		Version:  "1.2.5",
		Metadata: map[string]string{policy.OSVMetaVulns: "GHSA-withdrawn"},
	})
	syncInto(t, root, advisory("GHSA-unrelated", "leftpad", "0", "1.0.0"))

	// A --name nobody matches must not print requirement 3's clean shape and
	// exit 0: "0 newly flagged" over a typo reads as "nothing is vulnerable".
	_, stderr, err := runRescan(t, "--name", "not-a-package")
	if err == nil {
		t.Fatalf("--name matching nothing must not exit 0: stderr=%q", stderr)
	}
	if !strings.Contains(err.Error(), "not-a-package") {
		t.Errorf("the error must name what matched nothing: %v", err)
	}
	if st := stampOf(t, root, "1.2.5"); !st.Flagged() {
		t.Fatalf("a filtered-out package was rewritten: %+v", st)
	}

	stdout, stderr, err := runRescan(t, "--type", "npm", "--name", "minimist")
	if err != nil {
		t.Fatalf("rescan: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "1 newly cleared") {
		t.Errorf("a withdrawn advisory must report as cleared: %q", stderr)
	}
	if !strings.Contains(stdout, "cleared") {
		t.Errorf("the report must name the cleared version: %q", stdout)
	}
	st := stampOf(t, root, "1.2.5")
	if st.Flagged() {
		t.Errorf("the withdrawn id is still on disk: %+v", st)
	}
	if st.Checked.IsZero() {
		t.Error("a cleared version is a checked version and must carry the date")
	}
}

// TestRescanCommand_RefusesTypeOSVCannotAnswer keeps --type apt from reporting
// a clean walk over an ecosystem the gate has no records for.
func TestRescanCommand_RefusesTypeOSVCannotAnswer(t *testing.T) {
	rescanInstall(t)
	_, _, err := runRescan(t, "--type", "apt")
	if err == nil {
		t.Fatal("apt has no OSV ecosystem; rescan must refuse it")
	}
	for _, want := range []string{"apt", "OSV gate", "npm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q, got: %v", want, err)
		}
	}
}

// rescanAdd installs a second package into an existing rescanInstall root and
// re-writes the index the walk reads.
func rescanAdd(t *testing.T, root, name string, versions ...manifest.VersionEntry) {
	t.Helper()
	store := manifest.NewLocalStore(filepath.Join(root, "manifests"))
	if err := store.LoadIndex(context.Background()); err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	for _, ve := range versions {
		if err := store.AddVersion(context.Background(), manifest.TypeNpm, name, ve); err != nil {
			t.Fatalf("AddVersion %s@%s: %v", name, ve.Version, err)
		}
	}
	if err := store.SaveIndex(context.Background()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
}

// TestRescanCommand_NameTakesThePackagesOwnName pins --name to the spelling an
// operator types. The index keys packages by SafeName, so comparing the flag
// against the stored key raw walks zero versions for every scoped npm package
// and every gomod module path, and reports that as a clean run.
func TestRescanCommand_NameTakesThePackagesOwnName(t *testing.T) {
	root := rescanInstall(t, manifest.VersionEntry{Version: "1.2.5"})
	rescanAdd(t, root, "@types/node", manifest.VersionEntry{Version: "18.0.0"})
	syncInto(t, root, advisory("GHSA-node-types", "@types/node", "0", "18.1.0"))

	stdout, stderr, err := runRescan(t, "--name", "@types/node")
	if err != nil {
		t.Fatalf("rescan: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "1 answered") || !strings.Contains(stderr, "1 newly flagged") {
		t.Errorf("the scoped name must walk its own package: %q", stderr)
	}
	if !strings.Contains(stdout, "GHSA-node-types") {
		t.Errorf("the report must name the finding: %q", stdout)
	}
	// The encoded form still resolves: SafeName is idempotent, so an operator
	// reading a filename and typing what they saw is not punished for it.
	if _, stderr, err := runRescan(t, "--name", "@types--node"); err != nil ||
		!strings.Contains(stderr, "1 answered") {
		t.Errorf("the on-disk form must resolve too: err=%v stderr=%q", err, stderr)
	}
	// minimist is outside the filter and must keep its unchecked state.
	if st := stampOf(t, root, "1.2.5"); !st.Checked.IsZero() {
		t.Errorf("a filtered-out package was rescanned: %+v", st)
	}
}

// TestRescanCommand_UnreadableManifestKeepsTheReport is the walk's failure
// mode: one corrupt manifest used to abort the run before the table flushed
// and before the summary printed, while the versions already stamped were
// written to disk. State changed and nothing said what.
func TestRescanCommand_UnreadableManifestKeepsTheReport(t *testing.T) {
	root := rescanInstall(t, manifest.VersionEntry{Version: "1.2.0"})
	rescanAdd(t, root, "corrupt-pkg", manifest.VersionEntry{Version: "1.0.0"})
	corrupt := filepath.Join(root, "manifests", manifest.TypeNpm, "corrupt-pkg", "manifest.json")
	if err := os.WriteFile(corrupt, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	syncInto(t, root, advisory("GHSA-old", "minimist", "0", "1.2.3"))

	stdout, stderr, err := runRescan(t)
	if err == nil {
		t.Fatal("an unreadable manifest must not exit 0")
	}
	if !strings.Contains(stdout, "corrupt-pkg") || !strings.Contains(stdout, "unanswered") {
		t.Errorf("the table must name the package it could not read: %q", stdout)
	}
	if !strings.Contains(stderr, "1 newly flagged") {
		t.Errorf("the summary must survive the failure: %q", stderr)
	}
	if !strings.Contains(stderr, "unanswered; their previous stamp is unchanged") {
		t.Errorf("the failure must land in the unanswered count: %q", stderr)
	}
	if st := stampOf(t, root, "1.2.0"); !st.Flagged() {
		t.Errorf("the readable sibling was not rescanned: %+v", st)
	}
}

// TestRescanCommand_IndexEntryWithNoManifestIsUnanswered pins the drift
// 'bodega repair' already names: a package in the index whose manifest file is
// gone. The walk used to skip it with no row, no count and exit 0, so a run
// that answered for nothing printed the same three zeros as a clean one and a
// cron reading the exit code recorded it as a fleet with no findings.
func TestRescanCommand_IndexEntryWithNoManifestIsUnanswered(t *testing.T) {
	root := rescanInstall(t, manifest.VersionEntry{Version: "1.2.0"})
	rescanAdd(t, root, "ghost", manifest.VersionEntry{Version: "1.0.0"})
	if err := os.Remove(filepath.Join(root, "manifests", manifest.TypeNpm, "ghost", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	syncInto(t, root, advisory("GHSA-old", "minimist", "0", "1.2.3"))

	stdout, stderr, err := runRescan(t, "--name", "ghost")
	if err == nil {
		t.Fatal("an index entry with no manifest must not exit 0")
	}
	if !strings.Contains(stdout, "ghost") || !strings.Contains(stdout, "unanswered") {
		t.Errorf("the table must name the package it could not read: %q", stdout)
	}
	if !strings.Contains(stderr, "no manifest file") {
		t.Errorf("the summary must name the state it could not answer for: %q", stderr)
	}
	if !strings.Contains(stderr, "1 version(s) unanswered") {
		t.Errorf("the missing manifest must land in the unanswered count: %q", stderr)
	}
	if strings.Contains(err.Error(), "local OSV database") {
		t.Errorf("the error must name the store, not OSV: %v", err)
	}
}

// TestRescanCommand_RangeEntryPrintsItsMatchedRecord pins the operator-visible
// half of the range rule. The stamp is withheld because a point lookup cannot
// settle a constraint, but the record matched against the base version is the
// finding the run exists to surface, and a row carrying only the constraint
// prose buries it. Asserted on stdout because that is what an operator reads:
// the policy layer's Vulns field can be right while the row drops it.
func TestRescanCommand_RangeEntryPrintsItsMatchedRecord(t *testing.T) {
	root := rescanInstall(t, manifest.VersionEntry{
		Version:           "1.2.9",
		VersionConstraint: manifest.ConstraintCompatible,
	})
	syncInto(t, root, advisory("GHSA-range-hit", "minimist", "1.2.9", "1.3.0"))

	stdout, stderr, err := runRescan(t)
	if err == nil {
		t.Fatalf("a walk that answered for nothing must not exit 0: stdout=%q", stdout)
	}
	var row string
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "1.2.9") && strings.Contains(line, "unanswered") {
			row = line
		}
	}
	if row == "" {
		t.Fatalf("no unanswered row for the range entry: %q", stdout)
	}
	if !strings.Contains(row, "GHSA-range-hit") {
		t.Errorf("the matched record must be named in the row, got %q", row)
	}
	if i, j := strings.Index(row, "GHSA-range-hit"), strings.Index(row, "constraint"); j >= 0 && i > j {
		t.Errorf("the id must lead the reason prose, got %q", row)
	}
	if !strings.Contains(stderr, "0 answered") {
		t.Errorf("a range entry stays uncounted: %q", stderr)
	}
	if st := stampOf(t, root, "1.2.9"); !st.Checked.IsZero() || st.Flagged() {
		t.Errorf("an unanswered version is written nothing: %+v", st)
	}
}

// advisoryVersions builds an advisory naming its affected versions outright,
// which is the one way a record covers a version string no ordering places.
func advisoryVersions(id, pkg string, versions ...string) map[string]any {
	list := make([]any, 0, len(versions))
	for _, v := range versions {
		list = append(list, v)
	}
	return map[string]any{
		"id":       id,
		"modified": "2026-09-01T00:00:00Z",
		"affected": []any{map[string]any{
			"package":  map[string]any{"ecosystem": "npm", "name": pkg},
			"versions": list,
		}},
	}
}

// TestRescanCommand_RowNamesTheRecordNobodyCouldRead is the operator-visible
// half of the partial-read rule. A version one record covers by name while a
// second went unread is not a complete answer, and the row is where an
// operator learns that: a line carrying only the matched id reads as a settled
// verdict, and the record that could still cover the version appears nowhere
// but the stderr reason counts.
func TestRescanCommand_RowNamesTheRecordNobodyCouldRead(t *testing.T) {
	root := rescanInstall(t, manifest.VersionEntry{Version: "nightly-2026"})
	syncInto(t, root,
		advisoryVersions("GHSA-exact-2026", "minimist", "nightly-2026"),
		advisory("GHSA-ranged-2026", "minimist", "0", "9.9.9"),
	)

	stdout, stderr, err := runRescan(t)
	if err == nil {
		t.Fatalf("a walk that answered for nothing must not exit 0: stdout=%q", stdout)
	}
	var row string
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "nightly-2026") && strings.Contains(line, "GHSA-exact-2026") {
			row = line
		}
	}
	if row == "" {
		t.Fatalf("no row named the matched record: %q", stdout)
	}
	if !strings.Contains(row, "GHSA-ranged-2026") {
		t.Errorf("the row must name the record nobody could read, got %q", row)
	}
	if !strings.Contains(stderr, "0 answered") {
		t.Errorf("a partial read is not an answer: %q", stderr)
	}
	if st := stampOf(t, root, "nightly-2026"); !st.Checked.IsZero() {
		t.Errorf("a partial read earns no date: %+v", st)
	}
}

// TestRescanRow_FlaggedRowsCarryTheirReason drives the renderer directly. Both
// flagged arms are reachable only through a dating rule that admits a
// qualified answer, so an assertion routed through the command would go green
// the moment that rule tightened and stop guarding the row at all.
func TestRescanRow_FlaggedRowsCarryTheirReason(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ch        policy.OSVRescanChange
		wantState string
	}{
		{"new", policy.OSVRescanChange{
			Answered: true, Flagged: true,
			Vulns:  []string{"GHSA-hit"},
			Reason: "1 OSV record(s) were not evaluated: GHSA-unread",
		}, "flagged (new)"},
		{"standing", policy.OSVRescanChange{
			Answered: true,
			Vulns:    []string{"GHSA-hit"},
			Reason:   "1 OSV record(s) were not evaluated: GHSA-unread",
		}, "flagged"},
	} {
		state, detail := rescanRow(tc.ch)
		if state != tc.wantState {
			t.Errorf("%s: state = %q, want %q", tc.name, state, tc.wantState)
		}
		if !strings.Contains(detail, "GHSA-hit") {
			t.Errorf("%s: the matched id must lead the row, got %q", tc.name, detail)
		}
		if !strings.Contains(detail, "GHSA-unread") {
			t.Errorf("%s: the row must name what qualified the answer, got %q", tc.name, detail)
		}
	}

	// An unqualified answer earns no separator to trail.
	if _, detail := rescanRow(policy.OSVRescanChange{
		Answered: true, Flagged: true, Vulns: []string{"GHSA-hit"},
	}); detail != "GHSA-hit" {
		t.Errorf("a clean flagged row is the ids alone, got %q", detail)
	}
}
