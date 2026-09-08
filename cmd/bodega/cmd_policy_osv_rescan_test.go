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

	if _, stderr, err := runRescan(t, "--name", "not-a-package"); err != nil ||
		!strings.Contains(stderr, "Rescanned 0 version(s)") {
		t.Fatalf("--name must scope the walk: err=%v stderr=%q", err, stderr)
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
