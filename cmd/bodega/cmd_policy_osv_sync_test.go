package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/policy"
)

// syncInstall writes a config whose apt suites are the ones given, and points
// the sync command at a stand-in for OSV's export bucket.
func syncInstall(t *testing.T, aptCodename string, aptSuites ...string) string {
	t.Helper()
	root := t.TempDir()
	cfg := map[string]any{
		"manifest_dir": filepath.Join(root, "manifests"),
		"storage_path": filepath.Join(root, "storage"),
		"log_dir":      filepath.Join(root, "logs"),
		"osv_db_dir":   filepath.Join(root, "osv"),
		"apt_codename": aptCodename,
		"apt_suites":   aptSuites,
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

	old := osvExportBase
	osvExportBase = osvBucket(t).URL
	t.Cleanup(func() { osvExportBase = old })
	return root
}

// osvBucket stands in for OSV's export bucket, answering each ecosystem's
// archive with a record that names it. One record per ecosystem is the minimum:
// sync refuses to write an index no advisory named, because a database that
// distilled to nothing reports every version clean.
func osvBucket(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eco := strings.Trim(strings.TrimSuffix(r.URL.Path, "/all.zip"), "/")
		rec := map[string]any{
			"id":       "STAND-IN-" + eco,
			"modified": "2026-09-01T00:00:00Z",
			"affected": []any{map[string]any{
				"package": map[string]any{"ecosystem": eco, "name": "expat"},
				"ranges": []any{map[string]any{
					"type":   "ECOSYSTEM",
					"events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": "9.9.9"}},
				}},
			}},
		}
		if eco == "Ubuntu" || eco == "Debian" {
			// The aggregate archive carries every release at once, with the
			// release in each affected entry's ecosystem string; the distill
			// filter is what keys an index on one release.
			rel := "Ubuntu:22.04:LTS"
			if eco == "Debian" {
				rel = "Debian:12"
			}
			rec["affected"].([]any)[0].(map[string]any)["package"].(map[string]any)["ecosystem"] = rel
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, err := zw.Create(rec["id"].(string) + ".json")
		if err != nil {
			t.Errorf("zip create: %v", err)
			return
		}
		if err := json.NewEncoder(f).Encode(rec); err != nil {
			t.Errorf("zip write: %v", err)
			return
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

func runSync(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	cmd := newPolicyOSVSyncCmd(&globalFlags{})
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

// TestSyncCommand_HouseAptSuitesAreSkippedNotFailed covers the exit code of the
// form an operator runs from cron.
//
// apt joined the covered set, and apt resolves to one export per served suite,
// so an install whose suites are local names resolves to none. The documented
// mirror configuration is exactly that install: apt_codename "internal", built
// from noble upstreams. Failing there returns 1 out of a run where all four
// language ecosystems wrote, every night, over a suite set nobody can change
// without abandoning the mirror.
func TestSyncCommand_HouseAptSuitesAreSkippedNotFailed(t *testing.T) {
	root := syncInstall(t, "internal", "internal")

	stdout, stderr, err := runSync(t)
	if err != nil {
		t.Fatalf("no-argument sync must not fail on a suite set no OSV export covers: %v", err)
	}
	if !strings.Contains(stderr, "skipped apt") || !strings.Contains(stderr, `"internal"`) {
		t.Errorf("the skip has to name the suite, or the operator learns of it at import: %q", stderr)
	}
	for _, eco := range []string{"npm", "PyPI", "Go", "crates.io"} {
		if !strings.Contains(stdout, eco) {
			t.Errorf("%s never synced, so the exit code above proves nothing:\n%s", eco, stdout)
		}
	}
	if _, err := policy.NewOSVDatabase(filepath.Join(root, "osv")).Meta("npm"); err != nil {
		t.Errorf("npm wrote nothing to the database: %v", err)
	}

	// Naming apt on the command line still fails: that request asked for an
	// export and fetched nothing, and a script running it deserves to hear so.
	if _, stderr, err = runSync(t, "apt"); err == nil {
		t.Errorf("explicit 'sync apt' resolved to nothing and reported success; stderr = %q", stderr)
	}
}

// TestSyncCommand_MappedAptSuiteFetchesItsRelease is the other half: a served
// suite that names a release fetches that release's index, keyed on the
// release and not on one distro-wide identifier.
func TestSyncCommand_MappedAptSuiteFetchesItsRelease(t *testing.T) {
	root := syncInstall(t, "jammy", "jammy", "jammy-security")

	stdout, _, err := runSync(t, "apt")
	if err != nil {
		t.Fatalf("sync apt: %v", err)
	}
	if !strings.Contains(stdout, "Ubuntu:22.04:LTS") {
		t.Fatalf("the row has to name the release the records came from:\n%s", stdout)
	}
	if _, err := policy.NewOSVDatabase(filepath.Join(root, "osv")).Meta("Ubuntu:22.04:LTS"); err != nil {
		t.Errorf("the jammy index was not written: %v", err)
	}
}
