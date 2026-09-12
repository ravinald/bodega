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

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
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
			rels := []string{"Ubuntu:22.04:LTS", "Ubuntu:24.04:LTS"}
			if eco == "Debian" {
				rels = []string{"Debian:12"}
			}
			affected := rec["affected"].([]any)
			base := affected[0].(map[string]any)
			out := make([]any, 0, len(rels))
			for _, rel := range rels {
				one := map[string]any{
					"package": map[string]any{"ecosystem": rel, "name": "expat"},
					"ranges":  base["ranges"],
				}
				out = append(out, one)
			}
			rec["affected"] = out
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
	return runOSVCmd(t, newPolicyOSVSyncCmd(&globalFlags{}), args...)
}

// runOSVCmd drives one subcommand with the process streams redirected, because
// both commands write their table to os.Stdout and their warnings to os.Stderr
// rather than to the cobra streams.
func runOSVCmd(t *testing.T, cmd *cobra.Command, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

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

// storeAptEntry puts one apt version entry in the install's manifest store,
// index included: the walk lists packages out of the index, not off disk.
func storeAptEntry(t *testing.T, root, name string, ve manifest.VersionEntry) {
	t.Helper()
	store := manifest.NewLocalStore(filepath.Join(root, "manifests"))
	if err := store.AddVersion(context.Background(), manifest.TypeApt, name, ve); err != nil {
		t.Fatalf("AddVersion %s: %v", ve.Version, err)
	}
	if err := store.SaveIndex(context.Background()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
}

// TestSyncCommand_CapturedReleaseIsFetchedBesideTheServedSuite pins the set
// sync resolves apt from against the set the gate reads.
//
// capture_suite is the release the gate answers an entry from and apt_suites is
// where the .deb is published, so a bodega serving noble can hold a jammy
// capture. Resolving the fetch from the served suites alone leaves that entry
// unanswerable forever, and the warn names a sync that just ran.
func TestSyncCommand_CapturedReleaseIsFetchedBesideTheServedSuite(t *testing.T) {
	root := syncInstall(t, "noble", "noble")
	storeAptEntry(t, root, "libexpat1", manifest.VersionEntry{
		Version:       "2.4.7-1ubuntu0.2",
		SourcePackage: "expat",
		CaptureSuite:  "jammy",
		Suites:        []string{"noble"},
	})

	stdout, _, err := runSync(t, "apt")
	if err != nil {
		t.Fatalf("sync apt: %v", err)
	}
	for _, eco := range []string{"Ubuntu:22.04:LTS", "Ubuntu:24.04:LTS"} {
		if !strings.Contains(stdout, eco) {
			t.Errorf("%s is missing from the table:\n%s", eco, stdout)
		}
		if _, err := policy.NewOSVDatabase(filepath.Join(root, "osv")).Meta(eco); err != nil {
			t.Errorf("the %s index was not written: %v", eco, err)
		}
	}
}

// TestSyncCommand_MirrorInstallFetchesWhatItCaptured is the documented mirror:
// apt_codename is a house name OSV publishes nothing for, and the releases live
// on the captures alone. The skip covering the house name is not the whole of
// apt there, or that install's gate answers nothing at all.
func TestSyncCommand_MirrorInstallFetchesWhatItCaptured(t *testing.T) {
	root := syncInstall(t, "internal", "internal")
	storeAptEntry(t, root, "libexpat1", manifest.VersionEntry{
		Version:       "2.6.1-2build1",
		SourcePackage: "expat",
		CaptureSuite:  "noble",
		Suites:        []string{"internal"},
	})

	stdout, stderr, err := runSync(t)
	if err != nil {
		t.Fatalf("no-argument sync: %v", err)
	}
	if !strings.Contains(stdout, "Ubuntu:24.04:LTS") {
		t.Fatalf("the captured release was never fetched:\n%s\n%s", stdout, stderr)
	}
	if _, err := policy.NewOSVDatabase(filepath.Join(root, "osv")).Meta("Ubuntu:24.04:LTS"); err != nil {
		t.Errorf("the noble index was not written: %v", err)
	}
	if !strings.Contains(stderr, `"internal"`) {
		t.Errorf("the house suite still has to be named, since entries recording no release warn on it: %q", stderr)
	}
}

// TestSyncCommand_OneUnreadableAptManifestStillSyncsEverythingElse covers the
// form a cron runs. The manifest read happens before any fetch, so returning on
// the first unparsable apt package leaves npm, pypi, gomod and cargo unsynced
// over a file none of them has anything to do with.
func TestSyncCommand_OneUnreadableAptManifestStillSyncsEverythingElse(t *testing.T) {
	root := syncInstall(t, "noble", "noble")
	storeAptEntry(t, root, "libexpat1", manifest.VersionEntry{
		Version:       "2.4.7-1ubuntu0.2",
		SourcePackage: "expat",
		CaptureSuite:  "jammy",
		Suites:        []string{"noble"},
	})
	mpath := filepath.Join(root, "manifests", "apt", "libexpat1", "manifest.json")
	if err := os.WriteFile(mpath, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := runSync(t)
	if err != nil {
		t.Fatalf("one unreadable apt manifest failed the whole sync: %v", err)
	}
	for _, eco := range []string{"npm", "PyPI", "Go", "crates.io", "Ubuntu:24.04:LTS"} {
		if !strings.Contains(stdout, eco) {
			t.Errorf("%s never synced, so the exit code above proves nothing:\n%s", eco, stdout)
		}
	}
	if _, err := policy.NewOSVDatabase(filepath.Join(root, "osv")).Meta("npm"); err != nil {
		t.Errorf("npm wrote nothing to the database: %v", err)
	}
	if !strings.Contains(stderr, "libexpat1") {
		t.Errorf("the unreadable package has to be named, or its release is silently missing: %q", stderr)
	}
}

// setOSVPolicy writes one policy row into the install's audit store, which is
// what list reads its rows from.
func setOSVPolicy(t *testing.T, root, ecosystem, action string) {
	t.Helper()
	adb, err := audit.Open(filepath.Join(root, "logs", "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer adb.Close()
	if err := adb.SetOSVPolicy(context.Background(), audit.OSVPolicy{Ecosystem: ecosystem, Action: action}); err != nil {
		t.Fatalf("set %s policy: %v", ecosystem, err)
	}
}

// TestListCommand_AptReadsNeverWhenACapturedReleaseHasNoIndex pins list to the
// set sync resolves from. A release a capture records and no suite serves is
// one the gate reads, so an absent index for it is the row's answer: reporting
// the apt row synced off the served suites alone makes the command that reports
// the gate's health the one thing in the install that lies about it.
func TestListCommand_AptReadsNeverWhenACapturedReleaseHasNoIndex(t *testing.T) {
	root := syncInstall(t, "noble", "noble")
	storeAptEntry(t, root, "libexpat1", manifest.VersionEntry{
		Version:       "2.4.7-1ubuntu0.2",
		SourcePackage: "expat",
		CaptureSuite:  "jammy",
		Suites:        []string{"noble"},
	})
	setOSVPolicy(t, root, manifest.TypeApt, "block")
	if _, _, err := runSync(t, "apt"); err != nil {
		t.Fatalf("sync apt: %v", err)
	}

	stdout, _, err := runOSVCmd(t, newPolicyOSVListCmd(&globalFlags{}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if strings.Contains(stdout, "never") {
		t.Fatalf("both indexes are present, so the row must carry a sync time:\n%s", stdout)
	}

	jammy, err := filepath.Glob(filepath.Join(root, "osv", "Ubuntu-22.04-LTS.*"))
	if err != nil || len(jammy) == 0 {
		t.Fatalf("the jammy index is not where list looks for it: %v %v", jammy, err)
	}
	for _, f := range jammy {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}

	stdout, _, err = runOSVCmd(t, newPolicyOSVListCmd(&globalFlags{}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(stdout, "never") {
		t.Errorf("the captured release has no index and rescan says so; list reported apt synced:\n%s", stdout)
	}
}
