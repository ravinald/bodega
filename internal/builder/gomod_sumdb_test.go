package builder

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/provenance/sumdbtest"
)

// goproxy serves mod, zip and an .info for one module version.
func goproxy(t *testing.T, path, version string, mod, zip []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + path + "/@v/" + version + ".info":
			_, _ = w.Write([]byte(`{"Version":"` + version + `","Time":"2024-01-23T13:54:04Z"}`))
		case "/" + path + "/@v/" + version + ".mod":
			_, _ = w.Write(mod)
		case "/" + path + "/@v/" + version + ".zip":
			_, _ = w.Write(zip)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type gomodFetch struct {
	cfg     *Config
	store   *manifest.Store
	adb     *audit.DB
	out     *strings.Builder
	dir     string
	summary *Summary
}

func fetchGomodFrom(t *testing.T, app *config.Config, proxy *httptest.Server, path, version string, before func(adb *audit.DB)) gomodFetch {
	t.Helper()
	cfg, store, adb := pinEnv(t, &manifest.PackageManifest{
		Type: manifest.TypeGomod, Name: path,
		Versions: []manifest.VersionEntry{{Version: version, URL: proxy.URL}},
	})
	cfg.app = app
	out := &strings.Builder{}
	cfg.Stdout = out
	if before != nil {
		before(adb)
	}
	s := FetchGomod(cfg, store, "")
	return gomodFetch{cfg: cfg, store: store, adb: adb, out: out, summary: s,
		dir: gomodDir(buildDirs(cfg.rootFor(manifest.TypeGomod)), manifest.SafeName(path))}
}

func newestRow(t *testing.T, adb *audit.DB, path, version string) audit.Admission {
	t.Helper()
	rows, err := adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeGomod, PkgName: path, PkgVersion: version})
	if err != nil || len(rows) == 0 {
		t.Fatalf("no admission row for %s@%s: %v", path, version, err)
	}
	return rows[0]
}

func sumdbEntry(t *testing.T, row audit.Admission) audit.AdmissionCheck {
	t.Helper()
	c := admit.ChecksumDatabaseEntry(row)
	if c == nil {
		t.Fatalf("row carries no checksum_database outcome: %+v", row.Checks)
	}
	return *c
}

func TestFetchGomodMatchesTheChecksumDatabase(t *testing.T) {
	m := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "the published bytes")
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	log.AddModule(m)
	app := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier}

	f := fetchGomodFrom(t, app, goproxy(t, m.Path, m.Version, m.Mod, m.Zip), m.Path, m.Version, nil)
	if f.summary.Failures != 0 {
		t.Fatalf("fetch failed: %+v\n%s", f.summary.Results, f.out)
	}
	for _, ext := range []string{".info", ".mod", ".zip"} {
		if !fileExists(filepath.Join(f.dir, m.Version+ext)) {
			t.Errorf("%s not in the build root", ext)
		}
	}
	if c := sumdbEntry(t, newestRow(t, f.adb, m.Path, m.Version)); c.ChecksumDatabase.Outcome != audit.ProvenanceVerified || c.Status != audit.CheckPass {
		t.Errorf("checksum_database entry %+v", c)
	}
	if !strings.Contains(f.out.String(), "match the checksum database") {
		t.Errorf("output does not say the bytes were compared:\n%s", f.out)
	}
}

// A GOPROXY serving bytes other than the ones the database signed fails the
// fetch with no policy consulted, leaves nothing for the upload, and writes
// the refusal with both hashes.
func TestFetchGomodRefusesBytesTheChecksumDatabaseDidNotSign(t *testing.T) {
	honest := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "the published bytes")
	forged := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "a backdoor")
	for _, tc := range []struct {
		name     string
		mod, zip []byte
		file     string
		signed   string
		computed string
	}{
		{"zip", honest.Mod, forged.Zip, "v1.2.3.zip", honest.ZipHash, forged.ZipHash},
		{"go.mod", []byte("module example.com/widget\n\nrequire example.com/evil v1.0.0\n"), honest.Zip, "v1.2.3.mod", honest.ModHash, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := sumdbtest.New(t, sumdbtest.NewKey(t))
			log.AddModule(honest)
			app := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier}

			f := fetchGomodFrom(t, app, goproxy(t, honest.Path, honest.Version, tc.mod, tc.zip), honest.Path, honest.Version, nil)
			if f.summary.Failures != 1 || len(f.summary.Results) != 1 || f.summary.Results[0].Err == nil {
				t.Fatalf("fetch did not fail: %+v\n%s", f.summary.Results, f.out)
			}
			for _, ext := range []string{".info", ".mod", ".zip"} {
				if _, err := os.Stat(filepath.Join(f.dir, honest.Version+ext)); !os.IsNotExist(err) {
					t.Errorf("%s left in the build root: %v", ext, err)
				}
			}
			if paths := GomodArtifactPaths(f.cfg, f.store, ""); len(paths) != 0 {
				t.Errorf("upload would carry %+v", paths)
			}
			if got := storedVersion(t, f.store, manifest.TypeGomod, honest.Path, honest.Version); got.Checksum != nil {
				t.Errorf("the refused zip's digest was recorded: %+v", got.Checksum)
			}

			row := newestRow(t, f.adb, honest.Path, honest.Version)
			c := sumdbEntry(t, row)
			rec := c.ChecksumDatabase
			if row.Decision != audit.AdmissionPolicyBlocked || c.Status != audit.CheckBlock || rec.Outcome != audit.ProvenanceInvalid ||
				rec.File != tc.file || rec.ZipHash != honest.ZipHash || rec.ModHash != honest.ModHash || rec.Computed == "" {
				t.Fatalf("refusal row %s: %+v %+v", row.Decision, c, rec)
			}
			if tc.computed != "" && rec.Computed != tc.computed {
				t.Errorf("computed hash %q, want %q", rec.Computed, tc.computed)
			}
			if c.Unwaivable != admit.ChecksumDatabaseInvalidReason {
				t.Errorf("unwaivable = %q", c.Unwaivable)
			}
			msg := f.summary.Results[0].Err.Error()
			incident := strings.TrimSuffix(strings.Fields(c.Detail[strings.Index(c.Detail, "incident ")+len("incident "):])[0], ")")
			for _, want := range []string{honest.Path + "@" + honest.Version, tc.file, tc.signed, rec.Computed, "Incident " + incident, "compare what the upstream GOPROXY serves"} {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not carry %q", msg, want)
				}
			}
		})
	}
}

// A version the database was not consulted on, or could not answer for under
// an override, is fetched as before, and its row says the bytes were not
// compared and why.
func TestFetchGomodWithoutADatabaseHashIsNotCompared(t *testing.T) {
	m := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "x")
	silent := sumdbtest.New(t, sumdbtest.NewKey(t))
	for _, tc := range []struct {
		name    string
		app     *config.Config
		before  func(t *testing.T, app *config.Config, adb *audit.DB)
		outcome string
		why     string
	}{
		{name: "unavailable", app: &config.Config{GomodSumdbURL: silent.URL, GomodSumdbKey: silent.Key.Verifier, GomodNoSumdb: "example.com"},
			outcome: audit.ProvenanceUnavailable, why: `matches gomod_nosumdb pattern "example.com", so the checksum database was not consulted and the fetched bytes are not compared`},
		{name: "unknown under an override", app: &config.Config{GomodSumdbURL: silent.URL, GomodSumdbKey: silent.Key.Verifier},
			before: func(t *testing.T, app *config.Config, adb *audit.DB) {
				now := time.Now()
				o, err := admit.RequestOverride(t.Context(), adb, app, admit.OverrideRequest{Type: manifest.TypeGomod, Name: m.Path,
					Version: m.Version, Check: audit.CheckChecksumDatabase, Reason: "INC-9", Expires: "7d"}, audit.LocalOverrideCaller("alice"), now)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := admit.VoteOverride(t.Context(), adb, o.ID, audit.LocalOverrideCaller("bob"), true, "", now); err != nil {
					t.Fatal(err)
				}
			},
			outcome: audit.ProvenanceUnknown, why: "the fetched bytes are not compared, because the database gave no hash to compare them with"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fetchGomodFrom(t, tc.app, goproxy(t, m.Path, m.Version, m.Mod, m.Zip), m.Path, m.Version, func(adb *audit.DB) {
				if tc.before != nil {
					tc.before(t, tc.app, adb)
				}
			})
			if f.summary.Failures != 0 || !fileExists(filepath.Join(f.dir, m.Version+".zip")) {
				t.Fatalf("fetch failed: %+v\n%s", f.summary.Results, f.out)
			}
			c := sumdbEntry(t, newestRow(t, f.adb, m.Path, m.Version))
			if c.ChecksumDatabase.Outcome != tc.outcome || !strings.Contains(c.Detail, tc.why) {
				t.Errorf("entry %s: %q, want outcome %s and a detail carrying %q", c.ChecksumDatabase.Outcome, c.Detail, tc.outcome, tc.why)
			}
			if !strings.Contains(f.out.String(), "not compared") {
				t.Errorf("output does not say the bytes were not compared:\n%s", f.out)
			}
		})
	}
}

// A build root holding the .info but not the .zip, under a verified verdict,
// is fetched again and compared rather than reused with nothing to compare.
func TestFetchGomodRefetchesAPartialBuildRootUnderAVerifiedVerdict(t *testing.T) {
	m := sumdbtest.NewModule(t, "example.com/widget", "v1.2.3", "published")
	log := sumdbtest.New(t, sumdbtest.NewKey(t))
	log.AddModule(m)
	app := &config.Config{GomodSumdbURL: log.URL, GomodSumdbKey: log.Key.Verifier, GomodNoSumdb: "example.com"}
	f := fetchGomodFrom(t, app, goproxy(t, m.Path, m.Version, m.Mod, m.Zip), m.Path, m.Version, nil)
	if f.summary.Failures != 0 {
		t.Fatalf("excluded initial fetch: %+v", f.summary)
	}
	zip := filepath.Join(f.dir, m.Version+".zip")
	if err := os.Remove(zip); err != nil {
		t.Fatal(err)
	}
	app.GomodNoSumdb = ""
	f.cfg.Force = false
	second := FetchGomod(f.cfg, f.store, "")
	if second.Failures != 0 || second.Total != 1 {
		t.Fatalf("partial build root not fetched again: %+v", second)
	}
	if !fileExists(zip) {
		t.Fatal("zip not fetched again")
	}
	if c := sumdbEntry(t, newestRow(t, f.adb, m.Path, m.Version)); c.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
		t.Fatalf("outcome %s, want verified", c.ChecksumDatabase.Outcome)
	}
}
