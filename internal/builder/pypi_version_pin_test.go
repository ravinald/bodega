package builder

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// pypiRelease is one release in a fixture index. PyPI keeps the key of a
// deleted release and empties its file list, so a fixture that gives every
// release an empty array cannot tell an available release from a gone one.
type pypiRelease struct {
	version string
	deleted bool
}

// pypiIndexOf serves the JSON API for one distribution, with a realistic file
// record for every release that is not marked deleted.
func pypiIndexOf(t *testing.T, dist string, releases ...pypiRelease) *httptest.Server {
	t.Helper()
	files := map[string]any{}
	for _, rel := range releases {
		if rel.deleted {
			files[rel.version] = []any{}
			continue
		}
		files[rel.version] = []any{map[string]any{
			"filename":    fmt.Sprintf("%s-%s-py3-none-any.whl", dist, rel.version),
			"packagetype": "bdist_wheel",
			"url":         fmt.Sprintf("https://files.example/%s/%s.whl", dist, rel.version),
			"size":        11053,
			"yanked":      false,
			"digests":     map[string]any{"sha256": strings.Repeat("a", 64)},
		}}
	}
	body := map[string]any{"info": map[string]any{"name": dist}, "releases": files}
	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/"+dist+"/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// pypiIndex serves the JSON API for one distribution, every release available.
func pypiIndex(t *testing.T, dist string, versions ...string) *httptest.Server {
	t.Helper()
	releases := make([]pypiRelease, 0, len(versions))
	for _, v := range versions {
		releases = append(releases, pypiRelease{version: v})
	}
	return pypiIndexOf(t, dist, releases...)
}

// pypiFetchEnv runs FetchPypi over a single-entry pypi manifest and returns the
// summary and whatever combined-requirements.txt it wrote.
func pypiFetchEnv(t *testing.T, ve manifest.VersionEntry) (*Summary, string) {
	t.Helper()
	pm := &manifest.PackageManifest{Type: manifest.TypePypi, Name: "six", Versions: []manifest.VersionEntry{ve}}
	cfg, store, _ := pinEnv(t, pm)
	cfg.Stdout = io.Discard

	summary := FetchPypi(cfg, store)
	req, err := os.ReadFile(filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read combined-requirements.txt: %v", err)
	}
	return summary, string(req)
}

// TestFetchPypiPinsAVersionThatIsNotTheNewest is B57. The fetch wrote the bare
// distribution name into combined-requirements.txt and left the version to pip,
// so an entry pinning 1.16.0 produced six-1.17.0-py2.py3-none-any.whl in
// storage and the generated simple index published the 1.17.0 filename. A
// manifest that does not describe what was stored is not a record of what was
// approved.
func TestFetchPypiPinsAVersionThatIsNotTheNewest(t *testing.T) {
	srv := pypiIndex(t, "six", "1.14.0", "1.15.0", "1.16.0", "1.17.0")

	summary, req := pypiFetchEnv(t, manifest.VersionEntry{Version: "1.16.0", URL: srv.URL})
	if summary.HasFailures() {
		t.Fatalf("fetch reported %d failures: %+v", summary.Failures, summary.Results)
	}
	if !strings.Contains(req, "six===1.16.0") {
		t.Errorf("combined-requirements.txt does not pin the version the entry names:\n%s", req)
	}
	if strings.Contains(req, "1.17.0") {
		t.Errorf("combined-requirements.txt reaches a version the entry does not name:\n%s", req)
	}
}

// R2: silently taking a neighbor is what produced B57, so a version the index
// cannot answer is a failed fetch that names all three of the entry, the
// version asked for and what was on offer.
func TestFetchPypiFailsOnAVersionTheIndexDoesNotOffer(t *testing.T) {
	srv := pypiIndex(t, "six", "1.16.0", "1.17.0")

	summary, req := pypiFetchEnv(t, manifest.VersionEntry{Version: "1.99.0", URL: srv.URL})
	if !summary.HasFailures() {
		t.Fatalf("a version the index does not offer was accepted: %+v", summary.Results)
	}
	if req != "" {
		t.Errorf("a failed resolution still wrote a requirements file:\n%s", req)
	}
	var msg string
	for _, r := range summary.Results {
		if r.Err != nil {
			msg = r.Err.Error()
		}
	}
	for _, want := range []string{"six", "1.99.0", "1.16.0", "1.17.0"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the failure does not name %q: %s", want, msg)
		}
	}
}

// R3: the constraint values that reach the fetch, and what each resolves to.
// "latest" is said with version_constraint; it is never a reinterpretation of
// an exact version.
func TestFetchPypiConstraintResolution(t *testing.T) {
	releases := []string{"1.14.0", "1.15.0", "1.15.4", "1.16.0", "1.16.2", "2.0.0"}

	for _, tc := range []struct {
		constraint string
		version    string
		want       string
	}{
		{manifest.ConstraintExact, "1.16.0", "six===1.16.0"},
		{"", "1.16.0", "six===1.16.0"},
		{manifest.ConstraintPatch, "1.15.0", "six===1.15.4"},
		{manifest.ConstraintCompatible, "1.15.0", "six===1.16.2"},
		{manifest.ConstraintAny, "1.15.0", "six===2.0.0"},
		{manifest.ConstraintAny, "*", "six"},
		{manifest.ConstraintExact, "", "six"},
	} {
		name := fmt.Sprintf("%s/%s", tc.constraint, tc.version)
		t.Run(name, func(t *testing.T) {
			srv := pypiIndex(t, "six", releases...)
			summary, req := pypiFetchEnv(t, manifest.VersionEntry{
				Version: tc.version, VersionConstraint: tc.constraint, URL: srv.URL,
			})
			if summary.HasFailures() {
				t.Fatalf("fetch reported %d failures: %+v", summary.Failures, summary.Results)
			}
			line := ""
			for _, l := range strings.Split(req, "\n") {
				if strings.HasPrefix(l, "six") {
					line = l
				}
			}
			if line != tc.want {
				t.Errorf("requirement line is %q, want %q", line, tc.want)
			}
		})
	}
}

// R2: PyPI keeps the key of a deleted release and empties its file list, so a
// resolver reading keys alone hands pip a version it cannot download and the
// failure surfaces three minutes later inside the wheel build.
func TestFetchPypiFailsOnAReleaseWithNoFiles(t *testing.T) {
	srv := pypiIndexOf(t, "six",
		pypiRelease{version: "1.16.0"},
		pypiRelease{version: "2.15.0", deleted: true},
	)

	summary, req := pypiFetchEnv(t, manifest.VersionEntry{Version: "2.15.0", URL: srv.URL})
	if !summary.HasFailures() {
		t.Fatalf("a release with no downloadable files was accepted: %+v", summary.Results)
	}
	if req != "" {
		t.Errorf("a failed resolution still wrote a requirements file:\n%s", req)
	}
	var msg string
	for _, r := range summary.Results {
		if r.Err != nil {
			msg = r.Err.Error()
		}
	}
	for _, want := range []string{"six", "2.15.0", "1.16.0"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the failure does not name %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "offers 1.16.0, 2.15.0") {
		t.Errorf("the deleted release is still offered as a candidate: %s", msg)
	}
}

// R1: the resolve is now on the mandatory fetch path, so it has to survive a
// real package history. numpy's JSON response measured 3,672,920 bytes and
// pandas' 2,130,480 bytes, both past the 1 MiB read this used to do, and a
// truncated read parses as malformed JSON rather than as a size problem.
func TestPypiVersionsAtReadsPastOneMebibyte(t *testing.T) {
	const filler = 2 << 20
	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/six/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"info":{"description":"`+strings.Repeat("x", filler)+`"},`+
			`"releases":{"1.16.0":[{"filename":"six-1.16.0-py3-none-any.whl"}]}}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	got, err := pypiVersionsAt(srv.URL, "six")
	if err != nil {
		t.Fatalf("a %d-byte response failed to parse: %v", filler, err)
	}
	if len(got) != 1 || got[0] != "1.16.0" {
		t.Fatalf("got %v, want [1.16.0]", got)
	}
}

// A response past the cap is a limit to raise, not an index to fix. Saying
// "unexpected end of JSON input" sends whoever is reading it at the wrong one.
func TestPypiVersionsAtNamesAnOversizedResponse(t *testing.T) {
	chunk := strings.Repeat("x", 1<<20)
	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/six/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"info":{"description":"`)
		for written := 0; written <= pypiResponseMax; written += len(chunk) {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	_, err := pypiVersionsAt(srv.URL, "six")
	if err == nil {
		t.Fatal("an oversized response was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("the failure reads as malformed JSON rather than as a size: %v", err)
	}
}

// R3/R4: the index an entry names decides resolution, so it has to decide the
// download too. Resolving against a private index and then letting pip take
// its own default is how a version approved on one index arrives from another.
func TestFetchPypiSendsTheSelectedIndexToPip(t *testing.T) {
	srv := pypiIndex(t, "six", "1.16.0", "1.17.0")

	summary, req := pypiFetchEnv(t, manifest.VersionEntry{Version: "1.16.0", URL: srv.URL})
	if summary.HasFailures() {
		t.Fatalf("fetch reported %d failures: %+v", summary.Failures, summary.Results)
	}
	want := "--index-url " + srv.URL + "/simple/"
	if !strings.Contains(req, want) {
		t.Errorf("the requirements file pip is handed does not name %q:\n%s", want, req)
	}
}

// The default index is written out like any other. It used to be left unsaid
// so a deployment could point pip at its own mirror through pip.conf, but the
// build now runs pip with that configuration switched off, and an index
// nothing states is an index nothing enforces.
func TestFetchPypiWritesTheDefaultIndexToo(t *testing.T) {
	want := "--index-url " + defaultPypiIndex + "/simple/\n"
	if got := pypiIndexLine(defaultPypiIndex); got != want {
		t.Errorf("the default index reached pip as %q, want %q", got, want)
	}
}

// One requirements file carries one --index-url, so two entries naming
// different origins is a configuration this cannot satisfy. Picking a winner
// would download one of them from an index that never approved it.
func TestFetchPypiFailsOnConflictingIndexes(t *testing.T) {
	first := pypiIndex(t, "six", "1.16.0")
	second := pypiIndex(t, "attrs", "24.2.0")

	cfg, store, _ := pinEnv(t, &manifest.PackageManifest{
		Type: manifest.TypePypi, Name: "six",
		Versions: []manifest.VersionEntry{{Version: "1.16.0", URL: first.URL}},
	})
	cfg.Stdout = io.Discard
	if err := store.SavePackage(t.Context(), &manifest.PackageManifest{
		Type: manifest.TypePypi, Name: "attrs",
		Versions: []manifest.VersionEntry{{Version: "24.2.0", URL: second.URL}},
	}); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	summary := FetchPypi(cfg, store)
	if !summary.HasFailures() {
		t.Fatal("two entries naming different indexes were silently mixed")
	}
	if _, err := os.Stat(filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")); !os.IsNotExist(err) {
		t.Errorf("a fetch that could not pick an index still wrote a requirements file")
	}
	var msg string
	for _, r := range summary.Results {
		if r.Err != nil {
			msg = r.Err.Error()
		}
	}
	for _, want := range []string{first.URL, second.URL, "six", "attrs"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the failure does not name %q: %s", want, msg)
		}
	}
}

// A pip global option names no install target. Counting one builds a venv,
// runs pip wheel over a file naming nothing, and reports no error anywhere.
func TestHasInstallableRequirementsIgnoresPipOptions(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{
		{"# comment\n--index-url https://example/simple/\n", false},
		{"--index-url https://example/simple/\nsix==1.16.0\n", true},
		// An include names no target here any more: the generated file pulls
		// in no other file, so an application's requirements arrive as their
		// own lines and the only path option left is the `-c` naming the
		// generated constraints, which requests no installs.
		{"--index-url https://example/simple/\n-r /tmp/other.txt\n", false},
		{"-c /var/lib/bodega/pypi/combined-constraints.txt\n", false},
		{"\n\n", false},
	} {
		path := filepath.Join(t.TempDir(), "requirements.txt")
		if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := hasInstallableRequirements(path)
		if err != nil {
			t.Fatalf("hasInstallableRequirements: %v", err)
		}
		if got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.body, got, tc.want)
		}
	}
}

// pypiWheelBytes builds a minimal but valid wheel for one version, so a test
// can drive real pip over a fixture index rather than assert on the text of a
// requirements file and call the substitution disproven.
func pypiWheelBytes(t *testing.T, dist, version string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	info := fmt.Sprintf("%s-%s.dist-info/", dist, version)
	for name, body := range map[string]string{
		info + "METADATA": fmt.Sprintf("Metadata-Version: 2.1\nName: %s\nVersion: %s\n\n", dist, version),
		info + "WHEEL":    "Wheel-Version: 1.0\nGenerator: bodega-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
		info + "RECORD":   "",
		dist + ".py":      fmt.Sprintf("__version__ = %q\n", version),
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("wheel %s: %v", name, err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatalf("wheel %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("wheel: %v", err)
	}
	return buf.Bytes()
}

// pypiWheelIndex serves one distribution over the two surfaces a fetch uses:
// the JSON API the resolver reads, and the PEP 503 pages plus wheel bytes pip
// downloads from.
func pypiWheelIndex(t *testing.T, dist string, versions ...string) *httptest.Server {
	t.Helper()
	releases := map[string]any{}
	blobs := map[string][]byte{}
	var links string
	for _, v := range versions {
		file := fmt.Sprintf("%s-%s-py3-none-any.whl", dist, v)
		releases[v] = []any{map[string]any{"filename": file, "packagetype": "bdist_wheel"}}
		blobs["/files/"+file] = pypiWheelBytes(t, dist, v)
		links += fmt.Sprintf("<a href=\"/files/%s\">%s</a><br>\n", url.PathEscape(file), file)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/"+dist+"/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"releases": releases})
	})
	mux.HandleFunc("/simple/"+dist+"/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, links)
	})
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := blobs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// pypiWheelRun runs real pip over a generated requirements file and returns the
// wheel filenames it stored.
func pypiWheelRun(t *testing.T, requirements string) ([]string, string) {
	t.Helper()
	if err := exec.Command("python3", "-m", "pip", "--version").Run(); err != nil {
		t.Skipf("no python3 -m pip on this host: %v", err)
	}

	dir := t.TempDir()
	reqPath := filepath.Join(dir, "combined-requirements.txt")
	if err := os.WriteFile(reqPath, []byte(requirements), 0o600); err != nil {
		t.Fatalf("write requirements: %v", err)
	}
	cmd := exec.Command("python3", "-m", "pip", "wheel",
		"--no-deps", "--no-cache-dir", "--disable-pip-version-check",
		"--wheel-dir", dir, "-r", reqPath)
	// A PIP_* variable in the environment would decide the origin behind the
	// requirements file, which is the question this test is asking.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PIP_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "PIP_CONFIG_FILE=/dev/null")
	out, _ := cmd.CombinedOutput()

	stored, _ := filepath.Glob(filepath.Join(dir, "*.whl"))
	for i, whl := range stored {
		stored[i] = filepath.Base(whl)
	}
	return stored, string(out)
}

// R1: the pin has to survive acquisition, not just resolution. PEP 440 version
// matching ignores a candidate's local label when the specifier carries none,
// so `six==1.16.0` against an index offering 1.16.0 and 1.16.0+vendor.1 stored
// the vendored build under pip 26.2.1 — a new acquisition of a version nobody
// approved, from the index the manifest named.
func TestFetchPypiStoresTheVersionItResolved(t *testing.T) {
	srv := pypiWheelIndex(t, "six", "1.16.0", "1.16.0+vendor.1")

	summary, req := pypiFetchEnv(t, manifest.VersionEntry{Version: "1.16.0", URL: srv.URL})
	if summary.HasFailures() {
		t.Fatalf("fetch reported %d failures: %+v", summary.Failures, summary.Results)
	}

	stored, out := pypiWheelRun(t, req)
	if len(stored) != 1 || stored[0] != "six-1.16.0-py3-none-any.whl" {
		t.Errorf("a pin on 1.16.0 stored %v\nrequirements:\n%s\npip:\n%s", stored, req, out)
	}
}

// An entry naming a local build gets that build, so pinning the identity does
// not cost the ability to name one.
func TestFetchPypiStoresANamedLocalBuild(t *testing.T) {
	srv := pypiWheelIndex(t, "six", "1.16.0", "1.16.0+vendor.1")

	summary, req := pypiFetchEnv(t, manifest.VersionEntry{Version: "1.16.0+vendor.1", URL: srv.URL})
	if summary.HasFailures() {
		t.Fatalf("fetch reported %d failures: %+v", summary.Failures, summary.Results)
	}

	stored, out := pypiWheelRun(t, req)
	if len(stored) != 1 || stored[0] != "six-1.16.0+vendor.1-py3-none-any.whl" {
		t.Errorf("a pin on 1.16.0+vendor.1 stored %v\nrequirements:\n%s\npip:\n%s", stored, req, out)
	}
}

// R1: the store is what gets published, so the store is what gets checked. A
// specifier is a filter rather than a fact, and a wheels directory holding a
// version no pin names is the state B57 reported.
func TestVerifyPypiWheelsRejectsAVersionNoPinNames(t *testing.T) {
	for _, tc := range []struct {
		name   string
		wheels []string
		fails  bool
	}{
		{"the version the pin names", []string{"six-1.16.0-py3-none-any.whl"}, false},
		{"a local variant of it", []string{"six-1.16.0+vendor.1-py3-none-any.whl"}, true},
		{"a newer release", []string{"six-1.17.0-py2.py3-none-any.whl"}, true},
		{"the pin beside a leftover", []string{"six-1.16.0-py3-none-any.whl", "six-1.17.0-py3-none-any.whl"}, false},
		{"another spelling of it", []string{"six-1.16-py3-none-any.whl"}, false},
		{"nothing at all", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			reqPath := filepath.Join(dir, "combined-requirements.txt")
			if err := os.WriteFile(reqPath, []byte("--index-url https://example/simple/\nsix===1.16.0\n"), 0o600); err != nil {
				t.Fatalf("write requirements: %v", err)
			}
			for _, whl := range tc.wheels {
				if err := os.WriteFile(filepath.Join(dir, whl), []byte("x"), 0o600); err != nil {
					t.Fatalf("write wheel: %v", err)
				}
			}
			err := verifyPypiWheels(reqPath, dir)
			if tc.fails && err == nil {
				t.Errorf("%v passed against a pin on 1.16.0", tc.wheels)
			}
			if !tc.fails && err != nil {
				t.Errorf("%v failed against a pin on 1.16.0: %v", tc.wheels, err)
			}
		})
	}
}

// R1/R2: a failed fetch must leave no resolved state behind. CheckPypiStage
// reads the requirements file's existence as "fetch is done" and the pipeline
// skips the retry, so the previous run's file outlived the pin it came from:
// edit a version, watch the re-fetch fail, and `build run pypi` still built the
// closure of the version the manifest no longer names.
func TestFetchPypiDiscardsRequirementsWhenARefetchFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		breakIt func(t *testing.T, cfg *Config, store *manifest.Store, pm *manifest.PackageManifest)
	}{
		{"the pin moves to a version the index does not offer", func(t *testing.T, _ *Config, store *manifest.Store, pm *manifest.PackageManifest) {
			pm.Versions[0].Version = "1.99.0"
			if err := store.SavePackage(t.Context(), pm); err != nil {
				t.Fatalf("SavePackage: %v", err)
			}
		}},
		{"a second entry names another index", func(t *testing.T, _ *Config, store *manifest.Store, _ *manifest.PackageManifest) {
			other := pypiIndex(t, "attrs", "24.2.0")
			if err := store.SavePackage(t.Context(), &manifest.PackageManifest{
				Type: manifest.TypePypi, Name: "attrs",
				Versions: []manifest.VersionEntry{{Version: "24.2.0", URL: other.URL}},
			}); err != nil {
				t.Fatalf("SavePackage: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := pypiIndex(t, "six", "1.16.0", "1.17.0")
			pm := &manifest.PackageManifest{
				Type: manifest.TypePypi, Name: "six",
				Versions: []manifest.VersionEntry{{Version: "1.16.0", URL: srv.URL}},
			}
			cfg, store, _ := pinEnv(t, pm)
			cfg.Stdout = io.Discard

			if summary := FetchPypi(cfg, store); summary.HasFailures() {
				t.Fatalf("the first fetch failed: %+v", summary.Results)
			}
			combinedReq := filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")
			if _, err := os.Stat(combinedReq); err != nil {
				t.Fatalf("the first fetch wrote no requirements file: %v", err)
			}

			tc.breakIt(t, cfg, store, pm)
			if summary := FetchPypi(cfg, store); !summary.HasFailures() {
				t.Fatalf("the re-fetch succeeded: %+v", summary.Results)
			}

			if _, err := os.Stat(combinedReq); !os.IsNotExist(err) {
				body, _ := os.ReadFile(combinedReq)
				t.Errorf("a failed re-fetch left the previous run's requirements in place:\n%s", body)
			}
			if CheckPypiStage(cfg, store).Fetched {
				t.Error("a failed re-fetch still reports the fetch stage as done, so the pipeline skips the retry")
			}
			if summary := BuildPypi(cfg, store); !summary.HasFailures() {
				t.Errorf("a build after a failed re-fetch succeeded: %+v", summary.Results)
			}
		})
	}
}

// R3: local labels order by PEP 440 rather than as strings, and the resolver is
// where that decides which artifact a constraint reaches.
func TestResolvePypiVersionOrdersLocalLabels(t *testing.T) {
	for _, tc := range []struct {
		available  []string
		version    string
		constraint string
		want       string
	}{
		{[]string{"1.0+vendor.9", "1.0+vendor.10"}, "1.0", manifest.ConstraintAny, "1.0+vendor.10"},
		{[]string{"1.0+vendor.1"}, "1.0+vendor_1", manifest.ConstraintExact, "1.0+vendor.1"},
		{[]string{"1.0+9", "1.0+abc"}, "1.0", manifest.ConstraintAny, "1.0+9"},
	} {
		srv := pypiIndex(t, "six", tc.available...)
		got, err := resolvePypiVersion(srv.URL, "six", manifest.VersionEntry{
			Version: tc.version, VersionConstraint: tc.constraint,
		})
		if err != nil || got != tc.want {
			t.Errorf("%s %q over %v resolved to %q (err %v), want %q",
				tc.constraint, tc.version, tc.available, got, err, tc.want)
		}
	}
}

// pypiBaseReqEnv stands up a pypi entry whose base requirements come from a
// git application, and writes that application's requirements files.
func pypiBaseReqEnv(t *testing.T, index string, files map[string]string) (*Config, *manifest.Store) {
	t.Helper()
	cfg, store, _ := pinEnv(t, &manifest.PackageManifest{
		Type: manifest.TypePypi, Name: "six",
		Versions: []manifest.VersionEntry{{Version: "1.16.0", URL: index, RequiredBy: []string{"app"}}},
	})
	cfg.Stdout = io.Discard

	if err := store.SavePackage(t.Context(), &manifest.PackageManifest{
		Type: manifest.TypeGit, Name: "app",
		Versions: []manifest.VersionEntry{{Ref: "v1.0.0", URL: "https://example.org/app.git"}},
	}); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	work := gitReleaseDir(buildDirs(cfg.rootFor(manifest.TypeGit)), "app", manifest.VersionEntry{Ref: "v1.0.0"})
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatalf("mkdir worktree: %v", err)
	}
	for name, body := range files {
		path := filepath.Join(work, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return cfg, store
}

// R1/R4: pip parses an included requirements file after the generated header
// and honors the last index option it reads, so an application's own
// requirements.txt could replace the index the manifest resolved against, or
// add a second one beside it, with nothing in the resolver ever seeing it.
func TestFetchPypiFailsWhenIncludedRequirementsNameAnotherOrigin(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"an index of its own", map[string]string{
			"requirements.txt": "--index-url OTHER/simple/\nsix\n",
		}},
		{"an index of its own, joined by =", map[string]string{
			"requirements.txt": "--index-url=OTHER/simple/\nsix\n",
		}},
		{"a second index beside the selected one", map[string]string{
			"requirements.txt": "--extra-index-url OTHER/simple/\nsix\n",
		}},
		{"a directory of wheels", map[string]string{
			"requirements.txt": "--find-links OTHER/wheels/\nsix\n",
		}},
		{"an index one include further down", map[string]string{
			"requirements.txt": "-r nested/base.txt\nsix\n",
			"nested/base.txt":  "--index-url OTHER/simple/\n",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := pypiIndex(t, "six", "1.16.0")
			other := pypiIndex(t, "six", "1.16.0", "1.17.0")

			files := map[string]string{}
			for name, body := range tc.files {
				files[name] = strings.ReplaceAll(body, "OTHER", other.URL)
			}
			cfg, store := pypiBaseReqEnv(t, selected.URL, files)

			summary := FetchPypi(cfg, store)
			if !summary.HasFailures() {
				t.Fatalf("an included file replaced the selected index silently: %+v", summary.Results)
			}
			var msg string
			for _, r := range summary.Results {
				if r.Err != nil {
					msg = r.Err.Error()
				}
			}
			for _, want := range []string{"requirements.txt", other.URL, selected.URL} {
				if !strings.Contains(msg, want) {
					t.Errorf("the failure does not name %q: %s", want, msg)
				}
			}
			if _, err := os.Stat(filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")); !os.IsNotExist(err) {
				t.Error("a fetch that could not settle the origin still wrote a requirements file")
			}
		})
	}
}

// An included file that names the selected index is agreement, not conflict.
func TestFetchPypiAcceptsIncludedRequirementsOnTheSelectedIndex(t *testing.T) {
	selected := pypiIndex(t, "six", "1.16.0")
	cfg, store := pypiBaseReqEnv(t, selected.URL, map[string]string{
		"requirements.txt": "# app\n--index-url " + selected.URL + "/simple\nattrs\n",
	})

	if summary := FetchPypi(cfg, store); summary.HasFailures() {
		t.Fatalf("an included file naming the selected index failed the fetch: %+v", summary.Results)
	}
}

// pypiPipHonors runs real pip over the generated header and an application's
// requirements file, and returns the wheels pip stored. The selected index
// serves the JSON API and no wheel bytes, so a stored wheel is proof that
// something inside the application's file moved acquisition elsewhere.
func pypiPipHonors(t *testing.T, selected string, files map[string]string) ([]string, string) {
	t.Helper()
	app := t.TempDir()
	for name, body := range files {
		path := filepath.Join(app, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return pypiWheelRun(t, fmt.Sprintf("--index-url %s/simple/\n-r %s\n",
		strings.TrimRight(selected, "/"), filepath.Join(app, "requirements.txt")))
}

// R1: pip reads a requirements file by its own grammar. It joins a line ending
// in a backslash onto the next with no separator, takes a short option's value
// attached to it, resolves an unambiguous abbreviation of a long option, and
// honors global options out of a constraint file. Each of these names an index
// in a spelling that matches no whole-line token, so a fetch that accepted them
// approved a pin against one index and downloaded from another.
func TestFetchPypiFailsOnPipSyntaxThatMovesTheOrigin(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"a short option carrying its value", map[string]string{
			"requirements.txt": "-iOTHER/simple/\nsix\n",
		}},
		{"an include carrying its path", map[string]string{
			"requirements.txt": "-rnested.txt\nsix\n",
			"nested.txt":       "--index-url OTHER/simple/\n",
		}},
		{"a constraint file", map[string]string{
			"requirements.txt": "-c constraints.txt\nsix\n",
			"constraints.txt":  "--index-url OTHER/simple/\nsix==1.16.0\n",
		}},
		{"an option split across a continuation", map[string]string{
			"requirements.txt": "--index-\\\nurl OTHER/simple/\nsix\n",
		}},
		{"an abbreviated long option", map[string]string{
			"requirements.txt": "--index-ur OTHER/simple/\nsix\n",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := pypiIndex(t, "six", "1.16.0")
			other := pypiWheelIndex(t, "six", "1.16.0")

			files := map[string]string{}
			for name, body := range tc.files {
				files[name] = strings.ReplaceAll(body, "OTHER", other.URL)
			}

			cfg, store := pypiBaseReqEnv(t, selected.URL, files)
			summary := FetchPypi(cfg, store)
			if !summary.HasFailures() {
				t.Fatalf("an included file moved the origin silently: %+v", summary.Results)
			}
			var msg string
			for _, r := range summary.Results {
				if r.Err != nil {
					msg = r.Err.Error()
				}
			}
			for _, want := range []string{"requirements.txt", other.URL, selected.URL} {
				if !strings.Contains(msg, want) {
					t.Errorf("the failure does not name %q: %s", want, msg)
				}
			}
			if _, err := os.Stat(filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")); !os.IsNotExist(err) {
				t.Error("a fetch that could not settle the origin still wrote a requirements file")
			}

			// Rejecting a spelling pip ignores would prove nothing, so the
			// same file goes to real pip behind the same generated header.
			t.Run("pip acquires from it", func(t *testing.T) {
				stored, out := pypiPipHonors(t, selected.URL, files)
				if len(stored) == 0 {
					t.Skipf("pip stored nothing from %s, so this spelling proves nothing here:\n%s", other.URL, out)
				}
				if !strings.Contains(out, other.URL) {
					t.Errorf("pip stored %v without reading %s:\n%s", stored, other.URL, out)
				}
			})
		})
	}
}

// R1: an origin can also be named in syntax that classifies as nothing here —
// an option this fetch never taught itself, an abbreviation pip resolves and it
// cannot, an index switched off, a download that asks no index at all. Passing
// an unreadable line through leaves pip the only reader of it.
func TestFetchPypiRefusesRequirementSyntaxItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		name, requirements string
	}{
		{"an option this fetch does not interpret", "--use-deprecated=html5lib\nsix\n"},
		{"an abbreviation pip resolves and this does not", "--no- something\nsix\n"},
		{"the index switched off", "--no-index\nsix\n"},
		{"a requirement carrying its own download", "six @ https://example.invalid/six-1.16.0-py3-none-any.whl\n"},
		{"an editable checkout from a vcs", "-e git+https://example.invalid/six.git#egg=six\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := pypiIndex(t, "six", "1.16.0")
			cfg, store := pypiBaseReqEnv(t, selected.URL, map[string]string{
				"requirements.txt": tc.requirements,
			})

			summary := FetchPypi(cfg, store)
			if !summary.HasFailures() {
				t.Fatalf("a line this fetch cannot read reached pip unchallenged: %+v", summary.Results)
			}
			var msg string
			for _, r := range summary.Results {
				if r.Err != nil {
					msg = r.Err.Error()
				}
			}
			if !strings.Contains(msg, "requirements.txt") {
				t.Errorf("the failure does not name the file it read: %s", msg)
			}
		})
	}
}

// An application file may carry the pip options that decide nothing about the
// origin, and a fetch that refused those would reject files pip builds fine.
func TestFetchPypiAcceptsRequirementOptionsThatDecideNoOrigin(t *testing.T) {
	selected := pypiIndex(t, "six", "1.16.0")
	cfg, store := pypiBaseReqEnv(t, selected.URL, map[string]string{
		"requirements.txt": "# app\n--prefer-binary\n--only-binary :all:\n" +
			"-i " + selected.URL + "/simple/ # the index the manifest names\n" +
			"attrs==23.1.0 \\\n    --hash=sha256:" + strings.Repeat("a", 64) + "\n",
	})

	if summary := FetchPypi(cfg, store); summary.HasFailures() {
		t.Fatalf("options that name no origin failed the fetch: %+v", summary.Results)
	}
}

// R1: pip runs shlex over the option half of a line before optparse reads it,
// so one quote or one backslash hides an option from a scan that compares whole
// tokens while leaving pip reading it unchanged. Each case below downloads from
// the other index under pip 26.2.1 while naming no option a token comparison
// can see. The leading --pre is what carries them past pip's own args/options
// boundary, which is decided on the raw text before any quote is removed.
func TestFetchPypiFailsOnQuotedAndEscapedOptions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"an index option in quotes", map[string]string{
			"requirements.txt": "--pre \"--index-url\" OTHER/simple/\nsix\n",
		}},
		{"an index option behind a backslash", map[string]string{
			"requirements.txt": "--pre \\--index-url OTHER/simple/\nsix\n",
		}},
		{"an include in quotes", map[string]string{
			"requirements.txt": "--pre \"-r\" nested.txt\nsix\n",
			"nested.txt":       "--index-url OTHER/simple/\n",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := pypiIndex(t, "six", "1.16.0")
			other := pypiWheelIndex(t, "six", "1.16.0")

			files := map[string]string{}
			for name, body := range tc.files {
				files[name] = strings.ReplaceAll(body, "OTHER", other.URL)
			}

			cfg, store := pypiBaseReqEnv(t, selected.URL, files)
			summary := FetchPypi(cfg, store)
			if !summary.HasFailures() {
				t.Fatalf("quoting hid an index option from the fetch: %+v", summary.Results)
			}
			var msg string
			for _, r := range summary.Results {
				if r.Err != nil {
					msg = r.Err.Error()
				}
			}
			for _, want := range []string{"requirements.txt", other.URL, selected.URL} {
				if !strings.Contains(msg, want) {
					t.Errorf("the failure does not name %q: %s", want, msg)
				}
			}
			if _, err := os.Stat(filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")); !os.IsNotExist(err) {
				t.Error("a fetch that could not settle the origin still wrote a requirements file")
			}

			// The selected index serves no wheel bytes, so anything pip
			// stored it reached the other index to get.
			stored, out := pypiPipHonors(t, selected.URL, files)
			if len(stored) == 0 || !strings.Contains(out, other.URL) {
				t.Errorf("pip stored %v without reading %s, so this spelling proves nothing:\n%s", stored, other.URL, out)
			}
		})
	}
}

// Options this fetch cannot tokenize are options pip cannot tokenize either:
// shlex raises and pip fails the file. Passing the line through would leave the
// origin decided by whichever of the two guessed.
func TestFetchPypiRefusesOptionsItCannotTokenize(t *testing.T) {
	for _, tc := range []struct {
		name, requirements, want string
	}{
		{"a quotation nothing closes", "--index-url \"http://example.invalid/simple/\nsix\n", "closes no"},
		{"a backslash escaping nothing", "--find-links a\\ \nsix\n", "escapes nothing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := pypiIndex(t, "six", "1.16.0")
			cfg, store := pypiBaseReqEnv(t, selected.URL, map[string]string{
				"requirements.txt": tc.requirements,
			})

			summary := FetchPypi(cfg, store)
			if !summary.HasFailures() {
				t.Fatalf("a line neither reader can tokenize reached pip: %+v", summary.Results)
			}
			var msg string
			for _, r := range summary.Results {
				if r.Err != nil {
					msg = r.Err.Error()
				}
			}
			for _, want := range []string{"requirements.txt", tc.want} {
				if !strings.Contains(msg, want) {
					t.Errorf("the failure does not name %q: %s", want, msg)
				}
			}
		})
	}
}

// Quoting is ordinary in a requirements file, and a fetch that read it as
// concealment would reject files pip builds. A quoted index option naming the
// selected index agrees with the manifest, and a quoted path is how a file with
// a space in its name gets included at all.
func TestFetchPypiAcceptsQuotedValuesNamingTheSelectedIndex(t *testing.T) {
	selected := pypiIndex(t, "six", "1.16.0")
	cfg, store := pypiBaseReqEnv(t, selected.URL, map[string]string{
		"requirements.txt": "# app\n" +
			"--index-url \"" + selected.URL + "/simple/\"\n" +
			"--index-url='" + selected.URL + "/simple/'\n" +
			"-r \"app extras.txt\"\n" +
			"attrs\n",
		"app extras.txt": "-i '" + selected.URL + "/simple/'\nattrs\n",
	})

	if summary := FetchPypi(cfg, store); summary.HasFailures() {
		t.Fatalf("quoted values naming the selected index failed the fetch: %+v", summary.Results)
	}
}

// A quoted leading token is part of the requirement to pip, not an option: pip
// decides the args/options boundary on the raw text. Reading `"-r"` there as an
// include would refuse a line pip never treats as one.
func TestFetchPypiReadsAQuotedLeadingTokenAsPipDoes(t *testing.T) {
	line := "\"-r\" nested.txt"
	args, options := breakPypiArgsOptions(line)
	if options != "" || len(args) != 2 {
		t.Fatalf("breakPypiArgsOptions(%q) = %q, %q; pip reads the whole line as the requirement", line, args, options)
	}
}
