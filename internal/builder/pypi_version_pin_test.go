package builder

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
	if !strings.Contains(req, "six==1.16.0") {
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
		{manifest.ConstraintExact, "1.16.0", "six==1.16.0"},
		{"", "1.16.0", "six==1.16.0"},
		{manifest.ConstraintPatch, "1.15.0", "six==1.15.4"},
		{manifest.ConstraintCompatible, "1.15.0", "six==1.16.2"},
		{manifest.ConstraintAny, "1.15.0", "six==2.0.0"},
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

// The default index stays unsaid, so a deployment pointing pip at its own
// mirror through pip.conf keeps it.
func TestFetchPypiLeavesTheDefaultIndexUnsaid(t *testing.T) {
	if got := pypiIndexLine(defaultPypiIndex); got != "" {
		t.Errorf("the default index was written into the requirements file as %q", got)
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
		{"--index-url https://example/simple/\n-r /tmp/other.txt\n", true},
		{"--requirement=/tmp/other.txt\n", true},
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
