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

// pypiIndex serves the JSON API for one distribution with the given releases.
func pypiIndex(t *testing.T, dist string, releases ...string) *httptest.Server {
	t.Helper()
	body := map[string]any{"releases": map[string]any{}}
	for _, v := range releases {
		body["releases"].(map[string]any)[v] = []any{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/"+dist+"/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
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
