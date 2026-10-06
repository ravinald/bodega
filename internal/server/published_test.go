package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// npm reads time[version] for --min-release-age and --before, and treats a
// version with no entry as old enough. The packument dates what a fetch
// recorded and bounds created and modified by those dates alone.
func TestPackumentPublishesRecordedTimes(t *testing.T) {
	s := hostedServer(t)
	older := sha256Entry("1.3.0", leftPadTarball)
	older.PublishedAt = "2018-04-09T01:22:46Z"
	newer := sha256Entry("1.4.0", leftPadTarball)
	newer.PublishedAt = "2026-10-01T12:00:00Z"
	undated := sha256Entry("1.5.0", leftPadTarball)
	for _, ve := range []manifest.VersionEntry{older, newer, undated} {
		addVersion(t, s, manifest.TypeNpm, "left-pad", ve)
	}

	status, body := getStatusAndBody(t, s, "/npm/left-pad")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/left-pad = %d, want 200: %s", status, body)
	}
	times, ok := decodeJSON(t, body)["time"].(map[string]any)
	if !ok {
		t.Fatalf("the packument carries no time object: %s", body)
	}
	want := map[string]string{
		"1.3.0":    "2018-04-09T01:22:46.000Z",
		"1.4.0":    "2026-10-01T12:00:00.000Z",
		"created":  "2018-04-09T01:22:46.000Z",
		"modified": "2026-10-01T12:00:00.000Z",
	}
	for k, v := range want {
		if times[k] != v {
			t.Errorf("time[%s] = %v, want %s", k, times[k], v)
		}
	}
	if _, present := times["1.5.0"]; present {
		t.Errorf("a version with no recorded time was given one: %v", times)
	}
	if len(times) != len(want) {
		t.Errorf("time = %v, want exactly %v", times, want)
	}
}

// A packument with no dated version carries no time at all, rather than a
// created and modified invented from nothing.
func TestPackumentOmitsTimeWhenNoneRecorded(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeNpm, "left-pad", sha256Entry("1.3.0", leftPadTarball))

	_, body := getStatusAndBody(t, s, "/npm/left-pad")
	if _, present := decodeJSON(t, body)["time"]; present {
		t.Errorf("a packument with no recorded time published one: %s", body)
	}
}

// The bounds come after the filters: a hidden version's time would otherwise
// leak through modified, dating a release the caller cannot see.
func TestPackumentTimeBoundsSkipHiddenVersions(t *testing.T) {
	s := hostedServer(t)
	shown := sha256Entry("1.3.0", leftPadTarball)
	shown.PublishedAt = "2018-04-09T01:22:46Z"
	hidden := sha256Entry("1.4.0", leftPadTarball)
	hidden.PublishedAt = "2026-10-01T12:00:00Z"
	hidden.Hidden = true
	addVersion(t, s, manifest.TypeNpm, "left-pad", shown)
	addVersion(t, s, manifest.TypeNpm, "left-pad", hidden)

	_, body := getStatusAndBody(t, s, "/npm/left-pad")
	times, _ := decodeJSON(t, body)["time"].(map[string]any)
	if times["modified"] != "2018-04-09T01:22:46.000Z" {
		t.Errorf("time.modified = %v, want the visible version's time", times["modified"])
	}
	if _, present := times["1.4.0"]; present {
		t.Errorf("the hidden version is dated: %v", times)
	}
}

func pypiDatedServer(t *testing.T) *Server {
	t.Helper()
	s := hostedServer(t)
	addVersion(t, s, manifest.TypePypi, "six", manifest.VersionEntry{
		Version: "1.16.0", PublishedAt: "2021-05-05T14:21:23Z",
	})
	addVersion(t, s, manifest.TypePypi, "six", manifest.VersionEntry{Version: "1.17.0"})
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/six-1.16.0-py2.py3-none-any.whl": "wheel",
		"pypi/wheels/six-1.17.0-py2.py3-none-any.whl": "wheel",
	})
	return s
}

// PEP 700's upload-time, as a data attribute on the HTML form. The undated
// version's anchor carries no attribute rather than an invented time.
func TestPypiSimpleHTMLCarriesUploadTime(t *testing.T) {
	status, body := getStatusAndBody(t, pypiDatedServer(t), "/pypi/simple/six/")
	if status != http.StatusOK {
		t.Fatalf("GET /pypi/simple/six/ = %d: %s", status, body)
	}
	if !strings.Contains(body, `six-1.16.0-py2.py3-none-any.whl" data-upload-time="2021-05-05T14:21:23Z">`) {
		t.Errorf("the dated wheel carries no data-upload-time:\n%s", body)
	}
	if got := strings.Count(body, "data-upload-time"); got != 1 {
		t.Errorf("%d anchors carry data-upload-time, want only the dated one:\n%s", got, body)
	}
}

// pip and uv ask for PEP 691 JSON first, and read upload-time from it.
func TestPypiSimpleServesJSONWhenAsked(t *testing.T) {
	rec := doRequest(pypiDatedServer(t), http.MethodGet, "/pypi/simple/six/", map[string]string{
		"Accept": "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html; q=0.1, text/html; q=0.01",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /pypi/simple/six/ = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != pypiSimpleJSON {
		t.Errorf("Content-Type = %q, want %q", ct, pypiSimpleJSON)
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Accept") {
		t.Errorf("Vary = %q; a cache would serve one form to a client asking for the other", rec.Header().Get("Vary"))
	}
	doc := decodeJSON(t, rec.Body.String())
	if doc["name"] != "six" {
		t.Errorf("name = %v, want six", doc["name"])
	}
	files, _ := doc["files"].([]any)
	if len(files) != 2 {
		t.Fatalf("files = %v, want both wheels", doc["files"])
	}
	got := map[string]any{}
	for _, f := range files {
		m, _ := f.(map[string]any)
		if _, ok := m["hashes"].(map[string]any); !ok {
			t.Errorf("%v carries no hashes object, which PEP 691 requires", m["filename"])
		}
		got[m["filename"].(string)] = m["upload-time"]
	}
	if got["six-1.16.0-py2.py3-none-any.whl"] != "2021-05-05T14:21:23Z" {
		t.Errorf("1.16.0 upload-time = %v, want 2021-05-05T14:21:23Z", got["six-1.16.0-py2.py3-none-any.whl"])
	}
	if v, present := got["six-1.17.0-py2.py3-none-any.whl"]; !present || v != nil {
		t.Errorf("1.17.0 upload-time = %v, want the key absent", v)
	}
}

// A client that asks for nothing in particular, or ranks HTML first, gets the
// HTML it always got.
func TestPypiWantsJSON(t *testing.T) {
	cases := map[string]bool{
		"":                                    false,
		"*/*":                                 false,
		"text/html":                           false,
		"application/vnd.pypi.simple.v1+json": true,
		"application/vnd.pypi.simple.latest+json":                                                            true,
		"application/vnd.pypi.simple.v1+json; q=0, text/html":                                                false,
		"text/html, application/vnd.pypi.simple.v1+json; q=0.5":                                              false,
		"application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html; q=0.1, text/html; q=0.01": true,
	}
	for accept, want := range cases {
		if got := pypiWantsJSON(accept); got != want {
			t.Errorf("pypiWantsJSON(%q) = %v, want %v", accept, got, want)
		}
	}
}

const gomodInfoStored = `{"Version":"v1.6.0","Time":"2000-01-01T00:00:00Z","Origin":{"VCS":"git"}}`

// The hosted .info carries the recorded time, and keeps the fields it carried.
func TestGomodInfoCarriesRecordedTime(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeGomod, "github.com/google/uuid", manifest.VersionEntry{
		Version: "v1.6.0", PublishedAt: "2024-01-23T18:54:04Z",
	})
	seed(t, s, manifest.TypeGomod, map[string]string{
		manifest.GomodKey("github.com/google/uuid", "v1.6.0", ".info"): gomodInfoStored,
	})

	status, body := getStatusAndBody(t, s, "/go/github.com/google/uuid/@v/v1.6.0.info")
	if status != http.StatusOK {
		t.Fatalf("GET .info = %d: %s", status, body)
	}
	doc := decodeJSON(t, body)
	if doc["Time"] != "2024-01-23T18:54:04Z" {
		t.Errorf("Time = %v, want the recorded 2024-01-23T18:54:04Z", doc["Time"])
	}
	if doc["Version"] != "v1.6.0" || doc["Origin"] == nil {
		t.Errorf("the rewrite dropped a field: %s", body)
	}
}

// A version with no recorded time is served as stored, byte for byte.
func TestGomodInfoUndatedIsServedAsStored(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeGomod, "github.com/google/uuid", manifest.VersionEntry{Version: "v1.6.0"})
	seed(t, s, manifest.TypeGomod, map[string]string{
		manifest.GomodKey("github.com/google/uuid", "v1.6.0", ".info"): gomodInfoStored,
	})

	_, body := getStatusAndBody(t, s, "/go/github.com/google/uuid/@v/v1.6.0.info")
	if body != gomodInfoStored {
		t.Errorf(".info = %s, want the stored document unchanged", body)
	}
}
