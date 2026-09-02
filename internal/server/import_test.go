package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

func postImport(t *testing.T, s *Server, body, query string) (*httptest.ResponseRecorder, ImportResponse) {
	t.Helper()
	url := "/api/v1/packages/import"
	if query != "" {
		url += "?" + query
	}
	r := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleBulkImport(w, r)
	var resp ImportResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp
}

func aptManifest(name, version string) string {
	return fmt.Sprintf(`{"config_version":1,"name":%q,"type":"apt","versions":[{"version":%q,"source_name":%q}]}`,
		name, version, name)
}

// TestBulkImportAcceptsBothBodyShapes pins the two wire forms. A JSON array is
// what 'pkg convert' emits; NDJSON is what a caller streams when the catalog
// is too big to hold. Both decode one manifest at a time and must agree.
func TestBulkImportAcceptsBothBodyShapes(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"array", "[" + aptManifest("alpha", "1.0") + "," + aptManifest("beta", "2.0") + "]"},
		{"ndjson", aptManifest("alpha", "1.0") + "\n" + aptManifest("beta", "2.0") + "\n"},
		{"ndjson-no-trailing-newline", aptManifest("alpha", "1.0") + "\n" + aptManifest("beta", "2.0")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := refreshTestServer(t)
			w, resp := postImport(t, s, tc.body, "")
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			if resp.Imported != 2 {
				t.Fatalf("imported = %d, want 2; results: %+v", resp.Imported, resp.Results)
			}
			for _, name := range []string{"alpha", "beta"} {
				if pm, _ := s.store.GetPackage(t.Context(), manifest.TypeApt, name); pm == nil {
					t.Errorf("%s reported imported but is not in the store", name)
				}
			}
		})
	}
}

// TestBulkImportLandsPartially is the difference from the single-package
// route. One already-present package in a host catalog must not discard the
// rest, so the response reports per package and the status stays 200.
func TestBulkImportLandsPartially(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	if _, resp := postImport(t, s, "["+aptManifest("already", "1.0")+"]", ""); resp.Imported != 1 {
		t.Fatalf("seed failed: %+v", resp)
	}

	body := "[" + aptManifest("already", "1.0") + "," + aptManifest("new", "1.0") + "," +
		`{"config_version":1,"name":"broken","type":"apt","versions":[{}]}` + "]"
	w, resp := postImport(t, s, body, "")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a partial landing is the expected shape", w.Code)
	}
	if resp.Imported != 1 || resp.Skipped != 2 {
		t.Fatalf("imported = %d, skipped = %d, want 1 and 2; results: %+v", resp.Imported, resp.Skipped, resp.Results)
	}
	got := map[string]ImportOutcome{}
	for _, res := range resp.Results {
		got[res.Name] = res.Outcome
	}
	if got["already"] != ImportConflict {
		t.Errorf("already: outcome = %q, want conflict", got["already"])
	}
	if got["broken"] != ImportInvalid {
		t.Errorf("broken: outcome = %q, want invalid", got["broken"])
	}
	if got["new"] != ImportImported {
		t.Errorf("new: outcome = %q, want imported", got["new"])
	}
	if pm, _ := s.store.GetPackage(t.Context(), manifest.TypeApt, "new"); pm == nil {
		t.Error("the package that passed did not land because others failed")
	}
}

// TestBulkImportMergeAddsVersions covers a re-import of a host whose packages
// moved on. Without merge the whole catalog conflicts; with it, only the new
// versions are added and the recorded ones are left alone.
func TestBulkImportMergeAddsVersions(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	postImport(t, s, "["+aptManifest("curl", "8.5.0")+"]", "")

	w, resp := postImport(t, s, "["+aptManifest("curl", "8.6.0")+"]", "merge=true")
	if w.Code != http.StatusOK || resp.Merged != 1 {
		t.Fatalf("merged = %d, want 1; status %d, results %+v", resp.Merged, w.Code, resp.Results)
	}

	pm, _ := s.store.GetPackage(t.Context(), manifest.TypeApt, "curl")
	if pm == nil {
		t.Fatal("curl is gone")
	}
	if len(pm.Versions) != 2 {
		t.Fatalf("curl has %d versions, want 2: %+v", len(pm.Versions), pm.Versions)
	}
	if pm.Versions[0].Version != "8.5.0" {
		t.Errorf("the recorded version was overwritten: %q", pm.Versions[0].Version)
	}
}

// TestBulkImportRejectsAnUnknownType keeps a typo'd type from landing as a
// package nothing serves, while the rest of the push continues.
func TestBulkImportRejectsAnUnknownType(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	body := `[{"config_version":1,"name":"weird","type":"rpm","versions":[{"version":"1.0"}]},` + aptManifest("fine", "1.0") + "]"
	_, resp := postImport(t, s, body, "")
	if resp.Imported != 1 || resp.Skipped != 1 {
		t.Fatalf("imported = %d, skipped = %d, want 1 and 1", resp.Imported, resp.Skipped)
	}
	for _, res := range resp.Results {
		if res.Name == "weird" && res.Outcome != ImportInvalid {
			t.Errorf("an unknown type came back as %q", res.Outcome)
		}
	}
}

// TestBulkImportRejectsGarbage checks the error a caller who piped the wrong
// thing actually sees. "invalid request body" alone does not say what was
// expected.
func TestBulkImportRejectsGarbage(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	w, _ := postImport(t, s, "dpkg-query -W said hello\n", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "manifest") {
		t.Errorf("the error does not say what the endpoint wanted: %s", w.Body.String())
	}
}

// TestBulkImportCarriesAWholeHost is the scale case, and the bare package
// count is not what makes it one. 2000 minimal apt manifests are only 220 KB,
// comfortably under the single-package route's 1 MiB ceiling. What clears that
// ceiling is the metadata a real entry carries once it has been through the
// pipeline: architecture, section, pool path, description. A desktop Ubuntu
// install runs 3000 to 5000 packages, so this pushes a catalog of that shape
// and asserts it is genuinely over the old limit before pushing it.
func TestBulkImportCarriesAWholeHost(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	const count = 4000
	var b strings.Builder
	b.WriteByte('[')
	for i := range count {
		if i > 0 {
			b.WriteByte(',')
		}
		name := fmt.Sprintf("pkg-%04d", i)
		fmt.Fprintf(&b, `{"config_version":1,"name":%q,"type":"apt","description":`+
			`"a package carrying the metadata a real pool entry has",`+
			`"versions":[{"version":"1.0.0","source_name":%q,"metadata":{`+
			`"Architecture":"amd64","Priority":"optional","Section":"utils",`+
			`"_pool_path":"pool/main/p/%s/%s_1.0.0_amd64.deb"}}]}`, name, name, name, name)
	}
	b.WriteByte(']')
	if b.Len() <= 1<<20 {
		t.Fatalf("the catalog is %d bytes, at or under the single-package route's 1 MiB ceiling: "+
			"this test would pass without proving the new ceiling does anything", b.Len())
	}

	w, resp := postImport(t, s, b.String(), "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body starts: %.200s", w.Code, w.Body.String())
	}
	if resp.Imported != count {
		t.Fatalf("imported = %d, want %d", resp.Imported, count)
	}
	if len(resp.Results) != count {
		t.Errorf("results has %d entries, want one per package", len(resp.Results))
	}
}

// TestBulkImportRefusesAnOversizedBody keeps the ceiling real. Without it an
// unbounded decode is an unbounded allocation on an unauthenticated-shaped
// route.
func TestBulkImportRefusesAnOversizedBody(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	huge := strings.Repeat("x", importBodyLimit+1)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/packages/import", strings.NewReader("[\""+huge+"\"]"))
	w := httptest.NewRecorder()
	s.handleBulkImport(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", w.Code)
	}
	if !strings.Contains(w.Body.String(), "NDJSON") {
		t.Errorf("the error does not tell the caller what to do instead: %s", w.Body.String())
	}
}
