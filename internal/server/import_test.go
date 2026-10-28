package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/provenance"
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
	body := `[{"config_version":1,"name":"weird","type":"conda","versions":[{"version":"1.0"}]},` + aptManifest("fine", "1.0") + "]"
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

// aptManifestFrom is aptManifest with the origin the host cataloging it
// recorded.
func aptManifestFrom(name, version, origin string) string {
	return fmt.Sprintf(`{"config_version":1,"name":%q,"type":"apt","versions":[{"version":%q,"source_name":%q,"metadata":{"_origin":%q}}]}`,
		name, version, name, origin)
}

// originsOf reads the origins the store holds for one apt version.
func originsOf(t *testing.T, s *Server, name, version string) []string {
	t.Helper()
	pm, _ := s.store.GetPackage(t.Context(), manifest.TypeApt, name)
	if pm == nil {
		t.Fatalf("apt/%s is not in the store", name)
	}
	for _, ve := range pm.Versions {
		if ve.Version == version {
			return admit.Origins(ve)
		}
	}
	t.Fatalf("apt/%s has no version %s", name, version)
	return nil
}

// The bulk route is what 'bodega pkg import --server' pushes through, so a
// fleet cataloging itself over HTTP has to accumulate origins the same way the
// local store does. Both call admit.MergeVersions; this pins the behavior at
// the surface.
func TestBulkImportMergeAccumulatesOrigins(t *testing.T) {
	s, _, _ := refreshTestServer(t)

	if _, resp := postImport(t, s, "["+aptManifestFrom("curl", "8.5.0", "db01")+"]", ""); resp.Imported != 1 {
		t.Fatalf("first push: imported = %d, want 1; results: %+v", resp.Imported, resp.Results)
	}
	if _, resp := postImport(t, s, "["+aptManifestFrom("curl", "8.5.0", "db02")+"]", "merge=true"); resp.Merged != 1 {
		t.Fatalf("merge push: merged = %d, want 1; results: %+v", resp.Merged, resp.Results)
	}

	got := originsOf(t, s, "curl", "8.5.0")
	if len(got) != 2 || got[0] != "db01" || got[1] != "db02" {
		t.Errorf("origins = %v, want [db01 db02]", got)
	}
}

// osquery ships one .deb per architecture under one version. A merge push of
// the arm64 entry onto a stored amd64 one has to add it, or the arm64 .deb is
// never fetched and the push still reports success.
func TestBulkImportMergeAddsASecondArchitecture(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	const amd64, arm64 = "https://pkg.osquery.io/deb/osquery_5.23.1-1.linux_amd64.deb", "https://pkg.osquery.io/deb/osquery_5.23.1-1.linux_arm64.deb"
	entryAt := func(url string) string {
		return fmt.Sprintf(`[{"config_version":1,"name":"osquery","type":"apt","versions":[{"version":"5.23.1-1","source_name":"osquery","url":%q}]}]`, url)
	}

	if _, resp := postImport(t, s, entryAt(amd64), ""); resp.Imported != 1 {
		t.Fatalf("first push: imported = %d, want 1; results: %+v", resp.Imported, resp.Results)
	}
	if _, resp := postImport(t, s, entryAt(arm64), "merge=true"); resp.Merged != 1 {
		t.Fatalf("merge push: merged = %d, want 1; results: %+v", resp.Merged, resp.Results)
	}

	pm, _ := s.store.GetPackage(t.Context(), manifest.TypeApt, "osquery")
	if pm == nil {
		t.Fatal("apt/osquery is not in the store")
	}
	var urls []string
	for _, ve := range pm.Versions {
		urls = append(urls, ve.URL)
	}
	if !slices.Equal(urls, []string{amd64, arm64}) {
		t.Errorf("stored URLs = %v, want [%s %s]", urls, amd64, arm64)
	}
}

// A manifest's origin must not depend on which route wrote it: a package
// created through the single-entry route and one pushed in a bulk catalog
// carry the field alike.
func TestCreateEntryStoresTheOrigin(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	body := aptManifestFrom("wget", "1.21.4", "db01")
	r := httptest.NewRequest(http.MethodPost, "/api/v1/packages/apt", strings.NewReader(body))
	r.SetPathValue("type", manifest.TypeApt)
	w := httptest.NewRecorder()

	s.handleCreateEntry(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	if got := originsOf(t, s, "wget", "1.21.4"); len(got) != 1 || got[0] != "db01" {
		t.Errorf("origins = %v, want [db01]", got)
	}
}

// Both mutation routes date an imported version from the registry its url
// names, with no audit database and so no age policy to read it on the way.
func TestImportRoutesRecordUpstreamPublishTimes(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/left-pad" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"time":{"1.3.0":"2018-04-09T01:22:46.500Z"}}`))
	}))
	defer registry.Close()
	body := fmt.Sprintf(`{"name":"left-pad","type":"npm","versions":[{"version":"1.3.0","url":%q},{"version":"9.9.9","url":%q}]}`,
		registry.URL, registry.URL)

	check := func(t *testing.T, s *Server, warnings []string) {
		t.Helper()
		pm, _ := s.store.GetPackage(t.Context(), manifest.TypeNpm, "left-pad")
		if pm == nil {
			t.Fatal("left-pad not stored")
		}
		got := map[string]string{}
		for _, ve := range pm.Versions {
			got[ve.Version] = ve.PublishedAt
		}
		if got["1.3.0"] != "2018-04-09T01:22:46Z" {
			t.Errorf("1.3.0 published_at = %q, want 2018-04-09T01:22:46Z", got["1.3.0"])
		}
		if got["9.9.9"] != "" {
			t.Errorf("9.9.9 published_at = %q; upstream has no time for it", got["9.9.9"])
		}
		if warnings != nil && (len(warnings) != 1 || !strings.Contains(warnings[0], "9.9.9")) {
			t.Errorf("warnings = %v, want one naming 9.9.9", warnings)
		}
	}

	t.Run("bulk", func(t *testing.T) {
		s, _, _ := refreshTestServer(t)
		w, resp := postImport(t, s, body, "")
		if w.Code != http.StatusOK || resp.Imported != 1 {
			t.Fatalf("status = %d, imported = %d; body: %s", w.Code, resp.Imported, w.Body.String())
		}
		check(t, s, resp.Results[0].Warnings)
	})
	t.Run("create", func(t *testing.T) {
		s, _, _ := refreshTestServer(t)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm", strings.NewReader(body))
		r.SetPathValue("type", manifest.TypeNpm)
		w := httptest.NewRecorder()
		s.handleCreateEntry(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
		}
		check(t, s, nil)
	})
}

// TestBulkImportHoldsABoundHostToItsOwnOrigin covers what an operator reading
// _origin relies on: the row names the host that pushed it. A token bound to
// one host cannot catalog rows under another's name, and an unbound push from
// a workstation keeps the origin it claims because no identity says otherwise.
func TestBulkImportHoldsABoundHostToItsOwnOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, identity, body string
		outcome              ImportOutcome
		origin               string
	}{
		{"own origin", "db01", aptManifestFrom("curl", "8.5.0", "db01"), ImportImported, "db01"},
		{"no origin", "db01", aptManifest("curl", "8.5.0"), ImportImported, "db01"},
		{"unbound", "", aptManifestFrom("curl", "8.5.0", "db02"), ImportImported, "db02"},
		{"another host", "db01", aptManifestFrom("curl", "8.5.0", "db02"), ImportFailed, ""},
		{"another host among several", "db01", aptManifestFrom("curl", "8.5.0", "db01,db02"), ImportFailed, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDiscoveryServer(t)
			body := "[" + tc.body + "," + aptManifest("wget", "1.21") + "]"
			r := httptest.NewRequest(http.MethodPost, "/api/v1/packages/import", strings.NewReader(body))
			w := httptest.NewRecorder()
			s.handleBulkImport(w, withIdentity(r, tc.identity))
			var resp ImportResponse
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if w.Code != http.StatusOK || len(resp.Results) != 2 {
				t.Fatalf("status %d, results %+v", w.Code, resp.Results)
			}
			if got := resp.Results[0]; got.Outcome != tc.outcome {
				t.Fatalf("curl: outcome = %q (%s), want %q", got.Outcome, got.Reason, tc.outcome)
			}
			if resp.Results[1].Outcome != ImportImported {
				t.Errorf("wget beside it: outcome = %q (%s), want imported", resp.Results[1].Outcome, resp.Results[1].Reason)
			}

			all, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCreate, PkgName: "curl"})
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			// The admit path writes its own policy_warn row; the write is
			// the success row.
			var events []audit.StoredEvent
			for _, e := range all {
				if e.Status == "success" {
					events = append(events, e)
				}
			}
			pm, _ := s.store.GetPackage(t.Context(), manifest.TypeApt, "curl")

			if tc.outcome == ImportFailed {
				reason := resp.Results[0].Reason
				if !strings.Contains(reason, `"db02"`) || !strings.Contains(reason, `"db01"`) {
					t.Errorf("reason %q does not name both the claimed origin and the identity", reason)
				}
				if !strings.Contains(reason, "re-run 'bodega pkg convert --origin db01'") {
					t.Errorf("reason %q does not name the convert flag that fixes it", reason)
				}
				if pm != nil {
					t.Errorf("a refused package was saved: %+v", pm)
				}
				if len(all) != 0 {
					t.Errorf("a refused package wrote an audit row: %+v", all)
				}
				return
			}

			if pm == nil {
				t.Fatal("curl reported imported but is not in the store")
			}
			if got := pm.Versions[0].Metadata[admit.MetaOrigin]; got != tc.origin {
				t.Errorf("stored origin = %q, want %q", got, tc.origin)
			}
			if len(events) != 1 {
				t.Fatalf("create rows for curl = %d, want 1: %+v", len(events), events)
			}
			if ev := events[0]; ev.Identity != tc.identity || ev.ClientIP != ClientIP(r) || ev.ClientIP == "" {
				t.Errorf("audit row identity %q client %q, want %q and %q", ev.Identity, ev.ClientIP, tc.identity, ClientIP(r))
			}
		})
	}
}

// TestBulkImportRefusesAnotherHostOnMerge pins that a refused package is not
// merged either: a bound host adding its name to a row another host owns
// would be the same false claim arriving through the merge path.
func TestBulkImportRefusesAnotherHostOnMerge(t *testing.T) {
	s := newDiscoveryServer(t)
	seed := httptest.NewRequest(http.MethodPost, "/api/v1/packages/import", strings.NewReader("["+aptManifestFrom("curl", "8.5.0", "db02")+"]"))
	s.handleBulkImport(httptest.NewRecorder(), withIdentity(seed, "db02"))

	r := httptest.NewRequest(http.MethodPost, "/api/v1/packages/import?merge=true",
		strings.NewReader("["+aptManifestFrom("curl", "8.6.0", "db03")+"]"))
	w := httptest.NewRecorder()
	s.handleBulkImport(w, withIdentity(r, "db01"))
	var resp ImportResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Results) != 1 || resp.Results[0].Outcome != ImportFailed {
		t.Fatalf("results = %+v, want one failed", resp.Results)
	}
	pm, _ := s.store.GetPackage(t.Context(), manifest.TypeApt, "curl")
	if pm == nil || len(pm.Versions) != 1 {
		t.Fatalf("a refused merge changed the stored package: %+v", pm)
	}
}

// admittingServer is a server with an audit database, so admission writes its
// rows and the provenance check can pin, and an npm stub serving
// sigstore@3.0.0 with the bundle npm recorded for it. The provenance check
// reads that stub against the recorded Sigstore trusted root, so 3.0.0
// verifies the way it does in internal/provenance. It returns the stub's URL
// and seeds npm/sigstore at 2.0.0 straight into the store, so the seed itself
// writes no admission row and takes no pin.
func admittingServer(t *testing.T) (*Server, string) {
	t.Helper()
	td := filepath.Join("..", "provenance", "testdata")
	bundles, err := os.ReadFile(filepath.Join(td, "npm-sigstore-3.0.0.attestations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sigstore":
			dist := map[string]any{
				"integrity": "sha512-PHMifhh3EN4loMcHCz6l3v/luzgT3za+9f8subGgeMNjbJjzH4Ij/YoX3Gvu+kaouJRIlVdTHHCREADYf+ZteA==",
				"attestations": map[string]any{"url": srv.URL + "/att/sigstore@3.0.0",
					"provenance": map[string]any{"predicateType": provenance.SLSAProvenanceV1}},
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"versions": map[string]any{"3.0.0": map[string]any{"dist": dist}}})
		case "/att/sigstore@3.0.0":
			_, _ = w.Write(bundles)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	tr, err := provenance.LoadTrustedRootFile(filepath.Join(td, "trusted_root.json"))
	if err != nil {
		t.Fatal(err)
	}
	prev := admit.NewProvenanceVerifier
	admit.NewProvenanceVerifier = func(cfg *config.Config) *provenance.Verifier {
		v := prev(cfg)
		v.Root = func(context.Context) (root.TrustedMaterial, error) { return tr, nil }
		return v
	}
	t.Cleanup(func() { admit.NewProvenanceVerifier = prev })

	dir := t.TempDir()
	cfg := &config.Config{AptCodename: "noble", LogDir: dir, StoragePath: dir, AuditDB: filepath.Join(dir, "audit.db")}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB == nil {
		t.Fatal("audit DB not opened; the test would assert nothing")
	}
	t.Cleanup(func() { _ = s.auditDB.Close() })
	// The seeded npm age gate dates versions against the public registry.
	if _, err := s.auditDB.DeleteAgePolicy(t.Context(), manifest.TypeNpm); err != nil {
		t.Fatal(err)
	}
	seed := &manifest.PackageManifest{ConfigVersion: manifest.CurrentConfigVersion, Name: "sigstore", Type: manifest.TypeNpm,
		Versions: []manifest.VersionEntry{{Version: "2.0.0", URL: srv.URL}}}
	if err := s.store.SavePackage(t.Context(), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s, srv.URL
}

// admissionTrail reports what admission left behind for npm/sigstore: its
// admission rows and whether it holds a provenance pin.
func admissionTrail(t *testing.T, s *Server) ([]audit.Admission, bool) {
	t.Helper()
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeNpm, PkgName: "sigstore"})
	if err != nil {
		t.Fatalf("admissions: %v", err)
	}
	_, err = s.auditDB.GetProvenancePin(t.Context(), manifest.TypeNpm, "sigstore")
	if err != nil && !errors.Is(err, audit.ErrProvenancePinNotFound) {
		t.Fatalf("provenance pin: %v", err)
	}
	return rows, err == nil
}

// TestBulkImportConflictRecordsNoAdmission pins that a conflict is decided
// before admission. Admission records "admitted" and takes the provenance pin
// on first verify, so a conflict decided after it left an admitted row for a
// version never stored, and could make that version the pin every later one
// is held to. The merge import is the control: the same version, admitted and
// stored, does take the pin, so the stub verifies.
func TestBulkImportConflictRecordsNoAdmission(t *testing.T) {
	s, registry := admittingServer(t)
	body := fmt.Sprintf(`[{"name":"sigstore","type":"npm","versions":[{"version":"3.0.0","url":%q}]}]`, registry)

	_, resp := postImport(t, s, body, "")
	if len(resp.Results) != 1 || resp.Results[0].Outcome != ImportConflict ||
		resp.Results[0].Reason != "package already exists (retry with merge=true to add versions)" {
		t.Fatalf("results = %+v, want one conflict", resp.Results)
	}
	if rows, pinned := admissionTrail(t, s); len(rows) != 0 || pinned {
		t.Fatalf("a conflict left %d admission row(s) and pinned = %v: %+v", len(rows), pinned, rows)
	}

	if _, resp := postImport(t, s, body, "merge=true"); resp.Merged != 1 {
		t.Fatalf("control merge: %+v", resp.Results)
	}
	if rows, pinned := admissionTrail(t, s); len(rows) != 1 || rows[0].Decision != audit.AdmissionAdmitted || !pinned {
		t.Fatalf("control merge left %d row(s), pinned = %v; the stub does not verify and the test above proves nothing", len(rows), pinned)
	}
}
