package builder

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

func storedVersion(t *testing.T, store *manifest.Store, typ, name, version string) manifest.VersionEntry {
	t.Helper()
	pm, err := store.GetPackage(t.Context(), typ, name)
	if err != nil || pm == nil {
		t.Fatalf("read %s/%s back: %v", typ, name, err)
	}
	for _, ve := range pm.Versions {
		if ve.Version == version {
			return ve
		}
	}
	t.Fatalf("%s/%s has no version %s", typ, name, version)
	return manifest.VersionEntry{}
}

// npmRegistry serves one tarball and a packument whose time is timeJSON.
func npmRegistry(t *testing.T, pkg, version, timeJSON string) *httptest.Server {
	t.Helper()
	tarball := npmPackageTGZ(t, `{"name":"`+pkg+`","version":"`+version+`"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + pkg:
			_, _ = w.Write([]byte(`{"name":"` + pkg + `","time":` + timeJSON + `}`))
		case "/" + pkg + "/-/" + pkg + "-" + version + ".tgz":
			_, _ = w.Write(tarball)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// R1: a fetch reads the version's time out of the packument and records it
// in UTC.
func TestFetchNpmRecordsPublishedAt(t *testing.T) {
	srv := npmRegistry(t, "left-pad", "1.3.0", `{"created":"2014-03-14T00:00:00.000Z","1.3.0":"2018-04-09T01:22:46.123Z"}`)
	cfg, store, _ := pinEnv(t, &manifest.PackageManifest{
		Type: manifest.TypeNpm, Name: "left-pad",
		Versions: []manifest.VersionEntry{{Version: "1.3.0", URL: srv.URL}},
	})
	var out strings.Builder
	cfg.Stdout = &out

	if s := FetchNpm(cfg, store, "left-pad"); s.Failures != 0 {
		t.Fatalf("fetch reported %d failures: %+v", s.Failures, s.Results)
	}
	if got := storedVersion(t, store, manifest.TypeNpm, "left-pad", "1.3.0").PublishedAt; got != "2018-04-09T01:22:46Z" {
		t.Errorf("PublishedAt = %q, want 2018-04-09T01:22:46Z\n%s", got, out.String())
	}
}

// A packument with no time for the version records nothing, says why, and
// fails nothing: the artifact the fetch stored is good either way.
func TestFetchNpmLeavesAnUndatableVersionUndated(t *testing.T) {
	srv := npmRegistry(t, "left-pad", "1.3.0", `{}`)
	cfg, store, _ := pinEnv(t, &manifest.PackageManifest{
		Type: manifest.TypeNpm, Name: "left-pad",
		Versions: []manifest.VersionEntry{{Version: "1.3.0", URL: srv.URL}},
	})
	var out strings.Builder
	cfg.Stdout = &out

	if s := FetchNpm(cfg, store, "left-pad"); s.Failures != 0 {
		t.Fatalf("an undatable version failed the fetch: %+v", s.Results)
	}
	if got := storedVersion(t, store, manifest.TypeNpm, "left-pad", "1.3.0").PublishedAt; got != "" {
		t.Errorf("PublishedAt = %q, want nothing recorded", got)
	}
	if !strings.Contains(out.String(), "left-pad@1.3.0: WARNING: no publish time recorded: npm packument has no time entry for 1.3.0") {
		t.Errorf("no warning naming the version and the reason:\n%s", out.String())
	}
}

// gomod reads the .info the fetch just stored, so dating costs no request.
func TestFetchGomodRecordsInfoTime(t *testing.T) {
	const mod, version = "example.com/mod", "v1.2.0"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + mod + "/@v/" + version + ".info":
			_, _ = w.Write([]byte(`{"Version":"v1.2.0","Time":"2024-01-23T13:54:04-05:00"}`))
		case "/" + mod + "/@v/" + version + ".mod":
			_, _ = w.Write([]byte("module " + mod + "\n"))
		case "/" + mod + "/@v/" + version + ".zip":
			_, _ = w.Write([]byte("zip"))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	cfg, store, _ := pinEnv(t, &manifest.PackageManifest{
		Type: manifest.TypeGomod, Name: mod,
		Versions: []manifest.VersionEntry{{Version: version, URL: srv.URL}},
	})
	cfg.Stdout = &strings.Builder{}

	if s := FetchGomod(cfg, store, ""); s.Failures != 0 {
		t.Fatalf("fetch reported %d failures: %+v", s.Failures, s.Results)
	}
	if got := storedVersion(t, store, manifest.TypeGomod, mod, version).PublishedAt; got != "2024-01-23T18:54:04Z" {
		t.Errorf("PublishedAt = %q, want 2024-01-23T18:54:04Z", got)
	}
}

// cargo reads created_at from the crates.io API, a host neither the download
// root nor the sparse index is.
func TestFetchCargoRecordsCreatedAt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dl/itoa/1.0.11/download":
			_, _ = w.Write([]byte("crate"))
		case "/api/v1/crates/itoa/1.0.11":
			_, _ = w.Write([]byte(`{"version":{"created_at":"2024-03-26T17:24:39.112863+00:00"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	cfg, store, _ := pinEnv(t, &manifest.PackageManifest{
		Type: manifest.TypeCargo, Name: "itoa",
		Versions: []manifest.VersionEntry{{Version: "1.0.11"}},
	})
	cfg.Stdout = &strings.Builder{}
	cfg.CargoDLUpstream = srv.URL + "/dl"
	cfg.CargoUpstream = srv.URL + "/index"
	cfg.CratesAPI = srv.URL

	if s := FetchCargo(cfg, store, ""); s.Failures != 0 {
		t.Fatalf("fetch reported %d failures: %+v", s.Failures, s.Results)
	}
	if got := storedVersion(t, store, manifest.TypeCargo, "itoa", "1.0.11").PublishedAt; got != "2024-03-26T17:24:39Z" {
		t.Errorf("PublishedAt = %q, want 2024-03-26T17:24:39Z", got)
	}
}

// pypi dates each closure artifact a manifest entry names, from the earliest
// file upload PyPI's JSON API reports. attrs arrives only as six's dependency,
// has no entry to carry a time, and costs no request.
func TestStampPypiPublishedDatesTheEntriesTheClosureNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pypi/six/1.16.0/json" {
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"urls":[
			{"upload_time_iso_8601":"2021-05-05T14:21:25.000000Z"},
			{"upload_time_iso_8601":"2021-05-05T14:21:23.520102Z"}]}`))
	}))
	t.Cleanup(srv.Close)
	cfg, store, _ := pinEnv(t, &manifest.PackageManifest{
		Type: manifest.TypePypi, Name: "six",
		Versions: []manifest.VersionEntry{{Version: "1.16.0", URL: srv.URL}},
	})
	cfg.Stdout = &strings.Builder{}
	root := cfg.rootFor(manifest.TypePypi)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	lock := pypiLockBody([]pypiArtifact{
		{File: "six-1.16.0-py2.py3-none-any.whl", Dist: "six", Version: "1.16.0", Digest: strings.Repeat("a", 64)},
		{File: "attrs-24.2.0-py3-none-any.whl", Dist: "attrs", Version: "24.2.0", Digest: strings.Repeat("b", 64)},
	})
	if err := os.WriteFile(pypiLockPath(root), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg.stampPypiPublished(t.Context(), store)
	if got := storedVersion(t, store, manifest.TypePypi, "six", "1.16.0").PublishedAt; got != "2021-05-05T14:21:23Z" {
		t.Errorf("PublishedAt = %q, want the earliest upload, 2021-05-05T14:21:23Z", got)
	}
}

// R5: the backfill fills what it can read, counts what it cannot, leaves a
// recorded time and an unpinned entry alone, and dates a gomod version from
// the .info on disk without a request.
func TestBackfillPublished(t *testing.T) {
	var npmRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/left-pad":
			npmRequests++
			_, _ = w.Write([]byte(`{"time":{"1.3.0":"2018-04-09T01:22:46.000Z"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	cfg, store, _ := pinEnv(t, &manifest.PackageManifest{
		Type: manifest.TypeNpm, Name: "left-pad",
		Versions: []manifest.VersionEntry{
			{Version: "1.3.0", URL: srv.URL},
			{Version: "1.2.0", URL: srv.URL, PublishedAt: "2017-01-01T00:00:00Z"},
			{Version: "1.1.0", URL: srv.URL},
			{Version: "latest", URL: srv.URL},
			{Version: "1.0.0", URL: srv.URL, Frozen: true},
		},
	})
	var out strings.Builder
	cfg.Stdout = &out

	const mod = "example.com/mod"
	if err := store.SavePackage(t.Context(), &manifest.PackageManifest{
		Type: manifest.TypeGomod, Name: mod,
		Versions: []manifest.VersionEntry{{Version: "v1.2.0", URL: "http://127.0.0.1:1"}},
	}); err != nil {
		t.Fatal(err)
	}
	info := gomodInfoPath(cfg, manifest.SafeName(mod), "v1.2.0")
	if err := os.MkdirAll(filepath.Dir(info), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(info, []byte(`{"Version":"v1.2.0","Time":"2024-01-23T18:54:04Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	res := BackfillPublished(cfg, store, []string{manifest.TypeNpm, manifest.TypeGomod}, "", 0)
	if res.Filled != 2 || res.Failed != 2 {
		t.Errorf("filled %d, could not %d; want 2 and 2 (1.1.0 undated upstream, 1.0.0 frozen)\n%s", res.Filled, res.Failed, out.String())
	}
	want := map[string]string{
		"1.3.0":  "2018-04-09T01:22:46Z",
		"1.2.0":  "2017-01-01T00:00:00Z",
		"1.1.0":  "",
		"latest": "",
		"1.0.0":  "",
	}
	for v, w := range want {
		if got := storedVersion(t, store, manifest.TypeNpm, "left-pad", v).PublishedAt; got != w {
			t.Errorf("left-pad@%s PublishedAt = %q, want %q", v, got, w)
		}
	}
	if got := storedVersion(t, store, manifest.TypeGomod, mod, "v1.2.0").PublishedAt; got != "2024-01-23T18:54:04Z" {
		t.Errorf("gomod PublishedAt = %q, want the .info's time", got)
	}
	if npmRequests != 2 {
		t.Errorf("%d packument requests, want 2: one per undated pinned version", npmRequests)
	}
	for _, line := range []string{
		"left-pad@1.1.0: WARNING: no publish time recorded:",
		"left-pad@1.0.0: WARNING: no publish time recorded: the version is frozen",
	} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output does not name %q:\n%s", line, out.String())
		}
	}
}
