package builder

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// aptDebServer serves one .deb whose bytes a test can change under a URL that
// has not moved, which is what an upstream republishing a filename looks like.
func aptDebServer(t *testing.T, debName string, body *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+debName, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(*body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchAptDirectDebPinsOnFirstFetch covers the apt half of "pinned on first
// fetch, enforced on the next". A direct-URL .deb was downloaded and stamped
// for size and nothing else: the first digest arrived at the package stage, so
// a second fetch had no manifest checksum to compare against and no pool path
// to look a pinned row up by.
func TestFetchAptDirectDebPinsOnFirstFetch(t *testing.T) {
	const pkg, debName = "hello", "hello_2.10-3_amd64.deb"
	body := "hello deb bytes"
	srv := aptDebServer(t, debName, &body)

	pm := &manifest.PackageManifest{
		Type:     manifest.TypeApt,
		Name:     pkg,
		Versions: []manifest.VersionEntry{{Version: "2.10-3", URL: srv.URL + "/" + debName}},
	}
	cfg, store, db := pinEnv(t, pm)

	if s := FetchApt(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("first fetch reported %d failures: %+v", s.Failures, s.Results)
	}

	rows, err := db.ListChecksums(t.Context(), manifest.TypeApt, pkg)
	if err != nil {
		t.Fatalf("list checksums: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("a direct .deb fetch recorded %d checksum rows, want 1", len(rows))
	}
	wantKey := manifest.AptKey(aptPoolRelPath(pkg, debName))
	if rows[0].ObjectKey != wantKey {
		t.Errorf("row keyed on %q, want the pool key the server publishes under %q", rows[0].ObjectKey, wantKey)
	}
	pinned := ComputeBytesSHA256([]byte(body))
	if rows[0].Value != pinned {
		t.Errorf("row records %q, want the digest of the served bytes %q", rows[0].Value, pinned)
	}

	stored, err := store.GetPackage(t.Context(), manifest.TypeApt, pkg)
	if err != nil {
		t.Fatalf("GetPackage: %v", err)
	}
	if cs := stored.Versions[0].Checksum; cs == nil || cs.Value != pinned {
		t.Fatalf("the manifest entry carries %+v after a first fetch, want %s", cs, pinned)
	}

	// The build root already holds the .deb, so this run takes the skip path.
	// It re-digests the bytes on disk rather than checking nothing.
	if s := FetchApt(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("a re-fetch of untouched bytes was refused: %+v", s.Results)
	}

	// Same URL, same version, different bytes. A forced re-fetch downloads
	// them, and that is the case the pin exists for.
	body = "republished under the same filename"
	cfg.Force = true
	s := FetchApt(cfg, store, pkg)
	if s.Failures == 0 {
		t.Fatal("a republished .deb was accepted against a pinned digest")
	}
	if !strings.Contains(s.Results[0].Err.Error(), pkg) {
		t.Errorf("the refusal does not name the package: %v", s.Results[0].Err)
	}

	rows, err = db.ListChecksums(t.Context(), manifest.TypeApt, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Value != pinned {
		t.Errorf("the refused fetch changed the pin: %+v", rows)
	}
	stored, err = store.GetPackage(t.Context(), manifest.TypeApt, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if cs := stored.Versions[0].Checksum; cs == nil || cs.Value != pinned {
		t.Errorf("the refused fetch rewrote the manifest digest to %+v", cs)
	}
}

// TestVerifyFetchedCatchesAnEditedDeb guards the path a long-lived install
// actually takes. Every fetch past the first finds the .deb already on disk, so
// the skip path is the only place a build root edited between runs is caught.
func TestVerifyFetchedCatchesAnEditedDeb(t *testing.T) {
	const pkg, debName = "hello", "hello_2.10-3_amd64.deb"
	body := "hello deb bytes"
	srv := aptDebServer(t, debName, &body)

	pm := &manifest.PackageManifest{
		Type:     manifest.TypeApt,
		Name:     pkg,
		Versions: []manifest.VersionEntry{{Version: "2.10-3", URL: srv.URL + "/" + debName}},
	}
	cfg, store, _ := pinEnv(t, pm)

	if s := FetchApt(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("first fetch reported %d failures: %+v", s.Failures, s.Results)
	}

	path := cfg.fetchedArtifact(manifest.TypeApt, pkg, pm.Versions[0])
	if path == "" {
		t.Fatal("apt resolved no artifact path, so the skip path can check nothing")
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := FetchApt(cfg, store, pkg)
	if s.Failures == 0 {
		t.Fatal("a .deb edited in the build root passed the skip path")
	}
}
