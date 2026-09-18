package builder

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// npmDistTagRegistry serves a packument whose "latest" points at resolved, and
// the matching tarball. tarball is read on each request so a test can move the
// bytes under a tag that has not moved.
func npmDistTagRegistry(t *testing.T, pkg, resolved string, tarball *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+pkg, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"name":%q,"dist-tags":{"latest":%q}}`, pkg, resolved)
	})
	mux.HandleFunc(fmt.Sprintf("/%s/-/%s-%s.tgz", pkg, pkg, resolved), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(*tarball))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchNpmDistTagPinsResolvedVersion covers the npm half of B54's
// record-and-enforce claim. The dist-tag path resolved "latest" to a concrete
// version, downloaded it, printed a digest and recorded nothing, so
// `pkg checksum list` had no row for a tag-driven entry and the next fetch had
// nothing to enforce.
//
// The pin is keyed on the resolved version rather than on the tag: the tag is
// allowed to move, and moving it must not read as tampering.
func TestFetchNpmDistTagPinsResolvedVersion(t *testing.T) {
	const pkg, resolved = "left-pad", "1.3.0"
	tarball := string(npmPackageTGZ(t, `{"name":"left-pad","version":"1.3.0"}`))
	srv := npmDistTagRegistry(t, pkg, resolved, &tarball)

	pm := &manifest.PackageManifest{
		Type:     manifest.TypeNpm,
		Name:     pkg,
		Versions: []manifest.VersionEntry{{Version: "latest", URL: srv.URL}},
	}
	cfg, store, db := pinEnv(t, pm)

	if s := FetchNpm(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("first fetch reported %d failures: %+v", s.Failures, s.Results)
	}

	rows, err := db.ListChecksums(t.Context(), manifest.TypeNpm, pkg)
	if err != nil {
		t.Fatalf("list checksums: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("a dist-tag fetch recorded %d checksum rows, want 1", len(rows))
	}
	wantKey := manifest.NpmTarballKey(pkg, resolved)
	if rows[0].ObjectKey != wantKey {
		t.Errorf("row keyed on %q, want the resolved version's object key %q", rows[0].ObjectKey, wantKey)
	}
	if rows[0].PkgVersion != resolved {
		t.Errorf("row records version %q, want the resolved %q", rows[0].PkgVersion, resolved)
	}
	pinned := rows[0].Value

	// The tag has not moved and the bytes have. That is the case the pin exists
	// for, so the fetch must be refused and the pin must survive it.
	tarball = string(npmPackageTGZ(t, `{"name":"left-pad","version":"1.3.0","description":"republished"}`))
	s := FetchNpm(cfg, store, pkg)
	if s.Failures == 0 {
		t.Fatal("a republished tarball under an unmoved dist-tag was accepted")
	}

	rows, err = db.ListChecksums(t.Context(), manifest.TypeNpm, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Value != pinned {
		t.Errorf("the refused fetch changed the pin: %+v", rows)
	}
}

// TestFetchNpmDistTagLeavesEntryFloating guards the reason the pin is keyed on
// the resolved version. Writing the digest onto the "latest" entry would freeze
// the tag: the next release resolves to a new version, and the fetch that
// downloads it would be compared against the previous one's bytes and refused.
func TestFetchNpmDistTagLeavesEntryFloating(t *testing.T) {
	const pkg = "left-pad"
	first := string(npmPackageTGZ(t, `{"name":"left-pad","version":"1.3.0"}`))
	srv := npmDistTagRegistry(t, pkg, "1.3.0", &first)

	pm := &manifest.PackageManifest{
		Type:     manifest.TypeNpm,
		Name:     pkg,
		Versions: []manifest.VersionEntry{{Version: "latest", URL: srv.URL}},
	}
	cfg, store, db := pinEnv(t, pm)

	if s := FetchNpm(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("first fetch reported %d failures: %+v", s.Failures, s.Results)
	}

	stored, err := store.GetPackage(t.Context(), manifest.TypeNpm, pkg)
	if err != nil {
		t.Fatalf("GetPackage: %v", err)
	}
	if cs := stored.Versions[0].Checksum; cs != nil {
		t.Fatalf("the dist-tag entry was pinned to %s, which freezes the tag at 1.3.0", cs.Value)
	}

	// The tag moves to a new release with different bytes.
	second := string(npmPackageTGZ(t, `{"name":"left-pad","version":"1.4.0"}`))
	moved := npmDistTagRegistry(t, pkg, "1.4.0", &second)
	stored.Versions[0].URL = moved.URL
	if err := store.SavePackage(t.Context(), stored); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	if s := FetchNpm(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("a dist-tag advancing to a new release was refused: %+v", s.Results)
	}

	rows, err := db.ListChecksums(t.Context(), manifest.TypeNpm, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("two resolved versions produced %d rows, want one each: %+v", len(rows), rows)
	}
}
