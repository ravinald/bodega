package builder

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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

// TestFetchAptKeepsEachArchitectureOnItsOwnEntry covers one version published
// as one .deb per architecture, two entries that differ only by URL. Matching
// the stored entry by version alone stamped the second download's digest and
// pool path onto the first entry, so the next fetch refused the first .deb.
func TestFetchAptKeepsEachArchitectureOnItsOwnEntry(t *testing.T) {
	const pkg, amdDeb, armDeb = "osquery", "osquery_5.23.1-1.linux_amd64.deb", "osquery_5.23.1-1.linux_arm64.deb"
	amdBody, armBody := "amd64 deb bytes", "arm64 deb bytes"
	mux := http.NewServeMux()
	mux.HandleFunc("/"+amdDeb, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(amdBody)) })
	mux.HandleFunc("/"+armDeb, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(armBody)) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	amdSum, armSum := ComputeBytesSHA256([]byte(amdBody)), ComputeBytesSHA256([]byte(armBody))
	pm := &manifest.PackageManifest{
		Type: manifest.TypeApt,
		Name: pkg,
		Versions: []manifest.VersionEntry{
			{Version: "5.23.1-1", URL: srv.URL + "/" + amdDeb, Checksum: newSHA256Checksum(amdSum)},
			{Version: "5.23.1-1", URL: srv.URL + "/" + armDeb, Checksum: newSHA256Checksum(armSum)},
		},
	}
	cfg, store, _ := pinEnv(t, pm)

	if s := FetchApt(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("first fetch reported %d failures: %+v", s.Failures, s.Results)
	}
	stored, err := store.GetPackage(t.Context(), manifest.TypeApt, pkg)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []struct{ sum, deb string }{{amdSum, amdDeb}, {armSum, armDeb}} {
		ve := stored.Versions[i]
		if ve.Checksum == nil || ve.Checksum.Value != want.sum {
			t.Errorf("entry %d (%s) carries checksum %+v, want %s", i, want.deb, ve.Checksum, want.sum)
		}
		if got, wantPath := ve.Metadata["_pool_path"], aptPoolRelPath(pkg, want.deb); got != wantPath {
			t.Errorf("entry %d carries _pool_path %q, want %q", i, got, wantPath)
		}
	}

	if s := FetchApt(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("a re-fetch of both architectures was refused: %+v", s.Results)
	}
}

// writeTestDeb builds a .deb at dest whose control data PackageApt can read.
// Two calls differing only in description give two byte streams under one name.
func writeTestDeb(t *testing.T, dest, name, version, description string) {
	t.Helper()
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb is required to produce a .deb whose control data PackageApt can read")
	}
	staging := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(filepath.Join(staging, "DEBIAN"), 0o755); err != nil {
		t.Fatal(err)
	}
	control := "Package: " + name + "\nVersion: " + version +
		"\nArchitecture: all\nMaintainer: bodega <admin@example.com>\nDescription: " + description + "\n"
	if err := os.WriteFile(filepath.Join(staging, "DEBIAN", "control"), []byte(control), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("dpkg-deb", "--build", "--root-owner-group", staging, dest).CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb --build: %v\n%s", err, out)
	}
}

// TestPackageAptRefusalLeavesPoolUntouched replaces a packaged version's .deb
// with other bytes under the same name. The package stage refuses it, and the
// refusal has to leave the pool, the manifest and the pin as they were: a pool
// file the record does not vouch for is served to every client.
func TestPackageAptRefusalLeavesPoolUntouched(t *testing.T) {
	const pkg, version, debName = "widget", "2.0", "widget_2.0_all.deb"
	for _, tc := range []struct {
		kind  string
		entry manifest.VersionEntry
		deb   func(d dirs, ve manifest.VersionEntry) string
	}{
		{"direct URL", manifest.VersionEntry{Version: version, URL: "https://example.com/" + debName},
			func(d dirs, ve manifest.VersionEntry) string { return aptFetchedDeb(d, pkg, ve) }},
		{"git source build", manifest.VersionEntry{Version: version, URL: "https://example.com/widget.git", BuildCmd: "make deb", Ref: "v2.0.0"},
			func(d dirs, ve manifest.VersionEntry) string {
				cloneDir := aptSourceDir(d, pkg, ve)
				if err := os.MkdirAll(filepath.Join(cloneDir, ".git"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(aptRefMarkerPath(cloneDir), []byte(ve.Ref), 0o644); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(cloneDir, debName)
			}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			pm := &manifest.PackageManifest{Type: manifest.TypeApt, Name: pkg, Versions: []manifest.VersionEntry{tc.entry}}
			cfg, store, db := pinEnv(t, pm)
			d := buildDirs(cfg.rootFor(manifest.TypeApt))
			deb := tc.deb(d, tc.entry)
			writeTestDeb(t, deb, pkg, version, "first build")

			if s := PackageApt(cfg, store, pkg); s.Failures != 0 {
				t.Fatalf("first package failed: %+v", s.Results)
			}
			poolFile := filepath.Join(d.aptRepo, filepath.FromSlash(aptPoolRelPath(pkg, debName)))
			poolBefore, err := fileSHA256(poolFile)
			if err != nil {
				t.Fatalf("first package left no pool file: %v", err)
			}
			before, err := store.GetPackage(t.Context(), manifest.TypeApt, pkg)
			if err != nil {
				t.Fatal(err)
			}
			veBefore := before.Versions[0]
			if veBefore.Checksum == nil || veBefore.Checksum.Value != poolBefore {
				t.Fatalf("first package recorded %+v, want %s", veBefore.Checksum, poolBefore)
			}

			writeTestDeb(t, deb, pkg, version, "changed build")
			rebuilt, err := fileSHA256(deb)
			if err != nil || rebuilt == poolBefore {
				t.Fatalf("fixture: the rebuilt .deb has sha256 %s (%v), want bytes other than %s", rebuilt, err, poolBefore)
			}

			s := PackageApt(cfg, store, pkg)
			if s.Failures != 1 || len(s.Results) != 1 || s.Results[0].Err == nil {
				t.Fatalf("a .deb with other bytes was not refused once: %+v", s.Results)
			}
			if got, err := fileSHA256(poolFile); err != nil || got != poolBefore {
				t.Errorf("the refused package left the pool file at sha256 %s (%v), want %s", got, err, poolBefore)
			}
			after, err := store.GetPackage(t.Context(), manifest.TypeApt, pkg)
			if err != nil {
				t.Fatal(err)
			}
			veAfter := after.Versions[0]
			if veAfter.Checksum == nil || veAfter.Checksum.Value != poolBefore {
				t.Errorf("the refusal rewrote the checksum to %+v, want %s", veAfter.Checksum, poolBefore)
			}
			for _, k := range []string{"_pool_path", "_md5", "_sha1", "_sha256"} {
				if veAfter.Metadata[k] != veBefore.Metadata[k] {
					t.Errorf("the refusal rewrote %s from %q to %q", k, veBefore.Metadata[k], veAfter.Metadata[k])
				}
			}
			if veAfter.ArtifactSize != veBefore.ArtifactSize {
				t.Errorf("the refusal rewrote artifact_size from %d to %d", veBefore.ArtifactSize, veAfter.ArtifactSize)
			}
			if pin, err := db.GetChecksum(t.Context(), manifest.AptKey(aptPoolRelPath(pkg, debName))); err != nil || pin == nil || pin.Value != poolBefore {
				t.Errorf("the pin reads %+v (%v), want %s", pin, err, poolBefore)
			}

			msg := s.Results[0].Err.Error()
			if tc.entry.BuildCmd == "" {
				if !strings.Contains(msg, "recorded at fetch") {
					t.Errorf("a direct download's refusal changed wording: %q", msg)
				}
				return
			}
			for _, want := range []string{"ref v2.0.0", poolBefore, rebuilt, "version"} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal %q does not name %q", msg, want)
				}
			}
			if strings.Contains(msg, "recorded at fetch") {
				t.Errorf("a source build's refusal says the digest was recorded at fetch, which it was not: %q", msg)
			}
		})
	}
}
