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

// The record lives in the manifest and the bytes on the filesystem, so the two
// part company: re-importing a manifest onto a host that already holds the
// tarballs resets every entry while the stage check still reports fetched, and
// the fetch loop skips the step that writes the record. That host then serves a
// packument declaring no dependencies until somebody passes --force, with
// nothing in the output saying so.
//
// Found by the second consecutive e2e run, not by the first: run one fetched
// cold and passed, run two re-imported over tarballs already on disk and
// CLI-NPM-03 failed.
func TestFetchNpmBackfillsARecordThatWasResetUnderItsTarball(t *testing.T) {
	const pkg, version = "color-convert", "2.0.1"
	body := npmPackageTGZ(t, `{"name":"color-convert","version":"2.0.1",
		"dependencies":{"color-name":"~1.1.4"}}`)

	// No upstream: reaching one would mean the stage check did not
	// short-circuit, which is the behavior under test.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the fetch reached upstream for a tarball already on disk")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	pm := &manifest.PackageManifest{
		Type:     manifest.TypeNpm,
		Name:     pkg,
		Versions: []manifest.VersionEntry{{Version: version, URL: srv.URL}},
	}
	cfg, store, _ := pinEnv(t, pm)

	// The tarball as a previous fetch left it, under an entry recording
	// nothing, which is what a re-import produces.
	d := buildDirs(cfg.rootFor(manifest.TypeNpm))
	dest := npmTarballPath(d, pkg, pm.Versions[0])
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dest, body, 0o600); err != nil {
		t.Fatalf("write tarball: %v", err)
	}

	if s := FetchNpm(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("fetch reported %d failures: %+v", s.Failures, s.Results)
	}

	stored, err := store.GetPackage(t.Context(), manifest.TypeNpm, pkg)
	if err != nil || stored == nil {
		t.Fatalf("read the entry back: %v", err)
	}
	ve := stored.Versions[0]
	if len(ve.Dependencies) != 1 || ve.Dependencies[0].Name != "color-name" {
		t.Errorf("Dependencies = %+v, want color-name from the stored tarball", ve.Dependencies)
	}
	if ve.ArtifactDigest == "" {
		t.Error("ArtifactDigest is empty; dist.integrity has nothing to render from")
	}
}

// A backfill fills, it does not overwrite. An entry already recording a
// dependency list keeps it, so a value an operator pinned survives a fetch run
// against bytes that say something else.
func TestFetchNpmBackfillLeavesARecordedListAlone(t *testing.T) {
	const pkg, version = "color-convert", "2.0.1"
	body := npmPackageTGZ(t, `{"name":"color-convert","version":"2.0.1",
		"dependencies":{"color-name":"~1.1.4"}}`)

	pinned := []manifest.Dependency{{Name: "color-name", Req: "1.1.4"}}
	pm := &manifest.PackageManifest{
		Type: manifest.TypeNpm,
		Name: pkg,
		Versions: []manifest.VersionEntry{{
			Version:        version,
			Dependencies:   pinned,
			ArtifactDigest: "0000000000000000000000000000000000000000000000000000000000000000",
		}},
	}
	cfg, store, _ := pinEnv(t, pm)

	d := buildDirs(cfg.rootFor(manifest.TypeNpm))
	dest := npmTarballPath(d, pkg, pm.Versions[0])
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dest, body, 0o600); err != nil {
		t.Fatalf("write tarball: %v", err)
	}

	if s := FetchNpm(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("fetch reported %d failures: %+v", s.Failures, s.Results)
	}

	stored, err := store.GetPackage(t.Context(), manifest.TypeNpm, pkg)
	if err != nil || stored == nil {
		t.Fatalf("read the entry back: %v", err)
	}
	if got := stored.Versions[0].Dependencies[0].Req; got != "1.1.4" {
		t.Errorf("the recorded req became %q; the backfill overwrote a pinned value", got)
	}
}

// The demo-instance case behind B108: a version fetched before npm_bin
// existed records its dependencies and digest and nothing else. The backfill
// fills the executables from the stored tarball, and an unsafe entry in it is
// dropped with a line naming the package, version and entry.
func TestFetchNpmBackfillsBinOnAnEntryFetchedBeforeTheField(t *testing.T) {
	const pkg, version = "prettier", "3.9.9"
	body := npmPackageTGZ(t, `{"name":"prettier","version":"3.9.9",
		"dependencies":{"color-name":"~1.1.4"},
		"bin":{"prettier":"./bin/prettier.cjs","../evil":"./bin/x.js"}}`)

	pm := &manifest.PackageManifest{
		Type: manifest.TypeNpm,
		Name: pkg,
		Versions: []manifest.VersionEntry{{
			Version:        version,
			Dependencies:   []manifest.Dependency{{Name: "color-name", Req: "~1.1.4"}},
			ArtifactDigest: "0000000000000000000000000000000000000000000000000000000000000000",
		}},
	}
	cfg, store, _ := pinEnv(t, pm)
	var out strings.Builder
	cfg.Stdout = &out

	d := buildDirs(cfg.rootFor(manifest.TypeNpm))
	dest := npmTarballPath(d, pkg, pm.Versions[0])
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dest, body, 0o600); err != nil {
		t.Fatalf("write tarball: %v", err)
	}

	if s := FetchNpm(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("fetch reported %d failures: %+v", s.Failures, s.Results)
	}

	stored, err := store.GetPackage(t.Context(), manifest.TypeNpm, pkg)
	if err != nil || stored == nil {
		t.Fatalf("read the entry back: %v", err)
	}
	bin := stored.Versions[0].NpmBin
	if len(bin) != 1 || bin["prettier"] != "./bin/prettier.cjs" {
		t.Errorf("NpmBin = %v, want only prettier -> ./bin/prettier.cjs", bin)
	}
	if !strings.Contains(out.String(), `prettier@3.9.9: WARNING: dropped bin "../evil"`) {
		t.Errorf("no warning naming the dropped entry:\n%s", out.String())
	}
}

// A recorded executable map is the operator's, so the backfill leaves it.
func TestFetchNpmBackfillLeavesARecordedBinAlone(t *testing.T) {
	const pkg, version = "prettier", "3.9.9"
	body := npmPackageTGZ(t, `{"name":"prettier","version":"3.9.9","bin":"./bin/prettier.cjs"}`)

	pm := &manifest.PackageManifest{
		Type: manifest.TypeNpm,
		Name: pkg,
		Versions: []manifest.VersionEntry{{
			Version:        version,
			NpmBin:         map[string]string{"prettier": "./pinned.cjs"},
			ArtifactDigest: "0000000000000000000000000000000000000000000000000000000000000000",
		}},
	}
	cfg, store, _ := pinEnv(t, pm)

	d := buildDirs(cfg.rootFor(manifest.TypeNpm))
	dest := npmTarballPath(d, pkg, pm.Versions[0])
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dest, body, 0o600); err != nil {
		t.Fatalf("write tarball: %v", err)
	}

	if s := FetchNpm(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("fetch reported %d failures: %+v", s.Failures, s.Results)
	}
	stored, err := store.GetPackage(t.Context(), manifest.TypeNpm, pkg)
	if err != nil || stored == nil {
		t.Fatalf("read the entry back: %v", err)
	}
	if got := stored.Versions[0].NpmBin["prettier"]; got != "./pinned.cjs" {
		t.Errorf("NpmBin[prettier] = %q; the backfill overwrote a recorded value", got)
	}
}

// A cold fetch records the executables in the same pass as the dependencies.
func TestFetchNpmRecordsBin(t *testing.T) {
	const pkg, version = "prettier", "3.9.9"
	tarball := string(npmPackageTGZ(t, `{"name":"prettier","version":"3.9.9","bin":"./bin/prettier.cjs"}`))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prettier/-/prettier-3.9.9.tgz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(tarball))
	}))
	t.Cleanup(srv.Close)

	pm := &manifest.PackageManifest{
		Type:     manifest.TypeNpm,
		Name:     pkg,
		Versions: []manifest.VersionEntry{{Version: version, URL: srv.URL}},
	}
	cfg, store, _ := pinEnv(t, pm)
	if s := FetchNpm(cfg, store, pkg); s.Failures != 0 {
		t.Fatalf("fetch reported %d failures: %+v", s.Failures, s.Results)
	}
	stored, err := store.GetPackage(t.Context(), manifest.TypeNpm, pkg)
	if err != nil || stored == nil {
		t.Fatalf("read the entry back: %v", err)
	}
	if got := stored.Versions[0].NpmBin["prettier"]; got != "./bin/prettier.cjs" {
		t.Errorf("NpmBin = %v, want prettier -> ./bin/prettier.cjs", stored.Versions[0].NpmBin)
	}
}
