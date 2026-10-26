package builder

import (
	"crypto/sha1" //nolint:gosec // G505: the upstream checksum under test
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// mavenRepo is an httptest repository in Maven Central's layout. A file's
// .sha256 and .sha1 are computed from its bytes unless a test overrides or
// withholds them, which is how a mismatch and an old SHA-1-only artifact are
// staged.
type mavenRepo struct {
	srv   *httptest.Server
	hits  atomic.Int32
	mu    sync.Mutex
	files map[string][]byte
	sums  map[string]string // "<path>.<alg>" -> body; "" withholds it
}

func newMavenRepo(t *testing.T, files map[string][]byte) *mavenRepo {
	t.Helper()
	r := &mavenRepo{files: files, sums: map[string]string{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		r.mu.Lock()
		defer r.mu.Unlock()
		p := strings.TrimPrefix(req.URL.Path, "/")
		if body, ok := r.sums[p]; ok {
			if body == "" {
				http.NotFound(w, req)
				return
			}
			_, _ = w.Write([]byte(body))
			return
		}
		for _, alg := range []string{"sha256", "sha1"} {
			if base, ok := strings.CutSuffix(p, "."+alg); ok {
				body, found := r.files[base]
				if !found {
					http.NotFound(w, req)
					return
				}
				if alg == "sha256" {
					_, _ = w.Write([]byte(sha256Hex(body)))
				} else {
					// Some Central .sha1 files carry the file name after the digest.
					_, _ = w.Write([]byte(sha1Hex(body) + "  artifact.jar"))
				}
				return
			}
		}
		body, ok := r.files[p]
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *mavenRepo) set(path string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.files[path] = body
}

func (r *mavenRepo) checksum(path, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sums[path] = body
}

func sha1Hex(b []byte) string {
	sum := sha1.Sum(b) //nolint:gosec // G401: the upstream checksum under test
	return hex.EncodeToString(sum[:])
}

const (
	slf4jDir = "org/slf4j/slf4j-api/2.0.13/"
	bomDir   = "org/springframework/boot/spring-boot-dependencies/3.3.0/"
	langDir  = "commons-lang/commons-lang/2.6/"
)

func mavenFixture() map[string][]byte {
	return map[string][]byte{
		slf4jDir + "slf4j-api-2.0.13.pom":         []byte(`<project xmlns="http://maven.apache.org/POM/4.0.0"><artifactId>slf4j-api</artifactId><packaging>bundle</packaging></project>`),
		slf4jDir + "slf4j-api-2.0.13.jar":         []byte("slf4j-api jar bytes"),
		slf4jDir + "slf4j-api-2.0.13.module":      []byte(`{"formatVersion":"1.1"}`),
		slf4jDir + "slf4j-api-2.0.13-sources.jar": []byte("slf4j-api sources jar"),
		bomDir + "spring-boot-dependencies-3.3.0.pom": []byte(`<?xml version="1.0"?>
<project><artifactId>spring-boot-dependencies</artifactId><packaging>pom</packaging></project>`),
		langDir + "commons-lang-2.6.pom": []byte(`<project><artifactId>commons-lang</artifactId></project>`),
		langDir + "commons-lang-2.6.jar": []byte("commons-lang 2.6 jar"),
	}
}

func TestFetchMavenPlacesEveryFileWhereTheRouteReadsIt(t *testing.T) {
	files := mavenFixture()
	repo := newMavenRepo(t, files)
	// Central publishes no .sha256 for a file this old.
	repo.checksum(langDir+"commons-lang-2.6.pom.sha256", "")
	repo.checksum(langDir+"commons-lang-2.6.jar.sha256", "")

	pm := &manifest.PackageManifest{Type: manifest.TypeMaven, Name: "org.slf4j:slf4j-api",
		Versions: []manifest.VersionEntry{{Version: "2.0.13", Classifiers: []string{"sources"}}}}
	cfg, store, db := pinEnv(t, pm)
	cfg.MavenUpstreams = []string{repo.srv.URL}
	for _, extra := range []*manifest.PackageManifest{
		{Type: manifest.TypeMaven, Name: "org.springframework.boot:spring-boot-dependencies", Versions: []manifest.VersionEntry{{Version: "3.3.0"}}},
		{Type: manifest.TypeMaven, Name: "commons-lang:commons-lang", Versions: []manifest.VersionEntry{{Version: "2.6"}}},
	} {
		if err := store.SavePackage(t.Context(), extra); err != nil {
			t.Fatal(err)
		}
	}

	s := FetchMaven(cfg, store, "")
	if s.Failures != 0 || s.Total != 3 {
		t.Fatalf("fetch = %d of %d failed (%v); want all three versions fetched", s.Failures, s.Total, s.FirstError())
	}

	for _, tc := range []struct {
		name, main string
		ext        string
		files      []string
	}{
		{"org.slf4j:slf4j-api", slf4jDir + "slf4j-api-2.0.13.jar", "jar", []string{
			slf4jDir + "slf4j-api-2.0.13.jar", slf4jDir + "slf4j-api-2.0.13.pom",
			slf4jDir + "slf4j-api-2.0.13.module", slf4jDir + "slf4j-api-2.0.13-sources.jar"}},
		{"org.springframework.boot:spring-boot-dependencies", bomDir + "spring-boot-dependencies-3.3.0.pom", "pom", []string{
			bomDir + "spring-boot-dependencies-3.3.0.pom"}},
		{"commons-lang:commons-lang", langDir + "commons-lang-2.6.jar", "jar", []string{
			langDir + "commons-lang-2.6.jar", langDir + "commons-lang-2.6.pom"}},
	} {
		got, err := store.GetPackage(t.Context(), manifest.TypeMaven, tc.name)
		if err != nil || got == nil {
			t.Fatalf("reload %s: %v", tc.name, err)
		}
		ve := got.Versions[0]
		if ve.Checksum == nil || ve.Checksum.Value != sha256Hex(files[tc.main]) || ve.ArtifactDigest != sha256Hex(files[tc.main]) {
			t.Errorf("%s entry = %+v; want the main file's sha256 recorded against the version", tc.name, ve)
		}
		if ve.Metadata[manifest.MetaMavenExtension] != tc.ext {
			t.Errorf("%s extension = %q, want %q from the POM's packaging", tc.name, ve.Metadata[manifest.MetaMavenExtension], tc.ext)
		}
		listed, err := manifest.MavenVersionFiles(got.Name, ve)
		if err != nil || strings.Join(listed, ",") != strings.Join(tc.files, ",") {
			t.Errorf("%s files = %v, %v; want %v", tc.name, listed, err, tc.files)
		}
		for _, f := range tc.files {
			pin, err := db.GetChecksum(t.Context(), manifest.MavenKey(f))
			if err != nil || pin == nil || pin.Value != sha256Hex(files[f]) {
				t.Errorf("pin on %s = %+v, %v; want the file's sha256", f, pin, err)
			}
		}
	}

	// Upload carries every file and its companions, keyed where the /maven/
	// route reads them, so a catalog-mode version is answered from storage.
	keys := map[string]string{}
	for _, p := range MavenArtifactPaths(cfg, store, "") {
		keys[p.ObjectKey] = p.Local
	}
	for path, body := range files {
		local, ok := keys[manifest.MavenKey(path)]
		if !ok {
			t.Errorf("upload has no object for %s", path)
			continue
		}
		if b, err := os.ReadFile(local); err != nil || string(b) != string(body) {
			t.Errorf("%s holds %q, %v; want the upstream's bytes", local, b, err)
		}
		sha1Local, ok := keys[manifest.MavenKey(path+".sha1")]
		if !ok {
			t.Errorf("upload has no .sha1 for %s", path)
			continue
		}
		if b, _ := os.ReadFile(sha1Local); string(b) != sha1Hex(body) {
			t.Errorf("%s.sha1 = %q, want %s", path, b, sha1Hex(body))
		}
	}
	if want := len(files) * (1 + len(manifest.MavenChecksumCompanions)); len(keys) != want {
		t.Errorf("upload carries %d objects, want %d (each file and its %d companions)", len(keys), want, len(manifest.MavenChecksumCompanions))
	}

	before := repo.hits.Load()
	if s := FetchMaven(cfg, store, ""); s.Failures != 0 {
		t.Fatalf("re-fetch failed: %v", s.FirstError())
	}
	if repo.hits.Load() != before {
		t.Errorf("a second fetch read the upstream %d more time(s); fetched versions should be skipped", repo.hits.Load()-before)
	}
}

// Bytes that disagree with the upstream's own checksum are refused and leave
// nothing in maven_root for an upload to publish.
func TestFetchMavenRefusesAChecksumMismatch(t *testing.T) {
	newEnv := func(t *testing.T) (*mavenRepo, *Config, *manifest.Store) {
		repo := newMavenRepo(t, mavenFixture())
		pm := &manifest.PackageManifest{Type: manifest.TypeMaven, Name: "org.slf4j:slf4j-api",
			Versions: []manifest.VersionEntry{{Version: "2.0.13"}}}
		cfg, store, _ := pinEnv(t, pm)
		cfg.MavenUpstreams = []string{repo.srv.URL}
		return repo, cfg, store
	}
	assertNothingKept := func(t *testing.T, cfg *Config, store *manifest.Store) {
		t.Helper()
		var left []string
		_ = filepath.Walk(filepath.Join(cfg.BuildRoot, "maven"), func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && strings.Contains(p, "slf4j-api-2.0.13") {
				left = append(left, p)
			}
			return nil
		})
		if len(left) > 0 {
			t.Errorf("refused bytes left in maven_root: %v", left)
		}
		if paths := MavenArtifactPaths(cfg, store, ""); len(paths) != 0 {
			t.Errorf("upload would publish %d refused object(s)", len(paths))
		}
	}

	t.Run("upstream sha256", func(t *testing.T) {
		repo, cfg, store := newEnv(t)
		repo.checksum(slf4jDir+"slf4j-api-2.0.13.jar.sha256", strings.Repeat("b", 64))
		s := FetchMaven(cfg, store, "")
		if s.Failures != 1 || !strings.Contains(s.FirstError().Error(), "sha256 mismatch against the upstream") {
			t.Fatalf("fetch = %d failure(s), %v; want the jar refused against its .sha256", s.Failures, s.FirstError())
		}
		if got, _ := store.GetPackage(t.Context(), manifest.TypeMaven, "org.slf4j:slf4j-api"); got.Versions[0].Checksum != nil {
			t.Errorf("entry checksum = %+v; a refused fetch records none", got.Versions[0].Checksum)
		}
		assertNothingKept(t, cfg, store)
	})

	t.Run("upstream sha1 when no sha256", func(t *testing.T) {
		repo, cfg, store := newEnv(t)
		repo.checksum(slf4jDir+"slf4j-api-2.0.13.pom.sha256", "")
		repo.checksum(slf4jDir+"slf4j-api-2.0.13.pom.sha1", strings.Repeat("c", 40))
		s := FetchMaven(cfg, store, "")
		if s.Failures != 1 || !strings.Contains(s.FirstError().Error(), "sha1 mismatch against the upstream") {
			t.Fatalf("fetch = %d failure(s), %v; want the POM refused against its .sha1", s.Failures, s.FirstError())
		}
		assertNothingKept(t, cfg, store)
	})

	t.Run("no upstream checksum", func(t *testing.T) {
		repo, cfg, store := newEnv(t)
		repo.checksum(slf4jDir+"slf4j-api-2.0.13.jar.sha256", "")
		repo.checksum(slf4jDir+"slf4j-api-2.0.13.jar.sha1", "")
		s := FetchMaven(cfg, store, "")
		if s.Failures != 1 || !strings.Contains(s.FirstError().Error(), "neither .sha256 nor .sha1") {
			t.Fatalf("fetch = %d failure(s), %v; want a file with no checksum refused", s.Failures, s.FirstError())
		}
		assertNothingKept(t, cfg, store)
	})

	t.Run("pinned digest", func(t *testing.T) {
		repo, cfg, store := newEnv(t)
		if s := FetchMaven(cfg, store, ""); s.Failures != 0 {
			t.Fatalf("first fetch: %v", s.FirstError())
		}
		// Republished under the same name with a consistent .sha256: the
		// upstream agrees with itself, and the pin is what refuses it. The
		// .module rather than the jar, whose digest the entry also records.
		repo.set(slf4jDir+"slf4j-api-2.0.13.module", []byte(`{"formatVersion":"1.1","republished":true}`))
		cfg.Force = true
		s := FetchMaven(cfg, store, "")
		if s.Failures != 1 || !strings.Contains(s.FirstError().Error(), "mismatch against the pinned digest") {
			t.Fatalf("re-fetch = %d failure(s), %v; want the republished module refused against its pin", s.Failures, s.FirstError())
		}
		local := filepath.Join(cfg.BuildRoot, "maven", filepath.FromSlash(slf4jDir+"slf4j-api-2.0.13.module"))
		if b, _ := os.ReadFile(local); string(b) != `{"formatVersion":"1.1"}` {
			t.Errorf("maven_root holds %q; the pinned bytes must stay in place", b)
		}
	})
}

func TestFetchMavenRefusesASnapshot(t *testing.T) {
	repo := newMavenRepo(t, mavenFixture())
	pm := &manifest.PackageManifest{Type: manifest.TypeMaven, Name: "com.example:app",
		Versions: []manifest.VersionEntry{{Version: "1.0-SNAPSHOT"}}}
	cfg, store, _ := pinEnv(t, pm)
	cfg.MavenUpstreams = []string{repo.srv.URL}
	s := FetchMaven(cfg, store, "")
	if s.Failures != 1 || !strings.Contains(s.FirstError().Error(), "SNAPSHOT") {
		t.Fatalf("fetch = %d failure(s), %v; want the SNAPSHOT refused", s.Failures, s.FirstError())
	}
	if repo.hits.Load() != 0 {
		t.Errorf("the upstream was asked %d time(s) for a version that cannot be pinned", repo.hits.Load())
	}
}
