package builder

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// gemUpstream serves gem files the way rubygems.org does, under /gems/, and
// counts the requests so a test can tell a fetch from a skip.
func gemUpstream(t *testing.T, files map[string][]byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, ok := files[strings.TrimPrefix(r.URL.Path, "/gems/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestFetchRubygemsPlacesThePinnedGemWhereUploadReadsIt(t *testing.T) {
	plain, native := []byte("rack gem bytes"), []byte("nokogiri linux gem bytes")
	srv, hits := gemUpstream(t, map[string][]byte{
		"rack-3.1.8.gem":                   plain,
		"nokogiri-1.16.7-x86_64-linux.gem": native,
	})
	pm := &manifest.PackageManifest{Type: manifest.TypeRubygems, Name: "rack",
		Versions: []manifest.VersionEntry{{Version: "3.1.8"}}}
	cfg, store, db := pinEnv(t, pm)
	cfg.RubygemsUpstream = srv.URL
	if err := store.SavePackage(t.Context(), &manifest.PackageManifest{Type: manifest.TypeRubygems, Name: "nokogiri",
		Versions: []manifest.VersionEntry{{Version: "1.16.7-x86_64-linux"}}}); err != nil {
		t.Fatal(err)
	}

	s := FetchRubygems(cfg, store, "")
	if s.Failures != 0 || s.Total != 2 {
		t.Fatalf("fetch = %d of %d failed (%v); want both gems fetched", s.Failures, s.Total, s.FirstError())
	}

	for name, body := range map[string][]byte{"rack": plain, "nokogiri": native} {
		got, err := store.GetPackage(t.Context(), manifest.TypeRubygems, name)
		if err != nil || got == nil {
			t.Fatalf("reload %s: %v", name, err)
		}
		ve := got.Versions[0]
		if ve.Checksum == nil || ve.Checksum.Value != sha256Hex(body) || ve.ArtifactDigest != sha256Hex(body) {
			t.Errorf("%s entry = %+v; want the gem's sha256 recorded against the version", name, ve)
		}
		pin, err := db.GetChecksum(t.Context(), manifest.RubygemsGemKey(name, ve.Version))
		if err != nil || pin == nil || pin.Value != sha256Hex(body) {
			t.Errorf("%s pin = %+v, %v; want the sha256 under the key the /rubygems/gems/ route reads", name, pin, err)
		}
	}
	if got, _ := store.GetPackage(t.Context(), manifest.TypeRubygems, "nokogiri"); got.Versions[0].Platform != "x86_64-linux" {
		t.Errorf("nokogiri platform = %q, want the gem's own build", got.Versions[0].Platform)
	}

	// Upload reads what fetch wrote, keyed where the route serves it, so a
	// hosted gem is answered from storage with no upstream.
	paths := RubygemsArtifactPaths(cfg, store, "")
	keys := map[string]string{}
	for _, p := range paths {
		keys[p.ObjectKey] = p.Local
	}
	for _, want := range []string{manifest.RubygemsGemKey("rack", "3.1.8"), manifest.RubygemsGemKey("nokogiri", "1.16.7-x86_64-linux")} {
		local, ok := keys[want]
		if !ok {
			t.Errorf("upload has no object for %s; got %v", want, keys)
			continue
		}
		if b, err := os.ReadFile(local); err != nil || len(b) == 0 {
			t.Errorf("%s: %v", local, err)
		}
	}

	// A second run reads nothing upstream: the gem is on disk and verified.
	before := hits.Load()
	if s := FetchRubygems(cfg, store, ""); s.Failures != 0 {
		t.Fatalf("re-fetch failed: %v", s.FirstError())
	}
	if hits.Load() != before {
		t.Errorf("a second fetch read the upstream %d more time(s); the fetched gem should be skipped", hits.Load()-before)
	}
}

// A gem file never changes under its name, so bytes that disagree with what
// the entry declares are refused, as are bytes that disagree with the pin a
// previous fetch took.
func TestFetchRubygemsRefusesAChecksumMismatch(t *testing.T) {
	served := []byte("what the upstream serves today")
	srv, _ := gemUpstream(t, map[string][]byte{"rack-3.1.8.gem": served})

	t.Run("declared", func(t *testing.T) {
		declared := strings.Repeat("a", 64)
		pm := &manifest.PackageManifest{Type: manifest.TypeRubygems, Name: "rack",
			Versions: []manifest.VersionEntry{{Version: "3.1.8", Checksum: newSHA256Checksum(declared)}}}
		cfg, store, db := pinEnv(t, pm)
		cfg.RubygemsUpstream = srv.URL

		s := FetchRubygems(cfg, store, "")
		if s.Failures != 1 {
			t.Fatalf("failures = %d; want the mismatched gem refused", s.Failures)
		}
		if err := s.FirstError(); err == nil || !strings.Contains(err.Error(), "checksum") {
			t.Errorf("error = %v; want it to name the checksum", err)
		}
		if pin, _ := db.GetChecksum(t.Context(), manifest.RubygemsGemKey("rack", "3.1.8")); pin != nil {
			t.Errorf("a refused gem was pinned: %+v", pin)
		}
		if paths := RubygemsArtifactPaths(cfg, store, ""); len(paths) != 0 {
			t.Errorf("the refused gem is still where upload reads it: %+v", paths)
		}
	})

	t.Run("pinned", func(t *testing.T) {
		pm := &manifest.PackageManifest{Type: manifest.TypeRubygems, Name: "rack",
			Versions: []manifest.VersionEntry{{Version: "3.1.8"}}}
		cfg, store, db := pinEnv(t, pm)
		cfg.RubygemsUpstream = srv.URL
		key := manifest.RubygemsGemKey("rack", "3.1.8")
		earlier := strings.Repeat("b", 64)
		if err := db.StoreChecksum(t.Context(), key, manifest.TypeRubygems, "rack", "3.1.8", "sha256", earlier, "build"); err != nil {
			t.Fatal(err)
		}

		s := FetchRubygems(cfg, store, "")
		if s.Failures != 1 {
			t.Fatalf("failures = %d; want the republished gem refused against the pin", s.Failures)
		}
		if err := s.FirstError(); err == nil || !strings.Contains(err.Error(), earlier) || !strings.Contains(err.Error(), sha256Hex(served)) {
			t.Errorf("error = %v; want both the pinned and the fetched digest named", err)
		}
		if pin, _ := db.GetChecksum(t.Context(), key); pin == nil || pin.Value != earlier {
			t.Errorf("pin = %+v; the refused fetch must not replace it", pin)
		}
		if got, _ := store.GetPackage(t.Context(), manifest.TypeRubygems, "rack"); got.Versions[0].Checksum != nil {
			t.Errorf("the refused digest was recorded on the entry: %+v", got.Versions[0].Checksum)
		}
		if paths := RubygemsArtifactPaths(cfg, store, ""); len(paths) != 0 {
			t.Errorf("the refused gem is still where upload reads it: %+v", paths)
		}
	})
}

func TestRubygemsDownloadURL(t *testing.T) {
	ve := manifest.VersionEntry{Version: "1.16.7-x86_64-linux"}
	if got := rubygemsDownloadURL(&Config{}, "nokogiri", ve); got != "https://rubygems.org/gems/nokogiri-1.16.7-x86_64-linux.gem" {
		t.Errorf("default = %s", got)
	}
	ve.URL = "https://gems.example.com/"
	if got := rubygemsDownloadURL(&Config{RubygemsUpstream: "https://rubygems.org"}, "nokogiri", ve); got != "https://gems.example.com/gems/nokogiri-1.16.7-x86_64-linux.gem" {
		t.Errorf("entry URL = %s; want it to win over rubygems_upstream", got)
	}
}
