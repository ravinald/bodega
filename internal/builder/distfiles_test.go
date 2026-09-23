package builder

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

const distfileBody = "pcpustat source bytes"

// distfilesRun is a ports tree pinning two distfiles, one of them restricted,
// an https upstream serving body for both, and a store holding an entry for
// each. It returns the builder config and the upstream's request counter.
func distfilesRun(t *testing.T, body string) (*Config, *manifest.Store, *atomic.Int32) {
	t.Helper()
	tree := t.TempDir()
	put := func(root, rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte(distfileBody))
	put(tree, "Mk/bsd.licenses.db.mk", "")
	put(tree, "sysutils/pcpustat/Makefile", "DIST_SUBDIR=\tpcpustat\n")
	put(tree, "sysutils/pcpustat/distinfo", fmt.Sprintf("SHA256 (pcpustat/1.6.tar.bz2) = %x\nSIZE (pcpustat/1.6.tar.bz2) = %d\n", sum, len(distfileBody)))
	put(tree, "games/adom/Makefile", "RESTRICTED=\tno redistribution\n")
	put(tree, "games/adom/distinfo", fmt.Sprintf("SHA256 (adom.tar.gz) = %x\nSIZE (adom.tar.gz) = %d\n", sum, len(distfileBody)))

	var hits atomic.Int32
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)
	saved := distfilesClient
	distfilesClient = up.Client()
	t.Cleanup(func() { distfilesClient = saved })

	store := manifest.NewLocalStore(t.TempDir())
	for _, name := range []string{"pcpustat/1.6.tar.bz2", "adom.tar.gz"} {
		if err := store.AddVersion(t.Context(), manifest.TypeDistfiles, name, manifest.VersionEntry{}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &Config{
		BuildRoot:          t.TempDir(),
		Stdout:             io.Discard,
		DistfilesPortsTree: tree,
		DistfilesUpstream:  up.URL + "/",
	}
	return cfg, store, &hits
}

func distdirFiles(t *testing.T, cfg *Config) []string {
	t.Helper()
	root := ArtifactDir(cfg, manifest.TypeDistfiles)
	var out []string
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			rel, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

// A matching file lands in DISTDIR under its DIST_SUBDIR, readable by a build
// running as another user, and a restricted one is refused with the reason.
func TestFetchDistfilesWritesADistdir(t *testing.T) {
	cfg, store, _ := distfilesRun(t, distfileBody)
	s := FetchDistfiles(cfg, store, "")

	if s.Failures != 1 || len(s.Results) != 2 {
		t.Fatalf("summary: %d failures in %d results, want the restricted one alone to fail", s.Failures, len(s.Results))
	}
	for _, r := range s.Results {
		if r.Name == "adom.tar.gz" && (r.Err == nil || !strings.Contains(r.Err.Error(), "RESTRICTED")) {
			t.Errorf("adom.tar.gz: %v, want a refusal naming RESTRICTED", r.Err)
		}
	}
	if got := distdirFiles(t, cfg); strings.Join(got, ",") != "pcpustat/1.6.tar.bz2" {
		t.Fatalf("DISTDIR holds %v, want pcpustat/1.6.tar.bz2 alone", got)
	}
	dest := filepath.Join(ArtifactDir(cfg, manifest.TypeDistfiles), "pcpustat", "1.6.tar.bz2")
	fi, err := os.Stat(dest)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("%s: %v mode %v, want 0644", dest, err, fi.Mode().Perm())
	}
}

// Bytes distinfo did not pin never reach DISTDIR, under their own name or a
// temporary one. do-fetch.sh skips any file already present, so a wrong file
// left there is one the client would never re-fetch.
func TestFetchDistfilesWritesNothingOnAMismatch(t *testing.T) {
	cfg, store, _ := distfilesRun(t, "PCPUSTAT SOURCE BYTES")
	s := FetchDistfiles(cfg, store, "pcpustat/1.6.tar.bz2")
	if s.Failures != 1 || !strings.Contains(s.Results[0].Err.Error(), "does not match distinfo") {
		t.Fatalf("summary: %+v, want one failure naming the distinfo mismatch", s.Results)
	}
	if got := distdirFiles(t, cfg); len(got) != 0 {
		t.Errorf("DISTDIR holds %v after a refused fetch, want nothing", got)
	}
}

// A file already present is re-hashed: a match skips the fetch, anything else
// is replaced.
func TestFetchDistfilesChecksWhatIsAlreadyThere(t *testing.T) {
	cfg, store, hits := distfilesRun(t, distfileBody)
	dest := filepath.Join(ArtifactDir(cfg, manifest.TypeDistfiles), "pcpustat", "1.6.tar.bz2")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(dest, []byte("PCPUSTAT SOURCE BYTES"), 0o644); err != nil {
		t.Fatal(err)
	}
	if s := FetchDistfiles(cfg, store, "pcpustat/1.6.tar.bz2"); s.Failures != 0 || hits.Load() != 1 {
		t.Fatalf("a wrong file in place: %d failures after %d fetches, want it replaced by one", s.Failures, hits.Load())
	}
	if got, _ := os.ReadFile(dest); string(got) != distfileBody {
		t.Fatalf("DISTDIR holds %q, want the pinned bytes", got)
	}

	if s := FetchDistfiles(cfg, store, "pcpustat/1.6.tar.bz2"); s.Failures != 0 || hits.Load() != 1 {
		t.Errorf("a matching file in place: %d failures after %d fetches, want it skipped", s.Failures, hits.Load())
	}
}

// With no ports tree there is nothing to admit against, and every entry says
// so rather than falling back to pinning whatever arrives.
func TestFetchDistfilesRefusesWithoutAPortsTree(t *testing.T) {
	cfg, store, hits := distfilesRun(t, distfileBody)
	cfg.DistfilesPortsTree = ""
	s := FetchDistfiles(cfg, store, "")
	if s.Failures != 2 || hits.Load() != 0 {
		t.Fatalf("%d failures after %d fetches, want both refused before any fetch", s.Failures, hits.Load())
	}
	if !strings.Contains(s.Results[0].Err.Error(), "distfiles_ports_tree") {
		t.Errorf("error %q does not name the setting to fix", s.Results[0].Err)
	}
}
