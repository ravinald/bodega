package server

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

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

const distfileBody = "pcpustat source bytes"

// distfilesPortsTree writes a ports tree pinning pcpustat's distfile to
// distfileBody, beside a port whose license withholds dist-mirror.
func distfilesPortsTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	put := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte(distfileBody))
	put("Mk/bsd.licenses.db.mk", "")
	put("sysutils/pcpustat/Makefile", "DIST_SUBDIR=\tpcpustat\n")
	put("sysutils/pcpustat/distinfo", fmt.Sprintf("SHA256 (pcpustat/1.6.tar.bz2) = %x\nSIZE (pcpustat/1.6.tar.bz2) = %d\n", sum, len(distfileBody)))
	put("graphics/nonfree/Makefile", "LICENSE_PERMS=\tno-dist-mirror no-dist-sell auto-accept\n")
	put("graphics/nonfree/distinfo", fmt.Sprintf("SHA256 (nonfree.tar.gz) = %x\nSIZE (nonfree.tar.gz) = %d\n", sum, len(distfileBody)))
	return root
}

// distfilesFixture is an upstream serving body for every path, counting the
// requests it answers, and a bodega in front of it reading tree.
func distfilesFixture(t *testing.T, tree, body string) (*httptest.Server, *storage.Memory, *atomic.Int32) {
	t.Helper()
	saved := distfilesGuard
	distfilesGuard = func(rawURL string) error {
		if strings.HasPrefix(rawURL, "http://127.0.0.1:") {
			return nil
		}
		return saved(rawURL)
	}
	t.Cleanup(func() { distfilesGuard = saved })
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/pcpustat/1.6.tar.bz2" && r.URL.Path != "/nonfree.tar.gz" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)

	mem := storage.NewMemory()
	cfg := &config.Config{
		StorageBackend:     "local",
		ManifestDir:        "manifests",
		AptCodename:        "noble",
		DistfilesPortsTree: tree,
		DistfilesUpstream:  up.URL + "/",
		SpoolDir:           filepath.Join(t.TempDir(), "spool"),
	}
	store := manifest.NewLocalStore(t.TempDir())
	ts := httptest.NewServer(New(cfg, store, storage.NewSingle(mem), ":0", nil).Handler())
	t.Cleanup(ts.Close)
	return ts, mem, &hits
}

func getBody(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // httptest URL built in this test
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// A miss is fetched, held to the distinfo line, cached under the key that
// keeps DIST_SUBDIR, and the next request is served from the cache.
func TestDistfilesAdmitsBytesMatchingDistinfo(t *testing.T) {
	ts, mem, hits := distfilesFixture(t, distfilesPortsTree(t), distfileBody)

	code, body := getBody(t, ts.URL+"/distfiles/pcpustat/1.6.tar.bz2")
	if code != http.StatusOK || body != distfileBody {
		t.Fatalf("GET = %d %q, want 200 with the distfile", code, body)
	}
	if got, err := mem.Get(t.Context(), manifest.DistfilesKey("pcpustat/1.6.tar.bz2")); err != nil || string(got) != distfileBody {
		t.Fatalf("cached %q (err %v) under the DIST_SUBDIR key, want the distfile", got, err)
	}
	code, _ = getBody(t, ts.URL+"/distfiles/pcpustat/1.6.tar.bz2")
	if code != http.StatusOK || hits.Load() != 1 {
		t.Errorf("second GET = %d after %d upstream fetches, want 200 served from the cache after one", code, hits.Load())
	}
}

// The property this type exists for: bytes the ports tree did not pin are
// neither served nor cached, however the upstream presents them. binary would
// have pinned them on first sight.
func TestDistfilesRefusesBytesDistinfoDidNotPin(t *testing.T) {
	for name, body := range map[string]string{
		"same size, other bytes": "PCPUSTAT SOURCE BYTES",
		"other size":             distfileBody + " and a trailer",
	} {
		t.Run(name, func(t *testing.T) {
			ts, mem, _ := distfilesFixture(t, distfilesPortsTree(t), body)
			code, got := getBody(t, ts.URL+"/distfiles/pcpustat/1.6.tar.bz2")
			if code != http.StatusBadGateway || !strings.Contains(got, "do not match the ports tree's distinfo") {
				t.Fatalf("GET = %d %q, want 502 naming the distinfo mismatch", code, got)
			}
			if info, _ := mem.Head(t.Context(), manifest.DistfilesKey("pcpustat/1.6.tar.bz2")); info != nil && info.Exists {
				t.Error("cached bytes that disagree with distinfo")
			}
		})
	}
}

// A port that withholds dist-mirror is refused before any upstream is
// contacted, with a status that says why.
func TestDistfilesRefusesARestrictedDistfile(t *testing.T) {
	ts, mem, hits := distfilesFixture(t, distfilesPortsTree(t), distfileBody)
	code, body := getBody(t, ts.URL+"/distfiles/nonfree.tar.gz")
	if code != http.StatusUnavailableForLegalReasons {
		t.Fatalf("GET = %d %q, want 451", code, body)
	}
	if hits.Load() != 0 {
		t.Errorf("upstream contacted %d times for a file bodega may not redistribute", hits.Load())
	}
	if info, _ := mem.Head(t.Context(), manifest.DistfilesKey("nonfree.tar.gz")); info != nil && info.Exists {
		t.Error("cached a restricted distfile")
	}
}

// A restriction added after a file was cached still applies: distinfo decides
// before the cache does.
func TestDistfilesRestrictionOutranksTheCache(t *testing.T) {
	ts, mem, _ := distfilesFixture(t, distfilesPortsTree(t), distfileBody)
	mem.Seed(manifest.DistfilesKey("nonfree.tar.gz"), distfileBody)
	if code, _ := getBody(t, ts.URL+"/distfiles/nonfree.tar.gz"); code != http.StatusUnavailableForLegalReasons {
		t.Errorf("GET = %d, want 451 for a restricted file already in the cache", code)
	}
}

// A name no distinfo lists has no digest to hold it to, so the upstream is
// never asked, and a server with no ports tree configured admits nothing.
func TestDistfilesRefusesWithoutADigest(t *testing.T) {
	ts, _, hits := distfilesFixture(t, distfilesPortsTree(t), distfileBody)
	if code, _ := getBody(t, ts.URL+"/distfiles/pcpustat/9.9.tar.bz2"); code != http.StatusNotFound || hits.Load() != 0 {
		t.Errorf("unlisted name: %d after %d upstream fetches, want 404 after none", code, hits.Load())
	}
	// The subdirectory is part of the name: the bare file is not listed.
	if code, _ := getBody(t, ts.URL+"/distfiles/1.6.tar.bz2"); code != http.StatusNotFound || hits.Load() != 0 {
		t.Errorf("name without DIST_SUBDIR: %d after %d upstream fetches, want 404 after none", code, hits.Load())
	}

	unconfigured, _, _ := distfilesFixture(t, "", distfileBody)
	if code, _ := getBody(t, unconfigured.URL+"/distfiles/pcpustat/1.6.tar.bz2"); code != http.StatusNotFound {
		t.Errorf("no distfiles_ports_tree: %d, want 404", code)
	}
}

// Plain http is admitted for the distfiles upstream, and nothing else about
// the guard is relaxed: a host on this network is refused over either scheme.
func TestDistfilesGuardAdmitsHTTPAndNothingElse(t *testing.T) {
	for raw, ok := range map[string]bool{
		"http://127.0.0.1/ports-distfiles/x":  false,
		"https://127.0.0.1/ports-distfiles/x": false,
		"http://10.0.0.1/ports-distfiles/x":   false,
		"ftp://ftp.freebsd.org/x":             false,
	} {
		if err := distfilesGuard(raw); (err == nil) != ok {
			t.Errorf("distfilesGuard(%q) = %v, want admitted=%v", raw, err, ok)
		}
	}
	if err := upstreamGuard("http://distcache.FreeBSD.org/ports-distfiles/x"); err == nil {
		t.Error("upstreamGuard admitted plain http; the relaxation belongs to distfiles alone")
	}
}
