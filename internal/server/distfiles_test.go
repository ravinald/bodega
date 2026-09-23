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

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/distinfo"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
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

// makeOnlyRestrictions are pcpustat Makefiles that set NO_CDROM only through
// a make construct a lexical read gets wrong: a := taken before the variable
// it reads is reassigned, one file included twice under two values, a ?= after
// an .undef that may run, a .for variable shadowing a global one, an
// assignment whose name is computed, a path read through a variable an
// assignment make skips leaves undefined, and a slave naming its master
// through PORTSDIR. Base make on FreeBSD prints "No resale" for
// `make -V NO_CDROM` in each; for the slave, run in the slave's directory.
var makeOnlyRestrictions = map[string]map[string]string{
	"conditional undef": {
		"Makefile": "D=\tfiles/allowed.mk\n.if 1\n.undef D\n.endif\nD?=\tfiles/restricted.mk\n.include \"${D}\"\n",
	},
	"loop shadow": {
		"Makefile": "D=\tfiles/allowed.mk\n.for D in files/restricted.mk\n.include \"${D}\"\n.endfor\n",
	},
	"computed restriction": {
		"Makefile": "N=\tNO_CDROM\n${N}=\tNo resale\n",
	},
	"immediate assignment": {
		"Makefile": "D=\tfiles/restricted.mk\nP:=\t${D}\nD=\tfiles/allowed.mk\n.include \"${P}\"\n",
	},
	"repeated include": {
		"Makefile":          "D=\tfiles/allowed.mk\n.include \"files/dispatch.mk\"\nD=\tfiles/restricted.mk\n.include \"files/dispatch.mk\"\n",
		"files/dispatch.mk": ".include \"${.CURDIR}/${D}\"\n",
	},
	"undefined branch": {
		"Makefile":                    ".if 0\nD=\tfiles/allowed/\n.endif\n.include \"${D}restricted.mk\"\n",
		"restricted.mk":               "NO_CDROM=\tNo resale\n",
		"files/allowed/restricted.mk": "PORTNAME=\tpcpustat\n",
	},
	"slave with a master under PORTSDIR": {
		"Makefile":          "PORTNAME=\tpcpustat\n",
		"../slave/Makefile": "MASTERDIR=\t${PORTSDIR}/sysutils/pcpustat\nNO_CDROM=\tNo resale\n.include \"${MASTERDIR}/Makefile\"\n",
	},
}

// makeOnlyRefusal is what the refusal of a makeOnlyRestrictions case names:
// the restriction, or for a path the reader cannot resolve, that it cannot.
func makeOnlyRefusal(name string) string {
	if name == "undefined branch" {
		return "cannot be resolved"
	}
	return "NO_CDROM"
}

func writeMakeOnlyRestriction(t *testing.T, tree string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(tree, "sysutils", "pcpustat")
	all := map[string]string{"files/restricted.mk": "NO_CDROM=\tNo resale\n", "files/allowed.mk": "PORTNAME=\tpcpustat\n"}
	for rel, body := range files {
		all[rel] = body
	}
	for rel, body := range all {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A restriction only make's own reading of the Makefiles reaches is refused
// before any upstream is contacted.
func TestDistfilesRefusesARestrictionMakeReaches(t *testing.T) {
	for name, files := range makeOnlyRestrictions {
		t.Run(name, func(t *testing.T) {
			tree := distfilesPortsTree(t)
			writeMakeOnlyRestriction(t, tree, files)
			ts, _, hits := distfilesFixture(t, tree, distfileBody)
			code, body := getBody(t, ts.URL+"/distfiles/pcpustat/1.6.tar.bz2")
			want := makeOnlyRefusal(name)
			if code != http.StatusUnavailableForLegalReasons || !strings.Contains(body, want) || hits.Load() != 0 {
				t.Fatalf("GET = %d %q after %d upstream fetches, want 451 naming %q after none", code, body, hits.Load(), want)
			}
		})
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

// A stored object is not evidence of admission. One whose bytes disagree with
// the current pin, uploaded from a DISTDIR nobody checked or left from an
// older tree that pinned other bytes of the same length, is never served: the
// hit falls through to a verified fetch that replaces it.
func TestDistfilesCacheHitIsHeldToDistinfo(t *testing.T) {
	const stale = "PCPUSTAT SOURCE BYTES" // same length as distfileBody
	ts, mem, hits := distfilesFixture(t, distfilesPortsTree(t), distfileBody)
	mem.Seed(manifest.DistfilesKey("pcpustat/1.6.tar.bz2"), stale)

	code, body := getBody(t, ts.URL+"/distfiles/pcpustat/1.6.tar.bz2")
	if code != http.StatusOK || body != distfileBody || hits.Load() != 1 {
		t.Fatalf("GET = %d %q after %d upstream fetches, want the pinned bytes fetched once", code, body, hits.Load())
	}
	if got, _ := mem.Get(t.Context(), manifest.DistfilesKey("pcpustat/1.6.tar.bz2")); string(got) != distfileBody {
		t.Errorf("cache still holds %q, want it replaced by the verified fetch", got)
	}

	// With an upstream that cannot supply the pinned bytes either, nothing is
	// served at all rather than the stale object.
	ts2, mem2, _ := distfilesFixture(t, distfilesPortsTree(t), stale)
	mem2.Seed(manifest.DistfilesKey("pcpustat/1.6.tar.bz2"), stale)
	if code, body := getBody(t, ts2.URL+"/distfiles/pcpustat/1.6.tar.bz2"); code == http.StatusOK {
		t.Errorf("GET = 200 %q, served bytes neither the cache nor the upstream could match to distinfo", body)
	}
}

// A tree update that repins a name to other bytes of the same length reaches
// the cache: the object admitted under the old pin is replaced, not served.
func TestDistfilesSameSizeRepinReplacesTheCachedObject(t *testing.T) {
	const v1, v2 = "pcpustat source bytes", "pcpustat SOURCE bytes"
	tree := func(body string) string {
		root := t.TempDir()
		sum := sha256.Sum256([]byte(body))
		for rel, b := range map[string]string{
			"Mk/bsd.licenses.db.mk":      "",
			"sysutils/pcpustat/Makefile": "DIST_SUBDIR=\tpcpustat\n",
			"sysutils/pcpustat/distinfo": fmt.Sprintf("SHA256 (pcpustat/1.6.tar.bz2) = %x\nSIZE (pcpustat/1.6.tar.bz2) = %d\n", sum, len(body)),
		} {
			p := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}
	ts1, mem, _ := distfilesFixture(t, tree(v1), v1)
	if code, body := getBody(t, ts1.URL+"/distfiles/pcpustat/1.6.tar.bz2"); code != http.StatusOK || body != v1 {
		t.Fatalf("first tree: %d %q", code, body)
	}
	cached, _ := mem.Get(t.Context(), manifest.DistfilesKey("pcpustat/1.6.tar.bz2"))

	ts2, mem2, hits := distfilesFixture(t, tree(v2), v2)
	mem2.Seed(manifest.DistfilesKey("pcpustat/1.6.tar.bz2"), string(cached))
	code, body := getBody(t, ts2.URL+"/distfiles/pcpustat/1.6.tar.bz2")
	if code != http.StatusOK || body != v2 || hits.Load() != 1 {
		t.Fatalf("after repin: %d %q after %d fetches, want the newly pinned bytes", code, body, hits.Load())
	}
}

// The upstream allow-list applies to this type like any other: a digest says
// the bytes are right, not that the operator agreed to contact the host.
func TestDistfilesMissHonorsTheUpstreamAllowList(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string // "" means the upstream's own host
		want    int
		fetches int
	}{
		{"matching host", "", http.StatusOK, 1},
		{"other host", "allowed.example", http.StatusForbidden, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDiscoveryServer(t)
			s.distinfo = distinfo.NewTree(distfilesPortsTree(t), 0, nil)
			var hits atomic.Int32
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				_, _ = io.WriteString(w, distfileBody)
			}))
			defer up.Close()
			s.cfg.DistfilesUpstream = up.URL + "/"
			saved := distfilesGuard
			distfilesGuard = func(string) error { return nil }
			defer func() { distfilesGuard = saved }()

			pattern := tc.pattern
			if pattern == "" {
				pattern = "127.0.0.1"
			}
			if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "p", RegistryType: manifest.TypeDistfiles, RuleKind: policy.KindHost, Pattern: pattern}); err != nil {
				t.Fatal(err)
			}
			ts := httptest.NewServer(s.Handler())
			defer ts.Close()
			code, body := getBody(t, ts.URL+"/distfiles/pcpustat/1.6.tar.bz2")
			if code != tc.want || int(hits.Load()) != tc.fetches {
				t.Fatalf("GET = %d %q after %d upstream fetches, want %d after %d", code, body, hits.Load(), tc.want, tc.fetches)
			}
			if tc.want != http.StatusForbidden {
				return
			}
			rows, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCache})
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if row.Status == audit.CachePolicyViolation && row.PkgType == manifest.TypeDistfiles {
					return
				}
			}
			t.Errorf("no policy_violation row for the refused distfile: %+v", rows)
		})
	}
}
