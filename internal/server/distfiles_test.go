package server

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

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
	put("Mk/bsd.port.mk", "LOCALBASE?=\t/usr/local\n")
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
	return distfilesFixtureIn(t, tree, body, nil)
}

// distfilesFixtureIn is distfilesFixture with the config adjusted by set
// before the server is built.
func distfilesFixtureIn(t *testing.T, tree, body string, set func(*config.Config)) (*httptest.Server, *storage.Memory, *atomic.Int32) {
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
	if set != nil {
		set(cfg)
	}
	store := manifest.NewLocalStore(t.TempDir())
	h := New(cfg, store, storage.NewSingle(mem), ":0", nil).Handler()
	ts := httptest.NewServer(conformingClient(t, cfg, h))
	t.Cleanup(ts.Close)
	return ts, mem, &hits
}

// conformingClient is h as a client whose check measured the declared
// environment sees it: a request for /distfiles/<name> carries the digest the
// check names, as MASTER_SITE_OVERRIDE spells it. A path already naming an
// environment, and the check itself, pass through, so a test can still send
// what a drifted or unconfigured client would.
func conformingClient(t *testing.T, cfg *config.Config, h http.Handler) http.Handler {
	t.Helper()
	env, err := cfg.DistfilesEnvironment().Load()
	if err != nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rest, ok := strings.CutPrefix(r.URL.Path, "/distfiles/"); ok && !strings.HasPrefix(rest, "@") && r.Header.Get(unconfiguredClient) == "" {
			r.URL.Path = "/distfiles/@" + env.Digest() + "/" + rest
			r.URL.RawPath = ""
		}
		h.ServeHTTP(w, r)
	})
}

// unconfiguredClient is a request header conformingClient passes through
// untouched, for a test sending what a client with no check sends.
const unconfiguredClient = "X-Test-Unconfigured-Client"

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
// assignment make skips leaves undefined, a slave naming its master through
// PORTSDIR, and two slaves with no distinfo of their own that read the
// master's through a value only a shell command sets. Base make on FreeBSD
// prints "No resale" for `make -V NO_CDROM` in each; for a slave, run in the
// slave's directory, where `make -V DISTINFO_FILE` names the master's.
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
	"slave whose master a shell command names": {
		"Makefile":          "PORTNAME=\tpcpustat\n",
		"../slave/Makefile": "NO_CDROM=\tNo resale\nM!=\tprintf pcpustat\nDISTINFO_FILE=\t${.CURDIR}/../${M}/distinfo\n",
	},
	"slave whose distinfo suffix climbs out of its directory": {
		"Makefile":                  "PORTNAME=\tpcpustat\n",
		"../slave/Makefile":         "NO_CDROM=\tNo resale\nTAIL!=\tprintf '/../../pcpustat/distinfo'\nDISTINFO_FILE=\t${.CURDIR}/stub${TAIL}\n",
		"../slave/stub/placeholder": "",
	},
}

// makeOnlyRefusal is what the refusal of a makeOnlyRestrictions case names:
// the restriction, for a path the reader cannot resolve that it cannot, and
// for a distinfo it cannot place that the whole tree is refused.
func makeOnlyRefusal(name string) string {
	switch {
	case name == "undefined branch":
		return "cannot be resolved"
	case name == "conditional undef":
		// D?= with D undeclared: make.conf may set D first, so the port
		// refuses and names what to declare rather than reading NO_CDROM.
		return "it reads D, which make.conf"
	case strings.HasPrefix(name, "slave whose"):
		return "may obtain any distfile in the tree"
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
			ts := httptest.NewServer(conformingClient(t, &config.Config{}, s.Handler()))
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

// A hit is a request like a miss, so discover_mode counts it: an observe
// window over two `make fetch` runs of one port reports 2, on the one row the
// miss wrote, rather than the 1 that described how cold the cache was.
func TestDistfilesHitCountsInDiscovery(t *testing.T) {
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
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "p", RegistryType: manifest.TypeDistfiles, RuleKind: policy.KindHost, Pattern: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(conformingClient(t, &config.Config{}, s.Handler()))
	defer ts.Close()

	for i := range 2 {
		if code, body := getBody(t, ts.URL+"/distfiles/pcpustat/1.6.tar.bz2"); code != http.StatusOK {
			t.Fatalf("GET %d = %d %q, want 200", i+1, code, body)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream fetched %d times, want 1: the second GET has to be a cache hit for this to test anything", got)
	}
	// waitForPoolRow returns at a count of at least 2, so a hit recorded twice
	// would pass it. Close waits out both handlers, so every observation they
	// make is queued; the worker writes the queue in order, so once a sentinel
	// queued after them is visible, so is every one of theirs.
	ts.Close()
	s.discovery.Record(audit.DiscoveryRow{RegistryType: manifest.TypeDistfiles, Host: "sentinel.invalid", PkgName: "sentinel", Decision: audit.DecisionAllowed})
	waitForPoolRow(t, s, "sentinel", 1)
	row := waitForPoolRow(t, s, "pcpustat/1.6.tar.bz2", 2)
	if row.RequestCount != 2 {
		t.Errorf("request_count = %d, want 2: one miss and one hit", row.RequestCount)
	}
	if row.RegistryType != manifest.TypeDistfiles || row.Decision != audit.DecisionAllowed {
		t.Errorf("row = %+v, want a distfiles row the allow-list permits", row)
	}
}

// The F24 witness through HTTP: arabic/aspell reads ${LOCALBASE}/etc/aspell.ver
// on the client host, which base make shows can point its DISTINFO_FILE at
// pcpustat's and set NO_CDROM. pcpustat is served only when the declared
// environment says what that file holds, and refused, with nothing fetched,
// when the declaration carries the witness, alone or as one alternative.
func TestDistfilesHTTPHoldsTheDeclaredEnvironment(t *testing.T) {
	witness := filepath.Join(t.TempDir(), "aspell.ver")
	if err := os.WriteFile(witness, []byte("DISTINFO_FILE=${PORTSDIR}/sysutils/pcpustat/distinfo\nNO_CDROM=host file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	localbase := map[string][]string{"LOCALBASE": {"/usr/local"}}
	for name, tc := range map[string]struct {
		vars  map[string][]string
		files map[string][]string
		code  int
		hits  int32
	}{
		"nothing declared":           {nil, nil, http.StatusUnavailableForLegalReasons, 0},
		"file undeclared":            {localbase, nil, http.StatusUnavailableForLegalReasons, 0},
		"declared absent":            {localbase, map[string][]string{"/usr/local/etc/aspell.ver": {"absent"}}, http.StatusOK, 1},
		"declared as the witness":    {localbase, map[string][]string{"/usr/local/etc/aspell.ver": {witness}}, http.StatusUnavailableForLegalReasons, 0},
		"witness as one alternative": {localbase, map[string][]string{"/usr/local/etc/aspell.ver": {"absent", witness}}, http.StatusUnavailableForLegalReasons, 0},
	} {
		t.Run(name, func(t *testing.T) {
			tree := distfilesPortsTree(t)
			for rel, body := range map[string]string{
				"textproc/aspell/Makefile.inc": ".include <bsd.port.pre.mk>\n.if exists(${LOCALBASE}/etc/aspell.ver)\n. include \"${LOCALBASE}/etc/aspell.ver\"\n.endif\n",
				"arabic/aspell/Makefile":       ".include \"${.CURDIR}/../../textproc/aspell/Makefile.inc\"\n",
			} {
				p := filepath.Join(tree, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			ts, _, hits := distfilesFixtureIn(t, tree, distfileBody, func(cfg *config.Config) {
				cfg.DistfilesEnvironmentVariables = tc.vars
				cfg.DistfilesEnvironmentFiles = tc.files
			})
			code, body := getBody(t, ts.URL+"/distfiles/pcpustat/1.6.tar.bz2")
			if code != tc.code || hits.Load() != tc.hits {
				t.Fatalf("GET = %d %q after %d upstream fetches, want %d after %d", code, body, hits.Load(), tc.code, tc.hits)
			}
		})
	}
}

// The F24 witness after admission: a client that adds the witness file, or
// runs no check, or checks another declaration, is refused before storage or
// upstream is touched, for a name the index admits. Only the digest the index
// was admitted against is served, and the check that names it is served too.
func TestDistfilesRefusesAClientOutsideTheEnvironment(t *testing.T) {
	ts, mem, hits := distfilesFixture(t, distfilesPortsTree(t), distfileBody)
	env, err := distinfo.EnvironmentSpec{}.Load()
	if err != nil {
		t.Fatal(err)
	}
	other, err := distinfo.EnvironmentSpec{Variables: map[string][]string{"LOCALBASE": {"/usr/local"}}}.Load()
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"drifted client":    "/distfiles/@" + distinfo.ClientUnsupported + "/pcpustat/1.6.tar.bz2",
		"other declaration": "/distfiles/@" + other.Digest() + "/pcpustat/1.6.tar.bz2",
		"no check":          "/distfiles/pcpustat/1.6.tar.bz2",
		"empty environment": "/distfiles/@/pcpustat/1.6.tar.bz2",
	} {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+path, nil)
		req.Header.Set(unconfiguredClient, "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnavailableForLegalReasons || hits.Load() != 0 || !strings.Contains(string(body), "did not measure the environment") {
			t.Errorf("%s: GET %s = %d %q after %d upstream fetches, want 451 before any", name, path, resp.StatusCode, body, hits.Load())
		}
	}
	if info, _ := mem.Head(t.Context(), manifest.DistfilesKey("pcpustat/1.6.tar.bz2")); info != nil && info.Exists {
		t.Error("cached a distfile for a client outside the environment")
	}
	if code, body := getBody(t, ts.URL+"/distfiles/@"+env.Digest()+"/pcpustat/1.6.tar.bz2"); code != http.StatusOK || body != distfileBody || hits.Load() != 1 {
		t.Fatalf("GET under the admitted digest = %d %q after %d upstream fetches, want 200 after 1", code, body, hits.Load())
	}
	code, check := getBody(t, ts.URL+"/distfiles/@environment.mk")
	if code != http.StatusOK || !strings.Contains(check, ":?"+env.Digest()+":unsupported") {
		t.Fatalf("GET /distfiles/@environment.mk = %d %q, want the check naming %s", code, check, env.Digest())
	}
}

// The F25 audit fixtures through HTTP: ${P:tA} resolves link/.. after the
// symlink, as realpath(3) does, and ${P:H} leaves it for open(2) to, so both
// read the NO_CDROM base make reads.
func TestDistfilesSymlinkBeforeParentIsRestricted(t *testing.T) {
	for name, makefile := range map[string]string{
		":tA": "P=${.CURDIR}/link/../restricted/terms.mk\n.include \"${P:tA}\"\n",
		":H":  "P=${.CURDIR}/link/../restricted/leaf\n.include \"${P:H}/terms.mk\"\n",
	} {
		t.Run(name, func(t *testing.T) { symlinkBeforeParentHTTP(t, makefile) })
	}
}

func symlinkBeforeParentHTTP(t *testing.T, makefile string) {
	tree := distfilesPortsTree(t)
	for rel, body := range map[string]string{
		"misc/probe/Makefile":            makefile + "DISTINFO_FILE=${PORTSDIR}/sysutils/pcpustat/distinfo\n",
		"misc/probe/restricted/terms.mk": "OK=yes\n",
		"lang/restricted/terms.mk":       "NO_CDROM=symlink target terms\n",
	} {
		p := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(tree, "lang/master"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../lang/master", filepath.Join(tree, "misc/probe/link")); err != nil {
		t.Fatal(err)
	}
	ts, _, hits := distfilesFixture(t, tree, distfileBody)
	code, body := getBody(t, ts.URL+"/distfiles/pcpustat/1.6.tar.bz2")
	if code != http.StatusUnavailableForLegalReasons || hits.Load() != 0 || !strings.Contains(body, "symlink target terms") {
		t.Fatalf("GET = %d %q after %d upstream fetches, want 451 naming the symlink target's NO_CDROM before any", code, body, hits.Load())
	}
}

// The F25 audit's computed-name fixture through HTTP: _${N}!= writes the
// declared snapshot path, the port includes it, and a second _${N}!= puts the
// snapshot's bytes back. make reads NO_CDROM there, so the reader refuses the
// port, and pcpustat's distinfo, which it names, with it: even a cached copy
// is not served and upstream is never asked.
func TestDistfilesRefusesAComputedNameCommandBeforeASnapshot(t *testing.T) {
	host := "/client/terms.mk"
	snap := filepath.Join(t.TempDir(), "terms.mk")
	if err := os.WriteFile(snap, []byte("OK=yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := distfilesPortsTree(t)
	p := filepath.Join(tree, "misc/probe/Makefile")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	makefile := "N=W\n_${N}!= printf 'NO_CDROM=computed terms\\n' > " + host + "\n.sinclude \"" + host + "\"\nN=R\n_${N}!= printf 'OK=yes\\n' > " + host + "\nDISTINFO_FILE=${PORTSDIR}/sysutils/pcpustat/distinfo\n"
	if err := os.WriteFile(p, []byte(makefile), 0o644); err != nil {
		t.Fatal(err)
	}
	ts, mem, hits := distfilesFixtureIn(t, tree, distfileBody, func(cfg *config.Config) {
		cfg.DistfilesEnvironmentFiles = map[string][]string{host: {snap}}
	})
	mem.Seed(manifest.DistfilesKey("pcpustat/1.6.tar.bz2"), distfileBody)
	code, body := getBody(t, ts.URL+"/distfiles/pcpustat/1.6.tar.bz2")
	if code != http.StatusUnavailableForLegalReasons || hits.Load() != 0 || !strings.Contains(body, "misc/probe is restricted or unreadable") {
		t.Fatalf("GET = %d %q after %d upstream fetches, want 451 naming misc/probe before any", code, body, hits.Load())
	}
}

// Every refusal on this route reaches any client that can connect, so none
// may say where the server keeps its ports tree or its storage: the operator
// reads those in the log. The tree sits under a name no body has any other
// reason to carry, so a body naming it in any spelling (as configured,
// through a symlink, or resolved before one was retargeted) is caught by the
// name alone. Answers that name no server fact by construction are driven too,
// so a later edit that starts relaying an error there is caught here.
func TestDistfilesRefusalsNameNoServerPath(t *testing.T) {
	const marker = "b98-server-ports"
	put := func(t *testing.T, root, rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tree := func(t *testing.T, name string) string {
		t.Helper()
		root := filepath.Join(t.TempDir(), name)
		if err := os.Rename(distfilesPortsTree(t), root); err != nil {
			t.Fatal(err)
		}
		return root
	}
	// includeUnresolved makes pcpustat restricted by a file the reader reaches
	// through ${PORTSDIR}, which it expands to the root with symlinks resolved.
	includeUnresolved := func(t *testing.T, root string) {
		put(t, root, "sysutils/pcpustat/Makefile", "DIST_SUBDIR=\tpcpustat\n.include \"${PORTSDIR}/sysutils/pcpustat/review.mk\"\n")
		put(t, root, "sysutils/pcpustat/review.mk", ".include \"${UNDEFINED}/restricted.mk\"\n")
	}
	alias := func(t *testing.T, target string) string {
		t.Helper()
		link := filepath.Join(t.TempDir(), marker+"-alias")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		return link
	}
	type fixture struct {
		s    *Server
		root string // as configured
		mem  *storage.Memory
	}
	manifestOf := func(t *testing.T, f *fixture, ve manifest.VersionEntry) {
		t.Helper()
		pm := &manifest.PackageManifest{Name: "pcpustat/1.6.tar.bz2", Type: manifest.TypeDistfiles, Versions: []manifest.VersionEntry{ve}}
		if err := f.s.store.SavePackage(t.Context(), pm); err != nil {
			t.Fatal(err)
		}
	}
	failRewind := func(t *testing.T) {
		saved := rewindSpool
		rewindSpool = func(*os.File) error { return errors.New("seek " + marker + ": injected") }
		t.Cleanup(func() { rewindSpool = saved })
	}
	// moving is the three trees a symlink points at in turn while one read
	// runs: sysutils/pcpustat is read while it names the second, so only the
	// reader saw that one.
	var moving []string
	const pcpustat = "/distfiles/pcpustat/1.6.tar.bz2"
	for _, tc := range []struct {
		name     string
		path     string
		code     int
		logsRoot bool // the operator's log names where the lookup ran
		raw      bool // sent as a client with no check, path untouched
		root     func(t *testing.T) string
		upstream http.HandlerFunc
		setup    func(t *testing.T, f *fixture)
	}{
		{name: "invalid name", path: "/distfiles/pcpustat/a%5Cb", code: http.StatusBadRequest},
		{name: "no ports tree configured", path: pcpustat, code: http.StatusNotFound,
			setup: func(_ *testing.T, f *fixture) { f.s.distinfo = nil }},
		{name: "hidden", path: pcpustat, code: http.StatusNotFound,
			setup: func(t *testing.T, f *fixture) { manifestOf(t, f, manifest.VersionEntry{Version: "1.6", Hidden: true}) }},
		{name: "recorded storage not configured", path: pcpustat, code: http.StatusBadGateway,
			setup: func(t *testing.T, f *fixture) {
				manifestOf(t, f, manifest.VersionEntry{Version: "1.6", Storage: "elsewhere"})
			}},
		{name: "storage unavailable", path: pcpustat, code: http.StatusServiceUnavailable,
			setup: func(_ *testing.T, f *fixture) { f.s.stores = nil }},
		{name: "profile refusal", path: pcpustat, code: http.StatusForbidden,
			setup: func(t *testing.T, f *fixture) {
				bindProfileByCIDR(t, f.s, "locked", "locked01", cidrLoopback,
					[]audit.ProfileTypeRule{closedRule(manifest.TypeDistfiles, audit.VersionFloating, audit.ExpansionBlock)}, nil)
			}},
		{name: "unlisted", path: "/distfiles/pcpustat/9.9.tar.bz2", code: http.StatusNotFound, logsRoot: true},
		{name: "ambiguous digest", path: pcpustat, code: http.StatusNotFound, logsRoot: true,
			setup: func(t *testing.T, f *fixture) {
				put(t, f.root, "sysutils/pcpustat-devel/distinfo", fmt.Sprintf("SHA256 (pcpustat/1.6.tar.bz2) = %064d\nSIZE (pcpustat/1.6.tar.bz2) = %d\n", 0, len(distfileBody)))
			}},
		{name: "unusable digest", path: "/distfiles/pcpustat/2.0.tar.bz2", code: http.StatusNotFound, logsRoot: true,
			setup: func(t *testing.T, f *fixture) {
				put(t, f.root, "sysutils/pcpustat-devel/distinfo", "SHA256 (pcpustat/2.0.tar.bz2) = not-hex\nSIZE (pcpustat/2.0.tar.bz2) = 1\n")
			}},
		{name: "restricted", path: "/distfiles/nonfree.tar.gz", code: http.StatusUnavailableForLegalReasons},
		{name: "restriction make reaches", path: pcpustat, code: http.StatusUnavailableForLegalReasons, logsRoot: true,
			setup: func(t *testing.T, f *fixture) {
				writeMakeOnlyRestriction(t, f.root, makeOnlyRestrictions["undefined branch"])
			}},
		{name: "restriction under a symlinked root", path: pcpustat, code: http.StatusUnavailableForLegalReasons, logsRoot: true,
			root: func(t *testing.T) string {
				target := tree(t, marker+"-tree")
				includeUnresolved(t, target)
				return alias(t, target)
			}},
		{name: "restriction read before the root was retargeted", path: pcpustat, code: http.StatusUnavailableForLegalReasons, logsRoot: true,
			root: func(t *testing.T) string {
				target := tree(t, marker+"-tree")
				includeUnresolved(t, target)
				return alias(t, target)
			},
			setup: func(t *testing.T, f *fixture) {
				if err := f.s.distinfo.Wait(); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(f.root); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(tree(t, marker+"-next"), f.root); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "restriction read while the root moved twice", path: pcpustat, code: http.StatusUnavailableForLegalReasons, logsRoot: true,
			root: func(t *testing.T) string {
				moving = nil
				for _, n := range []string{"-a", "-b", "-c"} {
					root := tree(t, marker+n)
					includeUnresolved(t, root)
					for _, cat := range []string{"aaa", "zzz"} {
						fifo := filepath.Join(root, cat, "hold", "distinfo")
						if err := os.MkdirAll(filepath.Dir(fifo), 0o755); err != nil {
							t.Fatal(err)
						}
						if err := syscall.Mkfifo(fifo, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					moving = append(moving, root)
				}
				return alias(t, moving[0])
			},
			// Opening each FIFO's writer waits for the loader to open it, so
			// the retargets land before and after sysutils/ is read. The
			// request runs once the read has finished.
			setup: func(t *testing.T, f *fixture) {
				retarget := func(target string) {
					t.Helper()
					next := f.root + ".next"
					if err := os.Symlink(target, next); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(next, f.root); err != nil {
						t.Fatal(err)
					}
				}
				for i, fifo := range []string{filepath.Join(moving[0], "aaa", "hold", "distinfo"), filepath.Join(moving[1], "zzz", "hold", "distinfo")} {
					w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
					if err != nil {
						t.Fatal(err)
					}
					retarget(moving[i+1])
					if err := w.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.s.distinfo.Wait(); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "environment mismatch", path: "/distfiles/@" + distinfo.ClientUnsupported + "/pcpustat/1.6.tar.bz2", code: http.StatusUnavailableForLegalReasons, raw: true},
		{name: "environment another digest", path: "/distfiles/@0000/pcpustat/1.6.tar.bz2", code: http.StatusUnavailableForLegalReasons, raw: true},
		{name: "environment not measured", path: pcpustat, code: http.StatusUnavailableForLegalReasons, raw: true},
		{name: "not ready after a failed read", path: pcpustat, code: http.StatusServiceUnavailable, logsRoot: true,
			setup: func(t *testing.T, f *fixture) {
				if err := os.Remove(filepath.Join(f.root, "Mk", "bsd.licenses.db.mk")); err != nil {
					t.Fatal(err)
				}
				f.s.distinfo = distinfo.NewTree(f.root, 0, nil)
			}},
		{name: "not ready while loading", path: pcpustat, code: http.StatusServiceUnavailable, logsRoot: true,
			// The read blocks opening a FIFO nobody writes until cleanup, so
			// the lookup outwaits its first-read budget.
			setup: func(t *testing.T, f *fixture) {
				fifo := filepath.Join(f.root, "Mk", "bsd.licenses.db.mk")
				if err := os.Remove(fifo); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(fifo, 0o600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if w, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
						_ = w.Close()
					}
				})
				f.s.distinfo = distinfo.NewTree(f.root, 0, nil)
			}},
		{name: "client check before the environment is read", path: "/distfiles/@environment.mk", code: http.StatusServiceUnavailable,
			setup: func(_ *testing.T, f *fixture) {
				f.s.distinfo = distinfo.NewTreeIn(f.root, distinfo.EnvironmentSpec{Variables: map[string][]string{"1bad": {"x"}}}, 0, nil)
			}},
		{name: "upstream refused by the allow-list", path: pcpustat, code: http.StatusForbidden,
			setup: func(t *testing.T, f *fixture) {
				if err := f.s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "p", RegistryType: manifest.TypeDistfiles, RuleKind: policy.KindHost, Pattern: "allowed.example"}); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "policy database unavailable", path: pcpustat, code: http.StatusInternalServerError,
			setup: func(t *testing.T, f *fixture) {
				f.s.policy.Invalidate()
				if err := f.s.auditDB.Close(); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "upstream lacks it", path: pcpustat, code: http.StatusNotFound,
			upstream: http.NotFound},
		{name: "upstream unreachable", path: pcpustat, code: http.StatusBadGateway,
			setup: func(_ *testing.T, f *fixture) { f.s.cfg.DistfilesUpstream = "http://127.0.0.1:1/" }},
		{name: "upstream declares another length", path: pcpustat, code: http.StatusBadGateway,
			upstream: func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, distfileBody+" and a trailer") }},
		{name: "upstream bytes disagree", path: pcpustat, code: http.StatusBadGateway,
			upstream: func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "PCPUSTAT SOURCE BYTES") }},
		{name: "upstream transfer cut short", path: pcpustat, code: http.StatusBadGateway,
			upstream: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", fmt.Sprint(len(distfileBody)))
				_, _ = io.WriteString(w, distfileBody[:5])
			}},
		{name: "upstream spool rewind fails", path: pcpustat, code: http.StatusBadGateway,
			setup: func(t *testing.T, _ *fixture) { failRewind(t) }},
		{name: "cached object spool rewind fails", path: pcpustat, code: http.StatusBadGateway,
			setup: func(t *testing.T, f *fixture) {
				f.mem.Seed(manifest.DistfilesKey("pcpustat/1.6.tar.bz2"), distfileBody)
				failRewind(t)
			}},
		{name: "upstream over the spool ceiling", path: pcpustat, code: http.StatusServiceUnavailable,
			setup: func(t *testing.T, f *fixture) { f.s.spool = newSpoolLimiter(t.TempDir(), 4, 0) }},
		{name: "cached object over the spool ceiling", path: pcpustat, code: http.StatusServiceUnavailable,
			setup: func(t *testing.T, f *fixture) {
				f.mem.Seed(manifest.DistfilesKey("pcpustat/1.6.tar.bz2"), distfileBody)
				f.s.spool = newSpoolLimiter(t.TempDir(), 4, 0)
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := distfilesGuard
			distfilesGuard = func(string) error { return nil }
			t.Cleanup(func() { distfilesGuard = saved })
			upstream := tc.upstream
			if upstream == nil {
				upstream = func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/pcpustat/1.6.tar.bz2" {
						http.NotFound(w, r)
						return
					}
					_, _ = io.WriteString(w, distfileBody)
				}
			}
			up := httptest.NewServer(upstream)
			t.Cleanup(up.Close)

			f := &fixture{s: newDiscoveryServer(t)}
			if tc.root != nil {
				f.root = tc.root(t)
			} else {
				f.root = tree(t, marker+"-tree")
			}
			f.s.cfg.DistfilesUpstream = up.URL + "/"
			f.s.distinfo = distinfo.NewTree(f.root, 0, nil)
			var log strings.Builder
			f.s.logger = slog.New(slog.NewTextHandler(&log, nil))
			f.mem = f.s.typeStore(manifest.TypeDistfiles).(*storage.Memory)
			label := f.mem.Label()
			if tc.setup != nil {
				tc.setup(t, f)
			}

			ts := httptest.NewServer(conformingClient(t, &config.Config{}, f.s.Handler()))
			t.Cleanup(ts.Close)
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+tc.path, nil)
			if tc.raw {
				req.Header.Set(unconfiguredClient, "1")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.code {
				t.Fatalf("GET %s = %d %q, want %d", tc.path, resp.StatusCode, got, tc.code)
			}
			for _, secret := range []string{marker, label} {
				if strings.Contains(string(got), secret) {
					t.Errorf("GET %s = %d %q, names %s", tc.path, resp.StatusCode, got, secret)
				}
			}
			if tc.logsRoot && !strings.Contains(log.String(), marker) {
				t.Errorf("GET %s = %d: the log names no ports tree path, so the operator cannot see where the lookup ran:\n%s", tc.path, resp.StatusCode, log.String())
			}
		})
	}
}

// logRecords is a slog sink a test can read while the tree's background read
// is still writing to it.
type logRecords struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *logRecords) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// records is every line written so far, as its level and message.
func (l *logRecords) records(t *testing.T) []struct{ Level, Msg string } {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []struct{ Level, Msg string }
	for line := range strings.Lines(l.buf.String()) {
		var r struct{ Level, Msg string }
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, r)
	}
	return out
}

func (l *logRecords) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func noEnv(string) string { return "" }

// A failed read of the tree is a warning whether it is the first read or a
// later one, and a routine read stays at Info, so the journal at its default
// level shows an operator the tree the server cannot see.
func TestDistinfoTreeLogLevels(t *testing.T) {
	t.Run("first read of a root that does not exist", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "absent")
		var l logRecords
		_ = distinfo.NewTree(root, 0, distinfoLogf(l.logger(), root, noEnv)).Wait()
		got := l.records(t)
		if len(got) != 1 || got[0].Level != slog.LevelWarn.String() || !strings.Contains(got[0].Msg, "reading "+root+" failed") {
			t.Fatalf("log = %+v, want one WARN line naming the failed read of %s", got, root)
		}
	})
	t.Run("routine read", func(t *testing.T) {
		root := distfilesPortsTree(t)
		var l logRecords
		if err := distinfo.NewTree(root, 0, distinfoLogf(l.logger(), root, noEnv)).Wait(); err != nil {
			t.Fatal(err)
		}
		got := l.records(t)
		if len(got) != 1 || got[0].Level != slog.LevelInfo.String() || !strings.Contains(got[0].Msg, "distinfo: indexed") {
			t.Fatalf("log = %+v, want one INFO line for the index", got)
		}
	})
	t.Run("later read of a root that has gone", func(t *testing.T) {
		root := distfilesPortsTree(t)
		var l logRecords
		tr := distinfo.NewTree(root, time.Millisecond, distinfoLogf(l.logger(), root, noEnv))
		if err := tr.Wait(); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(root, root+".moved"); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			_, _ = tr.Lookup("pcpustat/1.6.tar.bz2")
			if got := l.records(t); len(got) > 1 {
				last := got[len(got)-1]
				if last.Level != slog.LevelWarn.String() || !strings.Contains(last.Msg, "failed") {
					t.Fatalf("re-read of a missing root logged %+v, want a WARN failure", last)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("no re-read was logged after the root went away")
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// The hint appears only for a root the shipped unit hides, a failure that
// looks like a missing tree, and a process systemd started. Every other case
// logs the plain failure.
func TestHiddenTreeHint(t *testing.T) {
	enoent := func(p string) error {
		return fmt.Errorf("read ports tree %s: %w", p, &fs.PathError{Op: "open", Path: p, Err: syscall.ENOENT})
	}
	eacces := func(p string) error {
		return fmt.Errorf("read ports tree %s: %w", p, &fs.PathError{Op: "open", Path: p, Err: syscall.EACCES})
	}
	systemd := func(k string) string {
		if k == "NOTIFY_SOCKET" {
			return "/run/systemd/notify"
		}
		return ""
	}
	alias := []string{"/srv/bodega-ports-source && mkdir /srv/bodega-ports`", "systemctl edit bodega", "BindReadOnlyPaths=/srv/bodega-ports-source:/srv/bodega-ports under [Service]", "set distfiles_ports_tree to /srv/bodega-ports in /etc/bodega/config.json", "Running under systemd"}
	for _, tc := range []struct {
		name   string
		root   string
		err    error
		getenv func(string) string
		want   []string // substrings of the hint; nil means no hint
	}{
		{"under /tmp", "/tmp/ports", enoent("/tmp/ports"), systemd,
			[]string{"PrivateTmp=true", "/usr/ports", "/srv", "systemctl edit bodega", `BindReadOnlyPaths="/tmp/ports" under`}},
		{"under /var/tmp", "/var/tmp/ports", enoent("/var/tmp/ports"), systemd,
			[]string{"PrivateTmp=true", "/usr/ports", "/srv", "systemctl edit bodega", `BindReadOnlyPaths="/var/tmp/ports" under`}},
		{"under /home, denied", "/home/op/ports", eacces("/home/op/ports"), systemd,
			[]string{"ProtectHome=true", "/usr/ports", "/srv", "systemctl edit bodega", `ProtectHome=tmpfs and BindReadOnlyPaths="/home/op/ports" under`}},
		{"under /home, missing", "/home/op/ports/", enoent("/home/op/ports/"), systemd,
			[]string{"ProtectHome=true", `BindReadOnlyPaths="/home/op/ports" under`}},
		{"a root with spaces", "/var/tmp/bodega review ports", enoent("/var/tmp/bodega review ports"), systemd,
			[]string{`BindReadOnlyPaths="/var/tmp/bodega review ports" under`}},
		{"a root with a separator, an escape and a specifier", `/var/tmp/a:b\c%d`, enoent(`/var/tmp/a:b\c%d`), systemd,
			[]string{`BindReadOnlyPaths="/var/tmp/a:b\\c%%d" under`}},
		{"a root with a double quote", `/var/tmp/a"b`, enoent(`/var/tmp/a"b`), systemd,
			append([]string{"PrivateTmp=true", "/usr/ports", `ln -sn '/var/tmp/a"b' `}, alias...)},
		{"a root with a single quote", "/home/o'neil/ports", eacces("/home/o'neil/ports"), systemd,
			append([]string{"ProtectHome=true", "/usr/ports", `ln -sn '/home/o'\''neil/ports' `}, alias...)},
		{"a root with a tab", "/tmp/a\tb", enoent("/tmp/a\tb"), systemd,
			append([]string{"PrivateTmp=true", `ln -sn $'/tmp/a\x09b' `}, alias...)},
		{"a root with a symlink and ..", "/var/tmp/x/link/../ports", enoent("/var/tmp/x/link/../ports"), systemd,
			append([]string{"PrivateTmp=true", "ln -sn '/var/tmp/x/link/../ports' "}, alias...)},
		{"outside the hidden paths", "/usr/ports", enoent("/usr/ports"), systemd, nil},
		{"a sibling sharing the prefix", "/tmpfs/ports", enoent("/tmpfs/ports"), systemd, nil},
		{"not under systemd", "/var/tmp/ports", enoent("/var/tmp/ports"), noEnv, nil},
		{"a failure that is not a missing tree", "/var/tmp/ports", errors.New("read category x: EIO"), systemd, nil},
		{"a missing file below the root", "/var/tmp/ports", enoent("/var/tmp/ports/Mk/bsd.licenses.db.mk"), systemd, nil},
		{"a forbidden category below the root", "/home/op/ports", eacces("/home/op/ports/sysutils"), systemd, nil},
		{"a missing file below /tmp itself", "/tmp", enoent("/tmp/Mk/bsd.licenses.db.mk"), systemd, nil},
		{"a missing-root error with no path", "/var/tmp/ports", fs.ErrNotExist, systemd, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hint := hiddenTreeHint(tc.root, tc.err, tc.getenv)
			var l logRecords
			plain := "distinfo: reading " + tc.root + " failed after 1ms, keeping the previous index: " + tc.err.Error()
			distinfoLogf(l.logger(), tc.root, tc.getenv)(slog.LevelWarn, tc.err, plain)
			got := l.records(t)
			if len(got) != 1 || got[0].Level != slog.LevelWarn.String() {
				t.Fatalf("log = %+v, want one WARN line", got)
			}
			if tc.want == nil {
				if hint != "" || got[0].Msg != plain {
					t.Fatalf("hint %q, logged %q; want no hint and the plain failure", hint, got[0].Msg)
				}
				return
			}
			if got[0].Msg != plain+"; "+hint {
				t.Errorf("logged %q, want the failure followed by the hint %q", got[0].Msg, hint)
			}
			for _, w := range tc.want {
				if !strings.Contains(hint, w) {
					t.Errorf("hint %q does not name %q", hint, w)
				}
			}
			if strings.Contains(hint, "ln -s") && strings.Contains(hint, `BindReadOnlyPaths="`) {
				t.Errorf("hint %q offers a direct bind for a root it had to alias", hint)
			}
		})
	}
}

// The alias a hint hands the operator has to reach the directory the server
// would have read at root: the same bytes, whatever the path's spelling. The
// test runs the hint's own ln -sn word through a shell, twice, and reads a
// marker on both sides. "link/../ports" is the case cleaning gets wrong: the
// kernel walks .. from the link's target, so it names target/ports, not ports.
func TestHiddenTreeHintAliasReadsTheConfiguredTree(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal("the alias is a shell command, and this test needs bash to run it:", err)
	}
	base, err := os.MkdirTemp("/var/tmp", "bodega-b100-alias-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	for dir, marker := range map[string]string{
		"target/child": "", "target/ports": "configured", "ports": "cleaned",
		"o'neil": "quote", `a"b`: "double quote", "a\tb": "tab", "a\\x41'\\'": "escapes", "a\t\\'b": "escapes and a tab",
	} {
		if err := os.MkdirAll(filepath.Join(base, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if marker != "" {
			if err := os.WriteFile(filepath.Join(base, dir, "marker"), []byte(marker), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Symlink(filepath.Join(base, "target", "child"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	systemd := func(k string) string {
		if k == "NOTIFY_SOCKET" {
			return "/run/systemd/notify"
		}
		return ""
	}
	for _, rel := range []string{"link/../ports", "o'neil", `a"b`, "a\tb", "a\\x41'\\'", "a\t\\'b"} {
		t.Run(rel, func(t *testing.T) {
			root := base + "/" + rel
			want, err := os.ReadFile(root + "/marker")
			if err != nil {
				t.Fatal(err)
			}
			hint := hiddenTreeHint(root, &fs.PathError{Op: "open", Path: root, Err: fs.ErrNotExist}, systemd)
			_, cmd, ok := strings.Cut(hint, "`ln -sn ")
			word, _, ok2 := strings.Cut(cmd, " "+aliasBindSource+" && ")
			if !ok || !ok2 {
				t.Fatalf("hint %q carries no ln -sn alias", hint)
			}
			if strings.Contains(hint, `BindReadOnlyPaths="`) {
				t.Fatalf("hint %q binds a spelling of root directly", hint)
			}
			alias := filepath.Join(t.TempDir(), "alias")
			if out, err := exec.Command(bash, "-c", "ln -sn "+word+" "+alias).CombinedOutput(); err != nil {
				t.Fatalf("ln -sn %s: %v: %s", word, err, out)
			}
			got, err := os.ReadFile(alias + "/marker")
			if err != nil || string(got) != string(want) {
				t.Fatalf("alias from %s reads %q (%v), want %q from the configured root", word, got, err, want)
			}
			if out, err := exec.Command(bash, "-c", "ln -sn "+word+" "+alias).CombinedOutput(); err == nil {
				t.Fatalf("a second ln -sn onto the existing alias succeeded: %s", out)
			}
			if entries, _ := os.ReadDir(root); len(entries) != 1 {
				t.Fatalf("the configured tree holds %v after a repeated ln, want only its marker", entries)
			}
		})
	}
}

// The hint is for the operator's journal. A client asking for a distfile
// while the tree is hidden gets the same 503 as for any failed read, naming
// no path and no unit setting.
func TestHiddenTreeHintStaysOutOfTheResponse(t *testing.T) {
	root := filepath.Join("/var/tmp", fmt.Sprintf("bodega-b100-absent-%d", time.Now().UnixNano()))
	systemd := func(k string) string {
		if k == "NOTIFY_SOCKET" {
			return "/run/systemd/notify"
		}
		return ""
	}
	s := newDiscoveryServer(t)
	var l logRecords
	s.distinfo = distinfo.NewTree(root, 0, distinfoLogf(l.logger(), root, systemd))
	_ = s.distinfo.Wait()
	got := l.records(t)
	if len(got) != 1 || !strings.Contains(got[0].Msg, "PrivateTmp=true") {
		t.Fatalf("log = %+v, want the failed read with its hint", got)
	}

	ts := httptest.NewServer(conformingClient(t, &config.Config{}, s.Handler()))
	t.Cleanup(ts.Close)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/distfiles/pcpustat/1.6.tar.bz2", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET = %d %q, want 503", resp.StatusCode, body)
	}
	for _, leak := range []string{root, hiddenTreeHint(root, &fs.PathError{Op: "open", Path: root, Err: fs.ErrNotExist}, systemd), "PrivateTmp", "ProtectHome", "BindReadOnlyPaths", "systemctl"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("503 body %q carries %q", body, leak)
		}
	}
}

// Only a failure to open the configured root is evidence the unit hides it. A
// root the server listed, with a file or directory below it missing or
// forbidden, is an incomplete tree, and the log says so without the hint even
// under systemd and a hidden prefix.
func TestHiddenTreeHintNeedsTheRootItself(t *testing.T) {
	systemd := func(k string) string {
		if k == "NOTIFY_SOCKET" {
			return "/run/systemd/notify"
		}
		return ""
	}
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, root string)
		hint   bool
	}{
		{"license database missing", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "Mk", "bsd.licenses.db.mk")); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"category unreadable", func(t *testing.T, root string) {
			dir := filepath.Join(root, "sysutils")
			if err := os.Chmod(dir, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		}, false},
		{"root missing", func(t *testing.T, root string) {
			if err := os.RemoveAll(root); err != nil {
				t.Fatal(err)
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if os.Geteuid() == 0 && !tc.hint {
				t.Skip("root reads a mode-000 directory")
			}
			root := copyTree(t, distfilesPortsTree(t), "/var/tmp")
			tc.damage(t, root)
			var l logRecords
			_ = distinfo.NewTree(root, 0, distinfoLogf(l.logger(), root, systemd)).Wait()
			got := l.records(t)
			if len(got) != 1 || got[0].Level != slog.LevelWarn.String() || !strings.Contains(got[0].Msg, "reading "+root+" failed") {
				t.Fatalf("log = %+v, want one WARN failure for %s", got, root)
			}
			if has := strings.Contains(got[0].Msg, "PrivateTmp=true"); has != tc.hint {
				t.Fatalf("hint present = %v, want %v: %q", has, tc.hint, got[0].Msg)
			}
		})
	}
}

// copyTree copies src into a fresh directory under dir, removed when the test
// ends, so a fixture can sit under a prefix the shipped unit hides.
func copyTree(t *testing.T, src, dir string) string {
	t.Helper()
	dst, err := os.MkdirTemp(dir, "bodega-b100-")
	if err != nil {
		t.Skipf("no writable %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dst) })
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	return dst
}
