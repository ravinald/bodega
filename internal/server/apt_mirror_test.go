package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/deb822"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/storage"
)

// The fixture archive stands in for archive.ubuntu.com: one Release signed by
// a key the test holds, one Packages, one by-hash copy of it, and one .deb.
// A live archive would make the assertions depend on what Canonical published
// this morning, and there is nothing about the protocol these bytes cannot
// exercise. The end-to-end run against a real archive is in the PR report.
const (
	mirroredCodename = "fixture"
	fixtureDeb       = "pool/main/n/nginx/nginx_1.24.0-2ubuntu7.1_amd64.deb"
	fixtureDebBody   = "\x21<arch>\nfixture nginx package bytes"
	fallbackDeb      = "pool/universe/h/htop/htop_3.3.0-4build1_amd64.deb"
	fallbackDebBody  = "\x21<arch>\nfixture htop package bytes"
	packagesPath     = "main/binary-amd64/Packages"
)

// fixtureArchive is one upstream Debian archive over httptest, counting the
// requests it served so a test can prove a fetch happened once rather than
// once per client.
type fixtureArchive struct {
	ts      *httptest.Server
	mu      sync.RWMutex // guards objects; setObject writes from the test goroutine
	objects map[string]string
	hits    sync.Map // path -> *atomic.Int64
	delay   time.Duration
	// gate, while set, parks every GET until it is closed: an upstream slow
	// enough that a rebuild reading it is still running when the test looks.
	gate chan struct{}
}

// hold parks every GET from here on until release is called.
func (a *fixtureArchive) hold(t testing.TB) (release func()) {
	t.Helper()
	gate := make(chan struct{})
	a.mu.Lock()
	a.gate = gate
	a.mu.Unlock()
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	return release
}

func (a *fixtureArchive) gated() chan struct{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.gate
}

// setObject replaces what the archive serves at rel, which is an upstream
// republishing different bytes under a path it already served.
func (a *fixtureArchive) setObject(rel, body string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.objects[rel] = body
}

// removeObject withdraws a path the archive was serving, which is an archive
// that publishes a digest for something it does not carry.
func (a *fixtureArchive) removeObject(rel string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.objects, rel)
}

func (a *fixtureArchive) object(rel string) (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	body, ok := a.objects[rel]
	return body, ok
}

func (a *fixtureArchive) count(path string) int64 {
	v, ok := a.hits.Load(path)
	if !ok {
		return 0
	}
	//nolint:forcetypeassert // only *atomic.Int64 is ever stored here.
	return v.(*atomic.Int64).Load()
}

// URL is the archive root, the directory holding dists/ and pool/.
func (a *fixtureArchive) URL() string { return a.ts.URL + "/ubuntu" }

// newFixtureArchive serves objects under /ubuntu/ and answers HEAD, which is
// what the pool probe uses.
func newFixtureArchive(t testing.TB, objects map[string]string) *fixtureArchive {
	t.Helper()
	a := &fixtureArchive{objects: objects}
	a.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(r.URL.Path, "/ubuntu/")
		body, ok := a.object(rel)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			ctr, _ := a.hits.LoadOrStore(rel, &atomic.Int64{})
			//nolint:forcetypeassert // only *atomic.Int64 is ever stored here.
			ctr.(*atomic.Int64).Add(1)
			if a.delay > 0 {
				time.Sleep(a.delay)
			}
			if gate := a.gated(); gate != nil {
				<-gate
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(a.ts.Close)
	return a
}

// fixtureDists builds a Release naming the Packages body beside it, signs it
// into an InRelease with kr, and returns the object map an archive serves.
//
// Release and InRelease are generated together from one Packages body on
// purpose: that is the invariant a client checks, and a fixture that hardcoded
// a digest would keep passing after the server started serving different bytes.
func fixtureDists(t *testing.T, kr *aptsign.KeyRing, packages string) map[string]string {
	t.Helper()
	return fixtureDistsArch(t, kr, packages, "amd64")
}

// fixtureDistsArch is fixtureDists for an archive publishing an architecture
// other than amd64, which is what a test driving a real apt in a container
// needs: the client reads binary-<its own arch>/Packages and nothing else, so
// an arm64 host handed an amd64-only Release reports a suite that does not
// support the architecture rather than the outcome under test.
//
// alsoDeclared names architectures the Release declares and publishes a digest
// for while the archive serves no body: archive.ubuntu.com is that archive,
// with one Release per suite naming all seven and amd64 and i386 alone served
// there. Deriving the Release from the one body written is what makes declared
// and published agree in a fixture and nowhere else, so a generator that takes
// a 404 on a declared architecture passes here and fails on Ubuntu.
func fixtureDistsArch(t *testing.T, kr *aptsign.KeyRing, packages, arch string, alsoDeclared ...string) map[string]string {
	t.Helper()
	return fixtureDistsFor(t, kr, mirroredCodename, packages, arch, alsoDeclared...)
}

// fixtureDistsFor is fixtureDistsArch for a codename other than the fixture's.
func fixtureDistsFor(t *testing.T, kr *aptsign.KeyRing, codename, packages, arch string, alsoDeclared ...string) map[string]string {
	t.Helper()
	packagesPath := "main/binary-" + arch + "/Packages"
	sum := sha256.Sum256([]byte(packages))
	digest := hex.EncodeToString(sum[:])
	// A real archive publishes both forms and lists both digests, and the
	// filtered-index generator reads the compressed one. A fixture that
	// published only the plain form would make every profile suite fail for a
	// reason no archive produces.
	gzBody := gzipFixture(packages)
	gzSum := sha256.Sum256(gzBody)

	digests := []string{
		fmt.Sprintf(" %s %d %s", digest, len(packages), packagesPath),
		fmt.Sprintf(" %s %d %s.gz", hex.EncodeToString(gzSum[:]), len(gzBody), packagesPath),
	}
	for _, other := range alsoDeclared {
		rest := "main/binary-" + other + "/Packages"
		digests = append(digests,
			fmt.Sprintf(" %s %d %s", strings.Repeat("0", 64), 1, rest),
			fmt.Sprintf(" %s %d %s", strings.Repeat("0", 64), 1, rest+".gz"))
	}

	release := strings.Join(append([]string{
		"Origin: Ubuntu",
		"Label: Ubuntu",
		"Suite: " + codename,
		"Codename: " + codename,
		"Components: main",
		"Architectures: " + strings.Join(append([]string{arch}, alsoDeclared...), " "),
		"Acquire-By-Hash: yes",
		"SHA256:",
	}, append(digests, "")...), "\n")

	inRelease, err := kr.ClearSign([]byte(release))
	if err != nil {
		t.Fatalf("clearsign fixture Release: %v", err)
	}
	detached, err := kr.DetachSign([]byte(release))
	if err != nil {
		t.Fatalf("detach-sign fixture Release: %v", err)
	}

	base := "dists/" + codename + "/"
	return map[string]string{
		base + "Release":            release,
		base + "InRelease":          string(inRelease),
		base + "Release.gpg":        string(detached),
		base + packagesPath:         packages,
		base + packagesPath + ".gz": string(gzBody),
		base + "main/binary-" + arch + "/by-hash/SHA256/" + digest: packages,
	}
}

// gzipFixture compresses an index the way an archive publishes it.
func gzipFixture(body string) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte(body))
	_ = gw.Close()
	return buf.Bytes()
}

// fixturePackages is the one-stanza index whose Filename points at the pool
// object the archive also serves, which is the hop apt makes on its own.
func fixturePackages(poolPath, body string) string {
	sum := sha256.Sum256([]byte(body))
	return strings.Join([]string{
		"Package: nginx",
		"Version: 1.24.0-2ubuntu7.1",
		"Architecture: amd64",
		"Depends: libc6",
		"Filename: " + poolPath,
		fmt.Sprintf("Size: %d", len(body)),
		"SHA256: " + hex.EncodeToString(sum[:]),
		"Description: fixture web server",
		"",
		"",
	}, "\n")
}

// mirrorServer wires a discovery server to one or more fixture archives and
// lifts the SSRF guard, which refuses a loopback listener by design.
func mirrorServer(t testing.TB, archives ...*fixtureArchive) *Server {
	t.Helper()
	s := newDiscoveryServer(t)
	s.cfg.AptCodename = "local"
	s.cfg.AptSuites = []string{"local"}
	s.cache = CacheConfig{Enabled: true, MetadataTTL: time.Hour}

	list := make([]config.AptUpstream, 0, len(archives))
	for _, a := range archives {
		list = append(list, config.AptUpstream{URL: a.URL()})
	}
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{mirroredCodename: list}

	// The real guard rejects loopback, which is the whole point of it. A
	// fixture archive can only run there, so the test swaps it for the scheme
	// check alone and restores it.
	saved := upstreamGuard
	upstreamGuard = func(rawURL string) error {
		if !strings.HasPrefix(rawURL, "http://127.0.0.1:") && !strings.HasPrefix(rawURL, "http://[::1]:") {
			return saved(rawURL)
		}
		return nil
	}
	t.Cleanup(func() { upstreamGuard = saved })
	return s
}

// waitForAptRows polls until want rows with the given decision are visible.
// The recorder writes off the request goroutine, so presence needs a window.
func waitForAptRows(t *testing.T, s *Server, decision string, want int) []audit.DiscoveryRow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var rows []audit.DiscoveryRow
	for time.Now().Before(deadline) {
		var err error
		rows, err = s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{Decision: decision})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		if len(rows) >= want {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s rows = %d after 3s, want %d (%+v)", decision, len(rows), want, rows)
	return nil
}

// mirrorGetHeader is mirrorGet for a test that asserts on response headers
// rather than on the body.
func mirrorGetHeader(t *testing.T, s *Server, path string) (int, http.Header) {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + path) //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header
}

func mirrorGet(t *testing.T, s *Server, path string) (int, []byte) {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + path) //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp.StatusCode, body
}

// TestMirroredInReleaseCoversTheServedPackages is requirement 1's guard, and
// the reason mirrored and generated codenames are disjoint.
//
// It does not trust that forwarding the bytes preserves the signature — it
// fetches the InRelease bodega serves, verifies it against the archive's key,
// then fetches the Packages bodega serves and checks its digest against the
// one the verified document names. A client that got an InRelease from one
// generation and a Packages from another is exactly the failure this rules out.
func TestMirroredInReleaseCoversTheServedPackages(t *testing.T) {
	kr, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}
	packages := fixturePackages(fixtureDeb, fixtureDebBody)
	objects := fixtureDists(t, kr, packages)
	objects[fixtureDeb] = fixtureDebBody
	s := mirrorServer(t, newFixtureArchive(t, objects))

	code, inRelease := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/InRelease")
	if code != http.StatusOK {
		t.Fatalf("InRelease = %d, want 200", code)
	}

	block, rest := clearsign.Decode(inRelease)
	if block == nil {
		t.Fatalf("served InRelease is not clearsigned (trailing %d bytes)", len(rest))
	}
	pub, err := kr.PublicKey()
	if err != nil {
		t.Fatalf("fixture public key: %v", err)
	}
	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(pub))
	if err != nil {
		t.Fatalf("read fixture keyring: %v", err)
	}
	if _, err := openpgp.CheckDetachedSignature(ring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
		t.Fatalf("served InRelease does not verify against the upstream key: %v", err)
	}

	code, served := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+packagesPath)
	if code != http.StatusOK {
		t.Fatalf("Packages = %d, want 200", code)
	}
	sum := sha256.Sum256(served)
	want := " " + hex.EncodeToString(sum[:]) + " " + fmt.Sprintf("%d", len(served)) + " " + packagesPath
	if !strings.Contains(string(block.Plaintext), want) {
		t.Fatalf("the verified InRelease does not name the Packages bodega served.\nwant line: %q\nsigned body:\n%s", want, block.Plaintext)
	}
}

// A signing key of bodega's own must not change what a mirrored suite serves.
// The tempting bug is signing everything under /apt/dists/, which would put
// bodega's signature over an index whose digests it never computed.
func TestBodegaKeyDoesNotTouchAMirroredSuite(t *testing.T) {
	kr, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}
	objects := fixtureDists(t, kr, fixturePackages(fixtureDeb, fixtureDebBody))
	s := mirrorServer(t, newFixtureArchive(t, objects))

	own, err := aptsign.Generate("bodega", "bodega@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate bodega key: %v", err)
	}
	pub, _ := own.PublicKey()
	ringBytes, _ := own.Keyring()
	s.aptSign.Store(&aptSigning{signer: own, pubArmored: pub, keyring: ringBytes})

	_, served := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/InRelease")
	if !bytes.Equal(served, []byte(objects["dists/"+mirroredCodename+"/InRelease"])) {
		t.Fatal("a mirrored InRelease was rewritten; it must be forwarded byte-for-byte")
	}
}

// The pool row is the one that records the dependency closure, so its package
// and version have to survive the trip through the object key.
func TestMirroredPoolFetchRecordsPackageAndVersion(t *testing.T) {
	kr, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}
	objects := fixtureDists(t, kr, fixturePackages(fixtureDeb, fixtureDebBody))
	objects[fixtureDeb] = fixtureDebBody
	archive := newFixtureArchive(t, objects)
	s := mirrorServer(t, archive)

	code, body := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusOK {
		t.Fatalf("pool fetch = %d, want 200", code)
	}
	if string(body) != fixtureDebBody {
		t.Fatalf("pool body = %q, want the archive's bytes", body)
	}

	rows := waitForAptRows(t, s, audit.DecisionNoPolicy, 1)
	var found *audit.DiscoveryRow
	for i := range rows {
		if rows[i].PkgName == "nginx" {
			found = &rows[i]
		}
	}
	if found == nil {
		t.Fatalf("no discovery row for the pooled .deb: %+v", rows)
	}
	if found.PkgVersion != "1.24.0-2ubuntu7.1" {
		t.Errorf("pkg_version = %q, want the version parsed from the filename", found.PkgVersion)
	}
	if found.RegistryType != manifest.TypeApt {
		t.Errorf("type = %q, want apt", found.RegistryType)
	}
	// pattern_hint is the host, which is what `policy add apt <host>` takes.
	if found.PatternHint != "127.0.0.1" || found.Host != "127.0.0.1" {
		t.Errorf("hint/host = %q/%q, want the archive host", found.PatternHint, found.Host)
	}

	// Second request, no second upstream GET: a .deb is immutable and the
	// first fetch cached it. Getting this wrong re-downloads the whole
	// dependency closure on every install in the fleet.
	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Fatalf("second pool fetch = %d", code)
	}
	if got := archive.count(fixtureDeb); got != 1 {
		t.Errorf("upstream GETs = %d, want 1 — a cached .deb was refetched", got)
	}
}

// A Packages file is republished in place, a by-hash entry never is. Treating
// the index as immutable freezes a suite forever; treating by-hash as mutable
// refetches every artifact on every install.
func TestMirroredIndexIsMutableAndByHashIsNot(t *testing.T) {
	kr, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}
	packages := fixturePackages(fixtureDeb, fixtureDebBody)
	objects := fixtureDists(t, kr, packages)
	archive := newFixtureArchive(t, objects)
	s := mirrorServer(t, archive)
	// Every mutable object re-checks upstream. A zero or negative TTL is
	// isCacheStale's "never expire", so the smallest positive value is what
	// expresses "always stale" here.
	s.cache.MetadataTTL = time.Nanosecond

	sum := sha256.Sum256([]byte(packages))
	byHash := "main/binary-amd64/by-hash/SHA256/" + hex.EncodeToString(sum[:])

	for range 2 {
		if code, _ := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+packagesPath); code != http.StatusOK {
			t.Fatal("Packages fetch failed")
		}
		if code, _ := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+byHash); code != http.StatusOK {
			t.Fatal("by-hash fetch failed")
		}
	}
	if got := archive.count("dists/" + mirroredCodename + "/" + packagesPath); got != 2 {
		t.Errorf("Packages upstream GETs = %d, want 2 — the index must be refetched past metadata_ttl", got)
	}
	if got := archive.count("dists/" + mirroredCodename + "/" + byHash); got != 1 {
		t.Errorf("by-hash upstream GETs = %d, want 1 — a content-addressed path never changes", got)
	}
}

// A pool path carries no codename, so bodega probes the configured archives in
// sorted order. The second one holds the .deb and has to be reached.
func TestPoolFallsBackToTheSecondArchive(t *testing.T) {
	first := newFixtureArchive(t, map[string]string{})
	second := newFixtureArchive(t, map[string]string{fallbackDeb: fallbackDebBody})
	s := mirrorServer(t, first, second)

	code, body := mirrorGet(t, s, "/apt/"+fallbackDeb)
	if code != http.StatusOK {
		t.Fatalf("pool fetch = %d, want 200 from the second archive", code)
	}
	if string(body) != fallbackDebBody {
		t.Fatalf("body = %q, want the second archive's bytes", body)
	}

	// A path in no archive is a 404 and is remembered as one. apt retries a
	// failed download, and without the negative entry each retry fans back out
	// across every configured host.
	missing := "pool/main/z/zzz/zzz_1.0-1_amd64.deb"
	if code, _ := mirrorGet(t, s, "/apt/"+missing); code != http.StatusNotFound {
		t.Fatalf("missing pool path = %d, want 404", code)
	}
	if url, fresh := s.aptRoutes.get(missing); !fresh || url != "" {
		t.Errorf("route cache holds %q/%v for a path no archive has; the next retry re-probes everything", url, fresh)
	}
}

// A fleet running `apt install` at the same minute must produce one upstream
// fetch of a .deb, not one per host.
func TestConcurrentPoolRequestsMakeOneUpstreamFetch(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	archive.delay = 50 * time.Millisecond
	s := mirrorServer(t, archive)

	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	const clients = 8
	var wg sync.WaitGroup
	codes := make([]int, clients)
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL + "/apt/" + fixtureDeb) //nolint:gosec,noctx // test-owned loopback URL
			if err != nil {
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			codes[i] = resp.StatusCode
		}()
	}
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("client %d got %d, want 200", i, code)
		}
	}
	if got := archive.count(fixtureDeb); got != 1 {
		t.Errorf("upstream GETs = %d for %d concurrent clients, want 1", got, clients)
	}
}

// Requirement 10: a refused archive is never contacted. The allow-list check
// has to run before the probe as well as before the fetch — a probe that asks
// first has already made the request the rule exists to prevent.
func TestDeniedArchiveIsNeverContacted(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID:           "apt-allow-elsewhere",
		RegistryType: manifest.TypeApt,
		RuleKind:     policy.KindHost,
		Pattern:      "archive.ubuntu.com",
	}); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	s.policy.Invalidate()

	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusForbidden {
		t.Fatalf("pool fetch = %d, want 403", code)
	}
	if got := archive.count(fixtureDeb); got != 0 {
		t.Fatalf("the refused archive was contacted %d times", got)
	}

	rows := waitForAptRows(t, s, audit.DecisionDenied, 1)
	if rows[0].PkgName != "nginx" {
		t.Errorf("denied row pkg_name = %q, want nginx", rows[0].PkgName)
	}
}

// Allowing one of two configured archives means "use that one". Aborting on
// whichever sorts first would refuse every pool path, including the ones the
// allowed archive serves, and the client would read a policy refusal as a
// package that does not exist.
func TestRefusedArchiveIsSkippedNotFatal(t *testing.T) {
	allowed := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, allowed)

	// A second archive that sorts ahead of the fixture, so it is the first
	// candidate the probe loop reaches. The leading "0" is what puts it there:
	// AptPoolUpstreams sorts, and "0-denied" precedes "127.0.0.1".
	s.cfg.AptUpstreams[mirroredCodename] = append(
		[]config.AptUpstream{{URL: "http://0-denied.invalid/ubuntu"}},
		s.cfg.AptUpstreams[mirroredCodename]...)

	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID:           "apt-allow-loopback-only",
		RegistryType: manifest.TypeApt,
		RuleKind:     policy.KindHost,
		Pattern:      "127.0.0.1",
	}); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	s.policy.Invalidate()

	// Aborting at the first refusal would make this a 403 and leave a package
	// the allowed archive serves unreachable.
	code, body := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusOK {
		t.Fatalf("pool fetch = %d, want 200 from the allowed archive", code)
	}
	if string(body) != fixtureDebBody {
		t.Fatalf("body = %q, want the allowed archive's bytes", body)
	}

	// The refusal is still recorded. Skipping it silently would leave an
	// operator with no way to see that an archive they configured is off the
	// list, since the request succeeded.
	rows := waitForAptRows(t, s, audit.DecisionDenied, 1)
	if !strings.Contains(rows[0].UpstreamURL, "0-denied.invalid") {
		t.Errorf("denied row names %q, want the refused archive", rows[0].UpstreamURL)
	}
}

// Every archive off the list is a 403, not a 404. A policy refusal that reads
// as "no such package" sends the operator looking for a typo in the name.
func TestAllArchivesRefusedIs403(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID:           "apt-allow-elsewhere-only",
		RegistryType: manifest.TypeApt,
		RuleKind:     policy.KindHost,
		Pattern:      "archive.ubuntu.com",
	}); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	s.policy.Invalidate()

	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusForbidden {
		t.Fatalf("pool fetch = %d, want 403", code)
	}
	if got := archive.count(fixtureDeb); got != 0 {
		t.Fatalf("the refused archive was contacted %d times", got)
	}
}

// One client download is one row. The probe checks the allow-list per
// candidate and the fetch checks it again, and recording at both would count a
// single install as two — on top of #127, which already makes the count a
// measure of the cache rather than the fleet.
func TestOnePoolFetchRecordsOneRow(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)

	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Fatal("pool fetch failed")
	}
	rows := waitForAptRows(t, s, audit.DecisionNoPolicy, 1)
	for _, row := range rows {
		if row.PkgName == "nginx" && row.RequestCount != 1 {
			t.Errorf("request_count = %d for one fetch, want 1", row.RequestCount)
		}
	}
}

// Requirement 8: an upstream fetch must never write over a pool path a
// manifest entry owns. The entry's Packages stanza already published a SHA256
// computed at package time, so caching another archive's artifact there serves
// bytes no client's hash check accepts.
func TestBuiltPoolPathIsNeverFetchedFromUpstream(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: "bytes from the archive, not from the build"})
	s := mirrorServer(t, archive)

	if err := s.store.AddVersion(t.Context(), manifest.TypeApt, "nginx", manifest.VersionEntry{
		Version:    "1.24.0-2ubuntu7.1",
		SourceName: "nginx",
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   fixtureDeb,
		},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	s.rebuildAptSnapshot(t.Context())

	// The .deb has not been uploaded yet: the entry exists and storage is
	// empty, which is the ordinary gap between `pkg create` and `pkg build`
	// and the exact window the guard is for.
	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusNotFound {
		t.Fatalf("pool fetch = %d, want 404 for a path bodega's own manifest owns", code)
	}
	if got := archive.count(fixtureDeb); got != 0 {
		t.Fatalf("upstream was contacted %d times for a locally-owned pool path", got)
	}
}

// A generated suite keeps working beside a mirrored one, which is what makes
// the disjoint-namespace rule usable rather than a choice between the two.
func TestGeneratedSuiteStillServesBesideAMirror(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{})
	s := mirrorServer(t, archive)
	s.rebuildAptSnapshot(t.Context())

	code, body := mirrorGet(t, s, "/apt/dists/local/Release")
	if code != http.StatusOK {
		t.Fatalf("generated Release = %d, want 200", code)
	}
	if !strings.Contains(string(body), "Origin: bodega") {
		t.Errorf("generated Release lost its own identity:\n%s", body)
	}
	if code, _ := mirrorGet(t, s, "/apt/dists/nosuchsuite/Release"); code != http.StatusNotFound {
		t.Errorf("an unserved suite must 404")
	}
}

// An archive publishes no Packages for an architecture it does not carry, and
// apt reads that 404 as "not published here" and moves on. Returning 502
// instead turns every arch and component a mirror legitimately lacks into an
// error the operator has to chase: an amd64-only archive answering an arm64
// client fails `apt update` on five paths that are all working as designed.
func TestUnpublishedUpstreamPathIs404Not502(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{})
	s := mirrorServer(t, archive)

	code, _ := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/main/binary-riscv64/Packages")
	if code != http.StatusNotFound {
		t.Errorf("unpublished index = %d, want 404", code)
	}
}

func TestAptDebIdentity(t *testing.T) {
	for _, tc := range []struct{ file, name, version string }{
		{"nginx_1.24.0-2ubuntu7.1_amd64.deb", "nginx", "1.24.0-2ubuntu7.1"},
		{"libssl3t64_3.0.13-0ubuntu3.4_arm64.deb", "libssl3t64", "3.0.13-0ubuntu3.4"},
		// An epoch's ":" is percent-encoded in a pool filename, and a row
		// carrying "1%3a2.3-1" as the version does not match the version an
		// operator reads out of `apt policy`.
		{"tzdata_2024a%3a1.0-1_all.deb", "tzdata", "2024a:1.0-1"},
		{"foo_1.0-1.udeb", "foo", "1.0-1"},
		{"nginx_1.24.0-2ubuntu7.1.dsc", "nginx", "1.24.0-2ubuntu7.1"},
		{"Packages", "", ""},
		{"nginx.deb", "", ""},
		{"_1.0_amd64.deb", "", ""},
	} {
		name, version := manifest.AptDebIdentity(tc.file)
		if name != tc.name || version != tc.version {
			t.Errorf("manifest.AptDebIdentity(%q) = (%q, %q), want (%q, %q)", tc.file, name, version, tc.name, tc.version)
		}
	}
}

func TestAptDistsImmutable(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"InRelease", false},
		{"Release", false},
		{"Release.gpg", false},
		{"main/binary-amd64/Packages", false},
		{"main/binary-amd64/Packages.xz", false},
		{"main/source/Sources.gz", false},
		{"main/i18n/Translation-en.xz", false},
		{"main/binary-amd64/by-hash/SHA256/deadbeef", true},
		{"main/by-hash/SHA256/deadbeef", true},
	} {
		if got := aptDistsImmutable(tc.path); got != tc.want {
			t.Errorf("aptDistsImmutable(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestAuditFallbackEntryAdoptsMirroredDeb is issue #170: a manifest entry with
// no _pool_path resolves against the whole pool, which on a mirroring instance
// holds artifacts bodega never built. The stanza that results carries no
// SHA256 and no Size, so nothing client-side catches the substitution — the
// host trusts bodega's archive key and installs an upstream binary believing
// it is the operator's build.
func TestAuditFallbackEntryAdoptsMirroredDeb(t *testing.T) {
	upstreamBytes := "\x21<arch>\nbytes from ports.ubuntu.com, not from the build"
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: upstreamBytes})
	s := mirrorServer(t, archive)

	// A legacy entry: name, version, arch, published to the generated suite,
	// no _pool_path and no _sha256.
	if err := s.store.AddVersion(t.Context(), manifest.TypeApt, "nginx", manifest.VersionEntry{
		Version:    "1.24.0-2ubuntu7.1",
		SourceName: "nginx",
		Suites:     []string{"local"},
		Metadata:   map[string]string{"Architecture": "amd64"},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	// A client installs from the mirrored suite; bodega caches the upstream .deb.
	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Fatalf("mirrored pool fetch failed")
	}
	s.rebuildAptSnapshot(t.Context())

	code, body := mirrorGet(t, s, "/apt/dists/local/main/binary-amd64/Packages")
	if code != http.StatusOK {
		t.Fatalf("generated Packages = %d, want 200", code)
	}
	if strings.Contains(string(body), "Filename: "+fixtureDeb) {
		t.Errorf("bodega's signed index publishes the cached upstream artifact:\n%s", body)
	}
}

// TestRetiringUpstreamsKeepsTheMirroredDebExcluded is #201. The exclusion used
// to be gated on len(cfg.AptUpstreams), which asks the config a question only
// the pool can answer. Mirror the .deb, drop apt_upstreams, and the cached
// upstream artifact is still in pool/ under the exact filename the fallback
// entry resolves by — so the stanza that reappears carries no SHA256 and the
// host installs archive bytes as the operator's build, which is #170 again.
func TestRetiringUpstreamsKeepsTheMirroredDebExcluded(t *testing.T) {
	upstreamBytes := "\x21<arch>\nbytes from ports.ubuntu.com, not from the build"
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: upstreamBytes})
	s := mirrorServer(t, archive)

	if err := s.store.AddVersion(t.Context(), manifest.TypeApt, "nginx", manifest.VersionEntry{
		Version:    "1.24.0-2ubuntu7.1",
		SourceName: "nginx",
		Suites:     []string{"local"},
		Metadata:   map[string]string{"Architecture": "amd64"},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Fatalf("mirrored pool fetch failed")
	}

	// The operator retires mirroring. The pool listing is dropped with it, so
	// the rebuild takes a fresh one and cannot inherit the earlier exclusion.
	s.cfg.AptUpstreams = nil
	s.aptPool.Store(nil)
	s.rebuildAptSnapshot(t.Context())

	code, body := mirrorGet(t, s, "/apt/dists/local/main/binary-amd64/Packages")
	if code != http.StatusOK {
		t.Fatalf("generated Packages = %d, want 200", code)
	}
	if strings.Contains(string(body), "Filename: "+fixtureDeb) {
		t.Errorf("retiring apt_upstreams republished the cached upstream artifact:\n%s", body)
	}
}

// TestAuditFallbackEntryCrossesArchitecture is the second half of #170: the
// prefix pass in findDebInPool drops the architecture, so an arm64 entry
// resolves to the amd64 artifact sitting in the pool.
func TestAuditFallbackEntryCrossesArchitecture(t *testing.T) {
	upstreamBytes := "\x21<arch>\nbytes from ports.ubuntu.com, not from the build"
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: upstreamBytes})
	s := mirrorServer(t, archive)

	if err := s.store.AddVersion(t.Context(), manifest.TypeApt, "nginx", manifest.VersionEntry{
		Version:    "1.24.0-2ubuntu7.1",
		SourceName: "nginx",
		Suites:     []string{"local"},
		Metadata:   map[string]string{"Architecture": "arm64"},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Fatalf("mirrored pool fetch failed")
	}
	s.rebuildAptSnapshot(t.Context())

	code, body := mirrorGet(t, s, "/apt/dists/local/main/binary-arm64/Packages")
	if code != http.StatusOK {
		t.Fatalf("generated arm64 Packages = %d, want 200", code)
	}
	if strings.Contains(string(body), "Filename: "+fixtureDeb) {
		t.Errorf("an arm64 entry published the amd64 artifact:\n%s", body)
	}
}

// The pool probe is the one place an allow-list refusal for a .deb can be
// observed: there is no fetch behind it to write the row. Issue #206 — it
// reached the discovery table and nothing else, so the same refusal was
// answerable from GET /api/v1/audit on the proxy path and not on this one.
func TestPoolAllowListRefusalRecordsAnAuditRow(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID:           "apt-allow-elsewhere",
		RegistryType: manifest.TypeApt,
		RuleKind:     policy.KindHost,
		Pattern:      "archive.ubuntu.com",
	}); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	s.policy.Invalidate()

	if code, _ := mirrorGetHeader(t, s, "/apt/"+fixtureDeb); code != http.StatusForbidden {
		t.Fatalf("pool fetch = %d, want 403", code)
	}

	rows, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCache})
	if err != nil {
		t.Fatalf("query audit db: %v", err)
	}
	var violations []audit.StoredEvent
	for _, row := range rows {
		if row.Status == "policy_violation" {
			violations = append(violations, row)
		}
	}
	if len(violations) != 1 {
		t.Fatalf("policy_violation rows = %d, want 1 (%+v)", len(violations), rows)
	}
	if violations[0].PkgType != manifest.TypeApt {
		t.Errorf("pkg_type = %q, want %q", violations[0].PkgType, manifest.TypeApt)
	}
	if !strings.Contains(violations[0].PkgName, fixtureDeb) {
		t.Errorf("pkg_name = %q, want the refused candidate URL", violations[0].PkgName)
	}
	// The discovery row is still written: the two tables answer different
	// questions and one is not a substitute for the other.
	waitForAptRows(t, s, audit.DecisionDenied, 1)
}

// TestPoolCacheControlFollowsTheOutcome is issue #171. handleAptPool set
// Cache-Control before it knew whether the request would succeed, and
// http.Error does not clear the header map — so a refusal shipped
// "public, max-age=31536000, immutable" and any caching proxy in front of the
// client held it for a year, outliving the "bodega policy add apt <host>" that
// was supposed to fix it.
func TestPoolCacheControlFollowsTheOutcome(t *testing.T) {
	const immutable = "public, max-age=31536000, immutable"

	t.Run("denied", func(t *testing.T) {
		archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
		s := mirrorServer(t, archive)
		if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
			ID:           "apt-allow-elsewhere",
			RegistryType: manifest.TypeApt,
			RuleKind:     policy.KindHost,
			Pattern:      "archive.ubuntu.com",
		}); err != nil {
			t.Fatalf("insert policy: %v", err)
		}
		s.policy.Invalidate()

		code, hdr := mirrorGetHeader(t, s, "/apt/"+fixtureDeb)
		if code != http.StatusForbidden {
			t.Fatalf("pool fetch = %d, want 403", code)
		}
		if got := hdr.Get("Cache-Control"); got != "" {
			t.Errorf("403 carries Cache-Control %q; a caching proxy would hold the refusal", got)
		}
	})

	t.Run("no archive publishes it", func(t *testing.T) {
		archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
		s := mirrorServer(t, archive)

		code, hdr := mirrorGetHeader(t, s, "/apt/"+fallbackDeb)
		if code != http.StatusNotFound {
			t.Fatalf("pool fetch = %d, want 404", code)
		}
		if got := hdr.Get("Cache-Control"); got != "" {
			t.Errorf("404 carries Cache-Control %q", got)
		}
	})

	t.Run("served", func(t *testing.T) {
		archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
		s := mirrorServer(t, archive)

		code, hdr := mirrorGetHeader(t, s, "/apt/"+fixtureDeb)
		if code != http.StatusOK {
			t.Fatalf("pool fetch = %d, want 200", code)
		}
		if got := hdr.Get("Cache-Control"); got != immutable {
			t.Errorf("Cache-Control = %q, want %q — a cached .deb is still immutable", got, immutable)
		}

		// The second request is the cache-hit path through proxyS3, which
		// takes a different route to the same header.
		code, hdr = mirrorGetHeader(t, s, "/apt/"+fixtureDeb)
		if code != http.StatusOK {
			t.Fatalf("cached pool fetch = %d, want 200", code)
		}
		if got := hdr.Get("Cache-Control"); got != immutable {
			t.Errorf("cache hit Cache-Control = %q, want %q", got, immutable)
		}
	})
}

// A .deb uploaded out of band still resolves: the exclusion is on the objects
// the mirror wrote, not on the fallback path itself. Without this the fix for
// #170 would have retired the out-of-band upload route instead of protecting
// it.
//
// On a pool that has held upstream bytes the entry has to carry its own digest.
// A filename match is not evidence of provenance there, and a stanza with no
// SHA256 gives the client nothing to check the substitution against, so the
// generator refuses it — see TestOutOfBandDebWithoutDigestStaysOut.
func TestOutOfBandDebStillResolves(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)

	if err := s.store.AddVersion(t.Context(), manifest.TypeApt, "htop", manifest.VersionEntry{
		Version:    "3.3.0-4build1",
		SourceName: "htop",
		Suites:     []string{"local"},
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_sha256":      fmt.Sprintf("%x", sha256.Sum256([]byte(fallbackDebBody))),
		},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	// Written straight to storage, which is what an out-of-band upload is: no
	// _pool_path on the entry and no checksum row for the object.
	if err := s.typeStore(manifest.TypeApt).Put(t.Context(), manifest.AptKey(fallbackDeb), []byte(fallbackDebBody)); err != nil {
		t.Fatalf("seed pool object: %v", err)
	}
	s.rebuildAptSnapshot(t.Context())

	code, body := mirrorGet(t, s, "/apt/dists/local/main/binary-amd64/Packages")
	if code != http.StatusOK {
		t.Fatalf("generated Packages = %d, want 200", code)
	}
	if !strings.Contains(string(body), "Filename: "+fallbackDeb) {
		t.Errorf("an out-of-band .deb did not reach the index:\n%s", body)
	}

	// With no audit database there is no way to tell that object from one the
	// mirror cached, so it drops out rather than being published on a guess.
	// Restored on the way out: newDiscoveryServer's own cleanup closes this
	// handle, and cleanups run last-registered-first.
	saved := s.auditDB
	t.Cleanup(func() { s.auditDB = saved })
	s.auditDB = nil
	s.aptPool.Store(nil)
	s.rebuildAptSnapshot(t.Context())

	code, body = mirrorGet(t, s, "/apt/dists/local/main/binary-amd64/Packages")
	if code != http.StatusOK {
		t.Fatalf("generated Packages = %d, want 200", code)
	}
	if strings.Contains(string(body), "Filename: "+fallbackDeb) {
		t.Errorf("an unverifiable pool object was published anyway:\n%s", body)
	}
}

// The same out-of-band upload with no digest recorded. The audit database is
// readable and says the object is not one the mirror wrote, so the exclusion
// admits it — and the stanza would still carry no SHA256, on a pool that
// demonstrably holds upstream bytes. Publishing it hands a client an
// unverifiable binary under bodega's archive key, which is #170 by a second
// route: nothing distinguishes this object from a mirrored one whose checksum
// row was never written (#225).
func TestOutOfBandDebWithoutDigestStaysOut(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)

	if err := s.store.AddVersion(t.Context(), manifest.TypeApt, "htop", manifest.VersionEntry{
		Version:    "3.3.0-4build1",
		SourceName: "htop",
		Suites:     []string{"local"},
		Metadata:   map[string]string{"Architecture": "amd64"},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := s.typeStore(manifest.TypeApt).Put(t.Context(), manifest.AptKey(fallbackDeb), []byte(fallbackDebBody)); err != nil {
		t.Fatalf("seed pool object: %v", err)
	}
	s.rebuildAptSnapshot(t.Context())

	code, body := mirrorGet(t, s, "/apt/dists/local/main/binary-amd64/Packages")
	if code != http.StatusOK {
		t.Fatalf("generated Packages = %d, want 200", code)
	}
	if strings.Contains(string(body), "Filename: "+fallbackDeb) {
		t.Errorf("a digest-less pool match was published on a mirroring instance:\n%s", body)
	}
}

// TestPoolCacheHitCountsAsARequest is the deployment shape discovery was built
// for: point a clean host at bodega, let it install, read back what it reached
// for. Recording only misses made the second run report almost nothing —
// request_count described how badly the cache was working and last_client named
// whoever missed first, which is close to inverted for anything ranking by
// demand (#127).
func TestPoolCacheHitCountsAsARequest(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)

	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Fatal("pool fetch failed")
	}
	waitForAptRows(t, s, audit.DecisionNoPolicy, 1)

	for range 2 {
		if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
			t.Fatal("cached pool fetch failed")
		}
	}
	if got := archive.count(fixtureDeb); got != 1 {
		t.Fatalf("upstream GETs = %d, want 1 — the second and third requests must be hits", got)
	}

	row := waitForPoolRow(t, s, "nginx", 3)
	if row.PatternHint != "127.0.0.1" || row.Host != "127.0.0.1" {
		t.Errorf("hint/host = %q/%q, want the archive host on the hit rows too — a hit must land on the miss's row, not beside it",
			row.PatternHint, row.Host)
	}
	if row.UpstreamURL == "" {
		t.Error("upstream_url was blanked by a hit; promote needs a fetchable URL")
	}
}

// waitForPoolRow polls for one pool row's request_count to reach want, and
// fails if the package ever occupies more than one row.
func waitForPoolRow(t *testing.T, s *Server, pkgName string, want int64) audit.DiscoveryRow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last audit.DiscoveryRow
	for time.Now().Before(deadline) {
		rows, err := s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		var matched []audit.DiscoveryRow
		for _, row := range rows {
			if row.PkgName == pkgName {
				matched = append(matched, row)
			}
		}
		if len(matched) > 1 {
			t.Fatalf("%q occupies %d rows, want 1 (%+v)", pkgName, len(matched), matched)
		}
		if len(matched) == 1 {
			last = matched[0]
			if last.RequestCount >= want {
				return last
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("request_count for %q = %d after 3s, want %d", pkgName, last.RequestCount, want)
	return last
}

// TestByHashRowNamesNoDigest bounds the discovery package name for a by-hash
// entry. The raw path is ~100 characters naming no package, and
// `bodega discover show apt <host>` sizes the PACKAGE column to the longest
// value — so six by-hash rows from one `apt install` push UPSTREAM URL off the
// terminal and make the pool rows beside them unreadable. The digest stays on
// the row, in the URL (#173).
func TestByHashRowNamesNoDigest(t *testing.T) {
	kr, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}
	packages := fixturePackages(fixtureDeb, fixtureDebBody)
	objects := fixtureDists(t, kr, packages)
	archive := newFixtureArchive(t, objects)
	s := mirrorServer(t, archive)

	sum := sha256.Sum256([]byte(packages))
	digest := hex.EncodeToString(sum[:])
	byHash := "main/binary-amd64/by-hash/SHA256/" + digest

	if code, _ := mirrorGet(t, s, "/apt/dists/"+mirroredCodename+"/"+byHash); code != http.StatusOK {
		t.Fatal("by-hash fetch failed")
	}

	rows := waitForAptRows(t, s, audit.DecisionNoPolicy, 1)
	var found bool
	for _, row := range rows {
		if strings.Contains(row.PkgName, digest) {
			t.Errorf("pkg_name = %q, want no digest — it is already in the upstream URL", row.PkgName)
		}
		if row.PkgName == mirroredCodename+"/by-hash" {
			found = true
			if !strings.Contains(row.UpstreamURL, digest) {
				t.Errorf("upstream_url = %q, want the digest still recoverable", row.UpstreamURL)
			}
		}
	}
	if !found {
		t.Errorf("no row named %q: %+v", mirroredCodename+"/by-hash", rows)
	}
}

// BenchmarkCachedPoolRequest measures what recording a hit costs the path that
// serves every .deb in a warm fleet. Run it as:
//
//	go test ./internal/server -run '^$' -bench BenchmarkCachedPoolRequest -benchtime 2000x
//
// The write itself is a send on a buffered channel; the addition on top of it
// is one policy verdict, which is a read-through cache with a 30s TTL, plus
// SuggestPattern. The numbers are in the PR.
func BenchmarkCachedPoolRequest(b *testing.B) {
	for _, mode := range []string{"", "observe"} {
		name := "discover_off"
		if mode != "" {
			name = "discover_" + mode
		}
		b.Run(name, func(b *testing.B) {
			archive := newFixtureArchive(b, map[string]string{fixtureDeb: fixtureDebBody})
			s := mirrorServer(b, archive)
			s.discoverMode = mode
			h := s.Handler()

			// Warm the cache: the first request is the miss, everything the
			// benchmark measures is a hit.
			warm := httptest.NewRecorder()
			h.ServeHTTP(warm, httptest.NewRequest(http.MethodGet, "/apt/"+fixtureDeb, nil))
			if warm.Code != http.StatusOK {
				b.Fatalf("warm request = %d, want 200", warm.Code)
			}

			b.ResetTimer()
			for range b.N {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/apt/"+fixtureDeb, nil))
				if rec.Code != http.StatusOK {
					b.Fatalf("request = %d, want 200", rec.Code)
				}
			}
			b.StopTimer()
			if dropped := s.discovery.dropped.Load(); dropped > 0 {
				b.Logf("discovery rows dropped: %d of %d requests", dropped, b.N)
			}
		})
	}
}

// A mirrored .deb has to land in the checksum table under its own type and
// name. Two things read that: aptMirroredPoolKeys, which asks the pkg_type
// column which pool objects came from an upstream, and `bodega pkg checksum clear
// apt <name>`, the only way out of a stale digest when an archive republishes
// bytes under a version it already served. Both matched nothing while the row
// was written by a parser that read request paths.
func TestMirroredPoolFetchIsCheckSummedUnderItsPackage(t *testing.T) {
	kr, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}
	objects := fixtureDists(t, kr, fixturePackages(fixtureDeb, fixtureDebBody))
	objects[fixtureDeb] = fixtureDebBody
	archive := newFixtureArchive(t, objects)
	s := mirrorServer(t, archive)

	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Fatalf("pool fetch = %d, want 200", code)
	}

	ctx := t.Context()
	rows, err := s.auditDB.ListChecksums(ctx, manifest.TypeApt, "")
	if err != nil {
		t.Fatalf("list apt checksums: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("apt checksum rows = %d, want 1 — the mirrored .deb is not filed under its type (%+v)", len(rows), rows)
	}
	row := rows[0]
	if row.ObjectKey != manifest.AptKey(fixtureDeb) {
		t.Errorf("object_key = %q, want %q", row.ObjectKey, manifest.AptKey(fixtureDeb))
	}
	if row.PkgName != "nginx" || row.PkgVersion != "1.24.0-2ubuntu7.1" {
		t.Errorf("identity = %q/%q, want nginx/1.24.0-2ubuntu7.1", row.PkgName, row.PkgVersion)
	}
	if row.Source != "computed" {
		t.Errorf("source = %q, want computed — aptMirroredPoolKeys filters on it", row.Source)
	}

	// The recovery command's query, against the row the fetch just wrote.
	cleared, _, err := s.auditDB.ClearChecksumsByPackage(ctx, manifest.TypeApt, "nginx")
	if err != nil {
		t.Fatalf("clear apt/nginx: %v", err)
	}
	if cleared != 1 {
		t.Errorf("cleared = %d, want 1 — clear reported success over a row it never matched", cleared)
	}
	left, err := s.auditDB.ListChecksums(ctx, manifest.TypeApt, "")
	if err != nil {
		t.Fatalf("re-list apt checksums: %v", err)
	}
	// The digest goes and the row stays: it is also the record that keeps this
	// object out of the index, and the .deb is still in pool/ (#225).
	if len(left) != 1 {
		t.Fatalf("apt checksum rows after clear = %d, want 1 — the mirrored-pool record went with the digest", len(left))
	}
	if left[0].Value != "" {
		t.Errorf("value after clear = %q, want empty — the stale digest survived the remedy", left[0].Value)
	}
	if left[0].Source != "computed" || left[0].ObjectKey != row.ObjectKey {
		t.Errorf("cleared row = %q/%q, want computed/%q — aptMirroredPoolKeys reads both", left[0].Source, left[0].ObjectKey, row.ObjectKey)
	}
}

// TestClearedChecksumKeepsTheMirroredDebOutOfTheIndex is #225, and the
// reproduction the follow-up carried: TestAuditFallbackEntryAdoptsMirroredDeb with
// the documented remedy run in the middle of it. `bodega pkg checksum clear apt
// nginx` used to delete the rows aptMirroredPoolKeys reads, and the cached
// upstream .deb stayed in pool/ under the exact filename the fallback entry
// resolves by, so the next rebuild published it with no SHA256.
//
// The assertion is on the generated Packages, not on the table: the table is
// the mechanism, and a fix that kept rows while losing the serve-path outcome
// would pass a table-level check.
func TestClearedChecksumKeepsTheMirroredDebOutOfTheIndex(t *testing.T) {
	upstreamBytes := "\x21<arch>\nbytes from ports.ubuntu.com, not from the build"
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: upstreamBytes})
	s := mirrorServer(t, archive)

	if err := s.store.AddVersion(t.Context(), manifest.TypeApt, "nginx", manifest.VersionEntry{
		Version:    "1.24.0-2ubuntu7.1",
		SourceName: "nginx",
		Suites:     []string{"local"},
		Metadata:   map[string]string{"Architecture": "amd64"},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Fatalf("mirrored pool fetch failed")
	}

	// The operator chases a 502 and reaches for the documented remedy.
	if _, _, err := s.auditDB.ClearChecksumsByPackage(t.Context(), manifest.TypeApt, "nginx"); err != nil {
		t.Fatalf("clear apt/nginx: %v", err)
	}
	s.aptPool.Store(nil)
	s.rebuildAptSnapshot(t.Context())

	code, body := mirrorGet(t, s, "/apt/dists/local/main/binary-amd64/Packages")
	if code != http.StatusOK {
		t.Fatalf("generated Packages = %d, want 200", code)
	}
	if strings.Contains(string(body), "Filename: "+fixtureDeb) {
		t.Errorf("clearing the checksum republished the cached upstream artifact:\n%s", body)
	}
	if strings.Contains(string(body), "Package: nginx") && !strings.Contains(string(body), "SHA256:") {
		t.Errorf("nginx published with no digest after the clear:\n%s", body)
	}
}

// The case clear is documented for, on the type where the row now survives it:
// an upstream republishes different bytes under a version it already served,
// every fetch answers 502, and clearing the digest is the way out. The row
// staying behind must not turn that remedy into a permanent 502 — a blank value
// takes the first-fetch path and stores what the next fetch computed.
func TestClearedChecksumLetsRepublishedBytesThrough(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)

	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Fatalf("first pool fetch failed")
	}

	// The archive republishes, and the cached object is dropped so the next
	// request goes upstream rather than being served from the pool.
	republished := "\x21<arch>\nrepublished under the same version"
	archive.setObject(fixtureDeb, republished)
	if err := s.typeStore(manifest.TypeApt).Delete(t.Context(), manifest.AptKey(fixtureDeb)); err != nil {
		t.Fatalf("drop cached object: %v", err)
	}
	code, body := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusBadGateway {
		t.Fatalf("republished fetch = %d, want 502 — the stored digest did not catch the change", code)
	}
	inc := bodyIncident(t, string(body), checkChecksum)
	rows, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCache})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	matched := false
	for _, row := range rows {
		matched = matched || (row.Status == audit.CacheChecksumMismatch && strings.Contains(row.Details, `"incident":"`+inc+`"`))
	}
	if !matched {
		t.Errorf("no checksum_mismatch row carries the refusal's incident %s: %+v", inc, rows)
	}
	if strings.Contains(string(body), manifest.AptKey(fixtureDeb)) {
		t.Errorf("the refusal names the storage key: %s", body)
	}

	if _, _, err := s.auditDB.ClearChecksumsByPackage(t.Context(), manifest.TypeApt, "nginx"); err != nil {
		t.Fatalf("clear apt/nginx: %v", err)
	}
	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Fatalf("fetch after clear = %d, want 200 — the remedy no longer clears the mismatch", code)
	}

	stored, err := s.auditDB.GetChecksum(t.Context(), manifest.AptKey(fixtureDeb))
	if err != nil {
		t.Fatalf("GetChecksum: %v", err)
	}
	if stored == nil || stored.Value != fmt.Sprintf("%x", sha256.Sum256([]byte(republished))) {
		t.Errorf("stored digest = %+v, want the republished bytes' — the next fetch recorded nothing to verify against", stored)
	}
	if stored != nil && stored.Source != "computed" {
		t.Errorf("source after re-store = %q, want computed — the mirrored-pool exclusion filters on it", stored.Source)
	}
}

// B75 R6: four mirrored codenames printed four stanzas, and an operator pasting
// the banner into /etc/apt/sources.list.d/bodega.sources gets four sources
// entries where apt wants one. The generated half already collapses its suites
// onto one Suites: line.
func TestBannerCollapsesMirroredCodenamesOntoOneStanza(t *testing.T) {
	s := mirrorServer(t)
	s.cfg.PublicURL = "https://bodega.example.com"
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{
		"resolute":          {{URL: "https://archive.ubuntu.com/ubuntu"}},
		"resolute-updates":  {{URL: "https://archive.ubuntu.com/ubuntu"}},
		"resolute-security": {{URL: "https://security.ubuntu.com/ubuntu"}},
	}

	banner := s.aptSourcesBanner()
	if got := strings.Count(banner, "Suites: resolute"); got != 1 {
		t.Errorf("banner carries %d mirrored stanzas, want 1:\n%s", got, banner)
	}
	if !strings.Contains(banner, "Suites: resolute resolute-security resolute-updates") {
		t.Errorf("the mirrored codenames are not on one Suites: line:\n%s", banner)
	}
	if !strings.Contains(banner, "Components: "+aptsources.MirroredComponents) {
		t.Errorf("banner names components the codename does not serve:\n%s", banner)
	}
}

// Two codenames whose archives publish different component sets cannot share a
// stanza: a stanza carries one Components: line, and apt would request a path
// one of them 404s.
func TestBannerSplitsMirroredCodenamesByComponentSet(t *testing.T) {
	s := mirrorServer(t)
	s.cfg.PublicURL = "https://bodega.example.com"
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{
		"bookworm": {{URL: "https://deb.debian.org/debian", Components: []string{"main", "contrib", "non-free"}}},
		"noble":    {{URL: "https://archive.ubuntu.com/ubuntu", Components: []string{"main", "universe"}}},
	}

	banner := s.aptSourcesBanner()
	if !strings.Contains(banner, "Suites: bookworm\n") || !strings.Contains(banner, "Components: main contrib non-free") {
		t.Errorf("the Debian codename lost its own component set:\n%s", banner)
	}
	if !strings.Contains(banner, "Suites: noble\n") || !strings.Contains(banner, "Components: main universe") {
		t.Errorf("the Ubuntu codename lost its own component set:\n%s", banner)
	}
}

// A codename declaring no components renders MirroredComponents, and one
// declaring exactly those four renders the same line. Grouping on the
// configured spelling put them in two stanzas apt cannot tell apart, and
// reordering one explicit set split it from its own twin.
func TestBannerGroupsMirroredCodenamesOnTheEffectiveComponentSet(t *testing.T) {
	s := mirrorServer(t)
	s.cfg.PublicURL = "https://bodega.example.com"
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{
		"resolute":          {{URL: "https://archive.ubuntu.com/ubuntu"}},
		"resolute-updates":  {{URL: "https://archive.ubuntu.com/ubuntu", Components: []string{"main", "restricted", "universe", "multiverse"}}},
		"resolute-security": {{URL: "https://security.ubuntu.com/ubuntu", Components: []string{"multiverse", "universe", "restricted", "main"}}},
	}

	banner := s.aptSourcesBanner()
	if got := strings.Count(banner, "Components: "+aptsources.MirroredComponents); got != 1 {
		t.Errorf("banner carries %d stanzas with the same Components: line, want 1:\n%s", got, banner)
	}
	if !strings.Contains(banner, "Suites: resolute resolute-security resolute-updates") {
		t.Errorf("equivalent component sets did not share a Suites: line:\n%s", banner)
	}
}

const (
	// debianSSLDevDeb is the path the B176 report names; debianSecuritySSLDevDeb
	// is the one debian-security serves the same build under, a level deeper.
	debianSSLDevDeb         = "pool/main/o/openssl/libssl-dev_3.5.7-1~deb13u3_amd64.deb"
	debianSecuritySSLDevDeb = "pool/updates/main/o/openssl/libssl-dev_3.5.7-1~deb13u3_amd64.deb"
	debianSSLDevBody        = "\x21<arch>\nlibssl-dev bytes"
)

// debianMirrorServer mirrors two archives the way a Debian host's sources
// do, deb.debian.org/debian for trixie and security.debian.org/debian-security
// for trixie-security, with the .deb at debPath on the one that serves it.
func debianMirrorServer(t *testing.T, debPath string, onSecurity bool) (*Server, *fixtureArchive) {
	t.Helper()
	archive := newFixtureArchive(t, map[string]string{})
	security := newFixtureArchive(t, map[string]string{})
	serving := archive
	if onSecurity {
		serving = security
	}
	serving.setObject(debPath, debianSSLDevBody)
	s := mirrorServer(t, archive, security)
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{
		"trixie":          {{URL: archive.URL()}},
		"trixie-security": {{URL: security.URL()}},
	}
	return s, serving
}

// restartedServer is a second Server over s's config, object store and audit
// database: the cache holds what s fetched, and nothing in memory says which
// archive it came from.
func restartedServer(t *testing.T, s *Server) *Server {
	t.Helper()
	s2 := newServer(s.cfg, s.store, s.stores, "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s2.cache = s.cache
	ctx, cancel := context.WithCancel(context.Background())
	go s2.discovery.Start(ctx)
	t.Cleanup(func() {
		cancel()
		_ = s2.auditDB.Close()
	})
	return s2
}

// requireNoPoolRow fails if any discovery row carries name, which is what a
// row keyed on the binary instead of the source would.
func requireNoPoolRow(t *testing.T, s *Server, name string) {
	t.Helper()
	rows, err := s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{})
	if err != nil {
		t.Fatalf("list discovery: %v", err)
	}
	for _, row := range rows {
		if row.PkgName == name {
			t.Errorf("discovery row named %q, the binary: a profile learned from it matches nothing (%+v)", name, row)
		}
	}
}

// B176. Profile membership and the pool gate close over the source package,
// so a discovery row naming the binary proposes a profile entry that matches
// nothing; on Debian that is most libraries. Both layouts are covered because
// debian-security's pool sits under pool/updates/, which is where the nightly's
// libssl-dev came from.
func TestDebianPoolDiscoveryRowsNameTheSource(t *testing.T) {
	for _, tc := range []struct {
		name       string
		debPath    string
		onSecurity bool
	}{
		{"archive", debianSSLDevDeb, false},
		{"security", debianSecuritySSLDevDeb, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, serving := debianMirrorServer(t, tc.debPath, tc.onSecurity)

			if code, body := mirrorGet(t, s, "/apt/"+tc.debPath); code != http.StatusOK || string(body) != debianSSLDevBody {
				t.Fatalf("pool miss = %d body %q, want 200 and the archive's bytes", code, body)
			}
			row := waitForPoolRow(t, s, "openssl", 1)
			if row.PkgVersion != "3.5.7-1~deb13u3" {
				t.Errorf("pkg_version = %q, want the .deb's own", row.PkgVersion)
			}
			if row.UpstreamURL != serving.URL()+"/"+tc.debPath {
				t.Errorf("upstream_url = %q, want the archive that served it", row.UpstreamURL)
			}

			s2 := restartedServer(t, s)
			if code, _ := mirrorGet(t, s2, "/apt/"+tc.debPath); code != http.StatusOK {
				t.Fatalf("pool hit on a restarted server = %d, want 200", code)
			}
			if got := serving.count(tc.debPath); got != 1 {
				t.Fatalf("upstream GETs = %d, want 1: the second request has to be a cache hit", got)
			}
			waitForPoolRow(t, s2, "openssl", 2)
			requireNoPoolRow(t, s2, "libssl-dev")

			// The audit trail records the file a client fetched.
			rows := cacheRows(t, s2)
			if len(rows) == 0 {
				t.Fatal("no cache rows in the audit trail")
			}
			for _, ev := range rows {
				if ev.PkgName != "libssl-dev" {
					t.Errorf("audit %s row pkg_name = %q, want the binary libssl-dev", ev.Status, ev.PkgName)
				}
			}
		})
	}
}

// B176's refusal half: the denied row a profile writes, and the hint it
// carries, name what `bodega profile add` has to list for the gate to pass.
func TestDebianPoolRefusalProposesTheSource(t *testing.T) {
	for _, tc := range []struct {
		name       string
		debPath    string
		onSecurity bool
	}{
		{"archive", debianSSLDevDeb, false},
		{"security", debianSecuritySSLDevDeb, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, serving := debianMirrorServer(t, tc.debPath, tc.onSecurity)
			f := bindProfile(t, s, "web", "web-host",
				[]audit.ProfileTypeRule{closedRule(manifest.TypeApt, audit.VersionFloating, audit.ExpansionBlock)},
				[]audit.ProfileEntry{{Type: manifest.TypeApt, Name: "curl"}})

			if code, body := f.get(t, "/apt/"+tc.debPath); code != http.StatusForbidden {
				t.Fatalf("pool fetch outside the profile = %d, want 403:\n%s", code, body)
			}
			if got := serving.count(tc.debPath); got != 0 {
				t.Errorf("upstream GETs = %d, want 0", got)
			}
			rows := waitForAptRows(t, s, audit.DecisionDenied, 1)
			if len(rows) != 1 || rows[0].PkgName != "openssl" {
				t.Fatalf("denied rows = %+v, want one named openssl", rows)
			}
			if want := "bodega profile add web apt openssl"; rows[0].PatternHint != want {
				t.Errorf("hint = %q, want %q", rows[0].PatternHint, want)
			}

			// Listing what the hint proposed is what admits the fetch.
			f = bindProfile(t, s, "web2", "web2-host",
				[]audit.ProfileTypeRule{closedRule(manifest.TypeApt, audit.VersionFloating, audit.ExpansionBlock)},
				[]audit.ProfileEntry{{Type: manifest.TypeApt, Name: "openssl"}})
			if code, body := f.get(t, "/apt/"+tc.debPath); code != http.StatusOK {
				t.Fatalf("pool fetch after listing openssl = %d, want 200:\n%s", code, body)
			}
		})
	}
}

// A generated suite lays its pool out under the binary name, so the path's
// segment four is the binary and the row keeps it: libexpat1, not expat.
func TestGeneratedPoolRefusalKeepsTheBinaryName(t *testing.T) {
	s := generatedSuiteServer(t)
	const deb = "pool/main/l/libexpat1/libexpat1_2.7.1-2_amd64.deb"
	body := "\x21<arch>\nlibexpat1 bytes"
	sum := sha256.Sum256([]byte(body))
	if err := s.store.AddVersion(t.Context(), manifest.TypeApt, "libexpat1", manifest.VersionEntry{
		Version:       "2.7.1-2",
		SourceName:    "libexpat1",
		SourcePackage: "expat",
		ArtifactSize:  int64(len(body)),
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   deb,
			"_sha256":      hex.EncodeToString(sum[:]),
		},
	}); err != nil {
		t.Fatalf("add libexpat1: %v", err)
	}
	pool, ok := s.stores.ForType(manifest.TypeApt).(*storage.Memory)
	if !ok {
		t.Fatal("the apt object store is not the in-memory one")
	}
	pool.Seed(manifest.AptKey(deb), body)
	if err := s.store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("save index: %v", err)
	}
	f := generatedSuiteBind(t, s, "web", "curl")

	if code, out := f.get(t, "/apt/"+deb); code != http.StatusForbidden {
		t.Fatalf("pool fetch outside the profile = %d, want 403:\n%s", code, out)
	}
	rows := waitForAptRows(t, s, audit.DecisionDenied, 1)
	if len(rows) != 1 || rows[0].PkgName != "libexpat1" {
		t.Fatalf("denied rows = %+v, want one named libexpat1", rows)
	}
	if want := "bodega profile add web apt libexpat1"; rows[0].PatternHint != want {
		t.Errorf("hint = %q, want %q", rows[0].PatternHint, want)
	}
}

// The age gate on mirrored apt dates a source version by the Release of the
// first index bodega read that lists it. These fixtures publish php8.5-fpm
// builds under the fixture codename, one index at a time.
const (
	ageDebOld    = "pool/universe/p/php8.5/php8.5-fpm_8.5.4-0ubuntu1_amd64.deb"
	ageDebNew    = "pool/universe/p/php8.5/php8.5-fpm_8.5.4-0ubuntu2_amd64.deb"
	ageDebSeed   = "pool/universe/p/php8.5/php8.5-fpm_8.5.3-0ubuntu1_amd64.deb"
	ageDebLatest = "pool/universe/p/php8.5/php8.5-fpm_8.5.4-0ubuntu3_amd64.deb"
)

func ageDeb(pool, version string) mirrorOSVDeb {
	return mirrorOSVDeb{pool, "php8.5-fpm", "php8.5", version, "deb " + version}
}

// publishAptIndex has the archive serve one index for the fixture codename,
// its Release dated generated, and has bodega read it as its next rebuild
// would: the cached Release and Packages and the pool index are dropped first.
func publishAptIndex(t *testing.T, s *Server, archive *fixtureArchive, generated time.Time, debs ...mirrorOSVDeb) {
	t.Helper()
	for rel, body := range mirrorOSVDists(mirroredCodename, debs...) {
		if strings.HasSuffix(rel, "/Release") {
			body = strings.Replace(body, "Codename: ", "Date: "+generated.UTC().Format(time.RFC1123)+"\nCodename: ", 1)
		}
		archive.setObject(rel, body)
	}
	s.aptUpstreamIdx.Clear()
	s.aptPoolIdx.mu.Lock()
	s.aptPoolIdx.idx = nil
	s.aptPoolIdx.mu.Unlock()
	if idx := s.buildAptPoolIndex(t.Context(), s.cfg.MirroredAptCodenames()); len(idx.failed) > 0 {
		t.Fatalf("read the fixture index: %v", idx.failed)
	}
}

func ageMirrorServer(t *testing.T) (*Server, *fixtureArchive) {
	t.Helper()
	archive := newFixtureArchive(t, map[string]string{})
	return mirrorServer(t, archive), archive
}

func aptDateOf(t *testing.T, s *Server, version string) audit.AptVersionDate {
	t.Helper()
	d, ok, err := s.auditDB.GetAptVersionDate(t.Context(), "php8.5", version)
	if err != nil || !ok {
		t.Fatalf("no date recorded for php8.5 %s (ok=%v, err=%v)", version, ok, err)
	}
	return d
}

func setAptAge(t *testing.T, s *Server, action string) {
	t.Helper()
	if err := s.auditDB.SetAgePolicy(t.Context(), audit.AgePolicy{Ecosystem: manifest.TypeApt,
		MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: action}); err != nil {
		t.Fatalf("set age policy: %v", err)
	}
}

// ageChecksFor is the age entry of every admission row for php8.5-fpm@version.
func ageChecksFor(t *testing.T, s *Server, version string) []audit.AdmissionCheck {
	t.Helper()
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeApt, PkgName: "php8.5-fpm", PkgVersion: version})
	if err != nil {
		t.Fatalf("Admissions: %v", err)
	}
	var out []audit.AdmissionCheck
	for _, r := range rows {
		for _, c := range r.Checks {
			if c.Check == audit.CheckAge {
				out = append(out, c)
			}
		}
	}
	return out
}

func lastAgeCheck(t *testing.T, s *Server, version string) audit.AdmissionCheck {
	t.Helper()
	checks := ageChecksFor(t, s, version)
	if len(checks) == 0 {
		t.Fatalf("no admission row for php8.5-fpm@%s carries an age check", version)
	}
	return checks[len(checks)-1]
}

// TestAptVersionDatesKeepTheFirstIndexThatListedThem is F112 requirement 1.
func TestAptVersionDatesKeepTheFirstIndexThatListedThem(t *testing.T) {
	s, archive := ageMirrorServer(t)
	first := time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	second := time.Date(2026, 11, 8, 6, 0, 0, 0, time.UTC)

	publishAptIndex(t, s, archive, first, ageDeb(ageDebSeed, "8.5.3-0ubuntu1"), ageDeb(ageDebOld, "8.5.4-0ubuntu1"))
	publishAptIndex(t, s, archive, second, ageDeb(ageDebOld, "8.5.4-0ubuntu1"), ageDeb(ageDebNew, "8.5.4-0ubuntu2"))

	if d := aptDateOf(t, s, "8.5.3-0ubuntu1"); d.DatedBy != audit.AptDatedByPredates || d.Codename != mirroredCodename {
		t.Errorf("a version only the first index listed = %+v, want predating %s", d, mirroredCodename)
	}
	if d := aptDateOf(t, s, "8.5.4-0ubuntu1"); d.DatedBy != audit.AptDatedByPredates || !d.PublishedAt.IsZero() {
		t.Errorf("a version both indexes listed = %+v, want the first index's record kept: predating, not dated by the second Release", d)
	}
	if d := aptDateOf(t, s, "8.5.4-0ubuntu2"); d.DatedBy != audit.AptDatedByRelease || !d.PublishedAt.Equal(second) {
		t.Errorf("a version new in the second index = %+v, want dated by the second Release's Date: %s", d, second)
	}

	// The records are the audit database's, not the pool index's: a third
	// index dropping a version and a restarted server both leave them alone.
	publishAptIndex(t, s, archive, second.Add(24*time.Hour), ageDeb(ageDebNew, "8.5.4-0ubuntu2"))
	reopened, err := audit.Open(s.cfg.AuditDB)
	if err != nil {
		t.Fatalf("reopen the audit db: %v", err)
	}
	defer reopened.Close()
	if d, ok, err := reopened.GetAptVersionDate(t.Context(), "php8.5", "8.5.4-0ubuntu2"); err != nil || !ok || !d.PublishedAt.Equal(second) {
		t.Errorf("after a third index and a reopen = %+v ok=%v err=%v, want the second Release's date", d, ok, err)
	}
	if _, ok, _ := reopened.GetAptVersionDate(t.Context(), "php8.5", "8.5.3-0ubuntu1"); !ok {
		t.Error("a version the latest index no longer lists lost its record")
	}
}

// TestAptMirrorAgeBlockRefusesTheNewVersionAndServesTheOld is F112
// requirement 2, through the pool route.
func TestAptMirrorAgeBlockRefusesTheNewVersionAndServesTheOld(t *testing.T) {
	s, archive := ageMirrorServer(t)
	setAptAge(t, s, policy.ActionBlock)
	now := time.Now().UTC().Truncate(time.Second)
	old, fresh := now.Add(-30*24*time.Hour), now.Add(-time.Hour)

	publishAptIndex(t, s, archive, old.Add(-24*time.Hour), ageDeb(ageDebSeed, "8.5.3-0ubuntu1"))
	publishAptIndex(t, s, archive, old, ageDeb(ageDebOld, "8.5.4-0ubuntu1"))
	publishAptIndex(t, s, archive, fresh, ageDeb(ageDebSeed, "8.5.3-0ubuntu1"), ageDeb(ageDebOld, "8.5.4-0ubuntu1"), ageDeb(ageDebNew, "8.5.4-0ubuntu2"))
	archive.setObject(ageDebLatest, "unlisted deb")

	code, body := mirrorOSVGet(t, s, ageDebNew)
	if code != http.StatusForbidden || !strings.Contains(body, "age") {
		t.Fatalf("a version an hour old under 7d block = %d %q, want a 403 age refusal", code, body)
	}
	if archive.count(ageDebNew) != 0 {
		t.Error("the refused .deb was fetched from the archive")
	}
	wantNew := "dated by the Release of " + mirroredCodename + " generated " + fresh.Format(time.RFC3339)
	if c := lastAgeCheck(t, s, "8.5.4-0ubuntu2"); c.Status != audit.CheckBlock || !strings.HasSuffix(c.Detail, wantNew) {
		t.Errorf("age check = %+v, want a block ending %q", c, wantNew)
	}

	if code, body := mirrorOSVGet(t, s, ageDebOld); code != http.StatusOK || body != "deb 8.5.4-0ubuntu1" {
		t.Fatalf("a version 30 days old = %d %q, want 200 and the archive's bytes", code, body)
	}
	wantOld := "dated by the Release of " + mirroredCodename + " generated " + old.Format(time.RFC3339)
	if c := lastAgeCheck(t, s, "8.5.4-0ubuntu1"); c.Status != audit.CheckPass || !strings.HasSuffix(c.Detail, wantOld) {
		t.Errorf("age check = %+v, want a pass ending %q", c, wantOld)
	}

	if code, _ := mirrorOSVGet(t, s, ageDebSeed); code != http.StatusOK {
		t.Fatalf("a version the first index listed = %d, want 200", code)
	}
	if c := lastAgeCheck(t, s, "8.5.3-0ubuntu1"); c.Status != audit.CheckPass || !strings.HasSuffix(c.Detail, "listed before bodega first read "+mirroredCodename) {
		t.Errorf("age check = %+v, want a pass naming the first read", c)
	}

	// No paragraph lists it, so no record dates it: served, never warn or block.
	if code, _ := mirrorOSVGet(t, s, ageDebLatest); code != http.StatusOK {
		t.Fatalf("an undated version = %d, want 200", code)
	}
	if c := lastAgeCheck(t, s, "8.5.4-0ubuntu3"); c.Status != audit.CheckNotEvaluated || !strings.Contains(c.Detail, "no Packages paragraph") {
		t.Errorf("age check = %+v, want not evaluated with the reason", c)
	}
}

// TestAptMirrorAgeCachedDebTakesItsFillsVerdict is F112 requirement 3: the
// hit neither re-judges the version nor reads the index to do it.
func TestAptMirrorAgeCachedDebTakesItsFillsVerdict(t *testing.T) {
	s, archive := ageMirrorServer(t)
	setAptAge(t, s, policy.ActionWarn)
	now := time.Now().UTC().Truncate(time.Second)
	publishAptIndex(t, s, archive, now.Add(-48*time.Hour), ageDeb(ageDebSeed, "8.5.3-0ubuntu1"))
	publishAptIndex(t, s, archive, now.Add(-time.Hour), ageDeb(ageDebNew, "8.5.4-0ubuntu2"))

	if code, _ := mirrorOSVGet(t, s, ageDebNew); code != http.StatusOK {
		t.Fatalf("a new version under warn = %d, want 200", code)
	}
	if c := lastAgeCheck(t, s, "8.5.4-0ubuntu2"); c.Status != audit.CheckWarn {
		t.Fatalf("the fill's age check = %+v, want warn", c)
	}

	setAptAge(t, s, policy.ActionBlock)
	s.aptUpstreamIdx.Clear()
	s.aptPoolIdx.mu.Lock()
	s.aptPoolIdx.idx = nil
	s.aptPoolIdx.mu.Unlock()
	release := "dists/" + mirroredCodename + "/Release"
	reads, checks := archive.count(release), len(ageChecksFor(t, s, "8.5.4-0ubuntu2"))

	if code, body := mirrorOSVGet(t, s, ageDebNew); code != http.StatusOK || body != "deb 8.5.4-0ubuntu2" {
		t.Fatalf("the cached .deb = %d %q, want 200: its fill admitted it", code, body)
	}
	if got := archive.count(release); got != reads {
		t.Errorf("Release reads = %d after the hit, want %d: a hit read the index", got, reads)
	}
	if got := len(ageChecksFor(t, s, "8.5.4-0ubuntu2")); got != checks {
		t.Errorf("age checks = %d after the hit, want %d: the hit re-judged the version", got, checks)
	}
	if archive.count(ageDebNew) != 1 {
		t.Errorf("the .deb was fetched %d times, want once", archive.count(ageDebNew))
	}
}

func TestReviewF112ProfileIndexReadsRecordVersionDates(t *testing.T) {
	s, archive := aptProfileServer(t)
	setAptAge(t, s, policy.ActionBlock)
	now := time.Now().UTC().Truncate(time.Second)
	publish := func(date time.Time, debs ...mirrorOSVDeb) {
		for rel, body := range mirrorOSVDists(mirroredCodename, debs...) {
			if strings.HasSuffix(rel, "/Release") {
				body = "Date: " + date.Format(time.RFC1123) + "\n" + body
			}
			archive.setObject(rel, body)
		}
		s.aptUpstreamIdx.Clear()
	}
	publish(now.Add(-30*24*time.Hour), ageDeb(ageDebSeed, "8.5.3-0ubuntu1"))
	f := aptProfileBind(t, s, "web", audit.ExpansionBlock, "php8.5")
	if archive.count("dists/fixture/universe/binary-amd64/Packages.gz") == 0 {
		t.Fatal("profile rebuild did not read the mirrored Packages")
	}
	if d, ok, err := s.auditDB.GetAptVersionDate(t.Context(), "php8.5", "8.5.3-0ubuntu1"); err != nil || !ok || d.DatedBy != audit.AptDatedByPredates {
		t.Errorf("first profile read: record=%+v ok=%v err=%v; want a predating record", d, ok, err)
	}
	fresh := now.Add(-time.Hour)
	publish(fresh, ageDeb(ageDebSeed, "8.5.3-0ubuntu1"), ageDeb(ageDebNew, "8.5.4-0ubuntu2"))
	s.rebuildAptSnapshot(t.Context())
	if d, ok, err := s.auditDB.GetAptVersionDate(t.Context(), "php8.5", "8.5.4-0ubuntu2"); err != nil || !ok || d.DatedBy != audit.AptDatedByRelease || !d.PublishedAt.Equal(fresh) {
		t.Errorf("second profile read: record=%+v ok=%v err=%v; want Release date %s", d, ok, err, fresh)
	}
	if code, body := f.get(t, "/apt/"+ageDebNew); code != http.StatusForbidden {
		t.Errorf("new version after two profile index reads = %d %q; want 403 under 7d block", code, body)
	}
}

func TestReviewF112MirroredDistsReadsRecordVersionDates(t *testing.T) {
	s, archive := ageMirrorServer(t)
	s.cache.MetadataTTL = time.Nanosecond
	setAptAge(t, s, policy.ActionBlock)
	now := time.Now().UTC().Truncate(time.Second)
	for i, version := range []string{"8.5.3-0ubuntu1", "8.5.4-0ubuntu2"} {
		pool := ageDebSeed
		if i == 1 {
			pool = ageDebNew
		}
		date := now.Add(-time.Duration(24-i*23) * time.Hour)
		for rel, body := range mirrorOSVDists(mirroredCodename, ageDeb(pool, version)) {
			if strings.HasSuffix(rel, "/Release") {
				body = "Date: " + date.Format(time.RFC1123) + "\n" + body
			}
			archive.setObject(rel, body)
		}
		for _, rest := range []string{"Release", "universe/binary-amd64/Packages.gz"} {
			if code, _ := mirrorGet(t, s, "/apt/dists/fixture/"+rest); code != http.StatusOK {
				t.Fatalf("read %s = %d; want 200", rest, code)
			}
		}
		d, ok, err := s.auditDB.GetAptVersionDate(t.Context(), "php8.5", version)
		if err != nil || !ok {
			t.Errorf("mirrored dists read %d: date record ok=%v err=%v; want a record for %s", i+1, ok, err, version)
		} else if i == 0 && d.DatedBy != audit.AptDatedByPredates {
			t.Errorf("first read = %+v; want predating", d)
		} else if i == 1 && (d.DatedBy != audit.AptDatedByRelease || !d.PublishedAt.Equal(date)) {
			t.Errorf("second read = %+v; want Release date %s", d, date)
		}
	}
	if code, body := mirrorOSVGet(t, s, ageDebNew); code != http.StatusForbidden {
		t.Errorf("new version after two mirrored dists reads = %d %q; want 403 under 7d block", code, body)
	}
}

func TestReviewF112PartialReadDoesNotGrandfatherLaterVersion(t *testing.T) {
	s, archive := ageMirrorServer(t)
	setAptAge(t, s, policy.ActionBlock)
	now := time.Now().UTC().Truncate(time.Second)
	broken := "not a gzip file"
	sum := sha256.Sum256([]byte(broken))
	for rel, body := range mirrorOSVDists(mirroredCodename, ageDeb(ageDebSeed, "8.5.3-0ubuntu1")) {
		if strings.HasSuffix(rel, "/Release") {
			body = "Date: " + now.Add(-24*time.Hour).Format(time.RFC1123) + "\n" + body
			body = strings.Replace(body, "Components: universe", "Components: universe main", 1)
			body += fmt.Sprintf(" %x %d main/binary-amd64/Packages.gz\n", sum, len(broken))
		}
		archive.setObject(rel, body)
	}
	archive.setObject("dists/fixture/main/binary-amd64/Packages.gz", broken)
	idx := s.buildAptPoolIndex(t.Context(), s.cfg.MirroredAptCodenames())
	if len(idx.failed) == 0 {
		t.Fatal("fixture must fail after reading universe")
	}
	if d := aptDateOf(t, s, "8.5.3-0ubuntu1"); d.DatedBy != audit.AptDatedByPredates {
		t.Fatalf("first read's version = %+v; want predating", d)
	}
	fresh := now.Add(-time.Hour)
	publishAptIndex(t, s, archive, fresh, ageDeb(ageDebSeed, "8.5.3-0ubuntu1"), ageDeb(ageDebNew, "8.5.4-0ubuntu2"))
	if d := aptDateOf(t, s, "8.5.4-0ubuntu2"); d.DatedBy != audit.AptDatedByRelease || !d.PublishedAt.Equal(fresh) {
		t.Errorf("version added after the first read = %+v; want Release date %s", d, fresh)
	}
	if code, body := mirrorOSVGet(t, s, ageDebNew); code != http.StatusForbidden {
		t.Errorf("new version after partial first read = %d %q; want 403 under 7d block", code, body)
	}
}

func TestReviewF112RemovedVersionUsesPersistedDate(t *testing.T) {
	s, archive := ageMirrorServer(t)
	setAptAge(t, s, policy.ActionBlock)
	now := time.Now().UTC().Truncate(time.Second)
	publishAptIndex(t, s, archive, now.Add(-24*time.Hour), ageDeb(ageDebSeed, "8.5.3-0ubuntu1"))
	fresh := now.Add(-time.Hour)
	publishAptIndex(t, s, archive, fresh, ageDeb(ageDebNew, "8.5.4-0ubuntu2"))
	publishAptIndex(t, s, archive, now, ageDeb(ageDebLatest, "8.5.4-0ubuntu3"))
	if d := aptDateOf(t, s, "8.5.4-0ubuntu2"); d.DatedBy != audit.AptDatedByRelease || !d.PublishedAt.Equal(fresh) {
		t.Fatalf("fixture lost its known date: %+v", d)
	}
	if code, body := mirrorOSVGet(t, s, ageDebNew); code != http.StatusForbidden {
		t.Errorf("known young version removed from the latest index = %d %q; want 403 under 7d block", code, body)
	}
	if c := lastAgeCheck(t, s, "8.5.4-0ubuntu2"); c.Status != audit.CheckBlock {
		t.Errorf("persisted version's age check = %+v; want block", c)
	}
}

func TestReviewF112ByHashDatesTheIndexActuallyServed(t *testing.T) {
	s, archive := ageMirrorServer(t)
	setAptAge(t, s, policy.ActionBlock)
	now := time.Now().UTC().Truncate(time.Second)
	objects := mirrorOSVDists(mirroredCodename, ageDeb(ageDebSeed, "8.5.3-0ubuntu1"))
	oldBody := objects["dists/fixture/universe/binary-amd64/Packages.gz"]
	sum := sha256.Sum256([]byte(oldBody))
	byHash := fmt.Sprintf("dists/fixture/universe/binary-amd64/by-hash/SHA256/%x", sum)
	for rel, body := range objects {
		if strings.HasSuffix(rel, "/Release") {
			body = "Date: " + now.Add(-24*time.Hour).Format(time.RFC1123) + "\n" + body
		}
		archive.setObject(rel, body)
	}
	archive.setObject(byHash, oldBody)
	if code, _ := mirrorGet(t, s, "/apt/dists/fixture/Release"); code != http.StatusOK {
		t.Fatalf("first Release = %d", code)
	}
	// The archive rotates after apt fetched Release; by-hash still serves its index.
	for rel, body := range mirrorOSVDists(mirroredCodename, ageDeb(ageDebNew, "8.5.4-0ubuntu2")) {
		if strings.HasSuffix(rel, "/Release") {
			body = "Date: " + now.Add(-time.Hour).Format(time.RFC1123) + "\n" + body
		}
		archive.setObject(rel, body)
	}
	if code, body := mirrorGet(t, s, "/apt/"+byHash); code != http.StatusOK || string(body) != oldBody {
		t.Fatalf("by-hash = %d; want the old index's exact bytes", code)
	}
	if d, ok, err := s.auditDB.GetAptVersionDate(t.Context(), "php8.5", "8.5.3-0ubuntu1"); err != nil || !ok || d.DatedBy != audit.AptDatedByPredates {
		t.Errorf("served first index's version = %+v ok=%v err=%v; want predating", d, ok, err)
	}
	if code, body := mirrorOSVGet(t, s, ageDebNew); code != http.StatusForbidden {
		t.Errorf("version only in the later index = %d %q; want 403 under 7d block", code, body)
	}
	if d := aptDateOf(t, s, "8.5.4-0ubuntu2"); d.DatedBy != audit.AptDatedByRelease {
		t.Errorf("later index's version = %+v; want Release dated", d)
	}
}

func TestReviewF112LaterArchitectureCannotGrandfatherNewSource(t *testing.T) {
	s, archive := ageMirrorServer(t)
	setAptAge(t, s, policy.ActionBlock)
	s.cache.MetadataTTL = time.Nanosecond
	now := time.Now().UTC().Truncate(time.Second)
	publish := func(date time.Time, version string) {
		release := "Date: " + date.Format(time.RFC1123) + "\nCodename: fixture\nComponents: universe\nArchitectures: amd64 arm64\nSHA256:\n"
		for _, arch := range []string{"amd64", "arm64"} {
			pool := "pool/universe/p/php8.5/php8.5-fpm_" + version + "_" + arch + ".deb"
			body := fmt.Sprintf("Package: php8.5-fpm\nSource: php8.5\nVersion: %s\nArchitecture: %s\nFilename: %s\n\n", version, arch, pool)
			gz := gzipFixture(body)
			sum := sha256.Sum256(gz)
			rest := "universe/binary-" + arch + "/Packages.gz"
			release += fmt.Sprintf(" %x %d %s\n", sum, len(gz), rest)
			archive.setObject("dists/fixture/"+rest, string(gz))
			archive.setObject(pool, "deb "+version)
		}
		archive.setObject("dists/fixture/Release", release)
	}
	publish(now.Add(-24*time.Hour), "8.5.3-0ubuntu1")
	if code, _ := mirrorGet(t, s, "/apt/dists/fixture/universe/binary-amd64/Packages.gz"); code != http.StatusOK {
		t.Fatalf("first amd64 index = %d", code)
	}
	if d := aptDateOf(t, s, "8.5.3-0ubuntu1"); d.DatedBy != audit.AptDatedByPredates {
		t.Fatalf("first version = %+v; want predating", d)
	}
	fresh := now.Add(-time.Hour)
	publish(fresh, "8.5.4-0ubuntu2")
	for _, arch := range []string{"arm64", "amd64"} {
		if code, _ := mirrorGet(t, s, "/apt/dists/fixture/universe/binary-"+arch+"/Packages.gz"); code != http.StatusOK {
			t.Fatalf("second %s index = %d", arch, code)
		}
	}
	if d := aptDateOf(t, s, "8.5.4-0ubuntu2"); d.DatedBy != audit.AptDatedByRelease || !d.PublishedAt.Equal(fresh) {
		t.Errorf("source added after the codename's first read = %+v; want Release date %s", d, fresh)
	}
	if code, body := mirrorOSVGet(t, s, ageDebNew); code != http.StatusForbidden {
		t.Errorf("new amd64 build after arm64's first read = %d %q; want 403 under 7d block", code, body)
	}
}

// A version only an architecture nobody read listed when bodega found the
// codename still predates bodega: the first Release's copy of that index is
// read by hash before a later copy dates anything in it.
func TestAptVersionDatesBackfillTheFirstReleasesUnreadIndex(t *testing.T) {
	s, archive := ageMirrorServer(t)
	s.cache.MetadataTTL = time.Nanosecond
	now := time.Now().UTC().Truncate(time.Second)
	publish := func(date time.Time, versions map[string]string) {
		release := "Date: " + date.Format(time.RFC1123) + "\nCodename: fixture\nComponents: universe\nArchitectures: amd64 arm64\nSHA256:\n"
		for _, arch := range []string{"amd64", "arm64"} {
			body := ""
			if v := versions[arch]; v != "" {
				body = fmt.Sprintf("Package: php8.5-fpm\nSource: php8.5\nVersion: %s\nArchitecture: %s\nFilename: pool/universe/p/php8.5/php8.5-fpm_%s_%s.deb\n\n", v, arch, v, arch)
			}
			gz := gzipFixture(body)
			sum := sha256.Sum256(gz)
			rest := "universe/binary-" + arch + "/Packages.gz"
			release += fmt.Sprintf(" %x %d %s\n", sum, len(gz), rest)
			archive.setObject("dists/fixture/"+rest, string(gz))
			archive.setObject(fmt.Sprintf("dists/fixture/universe/binary-%s/by-hash/SHA256/%x", arch, sum), string(gz))
		}
		archive.setObject("dists/fixture/Release", release)
	}
	publish(now.Add(-24*time.Hour), map[string]string{"arm64": "8.5.3-0ubuntu1"})
	if code, _ := mirrorGet(t, s, "/apt/dists/fixture/universe/binary-amd64/Packages.gz"); code != http.StatusOK {
		t.Fatalf("first amd64 index = %d", code)
	}
	fresh := now.Add(-time.Hour)
	publish(fresh, map[string]string{"arm64": "8.5.4-0ubuntu2"})
	if code, _ := mirrorGet(t, s, "/apt/dists/fixture/universe/binary-arm64/Packages.gz"); code != http.StatusOK {
		t.Fatalf("second arm64 index = %d", code)
	}
	if d := aptDateOf(t, s, "8.5.3-0ubuntu1"); d.DatedBy != audit.AptDatedByPredates {
		t.Errorf("a version the first Release's unread arm64 index listed = %+v, want predating", d)
	}
	if d := aptDateOf(t, s, "8.5.4-0ubuntu2"); d.DatedBy != audit.AptDatedByRelease || !d.PublishedAt.Equal(fresh) {
		t.Errorf("a version the later arm64 index added = %+v, want Release date %s", d, fresh)
	}
}

// An InRelease a client fetches records its Release like a plain one.
func TestAptClearsignedBodyReadsInRelease(t *testing.T) {
	in := "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nDate: Sun, 08 Nov 2026 06:00:00 UTC\nCodename: fixture\nSHA256:\n abc 1 universe/binary-amd64/Packages.gz\n-----BEGIN PGP SIGNATURE-----\n\nsig\n-----END PGP SIGNATURE-----\n"
	release, err := deb822.ParseSingle(aptClearsignedBody([]byte(in)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, err := aptReleaseDate(release); err != nil || !got.Equal(time.Date(2026, 11, 8, 6, 0, 0, 0, time.UTC)) {
		t.Errorf("Date = %v %v", got, err)
	}
	if got := aptReleaseDigests(release)["universe/binary-amd64/Packages.gz"]; got != "abc" {
		t.Errorf("digest = %q, want abc", got)
	}
	if plain := []byte("Codename: x\n"); string(aptClearsignedBody(plain)) != string(plain) {
		t.Error("a plain Release was rewritten")
	}
}

func TestReviewF112BackgroundRefreshRecordsTheIndexItReads(t *testing.T) {
	s, archive := ageMirrorServer(t)
	setAptAge(t, s, policy.ActionBlock)
	s.cache.MetadataTTL = time.Nanosecond
	now := time.Now().UTC().Truncate(time.Second)
	publish := func(date time.Time, deb mirrorOSVDeb) map[string]string {
		objects := mirrorOSVDists(mirroredCodename, deb)
		for rel, body := range objects {
			if strings.HasSuffix(rel, "/Release") {
				body = "Date: " + date.Format(time.RFC1123) + "\n" + body
				objects[rel] = body
			}
			archive.setObject(rel, body)
		}
		return objects
	}
	get := func(rest string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/apt/dists/fixture/"+rest, nil)
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d %s", rest, w.Code, w.Body.String())
		}
		return w
	}
	const rest = "universe/binary-amd64/Packages.gz"
	first := publish(now.Add(-24*time.Hour), ageDeb(ageDebSeed, "8.5.3-0ubuntu1"))
	get("Release")
	get(rest)
	if d := aptDateOf(t, s, "8.5.3-0ubuntu1"); d.DatedBy != audit.AptDatedByPredates {
		t.Fatalf("first version = %+v; want predating", d)
	}
	fresh := now.Add(-time.Hour)
	second := publish(fresh, ageDeb(ageDebNew, "8.5.4-0ubuntu2"))
	get("Release")
	s.cache.StaleGrace = time.Millisecond
	release := archive.hold(t)
	w := get(rest)
	release()
	if w.Body.String() != first["dists/fixture/"+rest] {
		t.Fatal("the request did not take the stale response path")
	}
	store := s.typeStore(manifest.TypeApt).(*storage.Memory)
	key := manifest.AptKey("dists/fixture/" + rest)
	waitFor(t, func() bool { return cachedBody(t, store, key) == second["dists/fixture/"+rest] })
	waitFor(t, refreshIdle(s, key))
	if d, ok, err := s.auditDB.GetAptVersionDate(t.Context(), "php8.5", "8.5.4-0ubuntu2"); err != nil || !ok || d.DatedBy != audit.AptDatedByRelease || !d.PublishedAt.Equal(fresh) {
		t.Errorf("completed background index read: record=%+v ok=%v err=%v; want Release date %s", d, ok, err, fresh)
	}
	// Rotation must not erase a version the completed refresh already read.
	publishAptIndex(t, s, archive, now, ageDeb(ageDebLatest, "8.5.4-0ubuntu3"))
	if code, body := mirrorOSVGet(t, s, ageDebNew); code != http.StatusForbidden {
		t.Errorf("young version read by the refresh, then rotated out = %d %q; want 403 under 7d block", code, body)
	}
	if c := lastAgeCheck(t, s, "8.5.4-0ubuntu2"); c.Status != audit.CheckBlock {
		t.Errorf("age admission = %+v; want block", c)
	}
}

type reviewF112ShortWriter struct {
	*httptest.ResponseRecorder
	remaining int
}

func (w *reviewF112ShortWriter) Write(p []byte) (int, error) {
	n := min(len(p), w.remaining)
	w.remaining -= n
	_, _ = w.ResponseRecorder.Write(p[:n])
	return n, io.ErrClosedPipe
}

func TestReviewF112IncompleteDeliveryCannotSetInitialRelease(t *testing.T) {
	s, archive := ageMirrorServer(t)
	setAptAge(t, s, policy.ActionBlock)
	now := time.Now().UTC().Truncate(time.Second)
	dateLine := "Date: " + now.Add(-time.Hour).Format(time.RFC1123) + "\n"
	objects := mirrorOSVDists(mirroredCodename, ageDeb(ageDebSeed, "8.5.3-0ubuntu1"))
	for rel, body := range objects {
		if strings.HasSuffix(rel, "/Release") {
			body = dateLine + body
			objects[rel] = body
		}
		archive.setObject(rel, body)
	}
	w := &reviewF112ShortWriter{ResponseRecorder: httptest.NewRecorder(), remaining: len(dateLine)}
	r := httptest.NewRequest(http.MethodGet, "/apt/dists/fixture/Release", nil)
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != dateLine {
		t.Fatalf("partial response = %d %q; want only the Date line", w.Code, w.Body.String())
	}
	store := s.typeStore(manifest.TypeApt).(*storage.Memory)
	if got := cachedBody(t, store, manifest.AptKey("dists/fixture/Release")); got != objects["dists/fixture/Release"] {
		t.Fatal("the proxy did not finish reading and caching the full Release")
	}
	const rest = "universe/binary-amd64/Packages.gz"
	sum := sha256.Sum256([]byte(objects["dists/fixture/"+rest]))
	if snap, ok, err := s.auditDB.LookupAptIndex(t.Context(), mirroredCodename, fmt.Sprintf("%x", sum)); err != nil || !ok || !snap.Initial {
		t.Errorf("completed first Release: snapshot=%+v ok=%v err=%v; want initial=true", snap, ok, err)
	}
	if code, _ := mirrorGet(t, s, "/apt/dists/fixture/"+rest); code != http.StatusOK {
		t.Fatalf("first Packages = %d; want 200", code)
	}
	if d := aptDateOf(t, s, "8.5.3-0ubuntu1"); d.DatedBy != audit.AptDatedByPredates {
		t.Errorf("first index version = %+v; want predating", d)
	}
	if code, body := mirrorOSVGet(t, s, ageDebSeed); code != http.StatusOK {
		t.Errorf("first index's version under 7d block = %d %q; want 200", code, body)
	}
	if c := lastAgeCheck(t, s, "8.5.3-0ubuntu1"); c.Status != audit.CheckPass || !strings.HasSuffix(c.Detail, "listed before bodega first read "+mirroredCodename) {
		t.Errorf("age admission = %+v; want pass naming the initial read", c)
	}
}

type reviewF112ObservedShortWriter struct {
	*httptest.ResponseRecorder
	offered bytes.Buffer
}

func (w *reviewF112ObservedShortWriter) Write(p []byte) (int, error) {
	_, _ = w.offered.Write(p)
	return 0, io.ErrClosedPipe
}

func TestReviewF112CompletedReadsSurviveResponseChoice(t *testing.T) {
	for _, mode := range []string{"head-fetch", "cached-disconnect"} {
		t.Run(mode, func(t *testing.T) {
			s, archive := ageMirrorServer(t)
			setAptAge(t, s, policy.ActionBlock)
			now := time.Now().UTC().Truncate(time.Second)
			first := mirrorOSVDists(mirroredCodename, ageDeb(ageDebSeed, "8.5.3-0ubuntu1"))
			store := s.typeStore(manifest.TypeApt).(*storage.Memory)
			for rel, body := range first {
				if strings.HasSuffix(rel, "/Release") {
					body = "Date: " + now.Add(-24*time.Hour).Format(time.RFC1123) + "\n" + body
					first[rel] = body
				}
				archive.setObject(rel, body)
				if mode == "cached-disconnect" {
					store.Seed(manifest.AptKey(rel), body)
				}
			}
			for _, rest := range []string{"Release", "universe/binary-amd64/Packages.gz"} {
				rel := "dists/fixture/" + rest
				if mode == "head-fetch" {
					w := httptest.NewRecorder()
					s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/apt/"+rel, nil))
					if w.Code != http.StatusOK || archive.count(rel) != 1 || cachedBody(t, store, manifest.AptKey(rel)) != first[rel] {
						t.Fatalf("HEAD %s did not fetch and cache the complete body: status=%d upstream_reads=%d", rest, w.Code, archive.count(rel))
					}
				} else {
					w := &reviewF112ObservedShortWriter{ResponseRecorder: httptest.NewRecorder()}
					s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apt/"+rel, nil))
					if w.Code != http.StatusOK || w.offered.String() != first[rel] || archive.count(rel) != 0 {
						t.Fatalf("GET %s did not read the complete cached body before delivery failed: status=%d offered=%d want=%d upstream_reads=%d", rest, w.Code, w.offered.Len(), len(first[rel]), archive.count(rel))
					}
				}
			}
			if d, ok, err := s.auditDB.GetAptVersionDate(t.Context(), "php8.5", "8.5.3-0ubuntu1"); err != nil || !ok || d.DatedBy != audit.AptDatedByPredates {
				t.Errorf("completed first Packages read: record=%+v ok=%v err=%v; want predating", d, ok, err)
			}
			fresh := now.Add(-time.Hour)
			publishAptIndex(t, s, archive, fresh, ageDeb(ageDebNew, "8.5.4-0ubuntu2"))
			if d := aptDateOf(t, s, "8.5.4-0ubuntu2"); d.DatedBy != audit.AptDatedByRelease || !d.PublishedAt.Equal(fresh) {
				t.Errorf("new version after completed first read = %+v; want Release date %s", d, fresh)
			}
			if code, body := mirrorOSVGet(t, s, ageDebNew); code != http.StatusForbidden {
				t.Errorf("new version under 7d block = %d %q; want 403", code, body)
			}
			if c := lastAgeCheck(t, s, "8.5.4-0ubuntu2"); c.Status != audit.CheckBlock {
				t.Errorf("new version's admission = %+v; want block", c)
			}
		})
	}
}

// TestAptVersionDatesDoNotDependOnRecordingOrder is F112 requirement 1: two
// successive snapshots of one codename, recorded in either order, give the
// same dates. A version both list predates bodega, one new in the second takes
// the second Release's Date:, and an index both Releases list unchanged is
// dated by the older Release even when the newer one was recorded first.
func TestAptVersionDatesDoNotDependOnRecordingOrder(t *testing.T) {
	first := time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	second := time.Date(2026, 11, 8, 6, 0, 0, 0, time.UTC)
	const packages = "universe/binary-amd64/Packages.gz"
	snapshot := func(date time.Time, debs ...mirrorOSVDeb) map[string]string {
		objects := mirrorOSVDists(mirroredCodename, debs...)
		for rel, body := range objects {
			if strings.HasSuffix(rel, "/Release") {
				objects[rel] = "Date: " + date.Format(time.RFC1123) + "\n" + body
			}
		}
		return objects
	}
	record := func(s *Server, objects map[string]string, rests ...string) {
		for _, rest := range rests {
			s.observeAptMirrorDists(t.Context(), mirroredCodename, rest, []byte(objects["dists/"+mirroredCodename+"/"+rest]))
		}
	}
	older := snapshot(first, ageDeb(ageDebSeed, "8.5.3-0ubuntu1"), ageDeb(ageDebOld, "8.5.4-0ubuntu1"))
	newer := snapshot(second, ageDeb(ageDebOld, "8.5.4-0ubuntu1"), ageDeb(ageDebNew, "8.5.4-0ubuntu2"))
	for _, order := range []string{"older-first", "newer-first"} {
		t.Run(order, func(t *testing.T) {
			s, _ := ageMirrorServer(t)
			snaps := []map[string]string{older, newer}
			if order == "newer-first" {
				snaps[0], snaps[1] = newer, older
			}
			for _, objects := range snaps {
				record(s, objects, "Release", packages)
			}
			if d := aptDateOf(t, s, "8.5.3-0ubuntu1"); d.DatedBy != audit.AptDatedByPredates {
				t.Errorf("a version only the older index listed = %+v, want predating", d)
			}
			if d := aptDateOf(t, s, "8.5.4-0ubuntu1"); d.DatedBy != audit.AptDatedByPredates {
				t.Errorf("a version both indexes listed = %+v, want predating", d)
			}
			if d := aptDateOf(t, s, "8.5.4-0ubuntu2"); d.DatedBy != audit.AptDatedByRelease || !d.PublishedAt.Equal(second) {
				t.Errorf("a version new in the newer index = %+v, want dated %s", d, second)
			}
		})
	}
	t.Run("unchanged-index-newer-first", func(t *testing.T) {
		s, archive := ageMirrorServer(t)
		same := []mirrorOSVDeb{ageDeb(ageDebSeed, "8.5.3-0ubuntu1")}
		a, b := snapshot(first, same...), snapshot(second, same...)
		gz := b["dists/"+mirroredCodename+"/"+packages]
		sum := sha256.Sum256([]byte(gz))
		archive.setObject(fmt.Sprintf("dists/%s/universe/binary-amd64/by-hash/SHA256/%x", mirroredCodename, sum), gz)
		record(s, b, "Release", packages)
		record(s, a, "Release")
		if d := aptDateOf(t, s, "8.5.3-0ubuntu1"); d.DatedBy != audit.AptDatedByPredates {
			t.Errorf("a version the older Release listed in the same bytes = %+v, want predating", d)
		}
	})
}

type reviewF112WaitingWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (w *reviewF112WaitingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.resume
	return w.ResponseRecorder.Write(p)
}

func TestReviewF112CompletedFetchCannotWaitForDelivery(t *testing.T) {
	s, archive := ageMirrorServer(t)
	setAptAge(t, s, policy.ActionBlock)
	now := time.Now().UTC().Truncate(time.Second)
	first := mirrorOSVDists(mirroredCodename, ageDeb(ageDebSeed, "8.5.3-0ubuntu1"))
	store := s.typeStore(manifest.TypeApt).(*storage.Memory)
	for rel, body := range first {
		if strings.HasSuffix(rel, "/Release") {
			body = "Date: " + now.Add(-24*time.Hour).Format(time.RFC1123) + "\n" + body
			first[rel] = body
		}
		archive.setObject(rel, body)
	}
	var releases []func()
	for _, rest := range []string{"Release", "universe/binary-amd64/Packages.gz"} {
		rel := "dists/fixture/" + rest
		w := &reviewF112WaitingWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), resume: make(chan struct{})}
		done := make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(w.resume); <-done }) }
		releases = append(releases, release)
		t.Cleanup(release)
		go func() {
			defer close(done)
			s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apt/"+rel, nil))
		}()
		select {
		case <-w.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("request never reached delivery")
		}
		if archive.count(rel) != 1 || cachedBody(t, store, manifest.AptKey(rel)) != first[rel] {
			t.Fatalf("%s was not fully fetched and cached before delivery", rest)
		}
	}
	fresh := now.Add(-time.Hour)
	publishAptIndex(t, s, archive, fresh, ageDeb(ageDebSeed, "8.5.3-0ubuntu1"), ageDeb(ageDebNew, "8.5.4-0ubuntu2"))
	for _, release := range releases {
		release()
	}
	if d := aptDateOf(t, s, "8.5.4-0ubuntu2"); d.DatedBy != audit.AptDatedByRelease || !d.PublishedAt.Equal(fresh) {
		t.Errorf("new version after earlier completed fetches = %+v; want Release date %s", d, fresh)
	}
	if code, body := mirrorOSVGet(t, s, ageDebNew); code != http.StatusForbidden {
		t.Errorf("new version under 7d block = %d %q; want 403", code, body)
	}
	if c := lastAgeCheck(t, s, "8.5.4-0ubuntu2"); c.Status != audit.CheckBlock {
		t.Errorf("admission = %+v; want block", c)
	}
}
