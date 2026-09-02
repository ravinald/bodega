package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
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
	objects map[string]string
	hits    sync.Map // path -> *atomic.Int64
	delay   time.Duration
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
func newFixtureArchive(t *testing.T, objects map[string]string) *fixtureArchive {
	t.Helper()
	a := &fixtureArchive{objects: objects}
	a.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(r.URL.Path, "/ubuntu/")
		body, ok := a.objects[rel]
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
	sum := sha256.Sum256([]byte(packages))
	digest := hex.EncodeToString(sum[:])

	release := strings.Join([]string{
		"Origin: Ubuntu",
		"Label: Ubuntu",
		"Suite: " + mirroredCodename,
		"Codename: " + mirroredCodename,
		"Components: main",
		"Architectures: amd64",
		"Acquire-By-Hash: yes",
		"SHA256:",
		fmt.Sprintf(" %s %d %s", digest, len(packages), packagesPath),
		"",
	}, "\n")

	inRelease, err := kr.ClearSign([]byte(release))
	if err != nil {
		t.Fatalf("clearsign fixture Release: %v", err)
	}
	detached, err := kr.DetachSign([]byte(release))
	if err != nil {
		t.Fatalf("detach-sign fixture Release: %v", err)
	}

	base := "dists/" + mirroredCodename + "/"
	return map[string]string{
		base + "Release":     release,
		base + "InRelease":   string(inRelease),
		base + "Release.gpg": string(detached),
		base + packagesPath:  packages,
		base + "main/binary-amd64/by-hash/SHA256/" + digest: packages,
	}
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
func mirrorServer(t *testing.T, archives ...*fixtureArchive) *Server {
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
		name, version := aptDebIdentity(tc.file)
		if name != tc.name || version != tc.version {
			t.Errorf("aptDebIdentity(%q) = (%q, %q), want (%q, %q)", tc.file, name, version, tc.name, tc.version)
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
