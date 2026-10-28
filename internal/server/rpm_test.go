package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// The fixture under testdata/rpm is one repository: a repomd.xml naming a
// gzipped primary, the same primary zstd-compressed beside it, and the two
// packages primary lists. nginx carries epoch 2, httpd epoch 0.
const (
	rpmFixtureDir    = "testdata/rpm"
	rpmPrimaryGz     = "repodata/c5f513aafe11233849144736137b1c720833b4e27b19be4a017ee699e2d8b9ec-primary.xml.gz"
	rpmPrimaryZst    = "repodata/218f2c851e092c16f556af85c3aa8c18cebe2475a415d429bf5b3da60cdb006f-primary.xml.zst"
	rpmNginxHref     = "Packages/n/nginx-1.20.1-20.el9.x86_64.rpm"
	rpmHttpdHref     = "Packages/h/httpd-2.4.57-5.el9.x86_64.rpm"
	rpmRepoPath      = "/rpm/rocky-baseos/9/x86_64/"
	rpmUpstreamTree  = "/9/BaseOS/x86_64/os/"
	rpmNginxEVR      = "2:1.20.1-20.el9"
	rpmHttpdEVR      = "2.4.57-5.el9"
	rpmFixtureRepoID = "rocky-baseos"
)

// rpmMirror serves the fixture under rpmUpstreamTree, any file replaced by
// what set gives it, and counts every path asked for.
type rpmMirror struct {
	ts       *httptest.Server
	mu       sync.Mutex
	hits     map[string]int
	override map[string][]byte
}

func newRPMMirror(t *testing.T) *rpmMirror {
	t.Helper()
	m := &rpmMirror{hits: map[string]int{}, override: map[string][]byte{}}
	m.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.hits[r.URL.Path]++
		body, replaced := m.override[r.URL.Path]
		m.mu.Unlock()
		rel, ok := strings.CutPrefix(r.URL.Path, rpmUpstreamTree)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if !replaced {
			b, err := os.ReadFile(filepath.Join(rpmFixtureDir, filepath.FromSlash(rel)))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			body = b
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		//nolint:gosec // G705: fixture bytes with an explicit Content-Type; the request picks which fixture file, never its content.
		_, _ = w.Write(body)
	}))
	t.Cleanup(m.ts.Close)
	return m
}

func (m *rpmMirror) set(rel string, body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.override[rpmUpstreamTree+rel] = body
}

func (m *rpmMirror) hitsFor(rel string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hits[rpmUpstreamTree+rel]
}

// rpmServer proxies rocky-baseos to the mirror and signs with a throwaway
// key, which it returns for verification.
func rpmServer(t *testing.T, m *rpmMirror) (*Server, *aptsign.KeyRing) {
	t.Helper()
	s := proxyingServer(t)
	s.cfg.RpmUpstreams = map[string]string{rpmFixtureRepoID: m.ts.URL + "/$releasever/BaseOS/$basearch/os/"}
	kr, err := aptsign.Generate("bodega test", "test@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, _ := kr.PublicKey()
	ring, _ := kr.Keyring()
	s.aptSign.Store(&aptSigning{signer: kr, pubArmored: pub, keyring: ring})
	return s, kr
}

func rpmFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rpmFixtureDir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rpmSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestRpmRepomdServedAndSignatureVerifies(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)

	rec := doRequest(s, http.MethodGet, rpmRepoPath+"repodata/repomd.xml", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != string(rpmFixture(t, "repodata/repomd.xml")) {
		t.Fatalf("repomd.xml: %d, want 200 and the upstream's bytes\n%s", rec.Code, rec.Body.String())
	}
	sig := doRequest(s, http.MethodGet, rpmRepoPath+"repodata/repomd.xml.asc", nil)
	if sig.Code != http.StatusOK {
		t.Fatalf("repomd.xml.asc: %d %s", sig.Code, sig.Body.String())
	}
	key := doRequest(s, http.MethodGet, "/rpm/bodega.gpg", nil)
	if key.Code != http.StatusOK {
		t.Fatalf("bodega.gpg: %d %s", key.Code, key.Body.String())
	}
	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key.Body.String()))
	if err != nil {
		t.Fatalf("bodega.gpg does not read as an armored key: %v", err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(ring, strings.NewReader(rec.Body.String()), strings.NewReader(sig.Body.String()), nil); err != nil {
		t.Errorf("repomd.xml.asc does not verify against /rpm/bodega.gpg: %v", err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(ring, strings.NewReader(rec.Body.String()+" "), strings.NewReader(sig.Body.String()), nil); err == nil {
		t.Error("the signature verifies over bytes repomd.xml did not serve")
	}
	if n := m.hitsFor("repodata/repomd.xml"); n != 1 {
		t.Errorf("upstream asked for repomd.xml %d times, want 1: the signature signs the cached copy", n)
	}
}

// The signature is over the copy repomd.xml last served, not a fresher one:
// dnf fetches the two in turn, and a document refreshed between them would
// fail repo_gpgcheck.
func TestRpmSignatureCoversTheServedRepomdAfterTheUpstreamMoves(t *testing.T) {
	m := newRPMMirror(t)
	s, kr := rpmServer(t, m)
	s.cache.MetadataTTL = time.Nanosecond
	served := doRequest(s, http.MethodGet, rpmRepoPath+"repodata/repomd.xml", nil).Body.String()
	m.set("repodata/repomd.xml", []byte(served+"<!-- moved -->\n"))
	sig := doRequest(s, http.MethodGet, rpmRepoPath+"repodata/repomd.xml.asc", nil)
	pub, _ := kr.PublicKey()
	ring, _ := openpgp.ReadArmoredKeyRing(strings.NewReader(string(pub)))
	if _, err := openpgp.CheckArmoredDetachedSignature(ring, strings.NewReader(served), strings.NewReader(sig.Body.String()), nil); err != nil {
		t.Errorf("signature does not cover the repomd.xml last served: %v", err)
	}
}

func TestRpmSignatureAbsentWithoutKey(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	s.aptSign.Store(nil)
	for _, p := range []string{rpmRepoPath + "repodata/repomd.xml.asc", "/rpm/bodega.gpg"} {
		if rec := doRequest(s, http.MethodGet, p, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s with no key: %d, want 404", p, rec.Code)
		}
	}
}

func TestRpmMetadataServedAndCachedUnderItsChecksum(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	want := rpmFixture(t, rpmPrimaryGz)
	for i := range 2 {
		rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmPrimaryGz, nil)
		if rec.Code != http.StatusOK || rec.Body.String() != string(want) {
			t.Fatalf("request %d: %d, want 200 and the gzip bytes as published", i+1, rec.Code)
		}
	}
	if n := m.hitsFor(rpmPrimaryGz); n != 1 {
		t.Errorf("upstream asked for primary %d times over two requests, want 1: it is immutable", n)
	}
	key := manifest.RpmMetadataKey(rpmFixtureRepoID, "9", "x86_64", rpmSHA256(want), filepath.Base(rpmPrimaryGz))
	if b, err := s.typeStore(manifest.TypeRpm).Get(t.Context(), key); err != nil || string(b) != string(want) {
		t.Errorf("primary not cached under %s: %v", key, err)
	}
}

func TestRpmPackageServedAndCached(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	want := rpmFixture(t, rpmNginxHref)
	for i := range 2 {
		rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil)
		if rec.Code != http.StatusOK || rec.Body.String() != string(want) {
			t.Fatalf("request %d: %d %q, want 200 and the package's bytes", i+1, rec.Code, rec.Body.String())
		}
	}
	if n := m.hitsFor(rpmNginxHref); n != 1 {
		t.Errorf("upstream asked for the package %d times over two requests, want 1: it is immutable", n)
	}
	key := manifest.RpmPackageKey(rpmFixtureRepoID, "9", "x86_64", "nginx", rpmNginxEVR, filepath.Base(rpmNginxHref))
	if b, err := s.typeStore(manifest.TypeRpm).Get(t.Context(), key); err != nil || string(b) != string(want) {
		t.Errorf("package not cached under %s: %v", key, err)
	}
	if typ, name, version := manifest.ParseKey(key); typ != manifest.TypeRpm || name != "nginx" || version != rpmNginxEVR {
		t.Errorf("ParseKey(%s) = %s %s %s, want rpm nginx %s", key, typ, name, version, rpmNginxEVR)
	}
}

// The serve_fetch row a package request writes carries the package's key,
// which is where reconciliation reads the epoch; the metadata reads the
// request makes on the way must not take it.
func TestRpmPackageServeRowCarriesItsKey(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	for i := range 2 {
		if rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	want := manifest.RpmPackageKey(rpmFixtureRepoID, "9", "x86_64", "nginx", rpmNginxEVR, filepath.Base(rpmNginxHref))
	objs, err := s.auditDB.ServedObjects(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range objs {
		if o.ObjectKey == want {
			if o.PkgType != manifest.TypeRpm || o.PkgName != "nginx" {
				t.Errorf("serve row %+v, want rpm nginx", o)
			}
			return
		}
	}
	t.Fatalf("no serve_fetch row names %s: %+v", want, objs)
}

// A primary in zstd is indexed the same as a gzipped one.
func TestRpmPackageServedFromAZstdPrimary(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	gz, zst := rpmFixture(t, rpmPrimaryGz), rpmFixture(t, rpmPrimaryZst)
	repomd := strings.NewReplacer(rpmPrimaryGz, rpmPrimaryZst, rpmSHA256(gz), rpmSHA256(zst)).Replace(string(rpmFixture(t, "repodata/repomd.xml")))
	m.set("repodata/repomd.xml", []byte(repomd))
	rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmHttpdHref, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != string(rpmFixture(t, rpmHttpdHref)) {
		t.Fatalf("httpd through a zstd primary: %d %s", rec.Code, rec.Body.String())
	}
	if m.hitsFor(rpmPrimaryZst) != 1 || m.hitsFor(rpmPrimaryGz) != 0 {
		t.Errorf("primary fetches: zst %d, gz %d; want the zst one repomd.xml names", m.hitsFor(rpmPrimaryZst), m.hitsFor(rpmPrimaryGz))
	}
}

func TestRpmTamperedMetadataIs502AndNothingCached(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	tampered := append(rpmFixture(t, rpmPrimaryGz), 0)
	m.set(rpmPrimaryGz, tampered)
	rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmPrimaryGz, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("tampered primary: %d, want 502 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkChecksum)
	for _, d := range []string{rpmSHA256(rpmFixture(t, rpmPrimaryGz)), rpmSHA256(tampered)} {
		if !strings.Contains(rec.Body.String(), d) {
			t.Errorf("refusal does not name %s:\n%s", d, rec.Body.String())
		}
	}
	key := manifest.RpmMetadataKey(rpmFixtureRepoID, "9", "x86_64", rpmSHA256(rpmFixture(t, rpmPrimaryGz)), filepath.Base(rpmPrimaryGz))
	if info, err := s.typeStore(manifest.TypeRpm).Head(t.Context(), key); err != nil || info.Exists {
		t.Errorf("tampered primary was cached at %s (err %v)", key, err)
	}
}

func TestRpmTamperedPackageIs502AndNothingCached(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	tampered := []byte("not the package primary lists")
	m.set(rpmNginxHref, tampered)
	rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("tampered package: %d, want 502 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkChecksum)
	for _, d := range []string{rpmSHA256(rpmFixture(t, rpmNginxHref)), rpmSHA256(tampered)} {
		if !strings.Contains(rec.Body.String(), d) {
			t.Errorf("refusal does not name %s:\n%s", d, rec.Body.String())
		}
	}
	keys, err := s.typeStore(manifest.TypeRpm).List(t.Context(), manifest.RpmPrefix+rpmFixtureRepoID+"/9/x86_64/packages/")
	if err != nil || len(keys) != 0 {
		t.Errorf("a tampered package left %v in the cache (err %v)", keys, err)
	}
}

func TestRpmUnlistedNamesAre404(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	m.set("repodata/other-primary.xml.gz", rpmFixture(t, rpmPrimaryGz))
	m.set("Packages/e/evil-1-1.x86_64.rpm", []byte("evil"))
	for _, p := range []string{"repodata/other-primary.xml.gz", "Packages/e/evil-1-1.x86_64.rpm"} {
		rec := doRequest(s, http.MethodGet, rpmRepoPath+p, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404 (%s)", p, rec.Code, rec.Body.String())
		}
		if n := m.hitsFor(p); n != 0 {
			t.Errorf("%s: upstream asked %d times for a name nothing lists", p, n)
		}
	}
}

func TestRpmPathValidation(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	for _, tc := range []struct {
		path string
		code int
		want string
	}{
		{"/rpm/epel/9/x86_64/repodata/repomd.xml", http.StatusNotFound, "rpm_upstreams"},
		{"/rpm/rocky-baseos/9-stream/x86_64/repodata/repomd.xml", http.StatusBadRequest, "releasever"},
		{"/rpm/rocky-baseos/9.4.1/x86_64/repodata/repomd.xml", http.StatusBadRequest, "releasever"},
		{"/rpm/rocky-baseos/9/i686/repodata/repomd.xml", http.StatusBadRequest, "basearch"},
		{"/rpm/rocky-baseos/9/x86_64%2F..%2F..%2Fetc/repodata/repomd.xml", http.StatusBadRequest, "basearch"},
	} {
		rec := doRequest(s, http.MethodGet, tc.path, nil)
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: %d %q, want %d naming %s", tc.path, rec.Code, rec.Body.String(), tc.code, tc.want)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.hits) != 0 {
		t.Errorf("upstream contacted for paths refused before any URL was built: %v", m.hits)
	}
}

func TestRpmRefusedByTheAllowListRecordsDiscovery(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	if err := s.auditDB.SetAdmissionMode(t.Context(), audit.AdmissionMode{Ecosystem: manifest.TypeRpm, Mode: audit.ModeListed}); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkAllowList)
	if !strings.Contains(rec.Body.String(), "bodega policy add rpm nginx") {
		t.Errorf("refusal does not name the command that admits the package:\n%s", rec.Body.String())
	}
	if n := m.hitsFor(rpmNginxHref); n != 0 {
		t.Errorf("upstream asked %d times for a package the allow-list refused", n)
	}
	waitForRpmDiscovery(t, s, "nginx", rpmNginxEVR, audit.DecisionDenied)

	// A rule naming the repository's base URL prefix admits every package
	// in it; one naming the package admits that package alone.
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeRpm, RuleKind: policy.KindPackage, Pattern: m.ts.URL + "/9/BaseOS/"}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	s.policy.Invalidate()
	if rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil); rec.Code != http.StatusOK {
		t.Errorf("after the base URL rule: %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	waitForRpmDiscovery(t, s, "nginx", rpmNginxEVR, audit.DecisionAllowed)
}

func TestRpmAdmittedByPackageName(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeRpm, RuleKind: policy.KindPackage, Pattern: "httpd"}); err != nil {
		t.Fatal(err)
	}
	s.policy.Invalidate()
	if rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmHttpdHref, nil); rec.Code != http.StatusOK {
		t.Errorf("httpd: %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil); rec.Code != http.StatusForbidden {
		t.Errorf("nginx: %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	waitForRpmDiscovery(t, s, "httpd", rpmHttpdEVR, audit.DecisionAllowed)
}

func waitForRpmDiscovery(t *testing.T, s *Server, name, version, decision string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, err := s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{RegistryType: manifest.TypeRpm})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		for _, r := range rows {
			if r.PkgName == name && r.PkgVersion == version && r.Decision == decision {
				if !strings.HasPrefix(r.UpstreamURL, s.cfg.RpmUpstreams[rpmFixtureRepoID][:len("http://127.0.0.1")]) {
					t.Errorf("discovery row names upstream %q, not the repository", r.UpstreamURL)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s discovery row for %s@%s in %+v", decision, name, version, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRpmHiddenVersionIs404(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	addVersion(t, s, manifest.TypeRpm, "nginx", manifest.VersionEntry{Version: rpmNginxEVR, Mode: manifest.ModeProxy, Hidden: true})
	rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("hidden version: %d, want the hidden refusal's 404 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkHidden)
	if n := m.hitsFor(rpmNginxHref); n != 0 {
		t.Errorf("upstream asked %d times for a hidden version", n)
	}
	if rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmHttpdHref, nil); rec.Code != http.StatusOK {
		t.Errorf("a package nothing hides: %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

func TestRpmVersionConstraint(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	addVersion(t, s, manifest.TypeRpm, "nginx", manifest.VersionEntry{Version: "2:1.22.1-1.el9", Mode: manifest.ModeProxy, VersionConstraint: manifest.ConstraintExact})
	rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a version outside the constraint: %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkConstraint)

	addVersion(t, s, manifest.TypeRpm, "httpd", manifest.VersionEntry{Version: rpmHttpdEVR, Mode: manifest.ModeProxy, VersionConstraint: manifest.ConstraintExact})
	if rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmHttpdHref, nil); rec.Code != http.StatusOK {
		t.Errorf("the pinned version: %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

// The parsed primary is kept until repomd.xml names another, and a new one
// is read the request after it appears.
func TestRpmPrimaryIndexFollowsTheChecksum(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	s.cache.MetadataTTL = time.Nanosecond
	for range 2 {
		if rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmHttpdHref, nil); rec.Code != http.StatusOK {
			t.Fatalf("httpd: %d %s", rec.Code, rec.Body.String())
		}
	}
	if n := m.hitsFor(rpmPrimaryGz); n != 1 {
		t.Errorf("primary fetched %d times while repomd.xml named one checksum, want 1", n)
	}
	gz, zst := rpmFixture(t, rpmPrimaryGz), rpmFixture(t, rpmPrimaryZst)
	m.set("repodata/repomd.xml", []byte(strings.NewReplacer(rpmPrimaryGz, rpmPrimaryZst, rpmSHA256(gz), rpmSHA256(zst)).Replace(string(rpmFixture(t, "repodata/repomd.xml")))))
	if rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil); rec.Code != http.StatusOK {
		t.Fatalf("nginx after the primary changed: %d %s", rec.Code, rec.Body.String())
	}
	if n := m.hitsFor(rpmPrimaryZst); n != 1 {
		t.Errorf("new primary fetched %d times, want 1", n)
	}
}
