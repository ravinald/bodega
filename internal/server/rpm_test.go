package server

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
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
// what set gives it, and counts every path asked for. A path stall holds
// answers nothing until it is released.
type rpmMirror struct {
	ts       *httptest.Server
	mu       sync.Mutex
	hits     map[string]int
	override map[string][]byte
	stalled  map[string]chan struct{}
}

func newRPMMirror(t *testing.T) *rpmMirror {
	t.Helper()
	m := &rpmMirror{hits: map[string]int{}, override: map[string][]byte{}, stalled: map[string]chan struct{}{}}
	m.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.hits[r.URL.Path]++
		body, replaced := m.override[r.URL.Path]
		gate := m.stalled[r.URL.Path]
		m.mu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
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

// stall holds every answer for rel until the returned release runs, which the
// test's cleanup also does so the mirror can close.
func (m *rpmMirror) stall(t *testing.T, rel string) (release func()) {
	t.Helper()
	gate := make(chan struct{})
	m.mu.Lock()
	m.stalled[rpmUpstreamTree+rel] = gate
	m.mu.Unlock()
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	return release
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
	s.cfg.RpmUpstreams = map[string]config.RpmUpstream{rpmFixtureRepoID: {URL: m.ts.URL + "/$releasever/BaseOS/$basearch/os/"}}
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
				if !strings.HasPrefix(r.UpstreamURL, s.cfg.RpmUpstreams[rpmFixtureRepoID].URL[:len("http://127.0.0.1")]) {
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

// A warm cache answers to the allow-list as a cold fill does: the package an
// operator stops admitting is refused even where bodega already holds it.
func TestRpmCachedPackageRefusedByTheAllowList(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	if rec := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil); rec.Code != http.StatusOK {
		t.Fatalf("warming nginx: %d (%s)", rec.Code, rec.Body.String())
	}
	if err := s.auditDB.SetAdmissionMode(t.Context(), audit.AdmissionMode{Ecosystem: manifest.TypeRpm, Mode: audit.ModeListed}); err != nil {
		t.Fatal(err)
	}
	s.policy.Invalidate()
	if cold := doRequest(s, http.MethodGet, rpmRepoPath+rpmHttpdHref, nil); cold.Code != http.StatusForbidden {
		t.Fatalf("cold httpd under listed mode: %d, want 403", cold.Code)
	}
	got := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil)
	if got.Code != http.StatusForbidden {
		t.Fatalf("cached nginx under listed mode: %d, want 403; body=%q", got.Code, got.Body.String())
	}
	refusalIncident(t, got.Header(), checkAllowList)
	if strings.Contains(got.Body.String(), "fixture bytes") {
		t.Errorf("refusal carries the package bytes: %q", got.Body.String())
	}
	if n := m.hitsFor(rpmNginxHref); n != 1 {
		t.Errorf("upstream asked %d times for nginx, want only the warming fetch", n)
	}
	waitForRpmDiscovery(t, s, "nginx", rpmNginxEVR, audit.DecisionDenied)
}

// The cached signature pair holds across a stale_grace refresh: the client
// served the old revision is signed the old revision, though the refresh has
// replaced the cached copy by the time it asks.
func TestRpmSignatureCoversTheStaleRepomdAfterARefreshLands(t *testing.T) {
	m := newRPMMirror(t)
	s, kr := rpmServer(t, m)
	s.cache.MetadataTTL = time.Nanosecond
	s.cache.StaleGrace = time.Millisecond
	handler := m.ts.Config.Handler
	m.ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		handler.ServeHTTP(w, r)
	})
	old := doRequest(s, http.MethodGet, rpmRepoPath+"repodata/repomd.xml", nil).Body.String()
	moved := old + "<!-- new revision -->"
	m.set("repodata/repomd.xml", []byte(moved))
	served := doRequest(s, http.MethodGet, rpmRepoPath+"repodata/repomd.xml", nil).Body.String()
	if served != old {
		t.Fatal("stale_grace did not serve the cached revision")
	}
	waitForRpmRepomd(t, s, moved)
	sig := doRequest(s, http.MethodGet, rpmRepoPath+"repodata/repomd.xml.asc", nil)
	if err := rpmVerifySignature(kr, served, sig.Body.String()); err != nil {
		t.Fatalf("signature after the refresh landed does not cover the served repomd.xml: %v", err)
	}
}

// Two clients holding two revisions are each signed their own.
func TestRpmSignatureFollowsEachClientsRevision(t *testing.T) {
	m := newRPMMirror(t)
	s, kr := rpmServer(t, m)
	s.cache.MetadataTTL = time.Nanosecond
	const hostA, hostB = "192.0.2.10:40000", "192.0.2.20:40000"
	first := rpmRequestFrom(s, hostA, rpmRepoPath+"repodata/repomd.xml").Body.String()
	m.set("repodata/repomd.xml", []byte(first+"<!-- new revision -->"))
	second := rpmRequestFrom(s, hostB, rpmRepoPath+"repodata/repomd.xml").Body.String()
	if first == second {
		t.Fatal("the second client was not served the new revision")
	}
	for _, c := range []struct{ addr, doc string }{{hostA, first}, {hostB, second}} {
		sig := rpmRequestFrom(s, c.addr, rpmRepoPath+"repodata/repomd.xml.asc")
		if err := rpmVerifySignature(kr, c.doc, sig.Body.String()); err != nil {
			t.Errorf("client %s: signature does not cover the repomd.xml it was served: %v", c.addr, err)
		}
	}
}

// Two hosts behind one address with no identity of their own are one client
// key, and the .asc request says nothing about which repomd.xml its reader
// got. So the key keeps the revision it holds while any reader may still be
// between its two requests, and a reader handed the held revision is served
// the metadata that revision names, after the cache stopped naming it.
func TestRpmSignatureSharedAddress(t *testing.T) {
	m := newRPMMirror(t)
	s, kr := rpmServer(t, m)
	clock := rpmTestClock(s)
	s.cache.MetadataTTL = time.Nanosecond
	const hostA, hostB, hostC = "192.0.2.10:40000", "192.0.2.10:40001", "192.0.2.10:40002"
	first := rpmRequestFrom(s, hostA, rpmRepoPath+"repodata/repomd.xml").Body.String()
	moved := strings.ReplaceAll(first, rpmPrimaryGz, "repodata/0000-primary.xml.gz") + "<!-- new revision -->"
	m.set("repodata/repomd.xml", []byte(moved))
	second := rpmRequestFrom(s, hostB, rpmRepoPath+"repodata/repomd.xml")
	if second.Body.String() != first {
		t.Fatal("the second reader behind the address was handed a revision the first reader's signature cannot cover")
	}
	if cl := second.Header().Get("Content-Length"); cl != "" && cl != strconv.Itoa(len(first)) {
		t.Errorf("Content-Length %s for a %d-byte document", cl, len(first))
	}
	waitForRpmRepomd(t, s, moved)
	if got := rpmRequestFrom(s, hostB, rpmRepoPath+rpmPrimaryGz); got.Code != http.StatusOK {
		t.Errorf("primary named by the revision the client holds: %d %s", got.Code, got.Body.String())
	}
	for _, addr := range []string{hostA, hostB} {
		sig := rpmRequestFrom(s, addr, rpmRepoPath+"repodata/repomd.xml.asc")
		if err := rpmVerifySignature(kr, first, sig.Body.String()); err != nil {
			t.Errorf("client %s: signature does not cover the repomd.xml it was served: %v", addr, err)
		}
	}
	clock.advance(rpmSignatureWait + time.Second)
	third := rpmRequestFrom(s, hostC, rpmRepoPath+"repodata/repomd.xml").Body.String()
	if third != moved {
		t.Fatal("the address stayed on the old revision after it was quiet for rpmSignatureWait")
	}
	sig := rpmRequestFrom(s, hostC, rpmRepoPath+"repodata/repomd.xml.asc")
	if err := rpmVerifySignature(kr, third, sig.Body.String()); err != nil {
		t.Errorf("signature does not cover the new revision: %v", err)
	}
}

// A signature request reads the revision a key holds and never moves it, so
// one reader asking for its signature again and again cannot hand another
// reader behind the same address a signature over a revision it never got.
// This is the reviewer's probe from F97's audit of 2d8f4b1, with C's request
// expected to be held rather than advanced: C arrives while B may still be
// between its two requests.
func TestRpmSignatureRetryKeepsAnotherReadersRevision(t *testing.T) {
	m := newRPMMirror(t)
	s, kr := rpmServer(t, m)
	rpmTestClock(s)
	s.cache.MetadataTTL = time.Nanosecond
	const a, b, c = "192.0.2.10:40000", "192.0.2.10:40001", "192.0.2.10:40002"
	first := rpmRequestFrom(s, a, rpmRepoPath+"repodata/repomd.xml").Body.String()
	held := rpmRequestFrom(s, b, rpmRepoPath+"repodata/repomd.xml").Body.String()
	for range 5 {
		sig := rpmRequestFrom(s, a, rpmRepoPath+"repodata/repomd.xml.asc")
		if err := rpmVerifySignature(kr, first, sig.Body.String()); err != nil {
			t.Fatal(err)
		}
	}
	m.set("repodata/repomd.xml", []byte(first+"<!-- next -->"))
	if next := rpmRequestFrom(s, c, rpmRepoPath+"repodata/repomd.xml").Body.String(); next != first {
		t.Fatal("a signature request let the key move while reader B was still owed its signature")
	}
	sig := rpmRequestFrom(s, b, rpmRepoPath+"repodata/repomd.xml.asc")
	if err := rpmVerifySignature(kr, held, sig.Body.String()); err != nil {
		t.Fatalf("reader B signature after reader A retried .asc: %v", err)
	}
}

// A key that is never quiet still moves once the cache has held a newer
// revision for rpmRolloverGrace, and from then on the pair it serves is the
// new one.
func TestRpmBusyAddressRollsOverAfterTheGrace(t *testing.T) {
	m := newRPMMirror(t)
	s, kr := rpmServer(t, m)
	clock := rpmTestClock(s)
	s.cache.MetadataTTL = time.Nanosecond
	const host = "192.0.2.10:40000"
	first := rpmRequestFrom(s, host, rpmRepoPath+"repodata/repomd.xml").Body.String()
	moved := first + "<!-- new revision -->"
	m.set("repodata/repomd.xml", []byte(moved))
	for elapsed := time.Duration(0); elapsed < rpmRolloverGrace; elapsed += rpmSignatureWait / 2 {
		if got := rpmRequestFrom(s, host, rpmRepoPath+"repodata/repomd.xml").Body.String(); got != first {
			t.Fatalf("moved %v into the grace while the key was busy", elapsed)
		}
		sig := rpmRequestFrom(s, host, rpmRepoPath+"repodata/repomd.xml.asc")
		if err := rpmVerifySignature(kr, first, sig.Body.String()); err != nil {
			t.Fatalf("%v into the grace: signature does not cover the held revision: %v", elapsed, err)
		}
		clock.advance(rpmSignatureWait / 2)
	}
	if got := rpmRequestFrom(s, host, rpmRepoPath+"repodata/repomd.xml").Body.String(); got != moved {
		t.Fatal("a busy key kept the old revision past rpmRolloverGrace")
	}
	sig := rpmRequestFrom(s, host, rpmRepoPath+"repodata/repomd.xml.asc")
	if err := rpmVerifySignature(kr, moved, sig.Body.String()); err != nil {
		t.Errorf("signature after the rollover does not cover the new revision: %v", err)
	}
}

type rpmFakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *rpmFakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *rpmFakeClock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// rpmTestClock gives the server's publication record a clock the test moves.
func rpmTestClock(s *Server) *rpmFakeClock {
	c := &rpmFakeClock{now: time.Unix(1_800_000_000, 0)}
	s.rpmServed.clock = c.read
	return c
}

// A conditional GET is answered in full, so the revision a client keeps is
// always one bodega recorded handing it.
func TestRpmRepomdIgnoresConditionalRequests(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	first := doRequest(s, http.MethodGet, rpmRepoPath+"repodata/repomd.xml", nil)
	req := httptest.NewRequest(http.MethodGet, rpmRepoPath+"repodata/repomd.xml", nil)
	req.Header.Set("If-None-Match", first.Header().Get("ETag"))
	req.Header.Set("If-Modified-Since", time.Now().UTC().Format(http.TimeFormat))
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != first.Body.String() {
		t.Errorf("conditional GET: %d, %d bytes; want 200 with the document", rec.Code, rec.Body.Len())
	}
}

// A key moves to a newer revision only on a repomd.xml request, and only
// once it was quiet for rpmSignatureWait or the cache held the newer one for
// rpmRolloverGrace. Reading what it holds never moves it.
func TestRpmServedRepomdsHold(t *testing.T) {
	const tree, key = "rocky-baseos/9/x86_64", "192.0.2.10\x00"
	r1, r2 := []byte("revision 1"), []byte("revision 2")
	t0 := time.Unix(1_800_000_000, 0)

	var c rpmServedRepomds
	if got := c.publish(tree, key, r1, t0); !bytes.Equal(got, r1) {
		t.Fatalf("first publish handed %q", got)
	}
	if got := c.publish(tree, key, r2, t0.Add(time.Second)); !bytes.Equal(got, r1) {
		t.Errorf("a reader may still be owed a signature: handed %q, want the held revision", got)
	}
	for range 10 {
		if got, _ := c.held(tree, key, t0.Add(2*time.Second)); !bytes.Equal(got, r1) {
			t.Fatalf("held %q, want the held revision", got)
		}
	}
	if got := c.publish(tree, key, r2, t0.Add(3*time.Second)); !bytes.Equal(got, r1) {
		t.Errorf("reading the signature moved the key: handed %q", got)
	}
	quiet := t0.Add(3*time.Second + rpmSignatureWait + time.Second)
	if got := c.publish(tree, key, r2, quiet); !bytes.Equal(got, r2) {
		t.Errorf("quiet for rpmSignatureWait: handed %q, want the new revision", got)
	}
	if got, ok := c.held(tree, key, quiet); !ok || !bytes.Equal(got, r2) {
		t.Errorf("held %q, %v", got, ok)
	}

	var busy rpmServedRepomds
	busy.publish(tree, key, r1, t0)
	newer := t0.Add(rpmSignatureWait / 2)
	at := newer
	for ; at.Sub(newer) < rpmRolloverGrace; at = at.Add(rpmSignatureWait / 2) {
		if got := busy.publish(tree, key, r2, at); !bytes.Equal(got, r1) {
			t.Fatalf("busy key moved %v after the newer revision appeared", at.Sub(newer))
		}
	}
	if got := busy.publish(tree, key, r2, at); !bytes.Equal(got, r2) {
		t.Errorf("busy key at rpmRolloverGrace: handed %q", got)
	}
	if _, ok := busy.held(tree, key, at.Add(rpmServedWindow+2*time.Second)); ok {
		t.Error("a record older than rpmServedWindow still answered the signature")
	}
}

// A package whose checksum changes in a new primary, at the same name,
// version and href, is never answered from the bytes cached under the old one.
func TestRpmCachedPackageDisagreeingWithPrimaryIs502(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	s.cache.MetadataTTL = time.Nanosecond
	first := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil)
	if first.Code != http.StatusOK {
		t.Fatal(first.Code, first.Body.String())
	}
	compressed := rpmFixture(t, rpmPrimaryGz)
	reader, closeFn, err := rpmDecompress(compressed, ".gz")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	closeFn()
	if err != nil {
		t.Fatal(err)
	}
	oldSum := rpmSHA256(first.Body.Bytes())
	replacement := []byte("new package bytes")
	newSum := rpmSHA256(replacement)
	raw = bytes.ReplaceAll(raw, []byte(oldSum), []byte(newSum))
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	newHref := "repodata/" + rpmSHA256(buf.Bytes()) + "-primary.xml.gz"
	repomd := strings.NewReplacer(rpmPrimaryGz, newHref, rpmSHA256(compressed), rpmSHA256(buf.Bytes())).Replace(string(rpmFixture(t, "repodata/repomd.xml")))
	m.set(newHref, buf.Bytes())
	m.set("repodata/repomd.xml", []byte(repomd))
	m.set(rpmNginxHref, replacement)

	for i := range 2 {
		got := doRequest(s, http.MethodGet, rpmRepoPath+rpmNginxHref, nil)
		if got.Code != http.StatusBadGateway {
			t.Fatalf("request %d after primary moved: %d, want 502; body sha256 %s", i, got.Code, rpmSHA256(got.Body.Bytes()))
		}
		refusalIncident(t, got.Header(), checkChecksum)
		if body := got.Body.String(); !strings.Contains(body, oldSum) || !strings.Contains(body, newSum) {
			t.Errorf("refusal does not name both digests:\n%s", body)
		}
	}
	stored, _ := s.typeStore(manifest.TypeRpm).Get(t.Context(), manifest.RpmPackageKey(rpmFixtureRepoID, "9", "x86_64", "nginx", rpmNginxEVR, path.Base(rpmNginxHref)))
	if rpmSHA256(stored) != oldSum {
		t.Errorf("the cached object changed under a refusal: sha256 %s", rpmSHA256(stored))
	}
}

func rpmRequestFrom(s *Server, remoteAddr, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	return rec
}

func rpmVerifySignature(kr *aptsign.KeyRing, doc, sig string) error {
	pub, err := kr.PublicKey()
	if err != nil {
		return err
	}
	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(pub))
	if err != nil {
		return err
	}
	_, err = openpgp.CheckArmoredDetachedSignature(ring, strings.NewReader(doc), strings.NewReader(sig), nil)
	return err
}

func waitForRpmRepomd(t *testing.T, s *Server, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, _ := s.typeStore(manifest.TypeRpm).Get(t.Context(), manifest.RpmRepomdKey(rpmFixtureRepoID, "9", "x86_64"))
		if string(b) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the background refresh never stored the new repomd.xml")
		}
		time.Sleep(time.Millisecond)
	}
}

// A repository that keeps primary's filename across revisions must not let a
// client holding the old revision index the old bytes under the new checksum:
// a fresh client would then be refused the current package.
func TestRpmPrimaryReusedHrefIndexesCurrentBytes(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	s.cache.MetadataTTL = time.Nanosecond
	const a, b = "192.0.2.10:40000", "192.0.2.20:40000"
	first := rpmRequestFrom(s, a, rpmRepoPath+"repodata/repomd.xml").Body.String()
	old := rpmFixture(t, rpmPrimaryGz)
	if rec := rpmRequestFrom(s, a, rpmRepoPath+rpmPrimaryGz); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	reader, closeFn, err := rpmDecompress(old, ".gz")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	closeFn()
	if err != nil {
		t.Fatal(err)
	}
	replacement := []byte("replacement package bytes")
	raw = bytes.ReplaceAll(raw, []byte(rpmSHA256(rpmFixture(t, rpmNginxHref))), []byte(rpmSHA256(replacement)))
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	m.set(rpmPrimaryGz, buf.Bytes())
	m.set("repodata/repomd.xml", []byte(strings.ReplaceAll(first, ">"+rpmSHA256(old)+"<", ">"+rpmSHA256(buf.Bytes())+"<")))
	m.set(rpmNginxHref, replacement)
	if rec := rpmRequestFrom(s, a, rpmRepoPath+rpmNginxHref); rec.Code != 200 {
		t.Fatalf("reader A holding the old repomd.xml: %d %s", rec.Code, rec.Body.String())
	}
	slot := s.rpmPrimaries.slot(rpmFixtureRepoID + "/9/x86_64")
	slot.mu.Lock()
	if slot.idx == nil {
		slot.mu.Unlock()
		t.Fatal("no index")
	}
	checksum, pkgSum := slot.idx.checksum, slot.idx.pkgs[rpmNginxHref].sum
	slot.mu.Unlock()
	if checksum != rpmSHA256(buf.Bytes()) || pkgSum != rpmSHA256(replacement) {
		t.Fatalf("index under primary %s gives nginx %s; want primary %s giving %s", checksum, pkgSum, rpmSHA256(buf.Bytes()), rpmSHA256(replacement))
	}
	rec := rpmRequestFrom(s, b, rpmRepoPath+rpmNginxHref)
	if rec.Code != 200 {
		t.Fatalf("fresh reader B: %d %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), replacement) {
		t.Fatalf("fresh reader got old package bytes")
	}
}

// rpmFixturePkg is one package rpmPublish lists in a primary of its own.
type rpmFixturePkg struct {
	name, epoch, ver, rel string
	build, file           time.Time
}

func (p rpmFixturePkg) href() string {
	return "Packages/" + p.name[:1] + "/" + p.name + "-" + p.ver + "-" + p.rel + ".x86_64.rpm"
}

func (p rpmFixturePkg) body() []byte { return []byte("fixture bytes of " + p.href()) }

// rpmPublish replaces the fixture's primary with one listing pkgs, each with
// the <time> element a real primary carries, and serves each package's bytes.
// A zero time is written as 0, which is how createrepo_c writes one it lacks.
func rpmPublish(t *testing.T, m *rpmMirror, pkgs ...rpmFixturePkg) {
	t.Helper()
	unix := func(at time.Time) int64 {
		if at.IsZero() {
			return 0
		}
		return at.Unix()
	}
	var doc strings.Builder
	doc.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="` + strconv.Itoa(len(pkgs)) + `">` + "\n")
	for _, p := range pkgs {
		doc.WriteString(`<package type="rpm"><name>` + p.name + `</name><arch>x86_64</arch>` +
			`<version epoch="` + p.epoch + `" ver="` + p.ver + `" rel="` + p.rel + `"/>` +
			`<checksum type="sha256" pkgid="YES">` + rpmSHA256(p.body()) + `</checksum>` +
			`<time file="` + strconv.FormatInt(unix(p.file), 10) + `" build="` + strconv.FormatInt(unix(p.build), 10) + `"/>` +
			`<location href="` + p.href() + `"/></package>` + "\n")
		m.set(p.href(), p.body())
	}
	doc.WriteString("</metadata>\n")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(doc.String()))
	_ = zw.Close()
	m.set(rpmPrimaryGz, gz.Bytes())
	repomd := strings.ReplaceAll(string(rpmFixture(t, "repodata/repomd.xml")), ">"+rpmSHA256(rpmFixture(t, rpmPrimaryGz))+"<", ">"+rpmSHA256(gz.Bytes())+"<")
	m.set("repodata/repomd.xml", []byte(repomd))
}

// gateRpm runs the proxy fill's real admission checks rather than the
// stubs proxyingServer installs.
func gateRpm(t *testing.T) {
	t.Helper()
	prev := fetchCheckers
	fetchCheckers = admit.VersionCheckers
	t.Cleanup(func() { fetchCheckers = prev })
}

// The age gate dates a package by primary's build time, or its file time
// when build is 0, and refuses one a day old under a seven-day minimum before
// it is fetched. A package past the window is served.
func TestRpmRefusedByAge(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	gateRpm(t)
	now := time.Now()
	fresh := rpmFixturePkg{name: "nginx", epoch: "2", ver: "1.26.3", rel: "1.el9", build: now.Add(-24 * time.Hour), file: now.Add(-30 * 24 * time.Hour)}
	byFile := rpmFixturePkg{name: "tmux", epoch: "0", ver: "3.2a", rel: "5.el9", file: now.Add(-24 * time.Hour)}
	old := rpmFixturePkg{name: "httpd", epoch: "0", ver: "2.4.62", rel: "1.el9", build: now.Add(-30 * 24 * time.Hour), file: now.Add(-time.Hour)}
	rpmPublish(t, m, fresh, byFile, old)
	if err := s.auditDB.SetAgePolicy(t.Context(), audit.AgePolicy{Ecosystem: manifest.TypeRpm, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	// nginx's file time is thirty days old, so only its build time refuses
	// it; tmux's build time is 0, so only its file time does.
	published := "was published " + now.Add(-24*time.Hour).UTC().Format("2006-01-02")
	for _, pkg := range []rpmFixturePkg{fresh, byFile} {
		rec := doRequest(s, http.MethodGet, rpmRepoPath+pkg.href(), nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403 (%s)", pkg.name, rec.Code, rec.Body.String())
		}
		refusalIncident(t, rec.Header(), checkAge)
		if !strings.Contains(rec.Body.String(), published) {
			t.Errorf("%s: refusal does not say the package %s:\n%s", pkg.name, published, rec.Body.String())
		}
		if n := m.hitsFor(pkg.href()); n != 0 {
			t.Errorf("%s: upstream asked %d times for a package the age gate refused", pkg.name, n)
		}
	}
	if rec := doRequest(s, http.MethodGet, rpmRepoPath+old.href(), nil); rec.Code != http.StatusOK {
		t.Errorf("a package built thirty days ago: %d (%s)", rec.Code, rec.Body.String())
	}
}

// rpmRockyRecord is RLSA-2024:6783 as OSV files it, cut to what the matcher
// reads: openssl in Rocky Linux 9, fixed at 1:3.0.7-28.el9_4.
//
// rpmRockyEL10Record is a synthetic advisory filed under Rocky Linux 10 alone,
// in the same export: it must refuse an EL10 build and say nothing about an
// EL9 one.
const rpmRockyEL10Record = `{"id":"EL10-ONLY","affected":[{"package":{"name":"openssl","ecosystem":"Rocky Linux:10"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.5.1-1.el10"}]}]}]}`

const rpmRockyRecord = `{"id":"RLSA-2024:6783","summary":"Moderate: openssl security update","affected":[{"package":{"name":"openssl","ecosystem":"Rocky Linux:9"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.0.7-28.el9_4"}]}]}]}`

// gateRpmOSV syncs "Rocky Linux" from an export holding rpmRockyRecord and
// rpmRockyEL10Record and
// turns the rpm advisory gate on.
func gateRpmOSV(t *testing.T, s *Server) {
	t.Helper()
	gateRpm(t)
	export := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Rocky Linux/all.zip" {
			http.NotFound(w, r)
			return
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, _ := zw.Create("RLSA-2024:6783.json")
		_, _ = f.Write([]byte(rpmRockyRecord))
		f, _ = zw.Create("EL10-ONLY.json")
		_, _ = f.Write([]byte(rpmRockyEL10Record))
		_ = zw.Close()
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(export.Close)
	s.cfg.OSVDBDir = t.TempDir()
	db := policy.NewOSVDatabase(s.cfg.OSVDBDir)
	db.ExportBase = export.URL
	if _, err := db.Sync(t.Context(), "Rocky Linux"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := s.auditDB.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeRpm, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
}

// A repository whose upstream is a Rocky mirror, named so by osv_ecosystem,
// has its packages checked against Rocky Linux's advisories with the epoch
// primary gives them: the vulnerable openssl is refused before it is fetched,
// naming the advisory, and the fixed one is served. The export also carries an
// EL10-only advisory, which refuses the EL10 build asked for under releasever
// 10 and not the EL9 build fixed under EL9's own.
func TestRpmRefusedByOSV(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	up := s.cfg.RpmUpstreams[rpmFixtureRepoID]
	up.OSVEcosystem = "Rocky Linux"
	s.cfg.RpmUpstreams[rpmFixtureRepoID] = up
	built := time.Now().Add(-90 * 24 * time.Hour)
	vulnerable := rpmFixturePkg{name: "openssl", epoch: "1", ver: "3.0.7", rel: "27.el9", build: built}
	fixed := rpmFixturePkg{name: "openssl", epoch: "1", ver: "3.0.7", rel: "28.el9_4", build: built}
	el10Vulnerable := rpmFixturePkg{name: "openssl", epoch: "1", ver: "3.5.0", rel: "1.el10", build: built}
	el10Fixed := rpmFixturePkg{name: "openssl", epoch: "1", ver: "3.5.1", rel: "1.el10", build: built}
	rpmPublish(t, m, vulnerable, fixed, el10Vulnerable, el10Fixed)
	// The mirror holds one tree, so the EL10 repository's URL names it
	// outright and only the releasever bodega is asked under says 10.
	s.cfg.RpmUpstreams["rocky-baseos-10"] = config.RpmUpstream{URL: m.ts.URL + "/9/BaseOS/$basearch/os/", OSVEcosystem: "Rocky Linux"}
	gateRpmOSV(t, s)

	rec := doRequest(s, http.MethodGet, rpmRepoPath+vulnerable.href(), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("openssl 1:3.0.7-27.el9: status %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkOSV)
	if !strings.Contains(rec.Body.String(), "RLSA-2024:6783") {
		t.Errorf("refusal does not name the advisory:\n%s", rec.Body.String())
	}
	if n := m.hitsFor(vulnerable.href()); n != 0 {
		t.Errorf("upstream asked %d times for a package OSV refused", n)
	}
	if rec := doRequest(s, http.MethodGet, rpmRepoPath+fixed.href(), nil); rec.Code != http.StatusOK {
		t.Errorf("openssl 1:3.0.7-28.el9_4: %d (%s)", rec.Code, rec.Body.String())
	}

	rec = doRequest(s, http.MethodGet, "/rpm/rocky-baseos-10/10/x86_64/"+el10Vulnerable.href(), nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "EL10-ONLY") || strings.Contains(rec.Body.String(), "RLSA-2024:6783") {
		t.Errorf("openssl 1:3.5.0-1.el10 under releasever 10: %d, want 403 naming EL10-ONLY alone (%s)", rec.Code, rec.Body.String())
	}
	if rec := doRequest(s, http.MethodGet, "/rpm/rocky-baseos-10/10/x86_64/"+el10Fixed.href(), nil); rec.Code != http.StatusOK {
		t.Errorf("openssl 1:3.5.1-1.el10 under releasever 10: %d (%s)", rec.Code, rec.Body.String())
	}
}

// EPEL belongs to no OSV ecosystem. Its package is served with the gate on,
// and the admission row records the check not run, naming the repository,
// rather than a pass nobody earned. With both OSV actions ignored it still
// is not a pass: ignoring a check that cannot run does not make it one that
// ran.
func TestRpmEPELRecordsOSVNotRun(t *testing.T) {
	for _, ignored := range []bool{false, true} {
		t.Run(fmt.Sprintf("ignored=%v", ignored), func(t *testing.T) { rpmEPELRecordsOSVNotRun(t, ignored) })
	}
}

func rpmEPELRecordsOSVNotRun(t *testing.T, ignored bool) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	s.cfg.RpmUpstreams["epel"] = config.RpmUpstream{URL: m.ts.URL + "/$releasever/BaseOS/$basearch/os/"}
	pkg := rpmFixturePkg{name: "htop", epoch: "0", ver: "3.3.0", rel: "1.el9", build: time.Now().Add(-90 * 24 * time.Hour)}
	rpmPublish(t, m, pkg)
	gateRpmOSV(t, s)
	if ignored {
		if err := s.auditDB.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeRpm, Action: policy.ActionIgnore}); err != nil {
			t.Fatal(err)
		}
		if err := s.auditDB.SetOSVMalwarePolicy(t.Context(), audit.OSVMalwarePolicy{Ecosystem: manifest.TypeRpm, Action: policy.ActionIgnore}); err != nil {
			t.Fatal(err)
		}
	}
	if rec := doRequest(s, http.MethodGet, "/rpm/epel/9/x86_64/"+pkg.href(), nil); rec.Code != http.StatusOK {
		t.Fatalf("htop from EPEL: %d (%s)", rec.Code, rec.Body.String())
	}
	rows, err := s.auditDB.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeRpm, PkgName: "htop", PkgVersion: "3.3.0-1.el9"})
	if err != nil || len(rows) == 0 {
		t.Fatalf("no admission row for htop: %v", err)
	}
	checks := rows[len(rows)-1].Checks
	i := slices.IndexFunc(checks, func(c audit.AdmissionCheck) bool { return c.Check == audit.CheckOSV })
	if i < 0 {
		t.Fatalf("admission row names no OSV check: %+v", checks)
	}
	if c := checks[i]; c.Status != audit.CheckNotEvaluated || !strings.Contains(c.Detail, "rpm repository epel belongs to no OSV ecosystem") {
		t.Errorf("osv check %+v, want not_evaluated naming epel", c)
	}
}

// A package whose name is one edit from one a stock EL9 host installs is
// held by the similarity gate before it is fetched.
func TestRpmNearMissNameHeld(t *testing.T) {
	m := newRPMMirror(t)
	s, _ := rpmServer(t, m)
	gateRpm(t)
	squat := rpmFixturePkg{name: "sytemd", epoch: "0", ver: "252", rel: "1.el9", build: time.Now().Add(-90 * 24 * time.Hour)}
	rpmPublish(t, m, squat)
	if err := s.auditDB.SetSimilarityPolicy(t.Context(), audit.SimilarityPolicy{Ecosystem: manifest.TypeRpm, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(s, http.MethodGet, rpmRepoPath+squat.href(), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("sytemd: status %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkSimilarity)
	if n := m.hitsFor(squat.href()); n != 0 {
		t.Errorf("upstream asked %d times for a held name", n)
	}
}
