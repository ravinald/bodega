package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// The index documents npm and cargo resolve through, generated from the
// manifest store.
//
// Every test here runs with the cache off and both upstreams pointed at a port
// that refuses connections. That is the assertion: a packument or a sparse
// index that arrives cannot have been proxied, because there was nothing to
// proxy from. Pointed at a live fixture registry instead, each of these would
// pass against the code that 404s a hosted package.

const (
	leftPadTarball = "\x1f\x8b left-pad 1.3.0 tarball bytes"
	itoaCrate      = "\x1f\x8b itoa 1.0.11 crate bytes"
	itoaOldCrate   = "\x1f\x8b itoa 1.0.10 crate bytes"
)

// deadUpstream is an address nothing listens on: a listener is opened for its
// port and closed again, so the address is real, unused, and refuses.
func deadUpstream(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port to refuse on: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close the reserved listener: %v", err)
	}
	return "http://" + addr
}

// hostedServer is the posture README.md opens with: artifacts hosted here,
// proxy_cache_enabled false, no route out.
func hostedServer(t *testing.T) *Server {
	t.Helper()
	s := newDiscoveryServer(t)
	s.cache = CacheConfig{}
	dead := deadUpstream(t)
	s.cfg.NpmUpstream = dead
	s.cfg.CargoUpstream = dead
	s.cfg.CargoDLUpstream = dead
	allowLoopbackUpstreams(t)
	return s
}

func sha256SRI(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func addVersion(t *testing.T, s *Server, typ, name string, ve manifest.VersionEntry) {
	t.Helper()
	if err := s.store.AddVersion(context.Background(), typ, name, ve); err != nil {
		t.Fatalf("add %s/%s@%s: %v", typ, name, ve.Version, err)
	}
}

func sha256Entry(version, content string) manifest.VersionEntry {
	return manifest.VersionEntry{
		Version:  version,
		Checksum: &manifest.Checksum{Algorithm: "sha256", Value: sha256Hex(content)},
	}
}

// decodeJSON fails the test rather than returning an error: every caller here
// has already asserted the status, so a body that will not parse is the
// finding.
func decodeJSON(t *testing.T, body string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("response is not JSON (%v): %s", err, body)
	}
	return doc
}

// cargoIndexRecords parses a sparse-index document back into the objects cargo
// reads. A line that does not parse is a failure, not a skip: this document is
// generated here, so nothing in it is somebody else's shape.
func cargoIndexRecords(t *testing.T, body string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("index line is not JSON (%v): %s", err, line)
		}
		out = append(out, rec)
	}
	return out
}

func npmVersionEntry(t *testing.T, doc map[string]any, version string) map[string]any {
	t.Helper()
	versions, ok := doc["versions"].(map[string]any)
	if !ok {
		t.Fatalf("packument carries no versions map: %+v", doc)
	}
	entry, ok := versions[version].(map[string]any)
	if !ok {
		return nil
	}
	return entry
}

// R1, R2, R6: the packument is generated, and the tarball it advertises is on
// this bodega and serves the bytes. A document naming registry.npmjs.org is
// the defect wearing a 200, and one naming a route that 404s is the same
// defect with an extra hop.
func TestNpmPackumentIsGeneratedForAHostedPackage(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeNpm, "left-pad", sha256Entry("1.3.0", leftPadTarball))
	seed(t, s, manifest.TypeNpm, map[string]string{
		manifest.NpmTarballKey("left-pad", "1.3.0"): leftPadTarball,
	})

	status, body := getStatusAndBody(t, s, "/npm/left-pad")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/left-pad = %d, want 200: %s", status, body)
	}
	doc := decodeJSON(t, body)
	if doc["name"] != "left-pad" {
		t.Errorf("packument name = %v, want left-pad", doc["name"])
	}
	entry := npmVersionEntry(t, doc, "1.3.0")
	if entry == nil {
		t.Fatalf("packument names no 1.3.0: %s", body)
	}
	dist, _ := entry["dist"].(map[string]any)
	tarball, _ := dist["tarball"].(string)
	if !strings.HasSuffix(tarball, "/npm/left-pad/-/left-pad-1.3.0.tgz") {
		t.Errorf("dist.tarball = %q, want this bodega's /npm route", tarball)
	}
	if got := dist["integrity"]; got != sha256SRI(leftPadTarball) {
		t.Errorf("dist.integrity = %v, want %q", got, sha256SRI(leftPadTarball))
	}
	tags, _ := doc["dist-tags"].(map[string]any)
	if tags["latest"] != "1.3.0" {
		t.Errorf("dist-tags.latest = %v, want 1.3.0", tags["latest"])
	}

	// The URL the document hands out, fetched. A packument nobody can follow
	// is the 404 this replaces, moved one request later.
	idx := strings.Index(tarball, "/npm/")
	if idx < 0 {
		t.Fatalf("dist.tarball %q carries no /npm route to follow", tarball)
	}
	tStatus, tBody := getStatusAndBody(t, s, tarball[idx:])
	if tStatus != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200: %s", tarball[idx:], tStatus, tBody)
	}
	if tBody != leftPadTarball {
		t.Errorf("the advertised tarball served %q, want the stored bytes", tBody)
	}
}

// R3, R4, R6: the sparse index is generated in the shape cargo's protocol
// requires, and cksum is the digest of the bytes /download serves.
func TestCargoIndexIsGeneratedForAHostedCrate(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeCargo, "itoa", sha256Entry("1.0.11", itoaCrate))
	// No recorded checksum: the digest has to come off the stored crate, or
	// the version is dropped rather than published with an empty cksum.
	addVersion(t, s, manifest.TypeCargo, "itoa", manifest.VersionEntry{Version: "1.0.10"})
	seed(t, s, manifest.TypeCargo, map[string]string{
		manifest.CargoCrateKey("itoa", "1.0.11"): itoaCrate,
		manifest.CargoCrateKey("itoa", "1.0.10"): itoaOldCrate,
	})

	status, body := getStatusAndBody(t, s, "/cargo/it/oa/itoa")
	if status != http.StatusOK {
		t.Fatalf("GET /cargo/it/oa/itoa = %d, want 200: %s", status, body)
	}
	recs := cargoIndexRecords(t, body)
	if len(recs) != 2 {
		t.Fatalf("index carries %d lines, want 2: %s", len(recs), body)
	}
	byVers := map[string]map[string]any{}
	for _, rec := range recs {
		vers, _ := rec["vers"].(string)
		byVers[vers] = rec
	}
	for vers, content := range map[string]string{"1.0.11": itoaCrate, "1.0.10": itoaOldCrate} {
		rec, ok := byVers[vers]
		if !ok {
			t.Fatalf("index names no %s: %s", vers, body)
		}
		if rec["name"] != "itoa" {
			t.Errorf("%s: name = %v, want itoa", vers, rec["name"])
		}
		if rec["cksum"] != sha256Hex(content) {
			t.Errorf("%s: cksum = %v, want the digest of the stored crate %q", vers, rec["cksum"], sha256Hex(content))
		}
		// deps and features are required members of cargo's record, and a
		// null for either fails to deserialize before the crate is reached.
		if deps, ok := rec["deps"].([]any); !ok || len(deps) != 0 {
			t.Errorf("%s: deps = %v, want an empty list", vers, rec["deps"])
		}
		if features, ok := rec["features"].(map[string]any); !ok || len(features) != 0 {
			t.Errorf("%s: features = %v, want an empty object", vers, rec["features"])
		}
		if rec["yanked"] != false {
			t.Errorf("%s: yanked = %v, want false", vers, rec["yanked"])
		}
	}

	dStatus, dBody := getStatusAndBody(t, s, "/cargo/itoa/1.0.11/download")
	if dStatus != http.StatusOK {
		t.Fatalf("GET /cargo/itoa/1.0.11/download = %d, want 200: %s", dStatus, dBody)
	}
	if dBody != itoaCrate {
		t.Errorf("the crate route served %q, want the bytes cksum names", dBody)
	}
}

// A version with no checksum and no stored bytes is dropped. Published with an
// empty cksum it fails in cargo as a corrupt download, which sends whoever
// hits it to their disk rather than to this registry.
func TestCargoIndexDropsAVersionItCannotChecksum(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeCargo, "itoa", sha256Entry("1.0.11", itoaCrate))
	addVersion(t, s, manifest.TypeCargo, "itoa", manifest.VersionEntry{Version: "9.9.9"})
	seed(t, s, manifest.TypeCargo, map[string]string{
		manifest.CargoCrateKey("itoa", "1.0.11"): itoaCrate,
	})

	status, body := getStatusAndBody(t, s, "/cargo/it/oa/itoa")
	if status != http.StatusOK {
		t.Fatalf("GET /cargo/it/oa/itoa = %d, want 200: %s", status, body)
	}
	if strings.Contains(body, "9.9.9") {
		t.Errorf("a version with no checksum reached the index: %s", body)
	}
}

// A hidden version is absent from both generated documents. Hiding one and
// having it published anyway is the whole of what the flag exists to stop.
func TestGeneratedDocumentsDropAHiddenVersion(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeNpm, "left-pad", sha256Entry("1.3.0", leftPadTarball))
	addVersion(t, s, manifest.TypeNpm, "left-pad", manifest.VersionEntry{Version: "1.2.0", Hidden: true})
	addVersion(t, s, manifest.TypeCargo, "itoa", sha256Entry("1.0.11", itoaCrate))
	addVersion(t, s, manifest.TypeCargo, "itoa", manifest.VersionEntry{
		Version: "1.0.10", Hidden: true,
		Checksum: &manifest.Checksum{Algorithm: "sha256", Value: sha256Hex(itoaOldCrate)},
	})

	status, body := getStatusAndBody(t, s, "/npm/left-pad")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/left-pad = %d, want 200: %s", status, body)
	}
	if npmVersionEntry(t, decodeJSON(t, body), "1.2.0") != nil {
		t.Errorf("the hidden npm version is in the packument: %s", body)
	}

	status, body = getStatusAndBody(t, s, "/cargo/it/oa/itoa")
	if status != http.StatusOK {
		t.Fatalf("GET /cargo/it/oa/itoa = %d, want 200: %s", status, body)
	}
	if strings.Contains(body, "1.0.10") {
		t.Errorf("the hidden crate version is in the index: %s", body)
	}
}

// R5: a profile's version rule decides the generated documents as it decides
// the proxied ones. A generated document that skipped the filter would hand a
// scoped host the versions its profile excludes, with nothing in the response
// saying so.
func TestGeneratedDocumentsKeepTheProfileFilter(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeNpm, "left-pad", sha256Entry("1.3.0", leftPadTarball))
	addVersion(t, s, manifest.TypeNpm, "left-pad", sha256Entry("1.2.0", "older left-pad"))
	addVersion(t, s, manifest.TypeCargo, "itoa", sha256Entry("1.0.11", itoaCrate))
	addVersion(t, s, manifest.TypeCargo, "itoa", sha256Entry("1.0.10", itoaOldCrate))

	f := bindProfile(t, s, "pinned", "host01",
		[]audit.ProfileTypeRule{
			closedRule(manifest.TypeNpm, audit.VersionFloating, audit.ExpansionBlock),
			closedRule(manifest.TypeCargo, audit.VersionFloating, audit.ExpansionBlock),
		},
		[]audit.ProfileEntry{
			{Type: manifest.TypeNpm, Name: "left-pad", Constraint: manifest.ConstraintExact, Version: "1.3.0"},
			{Type: manifest.TypeCargo, Name: "itoa", Constraint: manifest.ConstraintExact, Version: "1.0.11"},
		})

	status, body := f.get(t, "/npm/left-pad")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/left-pad = %d, want 200: %s", status, body)
	}
	doc := decodeJSON(t, body)
	if npmVersionEntry(t, doc, "1.2.0") != nil {
		t.Errorf("the packument carries a version the profile excludes: %s", body)
	}
	if npmVersionEntry(t, doc, "1.3.0") == nil {
		t.Errorf("the packument dropped the version the profile permits: %s", body)
	}
	// The tag has to name a version that survived the filter, or `npm install
	// left-pad` resolves what this host is refused.
	if tags, _ := doc["dist-tags"].(map[string]any); tags["latest"] != "1.3.0" {
		t.Errorf("dist-tags.latest = %v, want 1.3.0", tags["latest"])
	}

	status, body = f.get(t, "/cargo/it/oa/itoa")
	if status != http.StatusOK {
		t.Fatalf("GET /cargo/it/oa/itoa = %d, want 200: %s", status, body)
	}
	if strings.Contains(body, "1.0.10") {
		t.Errorf("the index carries a version the profile excludes: %s", body)
	}
	if !strings.Contains(body, "1.0.11") {
		t.Errorf("the index dropped the version the profile permits: %s", body)
	}
}

// An entry's own version constraint decides the generated documents too. It
// already decides the tarball and the crate download, and a document offering
// what those two refuse is an install that fails one request later.
func TestGeneratedDocumentsKeepTheVersionConstraint(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeNpm, "left-pad", manifest.VersionEntry{
		Version: "1.3.0", VersionConstraint: manifest.ConstraintExact,
		Checksum: &manifest.Checksum{Algorithm: "sha256", Value: sha256Hex(leftPadTarball)},
	})
	addVersion(t, s, manifest.TypeNpm, "left-pad", sha256Entry("1.2.0", "older left-pad"))
	addVersion(t, s, manifest.TypeCargo, "itoa", manifest.VersionEntry{
		Version: "1.0.11", VersionConstraint: manifest.ConstraintExact,
		Checksum: &manifest.Checksum{Algorithm: "sha256", Value: sha256Hex(itoaCrate)},
	})
	addVersion(t, s, manifest.TypeCargo, "itoa", sha256Entry("1.0.10", itoaOldCrate))

	status, body := getStatusAndBody(t, s, "/npm/left-pad")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/left-pad = %d, want 200: %s", status, body)
	}
	if npmVersionEntry(t, decodeJSON(t, body), "1.2.0") != nil {
		t.Errorf("the packument carries a version the constraint excludes: %s", body)
	}

	status, body = getStatusAndBody(t, s, "/cargo/it/oa/itoa")
	if status != http.StatusOK {
		t.Fatalf("GET /cargo/it/oa/itoa = %d, want 200: %s", status, body)
	}
	if strings.Contains(body, "1.0.10") {
		t.Errorf("the index carries a version the constraint excludes: %s", body)
	}
}

// R1: a package no entry names still proxies, and with the proxy off there is
// nothing to answer with. The generated path must not become the answer for
// every package, which would turn an unhosted package into a silent empty
// registry entry instead of a miss.
func TestAPackageNoEntryNamesIsNotGenerated(t *testing.T) {
	s := hostedServer(t)

	if status, _ := getStatusAndBody(t, s, "/npm/is-number"); status == http.StatusOK {
		t.Errorf("GET /npm/is-number = 200 with no entry and no upstream; it must not be generated")
	}
	if status, _ := getStatusAndBody(t, s, "/cargo/an/yh/anyhow"); status == http.StatusOK {
		t.Errorf("GET /cargo/an/yh/anyhow = 200 with no entry and no upstream; it must not be generated")
	}
}

// R1: an entry chooses generation, and the mode it records does not. Reserved
// for hosted entries, generation left a proxy-mode package answering the
// upstream's failure on the one route a client resolves through, while the
// versions it pins sat in the manifest the whole time.
func TestNpmPackumentIsGeneratedForAProxyModeEntry(t *testing.T) {
	s := hostedServer(t)
	ve := sha256Entry("1.3.0", leftPadTarball)
	ve.Mode = manifest.ModeProxy
	addVersion(t, s, manifest.TypeNpm, "left-pad", ve)

	status, body := getStatusAndBody(t, s, "/npm/left-pad")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/left-pad on a proxy-mode entry = %d, want 200: %s", status, body)
	}
	entry := npmVersionEntry(t, decodeJSON(t, body), "1.3.0")
	if entry == nil {
		t.Fatalf("packument names no 1.3.0: %s", body)
	}
	dist, _ := entry["dist"].(map[string]any)
	if tarball, _ := dist["tarball"].(string); !strings.HasSuffix(tarball, "/npm/left-pad/-/left-pad-1.3.0.tgz") {
		t.Errorf("dist.tarball = %q, want this bodega's /npm route", tarball)
	}
}

// R3: the same for the sparse index. cargo resolves through this document and
// nothing else, so a proxy-mode crate whose upstream is unreachable was a
// crate cargo could not name, with its versions recorded here all along.
func TestCargoIndexIsGeneratedForAProxyModeEntry(t *testing.T) {
	s := hostedServer(t)
	ve := sha256Entry("1.0.11", itoaCrate)
	ve.Mode = manifest.ModeProxy
	addVersion(t, s, manifest.TypeCargo, "itoa", ve)

	status, body := getStatusAndBody(t, s, "/cargo/it/oa/itoa")
	if status != http.StatusOK {
		t.Fatalf("GET /cargo/it/oa/itoa on a proxy-mode entry = %d, want 200: %s", status, body)
	}
	recs := cargoIndexRecords(t, body)
	if len(recs) != 1 {
		t.Fatalf("index carries %d lines, want 1: %s", len(recs), body)
	}
	if recs[0]["vers"] != "1.0.11" || recs[0]["cksum"] != sha256Hex(itoaCrate) {
		t.Errorf("index line = %v, want 1.0.11 carrying the crate's digest %s", recs[0], sha256Hex(itoaCrate))
	}
}

// #319: the version-manifest route resolves its manifest under the package,
// so the hidden-version and constraint policies reach it. Looked up under
// "<pkg>/<version>" the lookup never hit and every refusal below it was
// decided against a nil manifest.
func TestNpmVersionRouteAppliesVersionPolicy(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeNpm, "left-pad", sha256Entry("1.3.0", leftPadTarball))
	addVersion(t, s, manifest.TypeNpm, "left-pad", manifest.VersionEntry{Version: "1.2.0", Hidden: true})

	status, body := getStatusAndBody(t, s, "/npm/left-pad/1.3.0")
	if status != http.StatusOK {
		t.Fatalf("GET /npm/left-pad/1.3.0 = %d, want 200: %s", status, body)
	}
	doc := decodeJSON(t, body)
	if doc["version"] != "1.3.0" {
		t.Errorf("the version route answered %v, want the 1.3.0 document", doc["version"])
	}
	dist, _ := doc["dist"].(map[string]any)
	if tarball, _ := dist["tarball"].(string); !strings.HasSuffix(tarball, "/npm/left-pad/-/left-pad-1.3.0.tgz") {
		t.Errorf("dist.tarball = %q, want this bodega's /npm route", tarball)
	}

	if status, body := getStatusAndBody(t, s, "/npm/left-pad/1.2.0"); status != http.StatusNotFound {
		t.Errorf("GET a hidden version's document = %d, want 404: %s", status, body)
	}
	if status, body := getStatusAndBody(t, s, "/npm/left-pad/9.9.9"); status != http.StatusNotFound {
		t.Errorf("GET a version no entry names = %d, want 404: %s", status, body)
	}
}
