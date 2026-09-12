package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/deb822"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// These drive the shape apt inverts: the filtered index is the enforcement and
// the pool predicate is the backstop. Asserting entitle.Covers on an apt name
// would pass against a tree where no index generator consults it, which is the
// state F13 deliberately left for apt and this item changes.

const (
	// The fixture archive ships three binaries from two sources. nginx and
	// nginx-common share a source and are the requirement-3 case: a profile
	// listing the source has to carry both, because a set closed on binary
	// names fires the first time Ubuntu splits one.
	profileNginxDeb       = "pool/main/n/nginx/nginx_1.24.0-2ubuntu7.1_amd64.deb"
	profileNginxCommonDeb = "pool/main/n/nginx/nginx-common_1.24.0-2ubuntu7.1_amd64.deb"
	profileHtopDeb        = "pool/main/h/htop/htop_3.3.0-4build1_amd64.deb"
)

// aptProfilePackages is the upstream index the filter runs over: two binaries
// from source nginx and one from source htop.
func aptProfilePackages() string {
	stanza := func(pkg, source, version, poolPath, desc string) string {
		lines := []string{"Package: " + pkg}
		if source != "" {
			lines = append(lines, "Source: "+source)
		}
		lines = append(lines,
			"Version: "+version,
			"Architecture: amd64",
			"Filename: "+poolPath,
			"Size: 42",
			"SHA256: 0000000000000000000000000000000000000000000000000000000000000000",
			"Description: "+desc,
			" a continuation line the filter must not reflow",
			" .",
			" and a paragraph break inside the field",
			"", "")
		return strings.Join(lines, "\n")
	}
	return stanza("nginx", "", "1.24.0-2ubuntu7.1", profileNginxDeb, "fixture web server") +
		stanza("nginx-common", "nginx (1.24.0-2ubuntu7.1)", "1.24.0-2ubuntu7.1", profileNginxCommonDeb, "fixture web server common files") +
		stanza("htop", "", "3.3.0-4build1", profileHtopDeb, "fixture process viewer")
}

// aptProfileServer is a mirroring server with a bodega signing key installed,
// which is what a filtered codename needs: it is a generated suite, and a
// generated suite with no key serves an unsigned Release that Signed-By: on
// the client would then refuse.
func aptProfileServer(t *testing.T) (*Server, *fixtureArchive) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(aptsign.CredentialsEnv, dir)
	kr, err := aptsign.Generate("bodega test archive", "test@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := kr.WritePrivate(filepath.Join(dir, aptsign.KeyFileName)); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	upstreamKR, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate upstream key: %v", err)
	}
	objects := fixtureDists(t, upstreamKR, aptProfilePackages())
	objects[profileNginxDeb] = "\x21<arch>\nnginx bytes"
	objects[profileNginxCommonDeb] = "\x21<arch>\nnginx-common bytes"
	objects[profileHtopDeb] = "\x21<arch>\nhtop bytes"

	archive := newFixtureArchive(t, objects)
	s := mirrorServer(t, archive)
	if s.aptSign.Load() == nil {
		t.Fatal("no apt signing key loaded; every filtered Release would be unsigned")
	}
	return s, archive
}

// aptProfileBind writes a profile that scopes apt over the fixture codename
// and rebuilds the index, which is when a filtered codename comes into being.
func aptProfileBind(t *testing.T, s *Server, name string, expansion string, packages ...string) *profileFixture {
	t.Helper()
	rule := closedRule(manifest.TypeApt, audit.VersionFloating, expansion)
	rule.AptBase = mirroredCodename
	entries := make([]audit.ProfileEntry, 0, len(packages))
	for _, p := range packages {
		entries = append(entries, audit.ProfileEntry{Type: manifest.TypeApt, Name: p})
	}
	f := bindProfile(t, s, name, name+"-host", []audit.ProfileTypeRule{rule}, entries)
	s.rebuildAptSnapshot(context.Background())
	return f
}

// aptProfileIndex reads one filtered codename's Packages off the served tree.
func aptProfileIndex(t *testing.T, s *Server, codename string) string {
	t.Helper()
	code, body := mirrorGet(t, s, "/apt/dists/"+codename+"/main/binary-amd64/Packages")
	if code != http.StatusOK {
		t.Fatalf("GET the filtered Packages for %s = %d, want 200", codename, code)
	}
	return string(body)
}

// Requirement 1 and 3, and the first half of 8. The profile lists one source
// package; the codename it is served under carries that source's binaries and
// omits everything else, and the Release beside it is bodega's own signature
// over exactly those bytes.
func TestFilteredCodenameOmitsAPackageAndKeepsTheSourcesBinaries(t *testing.T) {
	s, _ := aptProfileServer(t)
	aptProfileBind(t, s, "web", audit.ExpansionBlock, "nginx")

	index := aptProfileIndex(t, s, "fixture-web")
	for _, want := range []string{"Package: nginx\n", "Package: nginx-common\n"} {
		if !strings.Contains(index, want) {
			t.Errorf("filtered index is missing %q; membership closed on the source has to carry every binary it builds:\n%s", want, index)
		}
	}
	if strings.Contains(index, "Package: htop") {
		t.Errorf("filtered index carries htop, which the profile does not list:\n%s", index)
	}
	// The paragraph is the upstream's own bytes. A re-serializer is what
	// flattens a Description's continuation onto one line, and apt reads the
	// result without complaining about it.
	if !strings.Contains(index, "\n a continuation line the filter must not reflow\n .\n") {
		t.Errorf("the kept paragraph lost its continuation layout, so it was rewritten rather than copied:\n%s", index)
	}

	// The signature covers what is served. Fetching the InRelease, verifying
	// it against bodega's own key and checking the digest it names against
	// the Packages body is the invariant a client applies.
	code, inRelease := mirrorGet(t, s, "/apt/dists/fixture-web/InRelease")
	if code != http.StatusOK {
		t.Fatalf("GET the filtered InRelease = %d, want 200: a filtered index nobody signed needs [trusted=yes]", code)
	}
	block, rest := clearsign.Decode(inRelease)
	if block == nil {
		t.Fatalf("the filtered InRelease is not a clearsigned document (trailing %q)", rest)
	}
	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(string(s.aptSign.Load().pub())))
	if err != nil {
		t.Fatalf("read bodega's published key: %v", err)
	}
	if _, err := openpgp.CheckDetachedSignature(ring, bytesReader(block.Bytes), block.ArmoredSignature.Body, nil); err != nil {
		t.Fatalf("the filtered InRelease does not verify against the key bodega publishes: %v", err)
	}
	if !strings.Contains(string(block.Plaintext), "Codename: fixture-web") {
		t.Errorf("the signed Release does not name the codename it is served under:\n%s", block.Plaintext)
	}
	if got := aptReleaseDigests(mustParseRelease(t, block.Plaintext))["main/binary-amd64/Packages"]; got != sha256Hex(index) {
		t.Errorf("the signed Release names %s for Packages and the served body hashes to %s", got, sha256Hex(index))
	}
}

// Requirement 5 and 8's fourth case. The predicate is the backstop, so a
// client that composed a pool URL for a package the index never offered is
// refused there, with the row that names which rule said no.
func TestPoolPredicateRefusesAnArtifactOutsideTheProfile(t *testing.T) {
	s, archive := aptProfileServer(t)
	f := aptProfileBind(t, s, "web", audit.ExpansionBlock, "nginx")

	code, body := f.get(t, "/apt/"+profileHtopDeb)
	if code != http.StatusForbidden {
		t.Fatalf("pool fetch outside the profile = %d, want 403", code)
	}
	if !strings.Contains(body, entitle.RefusalMembership) {
		t.Errorf("the refusal does not name which rule said no, so the operator cannot tell widen-the-set from move-the-pin:\n%s", body)
	}
	if got := archive.count(profileHtopDeb); got != 0 {
		t.Errorf("upstream GETs for a refused artifact = %d, want 0: the predicate has to run before the fetch", got)
	}
	if ev := profileDenial(t, s, audit.DenialProfileMembership); ev.PkgName != "htop" {
		t.Errorf("denial row names package %q, want the source htop", ev.PkgName)
	}

	// The same host's own package still serves, which is the difference
	// between a backstop and an outage.
	if code, _ := f.get(t, "/apt/"+profileNginxDeb); code != http.StatusOK {
		t.Fatalf("pool fetch inside the profile = %d, want 200", code)
	}
}

// Requirement 6 and 8's third case. Two profiles are two views over one
// catalog: they are told different things exist and are answered from the
// same object when they both fetch one.
func TestTwoProfilesShareOnePoolObject(t *testing.T) {
	s, archive := aptProfileServer(t)
	web := aptProfileBind(t, s, "web", audit.ExpansionBlock, "nginx")
	// A second profile listing both sources, so the two are told different
	// things and reach for the same .deb.
	edge := aptProfileBind(t, s, "edge", audit.ExpansionBlock, "nginx", "htop")

	if idx := aptProfileIndex(t, s, "fixture-edge"); !strings.Contains(idx, "Package: htop") {
		t.Errorf("the second profile's index omits a package it lists:\n%s", idx)
	}
	if idx := aptProfileIndex(t, s, "fixture-web"); strings.Contains(idx, "Package: htop") {
		t.Errorf("the first profile's index carries a package it does not list:\n%s", idx)
	}

	code, first := getWithToken(t, s, web.token, "/apt/"+profileNginxDeb)
	if code != http.StatusOK {
		t.Fatalf("web pool fetch = %d, want 200", code)
	}
	code, second := getWithToken(t, s, edge.token, "/apt/"+profileNginxDeb)
	if code != http.StatusOK {
		t.Fatalf("edge pool fetch = %d, want 200", code)
	}
	if first != second {
		t.Errorf("two profiles were served different bytes for one pool path")
	}
	if got := archive.count(profileNginxDeb); got != 1 {
		t.Errorf("upstream GETs = %d for two profiles fetching one .deb, want 1: the filtered index decides what a profile is told exists, not where the bytes live", got)
	}
	// One key, not one per profile. A forked object store is what gives one
	// artifact two checksum identities, which 011 refused at the storage level.
	keys, err := s.typeStore(manifest.TypeApt).List(t.Context(), manifest.AptPoolPrefix)
	if err != nil {
		t.Fatalf("list the apt pool: %v", err)
	}
	if len(keys) != 1 || keys[0] != manifest.AptKey(profileNginxDeb) {
		t.Errorf("pool objects after two profiles fetched one .deb = %v, want exactly %s", keys, manifest.AptKey(profileNginxDeb))
	}
}

// Requirement 8's last case. An open apt membership lists nothing to be
// outside of, so there is nothing to filter and nothing to re-sign: the host
// reads the mirrored codename, upstream signature intact.
func TestOpenAptMembershipGetsTheMirroredCodenameUnchanged(t *testing.T) {
	s, _ := aptProfileServer(t)
	rule := audit.ProfileTypeRule{
		Type: manifest.TypeApt, Membership: audit.MembershipOpen,
		VersionDefault: audit.VersionFloating,
	}
	f := bindProfile(t, s, "open", "open-host", []audit.ProfileTypeRule{rule}, nil)
	s.rebuildAptSnapshot(context.Background())

	if code, _ := mirrorGet(t, s, "/apt/dists/fixture-open/Release"); code != http.StatusNotFound {
		t.Errorf("an open apt membership was given a filtered codename; there is nothing to filter and re-signing would replace the archive's signature with one over identical bytes")
	}
	code, served := f.get(t, "/apt/dists/"+mirroredCodename+"/main/binary-amd64/Packages")
	if code != http.StatusOK {
		t.Fatalf("GET the mirrored Packages = %d, want 200", code)
	}
	if string(served) != aptProfilePackages() {
		t.Errorf("the mirrored index was altered for a profile that scopes nothing:\n%s", served)
	}
	// And the pool is not gated for it either: a refusal with no filtered
	// index behind it is the mid-transaction 403 this whole shape avoids.
	if code, _ := f.get(t, "/apt/"+profileHtopDeb); code != http.StatusOK {
		t.Fatalf("pool fetch under an open apt membership = %d, want 200", code)
	}
}

// A refusal a proxy can overturn is not a refusal. The pool ships public while
// nothing gates it and private the moment a profile does, because a shared
// cache would otherwise answer a refused host out of a permitted host's fetch
// with the request never reaching the predicate.
func TestAGatedPoolRouteLosesTheSharedCacheGrant(t *testing.T) {
	s, _ := aptProfileServer(t)
	f := aptProfileBind(t, s, "web", audit.ExpansionBlock, "nginx")

	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	header := func(token string) string {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/apt/"+profileNginxDeb, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET the pool: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET the pool = %d, want 200", resp.StatusCode)
		}
		return resp.Header.Get("Cache-Control")
	}
	if got := header(f.token); strings.Contains(got, "public") || !strings.Contains(got, "private") {
		t.Errorf("Cache-Control for a profile-gated pool fetch = %q, want private", got)
	}
	if got := header(""); !strings.Contains(got, "public") {
		t.Errorf("Cache-Control for an unprofiled pool fetch = %q, want public: apt pays nothing where no profile scopes it", got)
	}
}

// Requirement 7's server half: which codename a host reads is a fact only the
// running instance holds, so it answers with the stanza rather than leaving a
// client to pick one out of a list. Signed-By: is on it because the filtered
// index is signed, and [trusted=yes] would discard the reason it is.
func TestStatusNamesTheHostsOwnFilteredStanza(t *testing.T) {
	s, _ := aptProfileServer(t)
	f := aptProfileBind(t, s, "web", audit.ExpansionBlock, "nginx")

	code, body := f.get(t, "/api/v1/status")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/status = %d, want 200", code)
	}
	var payload struct {
		Apt struct {
			Filtered []string            `json:"filtered"`
			Profile  string              `json:"profile"`
			Host     *aptsources.Sources `json:"host"`
		} `json:"apt"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	if len(payload.Apt.Filtered) != 1 || payload.Apt.Filtered[0] != "fixture-web" {
		t.Fatalf("filtered codenames = %v, want [fixture-web]", payload.Apt.Filtered)
	}
	if payload.Apt.Profile != "web" {
		t.Errorf("status names profile %q for a host bound to web", payload.Apt.Profile)
	}
	if payload.Apt.Host == nil {
		t.Fatal("status names no stanza for a host whose profile scopes apt; bodega doctor --write-apt-sources has nothing to install")
	}
	if payload.Apt.Host.Suite != "fixture-web" {
		t.Errorf("the stanza names suite %q, want the host's own filtered codename", payload.Apt.Host.Suite)
	}
	if !strings.Contains(payload.Apt.Host.Deb822, "Signed-By: "+aptsources.ClientKeyringPath) {
		t.Errorf("the stanza carries no Signed-By:, so the client would need [trusted=yes]:\n%s", payload.Apt.Host.Deb822)
	}
	if strings.Contains(payload.Apt.Host.Deb822, "Trusted: yes") {
		t.Errorf("the stanza turns verification off for the source:\n%s", payload.Apt.Host.Deb822)
	}

	// An unidentified request is not handed a host's stanza. This instance
	// serves a generated suite, a mirrored codename and a filtered one, and
	// picking between them is nobody's guess to make.
	code, anon := mirrorGet(t, s, "/api/v1/status")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/status unidentified = %d, want 200", code)
	}
	// A second decode into the same value would keep the pointer the first one
	// set, which is the shape of the bug this assertion exists to catch.
	var unidentified struct {
		Apt struct {
			Profile string              `json:"profile"`
			Host    *aptsources.Sources `json:"host"`
		} `json:"apt"`
	}
	if err := json.Unmarshal(anon, &unidentified); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	if unidentified.Apt.Profile != "" {
		t.Errorf("an unidentified request resolved to profile %q", unidentified.Apt.Profile)
	}
	if unidentified.Apt.Host != nil {
		t.Errorf("an unidentified request was named a suite to read: %q", unidentified.Apt.Host.Suite)
	}
}

// A pin becomes real for apt through the index, not through a 403. The
// paragraph at the version the profile does not permit is simply absent, which
// is what apt reports as a package held back.
func TestAConstraintDropsTheVersionFromTheFilteredIndex(t *testing.T) {
	s, _ := aptProfileServer(t)
	rule := closedRule(manifest.TypeApt, audit.VersionFloating, audit.ExpansionBlock)
	rule.AptBase = mirroredCodename
	bindProfile(t, s, "pinned", "pinned-host", []audit.ProfileTypeRule{rule}, []audit.ProfileEntry{
		{Type: manifest.TypeApt, Name: "nginx", Constraint: manifest.ConstraintExact, Version: "1.20.0-1"},
	})
	s.rebuildAptSnapshot(context.Background())

	index := aptProfileIndex(t, s, "fixture-pinned")
	if strings.Contains(index, "Package: nginx") {
		t.Errorf("the filtered index carries a version the profile's pin refuses:\n%s", index)
	}
}

// A base no upstream archive serves is a control the operator believes they
// set. It has to leave no codename behind rather than a half-built one.
func TestAProfileOverAnUnmirroredBaseServesNothing(t *testing.T) {
	s, _ := aptProfileServer(t)
	rule := closedRule(manifest.TypeApt, audit.VersionFloating, audit.ExpansionBlock)
	rule.AptBase = "nosuchcodename"
	bindProfile(t, s, "stray", "stray-host", []audit.ProfileTypeRule{rule},
		[]audit.ProfileEntry{{Type: manifest.TypeApt, Name: "nginx"}})
	s.rebuildAptSnapshot(context.Background())

	if code, _ := mirrorGet(t, s, "/apt/dists/nosuchcodename-stray/Release"); code != http.StatusNotFound {
		t.Errorf("a profile over a base nothing mirrors was served a codename = %d, want 404", code)
	}
	if names, _ := s.aptFilteredSuites(); len(names) != 0 {
		t.Errorf("filtered codenames = %v, want none", names)
	}
}

// filterAptPackages is the one place binary and source identity could
// disagree, so it gets a direct case as well as the served ones above.
func TestFilterKeepsASourcesBinariesAndDropsTheRest(t *testing.T) {
	d := &audit.ProfileDetail{
		Profile: audit.Profile{Name: "web"},
		Types: []audit.ProfileTypeRule{{
			Type: manifest.TypeApt, Membership: audit.MembershipClosed,
			VersionDefault: audit.VersionFloating, Expansion: audit.ExpansionBlock,
			AptBase: mirroredCodename,
		}},
		Entries: []audit.ProfileEntry{{Type: manifest.TypeApt, Name: "nginx"}},
	}
	out, kept, dropped := filterAptPackages([]byte(aptProfilePackages()), entitle.New(d))
	if kept != 2 || dropped != 1 {
		t.Errorf("kept/dropped = %d/%d, want 2/1", kept, dropped)
	}
	if strings.Contains(string(out), "htop") {
		t.Errorf("filtered output carries a package outside the set:\n%s", out)
	}
	if !strings.Contains(string(out), "Package: nginx-common") {
		t.Errorf("filtered output dropped a binary of a source the profile lists:\n%s", out)
	}
}

// sha256Hex, bytesReader and mustParseRelease are the three small readers the
// signature assertion needs; each is one line at the call site and unreadable
// there.
func sha256Hex(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func mustParseRelease(t *testing.T, body []byte) map[string]string {
	t.Helper()
	fields, err := deb822.ParseSingle(body)
	if err != nil {
		t.Fatalf("parse the signed Release: %v", err)
	}
	return fields
}

// aptPoolSourceName is what makes the backstop close over the same identity
// the filter did, and it reads a path rather than an index.
func TestAptPoolSourceName(t *testing.T) {
	cases := map[string]string{
		profileNginxCommonDeb:                           "nginx",
		"pool/universe/libf/libfoo/libfoo1_1.0_all.deb": "libfoo",
		"pool/main/n/nginx":                             "",
		"nginx_1.0_amd64.deb":                           "",
	}
	for in, want := range cases {
		if got := aptPoolSourceName(in); got != want {
			t.Errorf("aptPoolSourceName(%q) = %q, want %q", in, got, want)
		}
	}
}
