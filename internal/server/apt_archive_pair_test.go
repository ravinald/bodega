package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// vendorNoble is the apt_upstreams key of a vendor publishing its own suite
// under the distribution's codename, mirrored beside that distribution.
const vendorNoble = "vendor/noble"

// noblePairUpstream is one upstream publishing dists/noble/ and one .deb at
// fixtureDeb, signed with its own key.
func noblePairUpstream(t *testing.T, publisher, debBody string) *fixtureArchive {
	t.Helper()
	kr, err := aptsign.Generate(publisher, publisher+"@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate %s key: %v", publisher, err)
	}
	objects := fixtureDistsFor(t, kr, "noble", fixturePackages(fixtureDeb, debBody), "amd64")
	objects[fixtureDeb] = debBody
	return newFixtureArchive(t, objects)
}

// noblePairServer mirrors Ubuntu's noble from one upstream and a vendor's
// noble from a second, whose Release, Packages and pool all differ, with a
// bodega signing key loaded so a hide rewrites what it touches.
func noblePairServer(t *testing.T) (s *Server, ubuntu, vendor *fixtureArchive) {
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
	ubuntu = noblePairUpstream(t, "ubuntu", "\x21<arch>\nnginx as Ubuntu built it")
	vendor = noblePairUpstream(t, "vendor", "\x21<arch>\nnginx as the vendor built it")
	s = mirrorServer(t)
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{
		"noble":     {{URL: ubuntu.URL()}},
		vendorNoble: {{URL: vendor.URL()}},
	}
	if s.aptSign.Load() == nil {
		t.Fatal("no apt signing key loaded")
	}
	return s, ubuntu, vendor
}

// F122 requirements 2 and 4: each dists/ path is its own upstream's bytes,
// and each pool's .deb comes from its own upstream, admitted on the SHA256
// its own codename's paragraph lists.
func TestQualifiedAptSuiteServesItsOwnUpstream(t *testing.T) {
	s, ubuntu, vendor := noblePairServer(t)
	roots := map[string]*fixtureArchive{"/apt/": ubuntu, "/apt/vendor/": vendor}

	for root, up := range roots {
		for _, rest := range []string{"dists/noble/InRelease", "dists/noble/Release", "dists/noble/" + packagesPath, fixtureDeb} {
			want, _ := up.object(rest)
			if code, body := mirrorGet(t, s, root+rest); code != http.StatusOK || string(body) != want {
				t.Errorf("GET %s%s = %d %q, want 200 and that upstream's bytes %q", root, rest, code, body, want)
			}
		}
	}
	if a, b := ubuntu.count("dists/noble/InRelease"), vendor.count("dists/noble/InRelease"); a != 1 || b != 1 {
		t.Errorf("InRelease fetched %d times from Ubuntu and %d from the vendor, want once each", a, b)
	}

	ctx := t.Context()
	pins, err := s.auditDB.ListChecksums(ctx, manifest.TypeApt, "nginx")
	if err != nil {
		t.Fatalf("list apt checksums: %v", err)
	}
	pinned := map[string]string{}
	for _, pin := range pins {
		pinned[pin.ObjectKey] = pin.Value
	}
	for archive, up := range map[string]*fixtureArchive{"": ubuntu, "vendor": vendor} {
		body, _ := up.object(fixtureDeb)
		sum := sha256.Sum256([]byte(body))
		want := hex.EncodeToString(sum[:])
		key := manifest.AptArchiveKey(archive, fixtureDeb)
		st, conflict := s.aptPoolParagraph(ctx, key)
		if conflict != nil || st == nil || st.sha256 != want {
			t.Fatalf("paragraph for %s = %+v %+v, want the one listing %s", key, st, conflict, want)
		}
		if wantKey, _ := s.cfg.AptSuiteAt(archive, "noble"); st.codename != wantKey {
			t.Errorf("paragraph for %s comes from %q, want %q", key, st.codename, wantKey)
		}
		if pinned[key] != want {
			t.Errorf("pin on %s = %q, want its own paragraph's %s", key, pinned[key], want)
		}
	}
}

// F122 requirements 2 and 4: a hide on a package in vendor/noble withdraws it
// from the vendor's index and pool and leaves Ubuntu's same-named package
// served in noble.
func TestQualifiedAptSuiteHideStaysInItsArchive(t *testing.T) {
	s, _, _ := noblePairServer(t)
	ctx := t.Context()
	codenames, err := s.locateMirroredAptVersion(ctx, "nginx", "1.24.0-2ubuntu7.1")
	if err != nil || strings.Join(codenames, " ") != "noble "+vendorNoble {
		t.Fatalf("locate nginx = %v %v, want both suites listing it", codenames, err)
	}
	if err := s.auditDB.InsertAptMirrorHide(ctx, audit.AptMirrorHide{
		Name: "nginx", Version: "1.24.0-2ubuntu7.1", Codenames: []string{vendorNoble}, HiddenBy: "tester",
	}); err != nil {
		t.Fatalf("record the hide: %v", err)
	}
	s.rebuildAptSnapshot(context.Background())

	if code, body := mirrorGet(t, s, "/apt/vendor/dists/noble/"+packagesPath); code != http.StatusOK || strings.Contains(string(body), "Package: nginx") {
		t.Errorf("GET the vendor's Packages = %d, want 200 without the hidden nginx:\n%s", code, body)
	}
	if code, body := mirrorGet(t, s, "/apt/vendor/"+fixtureDeb); code != http.StatusForbidden {
		t.Errorf("GET the vendor's nginx .deb = %d, want 403 for the hidden version:\n%s", code, body)
	}
	if code, body := mirrorGet(t, s, "/apt/dists/noble/"+packagesPath); code != http.StatusOK || !strings.Contains(string(body), "Package: nginx") {
		t.Errorf("GET Ubuntu's Packages = %d, want 200 still listing nginx:\n%s", code, body)
	}
	if code, body := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Errorf("GET Ubuntu's nginx .deb = %d, want 200: the hide is the vendor's:\n%s", code, body)
	}
	if s.aptMirrorRewritten("noble") || !s.aptMirrorRewritten(vendorNoble) {
		t.Errorf("rewritten noble=%v vendor/noble=%v, want only the vendor's", s.aptMirrorRewritten("noble"), s.aptMirrorRewritten(vendorNoble))
	}
}

// F122 requirement 2: /api/v1/status renders one block per (archive,
// codename), each at its own root with the codename as its suite.
func TestQualifiedAptSuiteStatusBlocks(t *testing.T) {
	s, _, _ := noblePairServer(t)
	st := s.aptStatusFor(nil)
	var got []string
	for _, src := range st.Sources {
		if src.Mirrored {
			got = append(got, src.Archive+"|"+src.Suite+"|"+src.OneLine)
		}
	}
	want := []string{
		"|noble|deb " + aptPlaceholderBase(st) + "/apt/ noble main restricted universe multiverse",
		"vendor|noble|deb " + aptPlaceholderBase(st) + "/apt/vendor/ noble main restricted universe multiverse",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("mirrored status blocks =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func aptPlaceholderBase(st aptStatus) string {
	return strings.TrimSuffix(st.Sources[0].URI, "/apt/")
}

// pairVendorServer mirrors Ubuntu's noble with no key beside a vendor's noble
// carrying its own signing key.
func pairVendorServer(t *testing.T) (*Server, *profileFixture, *vendorKeyHost) {
	t.Helper()
	s := hostedServer(t)
	s.cfg.PublicURL = "http://bodega.example.com:8080"
	vendor := newVendorKeyHost(t, "vendor")
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{
		"noble": {{URL: "https://archive.ubuntu.com/ubuntu"}},
		vendorNoble: {{URL: "https://pkgs.vendor.example/stable/ubuntu", Components: []string{"main"},
			SigningKeyURL: vendor.URL(), SigningKeyFingerprint: vendor.fingerprint}},
	}
	return s, clientProfile(t, s), vendor
}

// F122 requirement 3: archives=vendor/noble adds a stanza reading noble from
// /apt/vendor/ with its own Signed-By:, beside the host's own noble stanza
// at /apt/, and the key that Signed-By: names is the vendor's.
func TestClientPlanQualifiedVendorArchive(t *testing.T) {
	s, f, vendor := pairVendorServer(t)
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=/noble&archives="+vendorNoble), manifest.TypeApt)
	paths := make([]string, len(recs))
	for i, r := range recs {
		paths[i] = r.Path
	}
	want := []string{clientconf.AptSourcesPath, "/etc/apt/sources.list.d/bodega-vendor_noble.sources", "/etc/apt/keyrings/bodega-vendor_noble.asc"}
	if strings.Join(paths, " ") != strings.Join(want, " ") {
		t.Fatalf("apt paths = %v, want %v", paths, want)
	}
	if own := fetchRecord(t, s, f.token, recs[0]); !strings.Contains(own, "URIs: http://bodega.example.com:8080/apt/\nSuites: noble\n") {
		t.Errorf("host stanza is not Ubuntu's noble at /apt/:\n%s", own)
	}
	stanza := fetchRecord(t, s, f.token, recs[1])
	wantStanza := "Types: deb\nURIs: http://bodega.example.com:8080/apt/vendor/\nSuites: noble\nComponents: main\nSigned-By: /etc/apt/keyrings/bodega-vendor_noble.asc\n"
	if stanza != wantStanza {
		t.Errorf("vendor stanza =\n%s\nwant\n%s", stanza, wantStanza)
	}
	if got := keyFingerprints(t, fetchRecord(t, s, f.token, recs[2])); got[0] != vendor.fingerprint {
		t.Errorf("planned key = %v, want the vendor's %s", got, vendor.fingerprint)
	}
}

// F122 requirement 2: a bare codename mirrored in two named archives is
// refused on the client query, naming the qualified forms.
func TestClientPlanRefusesAmbiguousBareCodename(t *testing.T) {
	s, f, _ := pairVendorServer(t)
	s.cfg.AptArchives = map[string][]string{"ubuntu": {"noble"}}
	code, body := clientGet(t, s, f.token, "/client/plan?os=linux&codename=noble")
	if code != http.StatusBadRequest || !strings.Contains(body, "ubuntu/noble, vendor/noble") {
		t.Fatalf("plan for codename=noble = %d %s, want 400 naming ubuntu/noble, vendor/noble", code, body)
	}
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=ubuntu/noble"), manifest.TypeApt)
	if len(recs) == 0 || !strings.Contains(fetchRecord(t, s, f.token, recs[0]), "URIs: http://bodega.example.com:8080/apt/ubuntu/\nSuites: noble\n") {
		t.Errorf("codename=ubuntu/noble does not plan Ubuntu's noble at /apt/ubuntu/: %+v", recs)
	}
}

func TestReviewF122MixedSpellingKeepsSecurityPocket(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "http://bodega.example.com:8080"
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{
		"noble":                 {{URL: "https://archive.ubuntu.com/ubuntu"}},
		"ubuntu/noble-security": {{URL: "https://security.ubuntu.com/ubuntu"}},
	}
	s.cfg.AptArchives = map[string][]string{"ubuntu": {"noble"}}
	f := clientProfile(t, s)
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=ubuntu/noble"), manifest.TypeApt)
	if len(recs) == 0 {
		t.Fatal("no apt stanza")
	}
	got := fetchRecord(t, s, f.token, recs[0])
	if !strings.Contains(got, "Suites: noble noble-security\n") {
		t.Fatalf("same-archive security pocket missing from client stanza:\n%s", got)
	}
}

func TestReviewF122FilteredCodenamesInDifferentArchives(t *testing.T) {
	s, _, _ := noblePairServer(t)
	s.cfg.AptUpstreams["ports/noble"] = s.cfg.AptUpstreams[vendorNoble]
	delete(s.cfg.AptUpstreams, vendorNoble)
	kr, err := aptsign.Generate("ubuntu security", "security@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatal(err)
	}
	objects := fixtureDistsFor(t, kr, "noble-security", fixturePackages(fixtureDeb, fixtureDebBody), "amd64")
	security := newFixtureArchive(t, objects)
	s.cfg.AptUpstreams["noble-security"] = []config.AptUpstream{{URL: security.URL()}}
	aptProfileBindBase(t, s, "web", "noble", audit.ExpansionBlock, "nginx")
	aptProfileBindBase(t, s, "security-web", "ports/noble", audit.ExpansionBlock, "nginx")
	for _, root := range []string{"/apt/", "/apt/ports/"} {
		path := root + "dists/noble-security-web/" + packagesPath
		if code, body := mirrorGet(t, s, path); code != http.StatusOK || !strings.Contains(string(body), "Package: nginx\n") {
			t.Errorf("GET %s = %d %s; want its own profile index", path, code, body)
		}
	}
}

// F122 requirement 2: the inverse of the mixed spelling above, a qualified
// base whose pocket is listed bare in apt_archives, is one choice too.
func TestMixedSpellingQualifiedBaseKeepsBarePocket(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "http://bodega.example.com:8080"
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{
		"ubuntu/noble":   {{URL: "https://archive.ubuntu.com/ubuntu"}},
		"noble-security": {{URL: "https://security.ubuntu.com/ubuntu"}},
	}
	s.cfg.AptArchives = map[string][]string{"ubuntu": {"noble-security"}}
	if base, ok := s.aptPocketBase("noble-security"); !ok || base != "ubuntu/noble" {
		t.Errorf("aptPocketBase(noble-security) = %q %v, want ubuntu/noble", base, ok)
	}
	f := clientProfile(t, s)
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=ubuntu/noble"), manifest.TypeApt)
	if len(recs) == 0 {
		t.Fatal("no apt stanza")
	}
	if got := fetchRecord(t, s, f.token, recs[0]); !strings.Contains(got, "URIs: http://bodega.example.com:8080/apt/ubuntu/\n") ||
		!strings.Contains(got, "Suites: noble noble-security\n") {
		t.Fatalf("same-archive pocket missing from client stanza:\n%s", got)
	}
}

// F122 requirement 2: with noble mirrored in the default archive and in a
// vendor's, a plan naming bare noble is refused with both spellings, and a
// stored default-archive key is written back as /noble so it resolves again.
func TestClientPlanRefusesBareCodenameBesideDefault(t *testing.T) {
	s, f, _ := pairVendorServer(t)
	code, body := clientGet(t, s, f.token, "/client/plan?os=linux&codename=noble")
	if code == http.StatusOK || !strings.Contains(body, "/noble, vendor/noble") {
		t.Errorf("GET /client/plan?codename=noble = %d %s; want a refusal listing /noble, vendor/noble", code, body)
	}
	if got := s.aptSuiteParam("noble"); got != "/noble" {
		t.Errorf("aptSuiteParam(noble) = %q, want /noble", got)
	}
}

// F122 requirement 2: a vendor's noble beside Ubuntu's claims none of
// Ubuntu's pockets, and Ubuntu's claims none of the vendor's.
func TestPocketsStayWithTheirOwnBase(t *testing.T) {
	s := hostedServer(t)
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{
		"noble":                  {{URL: "https://archive.ubuntu.com/ubuntu"}},
		"noble-security":         {{URL: "https://security.ubuntu.com/ubuntu"}},
		"vendor/noble":           {{URL: "https://vendor.example/ubuntu"}},
		"vendor/noble-backports": {{URL: "https://vendor.example/ubuntu"}},
	}
	for base, want := range map[string]string{"noble": "noble-security", "vendor/noble": "vendor/noble-backports"} {
		if got := s.aptMirroredPockets(base); !slices.Equal(got, []string{want}) {
			t.Errorf("aptMirroredPockets(%s) = %v, want [%s]", base, got, want)
		}
	}
	for pocket, want := range map[string]string{"noble-security": "noble", "vendor/noble-backports": "vendor/noble"} {
		if got, ok := s.aptPocketBase(pocket); !ok || got != want {
			t.Errorf("aptPocketBase(%s) = %q %v, want %s", pocket, got, ok, want)
		}
	}
}

func TestReviewF122LegacyVendorBesideQualifiedDistribution(t *testing.T) {
	s, f, vendor := pairVendorServer(t)
	ubuntu := s.cfg.AptUpstreams["noble"]
	s.cfg.AptUpstreams["noble"] = s.cfg.AptUpstreams[vendorNoble]
	delete(s.cfg.AptUpstreams, vendorNoble)
	s.cfg.AptUpstreams["ubuntu/noble"] = ubuntu
	s.cfg.AptArchives = map[string][]string{"vendor": {"noble"}}
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=ubuntu/noble&archives=vendor/noble"), manifest.TypeApt)
	if len(recs) != 3 {
		t.Fatalf("apt plan = %+v; want distribution stanza, vendor stanza, vendor key", recs)
	}
	for _, rec := range recs {
		if rec.Action != planInstall {
			t.Fatalf("apt plan = %+v; want all records install", recs)
		}
	}
	if body := fetchRecord(t, s, f.token, recs[0]); !strings.Contains(body, "URIs: http://bodega.example.com:8080/apt/ubuntu/\nSuites: noble\n") {
		t.Errorf("distribution stanza = %s", body)
	}
	if body := fetchRecord(t, s, f.token, recs[1]); !strings.Contains(body, "URIs: http://bodega.example.com:8080/apt/vendor/\nSuites: noble\n") || !strings.Contains(body, "Signed-By: /etc/apt/keyrings/bodega-noble.asc\n") {
		t.Errorf("vendor stanza = %s", body)
	}
	if got := keyFingerprints(t, fetchRecord(t, s, f.token, recs[2])); got[0] != vendor.fingerprint {
		t.Errorf("vendor key = %v, want %s", got, vendor.fingerprint)
	}
}

func TestReviewF122QualifiedDuplicateStanzaRefused(t *testing.T) {
	s, f, _ := pairVendorServer(t)
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=vendor/noble&archives=vendor/noble"), manifest.TypeApt)
	for _, rec := range recs {
		if rec.Action == planRefuse {
			return
		}
	}
	t.Fatalf("apt plan = %+v; want refusal for two stanzas at the same (archive, codename) with different Signed-By", recs)
}

func TestReviewF122HideInSeparateSecurityArchive(t *testing.T) {
	s, _, _ := noblePairServer(t)
	delete(s.cfg.AptUpstreams, vendorNoble)
	kr, err := aptsign.Generate("security", "security@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatal(err)
	}
	securityVersion := "1.24.0-2ubuntu7.2"
	securityDeb := strings.ReplaceAll(fixtureDeb, "1.24.0-2ubuntu7.1", securityVersion)
	packages := strings.ReplaceAll(fixturePackages(securityDeb, fixtureDebBody), "1.24.0-2ubuntu7.1", securityVersion)
	objects := fixtureDistsFor(t, kr, "noble-security", packages, "amd64")
	security := newFixtureArchive(t, objects)
	s.cfg.AptUpstreams["noble-security"] = []config.AptUpstream{{URL: security.URL()}}
	s.cfg.AptArchives = map[string][]string{"security": {"noble-security"}}
	if got := s.aptMirroredPockets("noble"); !slices.Equal(got, []string{"noble-security"}) {
		t.Fatalf("pockets = %v, want security pocket in its own archive", got)
	}
	codenames, err := s.locateMirroredAptVersion(t.Context(), "nginx", securityVersion)
	if err != nil || !slices.Equal(codenames, []string{"noble-security"}) {
		t.Fatalf("locate security build = %v, %v; want noble-security alone", codenames, err)
	}
	if err := s.auditDB.InsertAptMirrorHide(t.Context(), audit.AptMirrorHide{
		Name: "nginx", Version: securityVersion, Codenames: codenames, HiddenBy: "tester",
	}); err != nil {
		t.Fatal(err)
	}
	s.rebuildAptSnapshot(context.Background())
	path := "/apt/security/dists/noble-security/" + packagesPath
	if code, body := mirrorGet(t, s, path); code != http.StatusOK || strings.Contains(string(body), "Package: nginx\n") {
		t.Errorf("GET %s = %d %s; want 200 with hidden nginx removed", path, code, body)
	}
	if code, body := mirrorGet(t, s, "/apt/security/"+securityDeb); code != http.StatusForbidden {
		t.Errorf("security pool = %d %s; want 403", code, body)
	}
}

func TestReviewF122GeneratedDefaultBesideVendor(t *testing.T) {
	s, f, _ := pairVendorServer(t)
	vendor := s.cfg.AptUpstreams[vendorNoble]
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{}
	s.cfg.AptCodename = "noble"
	s.cfg.AptSuites = []string{"noble"}
	want := "URIs: http://bodega.example.com:8080/apt/\nSuites: noble\n"
	if code, body := clientGet(t, s, f.token, "/client/apt?os=linux&codename=noble"); code != http.StatusOK || !strings.Contains(body, want) {
		t.Fatalf("before adding vendor: %d %s; want generated noble", code, body)
	}
	s.cfg.AptUpstreams[vendorNoble] = vendor
	code, body := clientGet(t, s, f.token, "/client/apt?os=linux&codename=/noble")
	if code != http.StatusOK || !strings.Contains(body, want) {
		t.Fatalf("GET /client/apt?os=linux&codename=/noble = %d %s; want generated noble at the default root", code, body)
	}
}

func TestReviewF122VendorAdditionKeepsSplitSecurity(t *testing.T) {
	s, f, _ := pairVendorServer(t)
	s.cfg.AptCodename = "house"
	s.cfg.AptSuites = []string{"house"}
	vendor := s.cfg.AptUpstreams[vendorNoble]
	delete(s.cfg.AptUpstreams, vendorNoble)
	s.cfg.AptUpstreams["noble-security"] = []config.AptUpstream{{URL: "https://security.ubuntu.com/ubuntu"}}
	s.cfg.AptArchives = map[string][]string{"security": {"noble-security"}}
	before := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=noble"), manifest.TypeApt)
	if len(before) != 1 || before[0].Action != planInstall {
		t.Fatalf("before adding vendor = %+v; want one main source file", before)
	}
	wantSecurity := "URIs: http://bodega.example.com:8080/apt/security/\nSuites: noble-security\n"
	if body := fetchRecord(t, s, f.token, before[0]); !strings.Contains(body, wantSecurity) {
		t.Fatalf("before adding vendor, security pocket missing: %s", body)
	}
	s.cfg.AptUpstreams[vendorNoble] = vendor
	after := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=/noble&archives=vendor/noble"), manifest.TypeApt)
	for _, rec := range after {
		if rec.Action == planRefuse {
			if !strings.Contains(rec.Reason, "noble-security") {
				t.Fatalf("refusal does not identify the unresolved pocket: %+v", rec)
			}
			return
		}
	}
	for _, rec := range after {
		if rec.Path == clientconf.AptSourcesPath && rec.Action == planInstall {
			if body := fetchRecord(t, s, f.token, rec); strings.Contains(body, wantSecurity) {
				return
			} else {
				t.Fatalf("adding vendor/noble silently removes the existing security pocket from the installed main file:\n%s\nwant its security stanza retained, or an explicit refusal", body)
			}
		}
	}
	t.Fatalf("no main source or refusal: %+v", after)
}

func TestReviewF122VendorAdditionKeepsProfileSecurity(t *testing.T) {
	s, _, _ := noblePairServer(t)
	s.cfg.PublicURL = "http://bodega.example.com:8080"
	vendor := s.cfg.AptUpstreams[vendorNoble]
	delete(s.cfg.AptUpstreams, vendorNoble)
	kr, err := aptsign.Generate("security", "security@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatal(err)
	}
	security := newFixtureArchive(t, fixtureDistsFor(t, kr, "noble-security", fixturePackages(fixtureDeb, fixtureDebBody), "amd64"))
	s.cfg.AptUpstreams["noble-security"] = []config.AptUpstream{{URL: security.URL()}}
	s.cfg.AptArchives = map[string][]string{"security": {"noble-security"}}
	f := aptProfileBindBase(t, s, "web", "noble", audit.ExpansionBlock, "nginx")
	wantSecurity := "URIs: http://bodega.example.com:8080/apt/security/\nSuites: noble-security-web\n"
	before := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=noble"), manifest.TypeApt)
	if len(before) == 0 || before[0].Action != planInstall || !strings.Contains(fetchRecord(t, s, f.token, before[0]), wantSecurity) {
		t.Fatalf("before adding vendor, filtered security pocket missing: %+v", before)
	}
	s.cfg.AptUpstreams[vendorNoble] = vendor
	s.rebuildAptSnapshot(context.Background())
	after := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=/noble"), manifest.TypeApt)
	for _, rec := range after {
		if rec.Action == planRefuse {
			if !strings.Contains(rec.Reason, "noble-security") {
				t.Fatalf("refusal does not identify the unresolved pocket: %+v", rec)
			}
			return
		}
	}
	for _, rec := range after {
		if rec.Path == clientconf.AptSourcesPath && rec.Action == planInstall {
			if body := fetchRecord(t, s, f.token, rec); strings.Contains(body, wantSecurity) {
				return
			} else {
				t.Fatalf("adding vendor/noble silently removes the existing filtered security pocket:\n%s\nwant its security stanza retained, or an explicit refusal", body)
			}
		}
	}
	t.Fatalf("no main source or refusal: %+v", after)
}

func TestReviewF122StatusKeepsSplitSecurity(t *testing.T) {
	s, _, _ := noblePairServer(t)
	s.cfg.PublicURL = "http://bodega.example.com:8080"
	vendor := s.cfg.AptUpstreams[vendorNoble]
	delete(s.cfg.AptUpstreams, vendorNoble)
	kr, err := aptsign.Generate("security", "security@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatal(err)
	}
	security := newFixtureArchive(t, fixtureDistsFor(t, kr, "noble-security", fixturePackages(fixtureDeb, fixtureDebBody), "amd64"))
	s.cfg.AptUpstreams["noble-security"] = []config.AptUpstream{{URL: security.URL()}}
	s.cfg.AptArchives = map[string][]string{"security": {"noble-security"}}
	f := aptProfileBindBase(t, s, "web", "noble", audit.ExpansionBlock, "nginx")
	read := func() *aptStatus {
		t.Helper()
		code, body := f.get(t, "/api/v1/status")
		if code != http.StatusOK {
			t.Fatalf("status = %d %s", code, body)
		}
		var status struct {
			Apt aptStatus `json:"apt"`
		}
		if err := json.Unmarshal([]byte(body), &status); err != nil {
			t.Fatal(err)
		}
		return &status.Apt
	}
	want := "URIs: http://bodega.example.com:8080/apt/security/\nSuites: noble-security-web\n"
	before := read()
	if before.Host == nil || !strings.Contains(before.Host.Deb822, want) {
		t.Fatalf("before adding vendor: %+v; want security stanza", before.Host)
	}
	s.cfg.AptUpstreams[vendorNoble] = vendor
	s.rebuildAptSnapshot(context.Background())
	after := read()
	if after.Host != nil && !strings.Contains(after.Host.Deb822, want) {
		t.Fatalf("status still recommends a host stanza after silently removing its security pocket:\n%s\nwant the complete stanza or no host recommendation", after.Host.Deb822)
	}
}

func TestReviewF122PackageSourcesKeepGeneratedArchive(t *testing.T) {
	s, _, _ := pairVendorServer(t)
	vendor := s.cfg.AptUpstreams[vendorNoble]
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{}
	s.cfg.AptCodename = "noble"
	s.cfg.AptSuites = []string{"noble"}
	pm := &manifest.PackageManifest{Type: manifest.TypeApt, Name: "local-widget",
		Versions: []manifest.VersionEntry{{Version: "1.0", Suites: []string{"noble"}}}}
	if err := s.store.SavePackage(t.Context(), pm); err != nil {
		t.Fatal(err)
	}
	read := func() []clientconf.File {
		t.Helper()
		code, body := mirrorGet(t, s, "/api/v1/packages/apt/local-widget")
		if code != http.StatusOK {
			t.Fatalf("package API = %d %s", code, body)
		}
		var payload packageResponse
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		return payload.ClientConfig
	}
	want := "URIs: http://bodega.example.com:8080/apt/\nSuites: noble\n"
	before := read()
	if len(before) != 1 || !strings.Contains(before[0].Content, want) {
		t.Fatalf("before adding vendor: %+v; want generated noble alone", before)
	}
	s.cfg.AptUpstreams[vendorNoble] = vendor
	after := read()
	var content strings.Builder
	for _, file := range after {
		content.WriteString(file.Content)
	}
	if len(after) != 1 || !strings.Contains(after[0].Content, want) {
		t.Fatalf("package API added another publisher's source for a package published only to generated noble:\n%s", content.String())
	}
}
