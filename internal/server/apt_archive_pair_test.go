package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
