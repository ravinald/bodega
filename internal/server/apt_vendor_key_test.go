package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// vendorKeyHost serves one vendor's armored public key at /gpg.key and counts
// the fetches, so a test can tell a cached answer from a second download.
type vendorKeyHost struct {
	ts          *httptest.Server
	fingerprint string
	hits        atomic.Int64
}

func newVendorKeyHost(t *testing.T, name string) *vendorKeyHost {
	t.Helper()
	ring, err := aptsign.Generate(name, name+"@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate %s key: %v", name, err)
	}
	pub, err := ring.PublicKey()
	if err != nil {
		t.Fatalf("armor %s key: %v", name, err)
	}
	h := &vendorKeyHost{fingerprint: ring.Fingerprints()[0]}
	h.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gpg.key" {
			http.NotFound(w, r)
			return
		}
		h.hits.Add(1)
		_, _ = w.Write(pub)
	}))
	t.Cleanup(h.ts.Close)
	return h
}

func (h *vendorKeyHost) URL() string { return h.ts.URL + "/gpg.key" }

// vendorArchiveServer mirrors noble with no key, as the host's own
// distribution, beside two vendor codenames that carry one each: Grafana's
// stable and a PGDG suite naming no components.
func vendorArchiveServer(t *testing.T) (*Server, *profileFixture, *vendorKeyHost, *vendorKeyHost) {
	t.Helper()
	s := hostedServer(t)
	s.cfg.PublicURL = "http://bodega.example.com:8080"
	grafana := newVendorKeyHost(t, "grafana")
	pgdg := newVendorKeyHost(t, "pgdg")
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{
		"noble": {{URL: "https://archive.ubuntu.com/ubuntu"}},
		"stable": {{URL: "https://apt.grafana.com", Components: []string{"main"},
			SigningKeyURL: grafana.URL(), SigningKeyFingerprint: grafana.fingerprint}},
		"noble-pgdg": {{URL: "https://apt.postgresql.org/pub/repos/apt",
			SigningKeyURL: pgdg.URL(), SigningKeyFingerprint: pgdg.fingerprint}},
	}
	return s, clientProfile(t, s), grafana, pgdg
}

func keyFingerprints(t *testing.T, armored string) []string {
	t.Helper()
	_, found, err := aptsign.VendorKey([]byte(armored), "")
	if len(found) == 0 {
		t.Fatalf("served key does not parse: %v\n%s", err, armored)
	}
	return found
}

// E22 R2: a key whose fingerprint matches is served, and once verified it is
// served again with the vendor's host gone.
func TestAptVendorKeyServesAVerifiedKeyFromCache(t *testing.T) {
	s, _, grafana, _ := vendorArchiveServer(t)
	code, body := clientGet(t, s, "", "/apt/keys/stable.asc")
	if code != http.StatusOK {
		t.Fatalf("GET /apt/keys/stable.asc = %d: %s", code, body)
	}
	if got := keyFingerprints(t, body); len(got) != 1 || got[0] != grafana.fingerprint {
		t.Fatalf("served key fingerprints = %v, want only %s", got, grafana.fingerprint)
	}

	grafana.ts.Close()
	code, again := clientGet(t, s, "", "/apt/keys/stable.asc")
	if code != http.StatusOK || again != body {
		t.Fatalf("with the vendor gone, GET = %d, same body %v; want the cached key", code, again == body)
	}
	if n := grafana.hits.Load(); n != 1 {
		t.Errorf("vendor fetched %d times, want 1", n)
	}
}

// E22 R2: a key carrying another fingerprint is a 502, logged with both
// fingerprints and the URL, and never cached.
func TestAptVendorKeyRefusesAMismatchedFingerprint(t *testing.T) {
	s, _, grafana, pgdg := vendorArchiveServer(t)
	var logged bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logged, nil))
	up := s.cfg.AptUpstreams["stable"]
	up[0].SigningKeyFingerprint = pgdg.fingerprint

	for range 2 {
		if code, body := clientGet(t, s, "", "/apt/keys/stable.asc"); code != http.StatusBadGateway {
			t.Fatalf("GET with a mismatched key = %d: %s", code, body)
		}
	}
	if n := grafana.hits.Load(); n != 2 {
		t.Errorf("vendor fetched %d times, want 2: a refused key must not be cached", n)
	}
	for _, want := range []string{grafana.fingerprint, pgdg.fingerprint, grafana.URL()} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("log lacks %s:\n%s", want, logged.String())
		}
	}
}

// E22 R2: a codename with no key configured, mirrored or not, is a 404.
func TestAptVendorKeyIsNotFoundWithoutAKey(t *testing.T) {
	s, _, _, _ := vendorArchiveServer(t)
	for _, path := range []string{"/apt/keys/noble.asc", "/apt/keys/jammy.asc", "/apt/keys/stable.gpg"} {
		if code, body := clientGet(t, s, "", path); code != http.StatusNotFound {
			t.Errorf("GET %s = %d: %s", path, code, body)
		}
	}
}

// fetchRecord reads what a plan record's URL serves and checks it against the
// record's digest, which is what doctor and setup.sh do before writing.
func fetchRecord(t *testing.T, s *Server, token string, rec planRecord) string {
	t.Helper()
	path := strings.TrimPrefix(rec.URL, s.cfg.PublicURL)
	code, body := clientGet(t, s, token, path)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, code, body)
	}
	sum := sha256.Sum256([]byte(body))
	if got := hex.EncodeToString(sum[:]); got != rec.SHA256 {
		t.Fatalf("%s serves sha256 %s, plan says %s", rec.URL, got, rec.SHA256)
	}
	return body
}

// E22 R3: one archive adds its stanza and its key after the host's own
// stanza, each under a digest covering what its URL serves.
func TestClientPlanAddsOneVendorArchive(t *testing.T) {
	s, f, grafana, _ := vendorArchiveServer(t)
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=noble&archives=stable"), manifest.TypeApt)
	paths := make([]string, len(recs))
	for i, r := range recs {
		paths[i] = r.Path
	}
	want := []string{clientconf.AptSourcesPath, "/etc/apt/sources.list.d/bodega-stable.sources", "/etc/apt/keyrings/bodega-stable.asc"}
	if strings.Join(paths, " ") != strings.Join(want, " ") {
		t.Fatalf("apt paths = %v, want %v", paths, want)
	}
	stanza := fetchRecord(t, s, f.token, recs[1])
	wantStanza := "Types: deb\nURIs: http://bodega.example.com:8080/apt/\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/keyrings/bodega-stable.asc\n"
	if stanza != wantStanza {
		t.Errorf("stanza =\n%s\nwant\n%s", stanza, wantStanza)
	}
	if got := keyFingerprints(t, fetchRecord(t, s, f.token, recs[2])); got[0] != grafana.fingerprint {
		t.Errorf("planned key = %v, want %s", got, grafana.fingerprint)
	}
	if own := fetchRecord(t, s, f.token, recs[0]); !strings.Contains(own, "Suites: noble\n") {
		t.Errorf("host stanza changed by archives=:\n%s", own)
	}
}

// E22 R3: two archives each bring both files, and an archive naming no
// components takes the mirrored default.
func TestClientPlanAddsTwoVendorArchives(t *testing.T) {
	s, f, _, _ := vendorArchiveServer(t)
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux&codename=noble&archives=stable,noble-pgdg"), manifest.TypeApt)
	if len(recs) != 5 {
		t.Fatalf("apt records = %+v, want the host stanza and two per archive", recs)
	}
	for _, c := range []string{"stable", "noble-pgdg"} {
		var stanza, key bool
		for _, r := range recs {
			if r.Action != planInstall {
				t.Errorf("record %+v does not install", r)
			}
			stanza = stanza || r.Path == clientconf.AptArchiveSourcesPath(c)
			key = key || r.Path == clientconf.AptArchiveKeyPath(c)
		}
		if !stanza || !key {
			t.Errorf("%s: stanza %v, key %v; want both", c, stanza, key)
		}
	}
	pgdg := fetchRecord(t, s, f.token, recs[3])
	if !strings.Contains(pgdg, "Suites: noble-pgdg\n") || !strings.Contains(pgdg, "Components: main restricted universe multiverse\n") {
		t.Errorf("pgdg stanza =\n%s", pgdg)
	}
}

// E22 R3: a codename not mirrored, or mirrored without a key, is refused with
// the codenames that would work.
func TestClientPlanRefusesAnArchiveWithNoKey(t *testing.T) {
	s, f, _, _ := vendorArchiveServer(t)
	for _, c := range []string{"jammy", "noble"} {
		code, body := clientGet(t, s, f.token, "/client/plan?os=linux&codename=noble&archives=stable,"+c)
		if code != http.StatusBadRequest {
			t.Fatalf("archives=stable,%s = %d: %s", c, code, body)
		}
		for _, want := range []string{"cannot configure the apt archive " + c + ":", "Archives it configures: noble-pgdg, stable"} {
			if !strings.Contains(body, want) {
				t.Errorf("archives=stable,%s refusal lacks %q:\n%s", c, want, body)
			}
		}
	}
}

const vendorGrafanaDeb = "pool/main/g/grafana/grafana_10.4.2_amd64.deb"

// scopedVendorServer is vendorArchiveServer with noble and stable served by
// fixture archives of their own, and a second host bound to "edge", a profile
// scoping apt to noble that lists nginx and grafana and no vendor archive.
// The first host's profile states no apt rule, so it is unscoped.
func scopedVendorServer(t *testing.T) (s *Server, unscoped, scoped *profileFixture) {
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
	s, unscoped, _, _ = vendorArchiveServer(t)
	if s.aptSign.Load() == nil {
		t.Fatal("no apt signing key loaded; the filtered codename would be unsigned")
	}

	upstreamKR, err := aptsign.Generate("fixture archive", "archive@fixture.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate upstream key: %v", err)
	}
	nobleObjects := fixtureDistsFor(t, upstreamKR, "noble", aptProfilePackages(), "amd64")
	for rel, body := range aptProfilePool() {
		nobleObjects[rel] = body
	}
	stableObjects := fixtureDistsFor(t, upstreamKR, "stable", fixturePackages(vendorGrafanaDeb, "grafana bytes"), "amd64")
	stableObjects[vendorGrafanaDeb] = "grafana bytes"
	s.cfg.AptUpstreams["noble"][0].URL = newFixtureArchive(t, nobleObjects).URL()
	s.cfg.AptUpstreams["stable"][0].URL = newFixtureArchive(t, stableObjects).URL()
	// On, so a .deb one host fetched is a cache hit for the next, which is
	// the branch that resolves no archive unless it has to.
	s.cache = CacheConfig{Enabled: true, MetadataTTL: time.Hour}

	rule := closedRule(manifest.TypeApt, audit.VersionFloating, audit.ExpansionBlock)
	rule.AptBase = "noble"
	scoped = bindProfile(t, s, "edge", "edge-host", []audit.ProfileTypeRule{rule},
		[]audit.ProfileEntry{{Type: manifest.TypeApt, Name: "nginx"}, {Type: manifest.TypeApt, Name: "grafana"}})
	s.rebuildAptSnapshot(t.Context())
	return s, unscoped, scoped
}

// listArchives rewrites edge's apt rule to admit the named vendor archives and
// drops the cached profile set, as the SIGHUP after a profile write does.
func listArchives(t *testing.T, s *Server, archives ...string) {
	t.Helper()
	rule := closedRule(manifest.TypeApt, audit.VersionFloating, audit.ExpansionBlock)
	rule.Profile, rule.AptBase, rule.AptArchives = "edge", "noble", archives
	if err := s.auditDB.SetProfileTypeRule(t.Context(), rule); err != nil {
		t.Fatalf("list archives: %v", err)
	}
	s.refreshProfiles(t.Context())
}

func assertArchiveRefusal(t *testing.T, what string, code int, body string) {
	t.Helper()
	if code != http.StatusForbidden {
		t.Fatalf("%s = %d, want 403: %s", what, code, body)
	}
	for _, want := range []string{"stable", `profile "edge"`, "bodega profile set edge apt --archives stable"} {
		if !strings.Contains(body, want) {
			t.Errorf("%s refusal lacks %q:\n%s", what, want, body)
		}
	}
}

// E24 R2 and R4: a scoped host is refused archives= on the plan and on
// /client/apt until its profile lists the archive, and served after; the
// unscoped host is served throughout.
func TestScopedProfileGovernsVendorArchivesOnTheClientRoutes(t *testing.T) {
	s, unscoped, scoped := scopedVendorServer(t)
	const plan = "/client/plan?os=linux&codename=noble&archives=stable"
	const stanza = "/client/apt?os=linux&codename=noble&archive=stable"

	code, body := clientGet(t, s, scoped.token, plan)
	assertArchiveRefusal(t, "scoped plan", code, body)
	code, body = clientGet(t, s, scoped.token, stanza)
	assertArchiveRefusal(t, "scoped /client/apt?archive=", code, body)
	if code, body := clientGet(t, s, scoped.token, "/client/plan?os=linux&codename=noble"); code != http.StatusOK {
		t.Fatalf("scoped plan naming no archive = %d: %s", code, body)
	}

	hasArchive := func(token string) bool {
		for _, r := range planRecordFor(planJSON(t, s, token, "os=linux&codename=noble&archives=stable"), manifest.TypeApt) {
			if r.Path == clientconf.AptArchiveSourcesPath("stable") && r.Action == planInstall {
				return true
			}
		}
		return false
	}
	if !hasArchive(unscoped.token) {
		t.Error("the unscoped host's plan lost the stable archive")
	}

	listArchives(t, s, "stable")
	if !hasArchive(scoped.token) {
		t.Error("the scoped host's plan does not install stable once its profile lists it")
	}
	if code, body := clientGet(t, s, scoped.token, stanza); code != http.StatusOK || !strings.Contains(body, "Suites: stable\n") {
		t.Errorf("scoped /client/apt?archive=stable once listed = %d:\n%s", code, body)
	}
	if !hasArchive(unscoped.token) {
		t.Error("the unscoped host's plan lost the stable archive")
	}

	// A list naming another archive admits that one alone.
	listArchives(t, s, "noble-pgdg")
	code, body = clientGet(t, s, scoped.token, plan)
	if code != http.StatusForbidden || !strings.Contains(body, "--archives noble-pgdg,stable") {
		t.Errorf("scoped plan with only noble-pgdg listed = %d, want 403 keeping the listed one in the command:\n%s", code, body)
	}
}

// E24 R3 and R4: the mirrored dists/ tree and the pool refuse a scoped host a
// vendor codename its profile does not list, with a denied discovery row, so
// a stanza written by hand reaches nothing. The host's own distribution is
// served throughout, and so is the unscoped host.
func TestScopedProfileGovernsVendorArchivesOnTheAptRoutes(t *testing.T) {
	s, unscoped, scoped := scopedVendorServer(t)
	const inRelease = "/apt/dists/stable/InRelease"
	const pool = "/apt/" + vendorGrafanaDeb

	code, body := clientGet(t, s, scoped.token, inRelease)
	assertArchiveRefusal(t, "scoped "+inRelease, code, body)
	rows := waitForAptRows(t, s, audit.DecisionDenied, 1)
	if !strings.Contains(rows[0].PatternHint, "bodega profile set edge apt --archives stable") {
		t.Errorf("denied row = %+v, want the command that admits the archive as its hint", rows[0])
	}
	code, body = clientGet(t, s, scoped.token, pool)
	assertArchiveRefusal(t, "scoped "+pool, code, body)

	for _, path := range []string{inRelease, pool} {
		if code, body := clientGet(t, s, unscoped.token, path); code != http.StatusOK {
			t.Errorf("unscoped %s = %d: %s", path, code, body)
		}
	}
	// The pool path now has a remembered route, which must not let the
	// scoped host past.
	code, body = clientGet(t, s, scoped.token, pool)
	assertArchiveRefusal(t, "scoped "+pool+" after an unscoped fetch", code, body)

	for _, path := range []string{"/apt/dists/noble-edge/InRelease", "/apt/dists/noble/InRelease", "/apt/" + profileNginxDeb} {
		if code, body := clientGet(t, s, scoped.token, path); code != http.StatusOK {
			t.Errorf("scoped host's own distribution %s = %d: %s", path, code, body)
		}
	}

	listArchives(t, s, "stable")
	for _, path := range []string{inRelease, pool} {
		if code, body := clientGet(t, s, scoped.token, path); code != http.StatusOK {
			t.Errorf("scoped %s once listed = %d: %s", path, code, body)
		}
		if code, body := clientGet(t, s, unscoped.token, path); code != http.StatusOK {
			t.Errorf("unscoped %s = %d: %s", path, code, body)
		}
	}
}
