package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ravinald/bodega/internal/aptsign"
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
