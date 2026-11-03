package provenance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

const (
	helmChart   = "podinfo"
	helmVersion = "6.7.0"
	helmFile    = helmChart + "-" + helmVersion + ".tgz"
)

func newHelmKey(t *testing.T, cfg *packet.Config) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("Chart Publisher", "", "charts@example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// writeHelmKeyring writes the public half of keys to a 0600 file, armored or
// binary.
func writeHelmKeyring(t *testing.T, armored bool, keys ...*openpgp.Entity) string {
	t.Helper()
	var buf bytes.Buffer
	var w interface {
		Write([]byte) (int, error)
		Close() error
	}
	if armored {
		aw, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
		if err != nil {
			t.Fatal(err)
		}
		w = aw
	}
	for _, e := range keys {
		var err error
		if w != nil {
			err = e.Serialize(w)
		} else {
			err = e.Serialize(&buf)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if w != nil {
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "keyring.gpg")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func helmChartArchive(t *testing.T, chartYAML string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: helmChart + "/Chart.yaml", Mode: 0o644, Size: int64(len(chartYAML)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write([]byte(chartYAML))
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// helmProv is a .prov in Helm's format, clearsigned by signer at cfg's time.
func helmProv(t *testing.T, signer *openpgp.Entity, cfg *packet.Config, chartYAML string, files map[string]string) []byte {
	t.Helper()
	var text strings.Builder
	text.WriteString(chartYAML)
	text.WriteString("\n...\nfiles:\n")
	for name, digest := range files {
		fmt.Fprintf(&text, "  %s: %s\n", name, digest)
	}
	var out bytes.Buffer
	w, err := clearsign.Encode(&out, signer.PrivateKey, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(text.String()))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// chartRepo is a loopback classic chart repository whose handlers a test
// sets per path, counting every request.
type chartRepo struct {
	*httptest.Server
	mu     sync.Mutex
	routes map[string]http.HandlerFunc
	hits   int
}

func newChartRepo(t *testing.T) *chartRepo {
	t.Helper()
	r := &chartRepo{routes: map[string]http.HandlerFunc{}}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.hits++
		h, ok := r.routes[req.URL.Path]
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, req)
			return
		}
		h(w, req)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *chartRepo) serve(path string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[path] = func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }
}

func (r *chartRepo) status(path string, code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[path] = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

// helmFixture is one signed chart under /charts/ of a loopback repository,
// with helm_keyrings naming the signer's key for the whole host.
type helmFixture struct {
	repo    *chartRepo
	key     *openpgp.Entity
	keyring string
	chart   []byte
	chartY  string
	v       *Verifier
}

func newHelmFixture(t *testing.T) *helmFixture {
	t.Helper()
	f := &helmFixture{repo: newChartRepo(t), key: newHelmKey(t, nil)}
	f.chartY = "apiVersion: v2\nname: " + helmChart + "\nversion: " + helmVersion + "\n"
	f.chart = helmChartArchive(t, f.chartY)
	f.keyring = writeHelmKeyring(t, false, f.key)
	f.repo.serve("/charts/"+helmFile, f.chart)
	f.repo.serve("/charts/"+helmFile+".prov", helmProv(t, f.key, nil, f.chartY, map[string]string{helmFile: "sha256:" + sha256Hex(f.chart)}))
	f.v = &Verifier{HTTP: &http.Client{Transport: loopbackOnly{t}}, HelmKeyrings: map[string]string{f.repo.URL + "/": f.keyring}}
	return f
}

func (f *helmFixture) check(t *testing.T, ve manifest.VersionEntry) Evidence {
	t.Helper()
	c := &Checker{Verifier: f.v}
	if ve.Version == "" {
		ve.Version = helmVersion
	}
	if ve.URL == "" {
		ve.URL = f.repo.URL + "/charts"
	}
	r := c.Check(context.Background(), &manifest.PackageManifest{Type: manifest.TypeHelm, Name: helmChart}, &ve)
	if r.Provenance == nil {
		t.Fatalf("no provenance recorded: %+v", r)
	}
	return Evidence{UpstreamProvenance: *r.Provenance, Detail: r.Reason, NoKeyring: r.Details[audit.DetailNoKeyring] == true}
}

func wantOutcome(t *testing.T, ev Evidence, outcome string, fragments ...string) {
	t.Helper()
	if ev.Outcome != outcome {
		t.Fatalf("outcome = %s (%s), want %s", ev.Outcome, ev.Detail, outcome)
	}
	for _, frag := range fragments {
		if !strings.Contains(ev.Detail, frag) {
			t.Errorf("detail does not name %q: %s", frag, ev.Detail)
		}
	}
}

func TestHelmProvVerifies(t *testing.T) {
	for _, armored := range []bool{false, true} {
		t.Run(fmt.Sprintf("armored=%v", armored), func(t *testing.T) {
			f := newHelmFixture(t)
			f.keyring = writeHelmKeyring(t, armored, f.key)
			f.v.HelmKeyrings[f.repo.URL+"/"] = f.keyring
			ev := f.check(t, manifest.VersionEntry{})
			wantOutcome(t, ev, audit.ProvenanceVerified, helmFile)
			fpr := strings.ToUpper(hex.EncodeToString(f.key.PrimaryKey.Fingerprint))
			if ev.SignerFingerprint != fpr || len(fpr) != 40 {
				t.Errorf("signer_fingerprint = %q, want %q", ev.SignerFingerprint, fpr)
			}
			if ev.SubjectDigest != "sha256:"+sha256Hex(f.chart) {
				t.Errorf("subject_digest = %q", ev.SubjectDigest)
			}
			if ev.SourceRepositoryURI != "" || ev.WorkflowRef != "" || ev.BuilderID != "" {
				t.Errorf("a .prov names no repository or builder, got %+v", ev.UpstreamProvenance)
			}
		})
	}
}

// An entry whose url is the archive itself reads the .prov beside that URL.
func TestHelmProvBesideADirectChartURL(t *testing.T) {
	f := newHelmFixture(t)
	ev := f.check(t, manifest.VersionEntry{URL: f.repo.URL + "/charts/" + helmFile})
	wantOutcome(t, ev, audit.ProvenanceVerified)
}

func TestHelmProvNotPublishedIsUnavailable(t *testing.T) {
	f := newHelmFixture(t)
	delete(f.repo.routes, "/charts/"+helmFile+".prov")
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceUnavailable, f.repo.URL+"/charts/"+helmFile+".prov", "404")
}

func TestHelmProvServerErrorIsUnknown(t *testing.T) {
	f := newHelmFixture(t)
	f.repo.status("/charts/"+helmFile+".prov", http.StatusInternalServerError)
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceUnknown, f.repo.URL+"/charts/"+helmFile+".prov", "HTTP 500")
}

func TestHelmProvOverTheCapIsUnknown(t *testing.T) {
	f := newHelmFixture(t)
	f.repo.serve("/charts/"+helmFile+".prov", bytes.Repeat([]byte("x"), MaxHelmProvBytes+1))
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceUnknown, "larger than the 1 MiB cap")
}

func TestHelmProvNotClearsignedIsUnknown(t *testing.T) {
	f := newHelmFixture(t)
	f.repo.serve("/charts/"+helmFile+".prov", []byte(f.chartY+"\n...\nfiles:\n  "+helmFile+": sha256:"+sha256Hex(f.chart)+"\n"))
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceUnknown, "not an OpenPGP clearsigned message")
}

func TestHelmProvWithNoKeyringIsUnknown(t *testing.T) {
	f := newHelmFixture(t)
	f.v.HelmKeyrings = map[string]string{"https://charts.elsewhere.example/": f.keyring}
	ev := f.check(t, manifest.VersionEntry{})
	chartURL := f.repo.URL + "/charts/" + helmFile
	keyID := fmt.Sprintf("%016X", f.key.PrimaryKey.KeyId)
	wantOutcome(t, ev, audit.ProvenanceUnknown,
		chartURL+".prov is signed by key "+keyID+", and helm_keyrings names no keyring for this repository, so the signature was not checked; add the publisher's public key under a helm_keyrings prefix that matches "+chartURL)
	if !ev.NoKeyring {
		t.Errorf("Details[%s] not set", audit.DetailNoKeyring)
	}
}

func TestHelmProvSignedOutsideTheKeyringIsInvalid(t *testing.T) {
	f := newHelmFixture(t)
	other := newHelmKey(t, nil)
	f.repo.serve("/charts/"+helmFile+".prov", helmProv(t, other, nil, f.chartY, map[string]string{helmFile: "sha256:" + sha256Hex(f.chart)}))
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceInvalid,
		fmt.Sprintf("%016X", other.PrimaryKey.KeyId), f.keyring, "rotated", "admits no override")
}

func TestHelmProvByAnExpiredKeyIsInvalid(t *testing.T) {
	past := func() time.Time { return time.Now().Add(-48 * time.Hour) }
	cfg := &packet.Config{Time: past, KeyLifetimeSecs: 3600}
	f := newHelmFixture(t)
	f.key = newHelmKey(t, cfg)
	f.v.HelmKeyrings[f.repo.URL+"/"] = writeHelmKeyring(t, false, f.key)
	f.repo.serve("/charts/"+helmFile+".prov", helmProv(t, f.key, &packet.Config{Time: past}, f.chartY, map[string]string{helmFile: "sha256:" + sha256Hex(f.chart)}))
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceInvalid, fmt.Sprintf("%016X", f.key.PrimaryKey.KeyId))
}

func TestHelmProvTamperedPlaintextIsInvalid(t *testing.T) {
	f := newHelmFixture(t)
	prov := helmProv(t, f.key, nil, f.chartY, map[string]string{helmFile: "sha256:" + sha256Hex(f.chart)})
	prov = bytes.Replace(prov, []byte("version: "+helmVersion), []byte("version: 6.7.9"), 1)
	f.repo.serve("/charts/"+helmFile+".prov", prov)
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceInvalid, "does not verify", f.keyring)
}

func TestHelmProvFilesMissingTheChartIsInvalid(t *testing.T) {
	f := newHelmFixture(t)
	f.repo.serve("/charts/"+helmFile+".prov", helmProv(t, f.key, nil, f.chartY, map[string]string{"other-1.0.0.tgz": "sha256:" + sha256Hex(f.chart)}))
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceInvalid, "no entry for "+helmFile, "other-1.0.0.tgz")

	f.repo.serve("/charts/"+helmFile+".prov", helmProv(t, f.key, nil, f.chartY, map[string]string{helmFile: "md5:abc"}))
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceInvalid, helmFile, `"md5:abc"`, "64 hex digits")
}

func TestHelmProvDigestDiffersFromTheEntryChecksum(t *testing.T) {
	f := newHelmFixture(t)
	other := strings.Repeat("ab", 32)
	ev := f.check(t, manifest.VersionEntry{Checksum: &manifest.Checksum{Algorithm: "sha256", Value: other}})
	wantOutcome(t, ev, audit.ProvenanceInvalid, "sha256:"+sha256Hex(f.chart), "sha256:"+other, "the entry records")
	if f.repo.hits != 1 {
		t.Errorf("%d requests; with the entry's checksum only the .prov is read", f.repo.hits)
	}
}

func TestHelmProvDigestDiffersFromTheDownloadedChart(t *testing.T) {
	f := newHelmFixture(t)
	served := helmChartArchive(t, f.chartY+"description: swapped\n")
	f.repo.serve("/charts/"+helmFile, served)
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceInvalid, "sha256:"+sha256Hex(f.chart), "sha256:"+sha256Hex(served))
}

func TestHelmChartDownloadFailureIsUnknown(t *testing.T) {
	f := newHelmFixture(t)
	f.repo.status("/charts/"+helmFile, http.StatusBadGateway)
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceUnknown, "downloading "+f.repo.URL+"/charts/"+helmFile, "HTTP 502")
}

func TestHelmKeyringUnloadableAtAdmissionIsUnknown(t *testing.T) {
	f := newHelmFixture(t)
	if err := os.Chmod(f.keyring, 0o666); err != nil {
		t.Fatal(err)
	}
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceUnknown, f.keyring, "writable by group or others")
}

func TestHelmOCIAndURLlessChartsFetchNothing(t *testing.T) {
	f := newHelmFixture(t)
	c := &Checker{Verifier: f.v}
	for _, tc := range []struct{ name, url, want string }{
		{"ghcr.io/stefanprodan/podinfo", "", "bodega does not read the provenance layer of a chart served over OCI yet"},
		{helmChart, "", "the entry names no chart URL to read a .prov beside"},
	} {
		r := c.Check(context.Background(), &manifest.PackageManifest{Type: manifest.TypeHelm, Name: tc.name}, &manifest.VersionEntry{Version: helmVersion, URL: tc.url})
		if r.Provenance == nil || r.Provenance.Outcome != audit.ProvenanceUnavailable || !strings.Contains(r.Reason, tc.want) {
			t.Errorf("%s: %+v, want unavailable saying %q", tc.name, r, tc.want)
		}
	}
	if f.repo.hits != 0 {
		t.Errorf("%d requests made", f.repo.hits)
	}
}

// Two prefixes on one host: each chart verifies against the key its longest
// matching prefix names, and a chart under the longer prefix signed by the
// shorter prefix's key does not.
func TestHelmKeyringLongestPrefixWins(t *testing.T) {
	f := newHelmFixture(t)
	team := newHelmKey(t, nil)
	teamKeyring := writeHelmKeyring(t, false, team)
	f.v.HelmKeyrings[f.repo.URL+"/team/"] = teamKeyring
	sum := map[string]string{helmFile: "sha256:" + sha256Hex(f.chart)}
	f.repo.serve("/team/"+helmFile, f.chart)

	f.repo.serve("/team/"+helmFile+".prov", helmProv(t, team, nil, f.chartY, sum))
	ev := f.check(t, manifest.VersionEntry{URL: f.repo.URL + "/team"})
	wantOutcome(t, ev, audit.ProvenanceVerified, teamKeyring)
	if ev.SignerFingerprint != strings.ToUpper(hex.EncodeToString(team.PrimaryKey.Fingerprint)) {
		t.Errorf("team chart signer = %s", ev.SignerFingerprint)
	}
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceVerified, f.keyring)

	f.repo.serve("/team/"+helmFile+".prov", helmProv(t, f.key, nil, f.chartY, sum))
	wantOutcome(t, f.check(t, manifest.VersionEntry{URL: f.repo.URL + "/team"}), audit.ProvenanceInvalid, teamKeyring)
	f.repo.serve("/charts/"+helmFile+".prov", helmProv(t, team, nil, f.chartY, sum))
	wantOutcome(t, f.check(t, manifest.VersionEntry{}), audit.ProvenanceInvalid, f.keyring)
}

// pinCounter fails the test on any pin read or write.
type pinCounter struct {
	*fakeStore
	reads, writes int
}

func (p *pinCounter) GetProvenancePin(ctx context.Context, typ, name string) (audit.ProvenancePin, error) {
	p.reads++
	return p.fakeStore.GetProvenancePin(ctx, typ, name)
}

func (p *pinCounter) PinProvenance(ctx context.Context, pin audit.ProvenancePin) (audit.ProvenancePin, bool, error) {
	p.writes++
	return p.fakeStore.PinProvenance(ctx, pin)
}

func TestHelmVerifiedTakesNoPin(t *testing.T) {
	f := newHelmFixture(t)
	const next = "6.8.0"
	nextFile := helmChart + "-" + next + ".tgz"
	f.repo.serve("/charts/"+nextFile, f.chart)
	f.repo.serve("/charts/"+nextFile+".prov", helmProv(t, f.key, nil, f.chartY, map[string]string{nextFile: "sha256:" + sha256Hex(f.chart)}))

	store := &pinCounter{fakeStore: &fakeStore{}}
	c := &Checker{Store: store, Verifier: f.v}
	pm := &manifest.PackageManifest{Type: manifest.TypeHelm, Name: helmChart}
	for _, v := range []string{helmVersion, next} {
		r := c.Check(context.Background(), pm, &manifest.VersionEntry{Version: v, URL: f.repo.URL + "/charts"})
		if r.Provenance == nil || r.Provenance.Outcome != audit.ProvenanceVerified {
			t.Fatalf("%s: %+v", v, r)
		}
	}
	if changed := c.Commit(context.Background()); changed != nil {
		t.Errorf("Commit changed %d verdicts", len(changed))
	}
	if store.reads != 0 || store.writes != 0 {
		t.Errorf("pin read %d times and written %d times; a helm signature is held to the keyring alone", store.reads, store.writes)
	}
}

func TestLoadHelmKeyringRefusals(t *testing.T) {
	key := newHelmKey(t, nil)
	good := writeHelmKeyring(t, false, key)
	write := func(name string, body []byte, mode os.FileMode) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	goodBytes, _ := os.ReadFile(good)
	var priv bytes.Buffer
	if err := key.SerializePrivate(&priv, nil); err != nil {
		t.Fatal(err)
	}
	var armoredPriv bytes.Buffer
	aw, _ := armor.Encode(&armoredPriv, openpgp.PrivateKeyType, nil)
	_, _ = aw.Write(priv.Bytes())
	_ = aw.Close()
	var empty bytes.Buffer
	ew, _ := armor.Encode(&empty, openpgp.PublicKeyType, nil)
	_ = ew.Close()

	for _, tc := range []struct {
		name, path, want string
	}{
		{"missing", filepath.Join(t.TempDir(), "absent.gpg"), "cannot be read"},
		{"directory", t.TempDir(), "not a regular file"},
		{"group writable", write("gw.gpg", goodBytes, 0o620), "chmod go-w"},
		{"other writable", write("ow.gpg", goodBytes, 0o602), "writable by group or others"},
		{"garbage", write("junk.gpg", []byte("not a keyring at all"), 0o600), "parses as neither a binary keyring"},
		{"no public key", write("empty.asc", empty.Bytes(), 0o600), "holds no public key"},
		{"binary private key", write("priv.gpg", priv.Bytes(), 0o600), "holds private key material"},
		{"armored private key", write("priv.asc", armoredPriv.Bytes(), 0o600), "holds private key material"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadHelmKeyring(tc.path, "https://charts.example.com/")
			if err == nil {
				t.Fatal("accepted")
			}
			for _, want := range []string{tc.path, tc.want, `helm_keyrings["https://charts.example.com/"]`} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not name %q: %v", want, err)
				}
			}
		})
	}
	if keys, err := LoadHelmKeyring(good, ""); err != nil || len(keys) != 1 {
		t.Errorf("a public keyring: %d keys, %v", len(keys), err)
	}
}

func TestHelmIsCovered(t *testing.T) {
	if !IsCovered(manifest.TypeHelm) || UncoveredReason(manifest.TypeHelm) != "" {
		t.Errorf("helm: covered=%v, uncovered reason %q", IsCovered(manifest.TypeHelm), UncoveredReason(manifest.TypeHelm))
	}
}
