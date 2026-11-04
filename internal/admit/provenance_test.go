package admit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/provenance"
)

// npmWithProvenance serves sigstore@3.0.0 with the bundle npm recorded for it
// and left-pad@1.3.0 with none, and points the provenance check at that stub
// and at the recorded Sigstore trusted root.
func npmWithProvenance(t *testing.T) string {
	t.Helper()
	td := filepath.Join("..", "provenance", "testdata")
	bundles, err := os.ReadFile(filepath.Join(td, "npm-sigstore-3.0.0.attestations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dist := map[string]any{"integrity": "sha512-PHMifhh3EN4loMcHCz6l3v/luzgT3za+9f8subGgeMNjbJjzH4Ij/YoX3Gvu+kaouJRIlVdTHHCREADYf+ZteA=="}
		switch r.URL.Path {
		case "/sigstore":
			dist["attestations"] = map[string]any{"url": srv.URL + "/att/sigstore@3.0.0",
				"provenance": map[string]any{"predicateType": provenance.SLSAProvenanceV1}}
			_ = json.NewEncoder(w).Encode(map[string]any{"versions": map[string]any{"3.0.0": map[string]any{"dist": dist}}})
		case "/left-pad":
			_ = json.NewEncoder(w).Encode(map[string]any{"versions": map[string]any{"1.3.0": map[string]any{"dist": dist}}})
		case "/att/sigstore@3.0.0":
			_, _ = w.Write(bundles)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	tr, err := provenance.LoadTrustedRootFile(filepath.Join(td, "trusted_root.json"))
	if err != nil {
		t.Fatal(err)
	}
	prev := NewProvenanceVerifier
	NewProvenanceVerifier = func(cfg *config.Config) *provenance.Verifier {
		v := prev(cfg)
		v.Root = func(context.Context) (root.TrustedMaterial, error) { return tr, nil }
		return v
	}
	t.Cleanup(func() { NewProvenanceVerifier = prev })
	return srv.URL
}

// An import records the outcome and the identity verified in the row's
// upstream_provenance check, pins the package, and refuses a version with no
// provenance once the action is block.
func TestAdmitRecordsUpstreamProvenance(t *testing.T) {
	f := newAdmissionFixture(t)
	registry := npmWithProvenance(t)
	entry := func(name, version string) *manifest.PackageManifest {
		return &manifest.PackageManifest{Type: manifest.TypeNpm, Name: name,
			Versions: []manifest.VersionEntry{{Version: version, URL: registry}}}
	}

	res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, entry("sigstore", "3.0.0"), "ravi")
	if res.Decision != Admitted {
		t.Fatalf("Decision = %v (%s)", res.Decision, res.Reason)
	}
	c := checkOf(t, f.rows(t, "sigstore")[0], audit.CheckUpstreamProvenance)
	if c.Status != audit.CheckPass || c.Action != policy.ActionWarn || c.Provenance == nil ||
		c.Provenance.Outcome != audit.ProvenanceVerified || c.Provenance.SourceRepositoryURI != "https://github.com/sigstore/sigstore-js" {
		t.Fatalf("upstream_provenance = %+v (%+v)", c, c.Provenance)
	}
	if pin, err := f.adb.GetProvenancePin(t.Context(), manifest.TypeNpm, "sigstore"); err != nil || pin.PinnedVersion != "3.0.0" {
		t.Errorf("pin = %+v, %v", pin, err)
	}

	res = Admit(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, entry("left-pad", "1.3.0"), "ravi")
	if res.Decision != Admitted || len(res.Warnings) != 0 {
		t.Fatalf("no provenance under warn: %v %v", res.Decision, res.Warnings)
	}
	if c := checkOf(t, f.rows(t, "left-pad")[0], audit.CheckUpstreamProvenance); c.Provenance.Outcome != audit.ProvenanceUnavailable || c.Status != audit.CheckPass {
		t.Errorf("left-pad under warn = %+v", c)
	}

	if err := f.adb.SetProvenancePolicy(t.Context(), audit.ProvenancePolicy{Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	res = Admit(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, entry("left-pad", "1.3.0"), "ravi")
	if res.Decision != PolicyBlocked || res.Check != audit.CheckUpstreamProvenance {
		t.Fatalf("no provenance under block: %v %q (%s)", res.Decision, res.Check, res.Reason)
	}
	if c := checkOf(t, f.rows(t, "left-pad")[0], audit.CheckUpstreamProvenance); c.Status != audit.CheckBlock || c.Action != policy.ActionBlock {
		t.Errorf("left-pad under block = %+v", c)
	}
}

// The builder's fetch and the proxy's fill admit through Fetch, which runs the
// same check and records it the same way.
func TestFetchRecordsUpstreamProvenance(t *testing.T) {
	f := newAdmissionFixture(t)
	registry := npmWithProvenance(t)
	cfg := *f.synced
	cfg.NpmUpstream = registry
	res := Fetch(t.Context(), f.adb, VersionCheckers(&cfg, f.adb), manifest.TypeNpm, "sigstore",
		manifest.VersionEntry{Version: "3.0.0", Mode: manifest.ModeProxy}, AllowListCheck(false, "sigstore", nil), Who{Identity: "host-a"}, "")
	if res.Block != nil {
		t.Fatalf("blocked: %+v", res.Block)
	}
	c := checkOf(t, res.Admission, audit.CheckUpstreamProvenance)
	if c.Provenance == nil || c.Provenance.Outcome != audit.ProvenanceVerified {
		t.Errorf("a proxy fill with no url read the configured npm upstream and got %+v", c)
	}

	res = Fetch(t.Context(), f.adb, nil, manifest.TypeNpm, "sigstore",
		manifest.VersionEntry{Version: "3.0.0"}, AllowListCheck(false, "sigstore", nil), Who{}, "not run: no version")
	if c := checkOf(t, res.Admission, audit.CheckUpstreamProvenance); c.Status != audit.CheckNotEvaluated {
		t.Errorf("a fill with no checkers recorded %+v", c)
	}
}

// A version another check refuses does not become the trust-on-first-use
// pin, through import or through a fetch, and neither does a version whose
// sibling in the same manifest is refused: nothing of a refused manifest is
// stored. The first version actually admitted takes the pin.
func TestRefusedVersionTakesNoProvenancePin(t *testing.T) {
	f := newAdmissionFixture(t)
	registry := npmWithProvenance(t)
	dir := t.TempDir()
	db := policy.NewOSVDatabase(dir)
	db.ExportBase = osvExport(t, map[string]any{
		"id": "GHSA-test-0002",
		"affected": []map[string]any{{
			"package":  map[string]string{"name": "sigstore", "ecosystem": "npm"},
			"versions": []string{"3.0.0", "2.0.0"},
		}},
	}).URL
	if _, err := db.Sync(t.Context(), "npm"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{StoragePath: t.TempDir(), OSVDBDir: dir, NpmUpstream: registry}
	noPin := func(when string) {
		t.Helper()
		if pin, err := f.adb.GetProvenancePin(t.Context(), manifest.TypeNpm, "sigstore"); !errors.Is(err, audit.ErrProvenancePinNotFound) {
			t.Fatalf("%s: pin = %+v, %v; want none", when, pin, err)
		}
	}

	res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, cfg, &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "sigstore",
		Versions: []manifest.VersionEntry{{Version: "3.0.0", URL: registry}}}, "ravi")
	if res.Decision != PolicyBlocked || res.Check != audit.CheckOSV {
		t.Fatalf("Decision = %v %q (%s)", res.Decision, res.Check, res.Reason)
	}
	c := checkOf(t, f.rows(t, "sigstore")[0], audit.CheckUpstreamProvenance)
	if c.Provenance == nil || c.Provenance.Outcome != audit.ProvenanceVerified || !strings.Contains(c.Detail, "pinned once admitted") {
		t.Errorf("a refused version's row = %+v", c)
	}
	noPin("after an import OSV refused")

	fr := Fetch(t.Context(), f.adb, VersionCheckers(cfg, f.adb), manifest.TypeNpm, "sigstore",
		manifest.VersionEntry{Version: "3.0.0", Mode: manifest.ModeProxy}, AllowListCheck(false, "sigstore", nil), Who{Identity: "host-a"}, "")
	if fr.Block == nil || fr.Block.Check != audit.CheckOSV {
		t.Fatalf("fetch block = %+v", fr.Block)
	}
	noPin("after a fetch OSV refused")

	// 3.0.0 passes its own checks; its sibling 2.0.0 is refused, so the
	// manifest is refused whole.
	db.ExportBase = osvExport(t, map[string]any{
		"id": "GHSA-test-0003",
		"affected": []map[string]any{{
			"package":  map[string]string{"name": "sigstore", "ecosystem": "npm"},
			"versions": []string{"2.0.0"},
		}},
	}).URL
	if _, err := db.Sync(t.Context(), "npm"); err != nil {
		t.Fatal(err)
	}
	res = Admit(t.Context(), policy.NewChecker(f.adb), f.adb, cfg, &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "sigstore",
		Versions: []manifest.VersionEntry{{Version: "3.0.0", URL: registry}, {Version: "2.0.0", URL: registry}}}, "ravi")
	if res.Decision != PolicyBlocked || res.Version != "2.0.0" {
		t.Fatalf("Decision = %v at %q (%s)", res.Decision, res.Version, res.Reason)
	}
	noPin("after a sibling was refused")

	res = Admit(t.Context(), policy.NewChecker(f.adb), f.adb, cfg, &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "sigstore",
		Versions: []manifest.VersionEntry{{Version: "3.0.0", URL: registry}}}, "ravi")
	if res.Decision != Admitted {
		t.Fatalf("Decision = %v (%s)", res.Decision, res.Reason)
	}
	pin, err := f.adb.GetProvenancePin(t.Context(), manifest.TypeNpm, "sigstore")
	if err != nil || pin.PinnedVersion != "3.0.0" || pin.SourceRepositoryURI != "https://github.com/sigstore/sigstore-js" {
		t.Fatalf("pin after an admitted version = %+v, %v", pin, err)
	}
}

// Two evaluations under one ShareLookups context see the same provenance
// answer, so a registry that fails the first read and answers the second
// cannot move a version between them. The control pair, evaluated without
// the shared context, shows the registry double is flaky.
func TestEvaluateSharesProvenanceLookups(t *testing.T) {
	f := newAdmissionFixture(t)
	registry := npmWithProvenance(t)
	var failNext atomic.Bool
	forward := httputil.NewSingleHostReverseProxy(mustURL(t, registry))
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sigstore" && failNext.Swap(false) {
			http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		forward.ServeHTTP(w, r)
	}))
	t.Cleanup(flaky.Close)
	if err := f.adb.SetProvenancePolicy(t.Context(), audit.ProvenancePolicy{Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	pm := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "sigstore",
		Versions: []manifest.VersionEntry{{Version: "3.0.0", URL: flaky.URL}}}
	twice := func(ctx context.Context) (Verdict, Verdict) {
		failNext.Store(true)
		now := time.Now()
		return Evaluate(ctx, f.synced, policy.NewChecker(f.adb), f.adb, nil, pm, now),
			Evaluate(ctx, f.synced, policy.NewChecker(f.adb), f.adb, nil, pm, now)
	}

	if first, second := twice(t.Context()); first.Decision == second.Decision {
		t.Fatalf("control: unshared evaluations agree (%v); the double is not flaky", first.Decision)
	}
	first, second := twice(policy.ShareLookups(t.Context()))
	if first.Decision != second.Decision || first.Decision != PolicyBlocked {
		t.Fatalf("shared evaluations = %v then %v (%s / %s); want the first answer, blocked, both times",
			first.Decision, second.Decision, first.Reason, second.Reason)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// signedHelmChart serves podinfo-6.7.0.tgz and a .prov clearsigned over it
// in Helm's format, and returns the repository URL, a keyring holding the
// signer's public key, and the signer's fingerprint and the chart's digest.
func signedHelmChart(t *testing.T) (repo, keyring, fingerprint, digest string) {
	t.Helper()
	key, err := openpgp.NewEntity("Chart Publisher", "", "charts@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	chart := []byte("podinfo chart archive bytes")
	sum := sha256.Sum256(chart)
	digest = "sha256:" + hex.EncodeToString(sum[:])
	var prov bytes.Buffer
	w, err := clearsign.Encode(&prov, key.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("apiVersion: v2\nname: podinfo\nversion: 6.7.0\n\n...\nfiles:\n  podinfo-6.7.0.tgz: " + digest + "\n"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/charts/podinfo-6.7.0.tgz":
			_, _ = rw.Write(chart)
		case "/charts/podinfo-6.7.0.tgz.prov":
			_, _ = rw.Write(prov.Bytes())
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(srv.Close)
	var pub bytes.Buffer
	if err := key.Serialize(&pub); err != nil {
		t.Fatal(err)
	}
	keyring = filepath.Join(t.TempDir(), "charts.gpg")
	if err := os.WriteFile(keyring, pub.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.URL + "/charts", keyring, strings.ToUpper(hex.EncodeToString(key.PrimaryKey.Fingerprint)), digest
}

// An imported chart whose .prov verifies against helm_keyrings records the
// signer and the signed digest in the row's upstream_provenance entry.
func TestAdmitRecordsVerifiedHelmProvenance(t *testing.T) {
	f := newAdmissionFixture(t)
	repo, keyring, fpr, digest := signedHelmChart(t)
	cfg := *f.synced
	cfg.HelmKeyrings = map[string]string{strings.TrimSuffix(repo, "charts"): keyring}
	pm := &manifest.PackageManifest{Type: manifest.TypeHelm, Name: "podinfo",
		Versions: []manifest.VersionEntry{{Version: "6.7.0", URL: repo}}}

	res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, &cfg, pm, "ravi")
	if res.Decision != Admitted {
		t.Fatalf("Decision = %v (%s)", res.Decision, res.Reason)
	}
	rows, err := f.adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeHelm, PkgName: "podinfo"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("admission rows = %d, %v", len(rows), err)
	}
	c := checkOf(t, rows[0], audit.CheckUpstreamProvenance)
	raw, _ := json.Marshal(c.Provenance)
	var got map[string]string
	_ = json.Unmarshal(raw, &got)
	if got["outcome"] != audit.ProvenanceVerified || got["signer_fingerprint"] != fpr || got["subject_digest"] != digest {
		t.Errorf("upstream_provenance = %s (%s), want verified by %s over %s", raw, c.Detail, fpr, digest)
	}
}

// pypiWithProvenance serves sampleproject 4.0.0's wheel with the PEP 740
// provenance PyPI recorded for it, over TLS as PyPI serves it, and points the
// provenance check at the recorded Sigstore trusted root and that server's
// certificate.
func pypiWithProvenance(t *testing.T) string {
	t.Helper()
	td := filepath.Join("..", "provenance", "testdata")
	prov, err := os.ReadFile(filepath.Join(td, "pypi-sampleproject-4.0.0-py3-none-any.whl.provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	const wheel = "sampleproject-4.0.0-py3-none-any.whl"
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/simple/sampleproject/":
			_ = json.NewEncoder(w).Encode(map[string]any{"meta": map[string]any{"api-version": "1.4"}, "name": "sampleproject",
				"files": []map[string]any{{"filename": wheel,
					"hashes":     map[string]string{"sha256": "c23e447ea90d796d1e645c35c4b2de125040add12a845825546f91c93f391b6b"},
					"provenance": srv.URL + "/integrity/sampleproject/4.0.0/" + wheel + "/provenance"}}})
		case "/integrity/sampleproject/4.0.0/" + wheel + "/provenance":
			_, _ = w.Write(prov)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	tr, err := provenance.LoadTrustedRootFile(filepath.Join(td, "trusted_root.json"))
	if err != nil {
		t.Fatal(err)
	}
	prev := NewProvenanceVerifier
	NewProvenanceVerifier = func(cfg *config.Config) *provenance.Verifier {
		v := prev(cfg)
		v.HTTP = srv.Client()
		v.Root = func(context.Context) (root.TrustedMaterial, error) { return tr, nil }
		return v
	}
	t.Cleanup(func() { NewProvenanceVerifier = prev })
	return srv.URL
}

// A pypi version admitted with no url reads pypi_upstream, records the
// verified identity in its admission row, and the dependency/v1 statement
// built from that row carries it as E27's mapping spells verified.
func TestAdmitRecordsVerifiedPypiProvenance(t *testing.T) {
	f := newAdmissionFixture(t)
	if _, err := f.adb.DeleteAgePolicy(t.Context(), manifest.TypePypi); err != nil {
		t.Fatal(err)
	}
	cfg := *f.synced
	cfg.PypiUpstream = pypiWithProvenance(t) + "/"
	if got := provenanceCheckerFrom(&cfg, nil).Verifier.PypiIndex; got != strings.TrimRight(cfg.PypiUpstream, "/") {
		t.Fatalf("PypiIndex = %q, want pypi_upstream %q", got, cfg.PypiUpstream)
	}
	pm := &manifest.PackageManifest{Type: manifest.TypePypi, Name: "sampleproject",
		Versions: []manifest.VersionEntry{{Version: "4.0.0"}}}
	res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, &cfg, pm, "ravi")
	if res.Decision != Admitted {
		t.Fatalf("Decision = %v (%s)", res.Decision, res.Reason)
	}
	rows, err := f.adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypePypi, PkgName: "sampleproject"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("admissions = %+v, %v", rows, err)
	}
	row := rows[0]
	c := checkOf(t, row, audit.CheckUpstreamProvenance)
	p := c.Provenance
	const repo = "https://github.com/pypa/sampleproject"
	if p == nil || p.Outcome != audit.ProvenanceVerified || p.SourceRepositoryURI != repo ||
		!strings.HasPrefix(p.WorkflowRef, repo+"/.github/workflows/release.yml@") || p.BuilderID != p.WorkflowRef ||
		!strings.HasPrefix(p.BundleDigest, "sha256:") {
		t.Fatalf("upstream_provenance = %+v (%+v)", c, p)
	}
	if pin, err := f.adb.GetProvenancePin(t.Context(), manifest.TypePypi, "sampleproject"); err != nil || pin.SourceRepositoryURI != repo {
		t.Errorf("pin = %+v, %v", pin, err)
	}

	st := attest.NewStatement(attest.Pin{Type: manifest.TypePypi, Name: "sampleproject", Version: "4.0.0",
		ObjectKey: "pypi/wheels/sampleproject-4.0.0-py3-none-any.whl", SHA256: strings.Repeat("a", 64)}, row, "test", time.Now())
	sig := st.Predicate.PublisherSignature
	_, digest, _ := strings.Cut(p.BundleDigest, ":")
	if sig.Result != attest.ResultVerified || sig.SourceRepositoryURI != repo || sig.WorkflowRef != p.WorkflowRef ||
		sig.BuilderID != p.BuilderID || sig.BundleDigest["sha256"] != digest {
		t.Errorf("publisherSignature = %+v, want verified with the row's identity", sig)
	}
	if st.Predicate.UpstreamProvenance.Result != attest.ResultVerified {
		t.Errorf("upstreamProvenance = %+v", st.Predicate.UpstreamProvenance)
	}
}
