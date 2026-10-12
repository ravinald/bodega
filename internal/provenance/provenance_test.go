package provenance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// The recorded fixtures under testdata/, all fetched on 2026-10-11:
//
//	trusted_root.json  Sigstore's public-good trusted root, through TUF
//	npm-sigstore-3.0.0.attestations.json
//	                   registry.npmjs.org/-/npm/v1/attestations/sigstore@3.0.0
//	npm-sigstore-3.0.0-tampered-subject.attestations.json
//	                   the same, with the SLSA statement's sha512 subject
//	                   digest altered by one hex digit
//	github-cli-2.102.0-provenance.json.sn
//	                   the actions/attest provenance GitHub serves for
//	                   cli/cli v2.102.0's gh_2.102.0_linux_386.tar.gz,
//	                   snappy-compressed as GitHub serves it
const (
	sigstoreIntegrity = "sha512-PHMifhh3EN4loMcHCz6l3v/luzgT3za+9f8subGgeMNjbJjzH4Ij/YoX3Gvu+kaouJRIlVdTHHCREADYf+ZteA=="
	sigstoreRepo      = "https://github.com/sigstore/sigstore-js"
	npmRunnerBuilder  = "https://github.com/actions/runner/github-hosted"
	ghAssetSHA256     = "307972902a54bf5e05e3cdc80a6ac0d30c2dd7c817ba5249a4ecccf9f11754f7"
	ghAsset           = "gh_2.102.0_linux_386.tar.gz"
)

// registry is a loopback stand-in for npm and GitHub, serving the recorded
// documents. Every request it answers is counted, so a test can say what it
// read.
type registry struct {
	*httptest.Server
	mu   sync.Mutex
	docs map[string][]byte
	hits map[string]int
}

func newRegistry(t *testing.T) *registry {
	t.Helper()
	r := &registry{docs: map[string][]byte{}, hits: map[string]int{}}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.hits[req.URL.Path]++
		body, ok := r.docs[req.URL.Path]
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *registry) put(path string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.docs[path] = body
}

func (r *registry) putJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	r.put(path, b)
}

// packument publishes name@version with integrity, and with provenance at
// attPath when that is set.
func (r *registry) packument(t *testing.T, name, version, integrity, attPath string) {
	t.Helper()
	dist := map[string]any{"integrity": integrity, "tarball": r.URL + "/" + name + "/-/x.tgz"}
	if attPath != "" {
		dist["attestations"] = map[string]any{
			"url":        r.URL + attPath,
			"provenance": map[string]any{"predicateType": SLSAProvenanceV1},
		}
	}
	r.putJSON(t, "/"+name, map[string]any{"name": name, "versions": map[string]any{version: map[string]any{"dist": dist}}})
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func recordedRoot(t *testing.T) RootFunc {
	t.Helper()
	tr, err := LoadTrustedRootFile(filepath.Join("testdata", "trusted_root.json"))
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context) (root.TrustedMaterial, error) { return tr, nil }
}

// loopbackOnly fails the test on any request off this host, which is how the
// suite proves it reaches no network.
type loopbackOnly struct{ t *testing.T }

func (l loopbackOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if ip := net.ParseIP(r.URL.Hostname()); ip == nil || !ip.IsLoopback() {
		l.t.Errorf("request to %s left the loopback interface", r.URL)
		return nil, fmt.Errorf("refused %s", r.URL.Host)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func newTestVerifier(t *testing.T, r *registry) *Verifier {
	return &Verifier{
		HTTP:        &http.Client{Transport: loopbackOnly{t}},
		NpmRegistry: r.URL,
		GitHubWeb:   r.URL,
		GitHubAPI:   r.URL + "/api",
		Root:        recordedRoot(t),
	}
}

func TestNpmValidBundleVerifies(t *testing.T) {
	r := newRegistry(t)
	r.packument(t, "sigstore", "3.0.0", sigstoreIntegrity, "/att/sigstore@3.0.0")
	r.put("/att/sigstore@3.0.0", fixture(t, "npm-sigstore-3.0.0.attestations.json"))

	ev := newTestVerifier(t, r).Npm(context.Background(), "", "sigstore", "3.0.0")
	if ev.Outcome != audit.ProvenanceVerified {
		t.Fatalf("outcome %s (%s), want verified", ev.Outcome, ev.Detail)
	}
	if ev.SourceRepositoryURI != sigstoreRepo {
		t.Errorf("source repository %q, want %q", ev.SourceRepositoryURI, sigstoreRepo)
	}
	if ev.BuilderID != npmRunnerBuilder {
		t.Errorf("builder %q, want %q", ev.BuilderID, npmRunnerBuilder)
	}
	if !strings.HasPrefix(ev.WorkflowRef, sigstoreRepo+"/.github/workflows/release.yml@") {
		t.Errorf("workflow ref %q does not name the release workflow", ev.WorkflowRef)
	}
	if !strings.HasPrefix(ev.BundleDigest, "sha256:") || len(ev.BundleDigest) != len("sha256:")+64 {
		t.Errorf("bundle digest %q is not sha256:<hex>", ev.BundleDigest)
	}
}

func TestNpmTamperedSubjectDigestIsInvalid(t *testing.T) {
	r := newRegistry(t)
	r.packument(t, "sigstore", "3.0.0", sigstoreIntegrity, "/att/sigstore@3.0.0")
	r.put("/att/sigstore@3.0.0", fixture(t, "npm-sigstore-3.0.0-tampered-subject.attestations.json"))

	ev := newTestVerifier(t, r).Npm(context.Background(), "", "sigstore", "3.0.0")
	if ev.Outcome != audit.ProvenanceInvalid {
		t.Fatalf("outcome %s (%s), want invalid", ev.Outcome, ev.Detail)
	}
	if ev.SourceRepositoryURI != "" {
		t.Errorf("an invalid bundle recorded an identity: %+v", ev.UpstreamProvenance)
	}
}

// The bundle is genuine, but the tarball the packument now names is not the
// one it was signed over: the case of a registry or mirror serving other
// bytes under a version that once had provenance.
func TestNpmIntegrityOtherThanTheSubjectIsInvalid(t *testing.T) {
	r := newRegistry(t)
	other := "sha512-" + strings.Repeat("A", 86) + "=="
	r.packument(t, "sigstore", "3.0.0", other, "/att/sigstore@3.0.0")
	r.put("/att/sigstore@3.0.0", fixture(t, "npm-sigstore-3.0.0.attestations.json"))

	ev := newTestVerifier(t, r).Npm(context.Background(), "", "sigstore", "3.0.0")
	if ev.Outcome != audit.ProvenanceInvalid {
		t.Fatalf("outcome %s (%s), want invalid", ev.Outcome, ev.Detail)
	}
}

func TestNpmWithoutProvenanceIsUnavailable(t *testing.T) {
	r := newRegistry(t)
	r.packument(t, "left-pad", "1.3.0", sigstoreIntegrity, "")

	ev := newTestVerifier(t, r).Npm(context.Background(), "", "left-pad", "1.3.0")
	if ev.Outcome != audit.ProvenanceUnavailable {
		t.Fatalf("outcome %s (%s), want unavailable", ev.Outcome, ev.Detail)
	}
	if !strings.Contains(ev.Detail, "publishes no provenance") {
		t.Errorf("detail %q does not say the package publishes none", ev.Detail)
	}
}

// Published provenance is never skipped into a pass: a bundle that cannot be
// read, or no trusted root to check it against, is invalid.
func TestNpmPublishedButUnverifiableIsInvalid(t *testing.T) {
	t.Run("bundle missing", func(t *testing.T) {
		r := newRegistry(t)
		r.packument(t, "sigstore", "3.0.0", sigstoreIntegrity, "/att/sigstore@3.0.0")
		ev := newTestVerifier(t, r).Npm(context.Background(), "", "sigstore", "3.0.0")
		if ev.Outcome != audit.ProvenanceInvalid {
			t.Fatalf("outcome %s (%s), want invalid", ev.Outcome, ev.Detail)
		}
	})
	t.Run("no trusted root", func(t *testing.T) {
		r := newRegistry(t)
		r.packument(t, "sigstore", "3.0.0", sigstoreIntegrity, "/att/sigstore@3.0.0")
		r.put("/att/sigstore@3.0.0", fixture(t, "npm-sigstore-3.0.0.attestations.json"))
		v := newTestVerifier(t, r)
		v.Root = func(context.Context) (root.TrustedMaterial, error) { return nil, errors.New("TUF unreachable") }
		ev := v.Npm(context.Background(), "", "sigstore", "3.0.0")
		if ev.Outcome != audit.ProvenanceInvalid || !strings.Contains(ev.Detail, "TUF unreachable") {
			t.Fatalf("outcome %s (%s), want invalid naming the root failure", ev.Outcome, ev.Detail)
		}
	})
}

func TestGitHubReleaseAssetAttestationVerifies(t *testing.T) {
	r := newRegistry(t)
	r.putJSON(t, "/api/repos/cli/cli/releases/tags/v2.102.0", map[string]any{
		"assets": []map[string]any{{"name": ghAsset, "digest": "sha256:" + ghAssetSHA256}},
	})
	r.putJSON(t, "/api/repos/cli/cli/attestations/sha256:"+ghAssetSHA256, map[string]any{
		"attestations": []map[string]any{{"bundle": nil, "bundle_url": r.URL + "/blob/provenance.json.sn"}},
	})
	r.put("/blob/provenance.json.sn", fixture(t, "github-cli-2.102.0-provenance.json.sn"))

	c := &Checker{Verifier: newTestVerifier(t, r)}
	pm := &manifest.PackageManifest{Type: manifest.TypeBinary, Name: "gh"}
	ve := &manifest.VersionEntry{Version: "2.102.0", URL: r.URL + "/cli/cli/releases/download/v2.102.0/" + ghAsset}
	res := c.Check(context.Background(), pm, ve)
	if res.Provenance == nil || res.Provenance.Outcome != audit.ProvenanceVerified {
		t.Fatalf("result %+v, want verified", res)
	}
	if res.Provenance.SourceRepositoryURI != "https://github.com/cli/cli" {
		t.Errorf("source repository %q", res.Provenance.SourceRepositoryURI)
	}
	if res.Provenance.BuilderID != "https://github.com/cli/cli/.github/workflows/deployment.yml@refs/heads/trunk" {
		t.Errorf("builder %q", res.Provenance.BuilderID)
	}
	if res.Action != policy.ActionPass {
		t.Errorf("action %s, want pass", res.Action)
	}

	// The same asset under a digest GitHub holds nothing for.
	ve.SHA256 = strings.Repeat("ab", 32)
	if got := c.Check(context.Background(), pm, ve); got.Provenance.Outcome != audit.ProvenanceUnavailable {
		t.Errorf("an unattested digest is %s (%s), want unavailable", got.Provenance.Outcome, got.Reason)
	}
}

// fakeStore is the policy and pin tables in memory.
type fakeStore struct {
	actions map[string]string
	pins    map[string]audit.ProvenancePin
}

func (f *fakeStore) GetProvenancePolicy(_ context.Context, eco string) (audit.ProvenancePolicy, error) {
	a, ok := f.actions[eco]
	if !ok {
		return audit.ProvenancePolicy{}, audit.ErrProvenancePolicyNotFound
	}
	return audit.ProvenancePolicy{Ecosystem: eco, Action: a}, nil
}

func (f *fakeStore) GetProvenancePin(_ context.Context, typ, name string) (audit.ProvenancePin, error) {
	if got, ok := f.pins[typ+"/"+name]; ok {
		return got, nil
	}
	return audit.ProvenancePin{}, audit.ErrProvenancePinNotFound
}

func (f *fakeStore) PinProvenance(_ context.Context, p audit.ProvenancePin) (audit.ProvenancePin, bool, error) {
	if f.pins == nil {
		f.pins = map[string]audit.ProvenancePin{}
	}
	k := p.PkgType + "/" + p.PkgName
	if got, ok := f.pins[k]; ok {
		return got, false, nil
	}
	f.pins[k] = p
	return p, true, nil
}

// The first verified version pins once its admission commits, and not
// before; a later one verified from another repository is a mismatch, and
// the pin is left as it was.
func TestFirstVerifiedVersionPinsAndAnotherRepositoryMismatches(t *testing.T) {
	r := newRegistry(t)
	r.packument(t, "sigstore", "3.0.0", sigstoreIntegrity, "/att/sigstore@3.0.0")
	r.put("/att/sigstore@3.0.0", fixture(t, "npm-sigstore-3.0.0.attestations.json"))
	store := &fakeStore{}
	c := &Checker{Store: store, Verifier: newTestVerifier(t, r)}
	pm := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "sigstore"}
	ve := &manifest.VersionEntry{Version: "3.0.0"}

	first := c.Check(context.Background(), pm, ve)
	if first.Provenance.Outcome != audit.ProvenanceVerified || first.Action != policy.ActionPass {
		t.Fatalf("first check %+v, want a verified pass", first)
	}
	if _, ok := store.pins["npm/sigstore"]; ok {
		t.Fatal("Check wrote the pin before the admission was decided")
	}
	if changed := c.Commit(context.Background()); changed != nil {
		t.Fatalf("an uncontested commit changed verdicts: %+v", changed)
	}
	pin := store.pins["npm/sigstore"]
	if pin.SourceRepositoryURI != sigstoreRepo || pin.BuilderID != npmRunnerBuilder || pin.PinnedVersion != "3.0.0" {
		t.Fatalf("pin %+v", pin)
	}
	if again := c.Check(context.Background(), pm, ve); again.Provenance.Outcome != audit.ProvenanceVerified {
		t.Fatalf("a second version from the pinned repository is %s", again.Provenance.Outcome)
	}

	// The package was pinned to another repository by an earlier version.
	store.pins["npm/sigstore"] = audit.ProvenancePin{PkgType: "npm", PkgName: "sigstore",
		SourceRepositoryURI: "https://github.com/example/sigstore-js", BuilderID: npmRunnerBuilder, PinnedVersion: "2.9.0"}
	got := c.Check(context.Background(), pm, ve)
	if got.Provenance.Outcome != audit.ProvenanceMismatch {
		t.Fatalf("outcome %s (%s), want mismatch", got.Provenance.Outcome, got.Reason)
	}
	if got.Action != policy.ActionWarn {
		t.Errorf("a mismatch under the default action is %s, want warn", got.Action)
	}
	if got.Provenance.SourceRepositoryURI != sigstoreRepo {
		t.Errorf("the row should record the repository this version came from, got %q", got.Provenance.SourceRepositoryURI)
	}
	if !strings.Contains(got.Reason, "bodega pkg trust reset npm sigstore") {
		t.Errorf("reason %q does not say how to clear the pin", got.Reason)
	}
	if store.pins["npm/sigstore"].SourceRepositoryURI != "https://github.com/example/sigstore-js" {
		t.Error("a mismatch overwrote the pin")
	}
}

// The outcome-by-action table of the check: invalid and mismatch fail under
// anything but ignore, and unavailable fails under block only.
func TestOutcomeAgainstAction(t *testing.T) {
	r := newRegistry(t)
	r.packument(t, "sigstore", "3.0.0", sigstoreIntegrity, "/att/sigstore@3.0.0")
	r.put("/att/sigstore@3.0.0", fixture(t, "npm-sigstore-3.0.0-tampered-subject.attestations.json"))
	r.packument(t, "left-pad", "1.3.0", sigstoreIntegrity, "")

	want := map[string]map[string]string{
		"sigstore": {"warn": policy.ActionWarn, "block": policy.ActionBlock, "ignore": policy.ActionPass, "": policy.ActionWarn},
		"left-pad": {"warn": policy.ActionPass, "block": policy.ActionBlock, "ignore": policy.ActionPass, "": policy.ActionPass},
	}
	for name, byAction := range want {
		for action, wantAction := range byAction {
			store := &fakeStore{actions: map[string]string{}}
			if action != "" {
				store.actions["npm"] = action
			}
			c := &Checker{Store: store, Verifier: newTestVerifier(t, r)}
			version := map[string]string{"sigstore": "3.0.0", "left-pad": "1.3.0"}[name]
			got := c.Check(context.Background(), &manifest.PackageManifest{Type: "npm", Name: name}, &manifest.VersionEntry{Version: version})
			if got.Action != wantAction {
				t.Errorf("%s under %q: action %s (%s), want %s", name, action, got.Action, got.Reason, wantAction)
			}
		}
	}
}

// Another admission pinned a different repository between this one's Check
// and its Commit: the version Check passed against its own pending pin is
// judged again against the pin that won.
func TestCommitJudgesAgainstThePinThatWon(t *testing.T) {
	r := newRegistry(t)
	r.packument(t, "sigstore", "3.0.0", sigstoreIntegrity, "/att/sigstore@3.0.0")
	r.put("/att/sigstore@3.0.0", fixture(t, "npm-sigstore-3.0.0.attestations.json"))
	store := &fakeStore{actions: map[string]string{"npm": policy.ActionBlock}}
	c := &Checker{Store: store, Verifier: newTestVerifier(t, r)}
	pm := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "sigstore"}
	ve := &manifest.VersionEntry{Version: "3.0.0"}
	if got := c.Check(context.Background(), pm, ve); got.Action != policy.ActionPass {
		t.Fatalf("check %+v", got)
	}
	store.pins = map[string]audit.ProvenancePin{"npm/sigstore": {PkgType: "npm", PkgName: "sigstore",
		SourceRepositoryURI: "https://github.com/example/sigstore-js", BuilderID: npmRunnerBuilder, PinnedVersion: "2.9.0"}}
	changed := c.Commit(context.Background())
	got, ok := changed[ve]
	if !ok || got.Provenance.Outcome != audit.ProvenanceMismatch || got.Action != policy.ActionBlock {
		t.Fatalf("commit after a lost race = %+v", changed)
	}
	if store.pins["npm/sigstore"].SourceRepositoryURI != "https://github.com/example/sigstore-js" {
		t.Error("commit overwrote the pin that won")
	}
}

// An oracle that did not answer is not an oracle saying "none": a rate limit,
// an outage or a truncated body is invalid, so it warns under the default
// action and provenance a package publishes is never skipped into a pass. A
// 404 on the attestation lookup is GitHub's answer that there is none.
func TestFailedLookupIsInvalidNotUnavailable(t *testing.T) {
	status := func(code int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
	}
	failing := func(t *testing.T, h http.Handler) *Verifier {
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		return &Verifier{HTTP: &http.Client{Transport: loopbackOnly{t}}, NpmRegistry: srv.URL,
			GitHubWeb: srv.URL, GitHubAPI: srv.URL + "/api", Root: recordedRoot(t)}
	}
	check := func(t *testing.T, v *Verifier, pm *manifest.PackageManifest, ve *manifest.VersionEntry) policy.Result {
		c := &Checker{Store: &fakeStore{}, Verifier: v}
		return c.Check(context.Background(), pm, ve)
	}
	gh := &manifest.PackageManifest{Type: manifest.TypeBinary, Name: "gh"}
	ghEntry := func(v *Verifier) *manifest.VersionEntry {
		return &manifest.VersionEntry{Version: "2.102.0", SHA256: ghAssetSHA256,
			URL: v.GitHubWeb + "/cli/cli/releases/download/v2.102.0/" + ghAsset}
	}
	npm := &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "sigstore"}

	cases := []struct {
		name        string
		handler     http.Handler
		pm          *manifest.PackageManifest
		ve          func(*Verifier) *manifest.VersionEntry
		wantOutcome string
		wantAction  string
	}{
		{"github attestations 403", status(http.StatusForbidden), gh, ghEntry, audit.ProvenanceInvalid, policy.ActionWarn},
		{"github attestations 404", status(http.StatusNotFound), gh, ghEntry, audit.ProvenanceUnavailable, policy.ActionPass},
		{"github attestations not JSON", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }),
			gh, ghEntry, audit.ProvenanceInvalid, policy.ActionWarn},
		{"github release digest 403", status(http.StatusForbidden), gh, func(v *Verifier) *manifest.VersionEntry {
			ve := ghEntry(v)
			ve.SHA256 = ""
			return ve
		}, audit.ProvenanceInvalid, policy.ActionWarn},
		{"git SHA256SUMS 503", status(http.StatusServiceUnavailable), &manifest.PackageManifest{Type: manifest.TypeGit, Name: "cli"},
			func(v *Verifier) *manifest.VersionEntry {
				return &manifest.VersionEntry{URL: v.GitHubWeb + "/cli/cli", Ref: "v2.102.0", Source: "release"}
			}, audit.ProvenanceInvalid, policy.ActionWarn},
		{"git SHA256SUMS 404", status(http.StatusNotFound), &manifest.PackageManifest{Type: manifest.TypeGit, Name: "cli"},
			func(v *Verifier) *manifest.VersionEntry {
				return &manifest.VersionEntry{URL: v.GitHubWeb + "/cli/cli", Ref: "v2.102.0", Source: "release"}
			}, audit.ProvenanceUnavailable, policy.ActionPass},
		{"npm packument 503", status(http.StatusServiceUnavailable), npm, func(*Verifier) *manifest.VersionEntry {
			return &manifest.VersionEntry{Version: "3.0.0"}
		}, audit.ProvenanceInvalid, policy.ActionWarn},
		{"npm packument 403", status(http.StatusForbidden), npm, func(*Verifier) *manifest.VersionEntry {
			return &manifest.VersionEntry{Version: "3.0.0"}
		}, audit.ProvenanceInvalid, policy.ActionWarn},
		{"npm packument not JSON", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{")) }),
			npm, func(*Verifier) *manifest.VersionEntry { return &manifest.VersionEntry{Version: "3.0.0"} },
			audit.ProvenanceInvalid, policy.ActionWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := failing(t, tc.handler)
			got := check(t, v, tc.pm, tc.ve(v))
			if got.Provenance == nil || got.Provenance.Outcome != tc.wantOutcome || got.Action != tc.wantAction {
				t.Fatalf("%+v (%s), want %s and %s", got, got.Reason, tc.wantOutcome, tc.wantAction)
			}
			if tc.wantOutcome == audit.ProvenanceInvalid && !strings.Contains(got.Reason, "failed") {
				t.Errorf("reason %q does not say the lookup failed", got.Reason)
			}
		})
	}
}

// A body past the cap is refused rather than truncated into a document that
// does not parse, or worse, one that does.
func TestOversizedBodyIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 2<<20+1)))
	}))
	t.Cleanup(srv.Close)
	v := &Verifier{HTTP: &http.Client{Transport: loopbackOnly{t}}}
	if _, err := v.get(context.Background(), srv.URL, nil, 2<<20); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v, want a size refusal", err)
	}
	if body, err := v.get(context.Background(), srv.URL, nil, 4<<20); err != nil || len(body) != 2<<20+1 {
		t.Fatalf("under the cap: %d bytes, %v", len(body), err)
	}
}

func TestUncoveredEcosystemsRecordWhy(t *testing.T) {
	c := &Checker{Verifier: &Verifier{HTTP: &http.Client{Transport: loopbackOnly{t}}, GitHubWeb: "https://github.com"}}
	for _, typ := range []string{manifest.TypePypi, manifest.TypeGomod, manifest.TypeCargo, manifest.TypeHelm,
		manifest.TypeApt, manifest.TypeFreeBSD, manifest.TypeDistfiles} {
		got := c.Check(context.Background(), &manifest.PackageManifest{Type: typ, Name: "x"}, &manifest.VersionEntry{Version: "1.0.0"})
		if got.Provenance == nil || got.Provenance.Outcome != audit.ProvenanceUnavailable {
			t.Errorf("%s: %+v, want unavailable", typ, got)
			continue
		}
		if !strings.Contains(got.Reason, UncoveredReason(typ)) || UncoveredReason(typ) == "" {
			t.Errorf("%s: reason %q does not say why", typ, got.Reason)
		}
	}
}

func TestUnpinnedNpmVersionIsNotEvaluated(t *testing.T) {
	c := &Checker{Verifier: &Verifier{HTTP: &http.Client{Transport: loopbackOnly{t}}}}
	got := c.Check(context.Background(), &manifest.PackageManifest{Type: "npm", Name: "x"}, &manifest.VersionEntry{Version: "*"})
	if got.Action != policy.ActionNotEvaluated || got.Provenance != nil {
		t.Errorf("%+v, want not evaluated", got)
	}
}

func TestLoadTrustedRootFileNamesTheFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.json")
	if _, err := LoadTrustedRootFile(missing); err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("missing file: %v", err)
	}
	junk := filepath.Join(dir, "junk.json")
	if err := os.WriteFile(junk, []byte(`{"mediaType":"nope"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustedRootFile(junk); err == nil || !strings.Contains(err.Error(), junk) || !strings.Contains(err.Error(), "not a Sigstore trusted root") {
		t.Errorf("unparsable file: %v", err)
	}
}

func TestPinnedBuilderDropsTheRef(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/o/r/.github/workflows/release.yml@refs/tags/v1.2.3": "https://github.com/o/r/.github/workflows/release.yml",
		npmRunnerBuilder:                       npmRunnerBuilder,
		"https://gitlab.com/o/r/-/runners/123": "https://gitlab.com/o/r/-/runners/123",
	} {
		if got := PinnedBuilder(in); got != want {
			t.Errorf("PinnedBuilder(%q) = %q, want %q", in, got, want)
		}
	}
}
