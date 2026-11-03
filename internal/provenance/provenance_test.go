package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
//	npm-vue.packument.json
//	                   registry.npmjs.org/vue fetched on 2026-10-13, cut
//	                   to 3.5.35 (published by GitHub Actions through
//	                   trusted publishing, with provenance) and 3.5.36
//	                   (published by hand by npm user daiwei1105, without),
//	                   each version cut to _npmUser.name, the
//	                   trustedPublisher marker and dist
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
// read is unknown, and so is one with no trusted root to check it against,
// whether TUF failed or sigstore_trusted_root names no readable file.
func TestNpmPublishedButUnverifiableIsNotAPass(t *testing.T) {
	t.Run("bundle missing", func(t *testing.T) {
		r := newRegistry(t)
		r.packument(t, "sigstore", "3.0.0", sigstoreIntegrity, "/att/sigstore@3.0.0")
		ev := newTestVerifier(t, r).Npm(context.Background(), "", "sigstore", "3.0.0")
		if ev.Outcome != audit.ProvenanceUnknown {
			t.Fatalf("outcome %s (%s), want unknown", ev.Outcome, ev.Detail)
		}
	})
	t.Run("no trusted root", func(t *testing.T) {
		r := newRegistry(t)
		r.packument(t, "sigstore", "3.0.0", sigstoreIntegrity, "/att/sigstore@3.0.0")
		r.put("/att/sigstore@3.0.0", fixture(t, "npm-sigstore-3.0.0.attestations.json"))
		v := newTestVerifier(t, r)
		v.Root = func(context.Context) (root.TrustedMaterial, error) { return nil, errors.New("TUF unreachable") }
		ev := v.Npm(context.Background(), "", "sigstore", "3.0.0")
		if ev.Outcome != audit.ProvenanceUnknown || !ev.NoTrustedRoot || !strings.Contains(ev.Detail, "TUF unreachable") {
			t.Fatalf("outcome %s (%s), want unknown naming the root failure", ev.Outcome, ev.Detail)
		}
		if !strings.Contains(ev.Detail, "not checked") || strings.Contains(ev.Detail, "did not verify") {
			t.Errorf("detail %q does not say the provenance went unchecked", ev.Detail)
		}
	})
	t.Run("sigstore_trusted_root missing", func(t *testing.T) {
		r := newRegistry(t)
		r.packument(t, "sigstore", "3.0.0", sigstoreIntegrity, "/att/sigstore@3.0.0")
		r.put("/att/sigstore@3.0.0", fixture(t, "npm-sigstore-3.0.0.attestations.json"))
		missing := filepath.Join(t.TempDir(), "trusted_root.json")
		v := newTestVerifier(t, r)
		v.Root = SharedRoot(missing)
		ev := v.Npm(context.Background(), "", "sigstore", "3.0.0")
		if ev.Outcome != audit.ProvenanceUnknown || !ev.NoTrustedRoot || !strings.Contains(ev.Detail, missing) {
			t.Fatalf("outcome %s (%s), want unknown naming %s", ev.Outcome, ev.Detail, missing)
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

// A release whose attestations were read but could not be checked for want
// of a trusted root is unknown, and its result says so in Details without
// carrying the root error there.
func TestGitHubReleaseWithoutTrustedRootIsUnknown(t *testing.T) {
	r := newRegistry(t)
	r.putJSON(t, "/api/repos/cli/cli/releases/tags/v2.102.0", map[string]any{
		"assets": []map[string]any{{"name": ghAsset, "digest": "sha256:" + ghAssetSHA256}},
	})
	r.putJSON(t, "/api/repos/cli/cli/attestations/sha256:"+ghAssetSHA256, map[string]any{
		"attestations": []map[string]any{{"bundle": nil, "bundle_url": r.URL + "/blob/provenance.json.sn"}},
	})
	r.put("/blob/provenance.json.sn", fixture(t, "github-cli-2.102.0-provenance.json.sn"))

	v := newTestVerifier(t, r)
	v.Root = func(context.Context) (root.TrustedMaterial, error) { return nil, errors.New("TUF unreachable") }
	c := &Checker{Verifier: v}
	pm := &manifest.PackageManifest{Type: manifest.TypeBinary, Name: "gh"}
	ve := &manifest.VersionEntry{Version: "2.102.0", URL: r.URL + "/cli/cli/releases/download/v2.102.0/" + ghAsset}
	res := c.Check(context.Background(), pm, ve)
	if res.Provenance == nil || res.Provenance.Outcome != audit.ProvenanceUnknown {
		t.Fatalf("result %+v, want unknown", res)
	}
	if !strings.Contains(res.Reason, "TUF unreachable") {
		t.Errorf("reason %q does not carry the root error", res.Reason)
	}
	if res.Details[audit.DetailNoTrustedRoot] != true {
		t.Errorf("details %v do not mark the missing trusted root", res.Details)
	}
	for k, d := range res.Details {
		if strings.Contains(fmt.Sprint(d), "TUF unreachable") {
			t.Errorf("details[%s] carries the root error: %v", k, d)
		}
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
// an outage, a truncated body or a packument that no longer lists the version
// is unknown, so it warns under the default action and provenance a package
// publishes is never skipped into a pass. Nor is it invalid: nothing was
// verified, so nothing failed to. A 404 on the attestation lookup is GitHub's
// answer that there is none.
func TestFailedLookupIsUnknown(t *testing.T) {
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
		{"npm packument lists no such version", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"versions":{"1.0.0":{}},"time":{"1.0.1":"2026-01-01T00:00:00Z"}}`))
		}), &manifest.PackageManifest{Type: manifest.TypeNpm, Name: "openai-pr-reviewer"},
			func(*Verifier) *manifest.VersionEntry { return &manifest.VersionEntry{Version: "1.0.1"} },
			audit.ProvenanceUnknown, policy.ActionWarn},
		{"github attestations 403", status(http.StatusForbidden), gh, ghEntry, audit.ProvenanceUnknown, policy.ActionWarn},
		{"github attestations 404", status(http.StatusNotFound), gh, ghEntry, audit.ProvenanceUnavailable, policy.ActionPass},
		{"github attestations not JSON", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }),
			gh, ghEntry, audit.ProvenanceUnknown, policy.ActionWarn},
		{"github release digest 403", status(http.StatusForbidden), gh, func(v *Verifier) *manifest.VersionEntry {
			ve := ghEntry(v)
			ve.SHA256 = ""
			return ve
		}, audit.ProvenanceUnknown, policy.ActionWarn},
		{"git SHA256SUMS 503", status(http.StatusServiceUnavailable), &manifest.PackageManifest{Type: manifest.TypeGit, Name: "cli"},
			func(v *Verifier) *manifest.VersionEntry {
				return &manifest.VersionEntry{URL: v.GitHubWeb + "/cli/cli", Ref: "v2.102.0", Source: "release"}
			}, audit.ProvenanceUnknown, policy.ActionWarn},
		{"git SHA256SUMS 404", status(http.StatusNotFound), &manifest.PackageManifest{Type: manifest.TypeGit, Name: "cli"},
			func(v *Verifier) *manifest.VersionEntry {
				return &manifest.VersionEntry{URL: v.GitHubWeb + "/cli/cli", Ref: "v2.102.0", Source: "release"}
			}, audit.ProvenanceUnavailable, policy.ActionPass},
		{"npm packument 503", status(http.StatusServiceUnavailable), npm, func(*Verifier) *manifest.VersionEntry {
			return &manifest.VersionEntry{Version: "3.0.0"}
		}, audit.ProvenanceUnknown, policy.ActionWarn},
		{"npm packument 403", status(http.StatusForbidden), npm, func(*Verifier) *manifest.VersionEntry {
			return &manifest.VersionEntry{Version: "3.0.0"}
		}, audit.ProvenanceUnknown, policy.ActionWarn},
		{"npm packument not JSON", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{")) }),
			npm, func(*Verifier) *manifest.VersionEntry { return &manifest.VersionEntry{Version: "3.0.0"} },
			audit.ProvenanceUnknown, policy.ActionWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := failing(t, tc.handler)
			got := check(t, v, tc.pm, tc.ve(v))
			if got.Provenance == nil || got.Provenance.Outcome != tc.wantOutcome || got.Action != tc.wantAction {
				t.Fatalf("%+v (%s), want %s and %s", got, got.Reason, tc.wantOutcome, tc.wantAction)
			}
			if tc.wantOutcome == audit.ProvenanceUnknown && !strings.Contains(got.Reason, "failed") && !strings.Contains(got.Reason, "lists no version") {
				t.Errorf("reason %q does not say why the evidence could not be read", got.Reason)
			}
		})
	}
}

// unknown warns under warn, refuses under block and is only recorded under
// ignore. It never takes a pin, and a pin already held never turns it into a
// mismatch, as it would an unavailable version published after the pin.
func TestUnknownFollowsTheActionAndLeavesThePinAlone(t *testing.T) {
	noVersion := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"versions":{"3.0.0":{}},"time":{"3.0.0":"2024-10-14T16:13:47Z","3.1.0":"2025-02-04T20:35:48Z"}}`))
	})
	srv := httptest.NewServer(noVersion)
	t.Cleanup(srv.Close)
	v := &Verifier{HTTP: &http.Client{Transport: loopbackOnly{t}}, NpmRegistry: srv.URL, Root: recordedRoot(t)}
	for _, pinned := range []bool{false, true} {
		for action, want := range map[string]string{"warn": policy.ActionWarn, "block": policy.ActionBlock, "ignore": policy.ActionPass} {
			store := &fakeStore{actions: map[string]string{"npm": action}}
			if pinned {
				store.pins = map[string]audit.ProvenancePin{"npm/sigstore": sigstorePin()}
			}
			c := &Checker{Store: store, Verifier: v}
			got := c.Check(context.Background(), &manifest.PackageManifest{Type: "npm", Name: "sigstore"}, &manifest.VersionEntry{Version: "3.1.0"})
			if got.Provenance == nil || got.Provenance.Outcome != audit.ProvenanceUnknown || got.Action != want {
				t.Errorf("pinned=%v %s: %+v (%s), want unknown and %s", pinned, action, got, got.Reason, want)
			}
			if changed := c.Commit(context.Background()); changed != nil {
				t.Errorf("pinned=%v %s: commit changed verdicts: %+v", pinned, action, changed)
			}
			if !pinned && store.pins != nil {
				t.Errorf("%s: an unknown version took a pin: %+v", action, store.pins)
			}
		}
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
	for _, typ := range []string{manifest.TypeGomod, manifest.TypeCargo, manifest.TypeHelm,
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

// sigstorePackument serves the recorded packument npm-sigstore.packument.json:
// registry.npmjs.org/sigstore fetched on 2026-10-12, cut to 0.1.1 (published
// before sigstore-js adopted provenance), 3.0.0 and 3.1.0, with 3.0.0's
// attestations URL made relative so it resolves on the loopback registry, and
// 3.1.0's dist.attestations removed so it reads as a publish from outside CI.
// edit changes the decoded document before it is served.
func sigstorePackument(t *testing.T, r *registry, edit func(doc map[string]any)) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(fixture(t, "npm-sigstore.packument.json"), &doc); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(doc)
	}
	r.putJSON(t, "/sigstore", doc)
	r.put("/-/npm/v1/attestations/sigstore@3.0.0", fixture(t, "npm-sigstore-3.0.0.attestations.json"))
}

func sigstorePin() audit.ProvenancePin {
	return audit.ProvenancePin{PkgType: "npm", PkgName: "sigstore",
		SourceRepositoryURI: sigstoreRepo, BuilderID: npmRunnerBuilder, PinnedVersion: "3.0.0"}
}

func TestNpmPublishTimesComeFromThePackument(t *testing.T) {
	r := newRegistry(t)
	sigstorePackument(t, r, func(doc map[string]any) { delete(doc["time"].(map[string]any), "3.1.0") })
	v := newTestVerifier(t, r)

	ev := v.Npm(context.Background(), "", "sigstore", "3.0.0")
	if ev.PublishedAt == nil || ev.PublishedAt.Format("2006-01-02T15:04:05.000Z07:00") != "2024-10-14T16:13:47.295Z" {
		t.Errorf("3.0.0 published at %v", ev.PublishedAt)
	}
	if got := ev.Published["0.1.1"]; got.IsZero() {
		t.Error("0.1.1's publish time is missing from Published")
	}
	ev = v.Npm(context.Background(), "", "sigstore", "3.1.0")
	if ev.Outcome != audit.ProvenanceUnavailable {
		t.Fatalf("3.1.0 is %s (%s)", ev.Outcome, ev.Detail)
	}
	if ev.PublishedAt != nil {
		t.Errorf("a version missing from time reads as published at %v, want unknown", ev.PublishedAt)
	}
	if _, ok := ev.Published["3.1.0"]; ok {
		t.Error("a version missing from time is in Published")
	}
}

// A package pinned to a CI identity that then publishes a version with no
// provenance at all reads mismatch: the stolen-token publish from a laptop.
// A version from before the pin, and any version of an unpinned package,
// stay unavailable.
func TestNpmWithoutProvenanceAgainstThePin(t *testing.T) {
	cases := []struct {
		name, version string
		pinned        bool
		wantOutcome   string
		wantByAction  map[string]string
		wantIn        []string
	}{
		{"after the pin", "3.1.0", true, audit.ProvenanceMismatch,
			map[string]string{"": policy.ActionWarn, "warn": policy.ActionWarn, "block": policy.ActionBlock, "ignore": policy.ActionPass},
			[]string{sigstoreRepo, npmRunnerBuilder, "version 3.0.0", "2024-10-14T16:13:47Z", "2025-02-04T20:35:48Z", "bodega pkg trust reset npm sigstore"}},
		{"before the pin", "0.1.1", true, audit.ProvenanceUnavailable,
			map[string]string{"": policy.ActionPass, "warn": policy.ActionPass, "block": policy.ActionBlock, "ignore": policy.ActionPass},
			[]string{"predates the pin", "2022-12-01T17:15:22Z"}},
		{"unpinned", "3.1.0", false, audit.ProvenanceUnavailable,
			map[string]string{"": policy.ActionPass, "warn": policy.ActionPass, "block": policy.ActionBlock, "ignore": policy.ActionPass},
			[]string{"publishes no provenance"}},
	}
	r := newRegistry(t)
	sigstorePackument(t, r, nil)
	for _, tc := range cases {
		for action, wantAction := range tc.wantByAction {
			t.Run(tc.name+"/"+action, func(t *testing.T) {
				store := &fakeStore{actions: map[string]string{}}
				if action != "" {
					store.actions["npm"] = action
				}
				if tc.pinned {
					store.pins = map[string]audit.ProvenancePin{"npm/sigstore": sigstorePin()}
				}
				c := &Checker{Store: store, Verifier: newTestVerifier(t, r)}
				got := c.Check(context.Background(), &manifest.PackageManifest{Type: "npm", Name: "sigstore"}, &manifest.VersionEntry{Version: tc.version})
				if got.Provenance == nil || got.Provenance.Outcome != tc.wantOutcome || got.Action != wantAction {
					t.Fatalf("%+v (%s), want %s and %s", got, got.Reason, tc.wantOutcome, wantAction)
				}
				for _, w := range tc.wantIn {
					if !strings.Contains(got.Reason, w) {
						t.Errorf("reason %q does not name %q", got.Reason, w)
					}
				}
				if changed := c.Commit(context.Background()); changed != nil {
					t.Errorf("commit changed verdicts: %+v", changed)
				}
				if !tc.pinned && store.pins != nil {
					t.Errorf("a version without provenance took a pin: %+v", store.pins)
				}
			})
		}
	}
}

// With a pin held, a publish time the packument does not give means the
// comparison could not run, so the version is unknown rather than passing
// as unavailable. A pin that cannot be read is unknown too.
func TestNpmWithoutProvenanceUnknownTimeIsUnknown(t *testing.T) {
	cases := []struct{ name, drop, want string }{
		{"version's time missing", "3.1.0", "this version's"},
		{"pinned version's time missing", "3.0.0", "pinned version 3.0.0's"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRegistry(t)
			sigstorePackument(t, r, func(doc map[string]any) { delete(doc["time"].(map[string]any), tc.drop) })
			store := &fakeStore{pins: map[string]audit.ProvenancePin{"npm/sigstore": sigstorePin()}}
			c := &Checker{Store: store, Verifier: newTestVerifier(t, r)}
			got := c.Check(context.Background(), &manifest.PackageManifest{Type: "npm", Name: "sigstore"}, &manifest.VersionEntry{Version: "3.1.0"})
			if got.Provenance.Outcome != audit.ProvenanceUnknown || got.Action != policy.ActionWarn {
				t.Fatalf("%+v (%s), want unknown and warn", got, got.Reason)
			}
			if !strings.Contains(got.Reason, tc.want) || !strings.Contains(got.Reason, "no publish time") {
				t.Errorf("reason %q does not say %s time is missing", got.Reason, tc.want)
			}
		})
	}
	t.Run("pin unreadable", func(t *testing.T) {
		r := newRegistry(t)
		sigstorePackument(t, r, nil)
		c := &Checker{Store: brokenPins{&fakeStore{}}, Verifier: newTestVerifier(t, r)}
		got := c.Check(context.Background(), &manifest.PackageManifest{Type: "npm", Name: "sigstore"}, &manifest.VersionEntry{Version: "3.1.0"})
		if got.Provenance.Outcome != audit.ProvenanceUnknown || !strings.Contains(got.Reason, "could not be read") {
			t.Fatalf("%+v (%s), want unknown naming the read", got, got.Reason)
		}
	})
}

type brokenPins struct{ *fakeStore }

func (brokenPins) GetProvenancePin(context.Context, string, string) (audit.ProvenancePin, error) {
	return audit.ProvenancePin{}, errors.New("database is locked")
}

// One admission imports 3.0.0 with provenance and 3.1.0 without, the package
// holding no pin yet: 3.1.0 is held to the pin 3.0.0 is about to take, in
// whichever order the manifest lists them.
func TestNpmBatchJudgesAgainstThePendingPin(t *testing.T) {
	for _, order := range [][]string{{"3.0.0", "3.1.0"}, {"3.1.0", "3.0.0"}} {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			r := newRegistry(t)
			sigstorePackument(t, r, nil)
			store := &fakeStore{actions: map[string]string{"npm": policy.ActionWarn}}
			c := &Checker{Store: store, Verifier: newTestVerifier(t, r)}
			pm := &manifest.PackageManifest{Type: "npm", Name: "sigstore"}
			got := map[string]policy.Result{}
			entries := map[string]*manifest.VersionEntry{}
			for _, v := range order {
				entries[v] = &manifest.VersionEntry{Version: v}
				got[v] = c.Check(context.Background(), pm, entries[v])
			}
			for ve, res := range c.Commit(context.Background()) {
				got[ve.Version] = res
			}
			if got["3.0.0"].Provenance.Outcome != audit.ProvenanceVerified {
				t.Errorf("3.0.0: %s (%s)", got["3.0.0"].Provenance.Outcome, got["3.0.0"].Reason)
			}
			if res := got["3.1.0"]; res.Provenance.Outcome != audit.ProvenanceMismatch || res.Action != policy.ActionWarn {
				t.Errorf("3.1.0: %s/%s (%s), want mismatch and warn", res.Provenance.Outcome, res.Action, res.Reason)
			}
			if store.pins["npm/sigstore"].PinnedVersion != "3.0.0" {
				t.Errorf("pin %+v", store.pins["npm/sigstore"])
			}
		})
	}
}

// Another admission pinned a different identity between Check and Commit: a
// version without provenance judged against this admission's pending pin is
// judged again against the pin that won, here one whose version the
// packument gives no time for.
func TestCommitJudgesUnavailableAgainstThePinThatWon(t *testing.T) {
	r := newRegistry(t)
	sigstorePackument(t, r, nil)
	store := &fakeStore{}
	c := &Checker{Store: store, Verifier: newTestVerifier(t, r)}
	pm := &manifest.PackageManifest{Type: "npm", Name: "sigstore"}
	c.Check(context.Background(), pm, &manifest.VersionEntry{Version: "3.0.0"})
	old := &manifest.VersionEntry{Version: "0.1.1"}
	if got := c.Check(context.Background(), pm, old); got.Provenance.Outcome != audit.ProvenanceUnavailable {
		t.Fatalf("0.1.1 against the pending pin: %s (%s)", got.Provenance.Outcome, got.Reason)
	}
	won := sigstorePin()
	won.SourceRepositoryURI, won.PinnedVersion = "https://github.com/example/sigstore-js", "0.0.0"
	store.pins = map[string]audit.ProvenancePin{"npm/sigstore": won}
	changed := c.Commit(context.Background())
	got, ok := changed[old]
	if !ok {
		t.Fatalf("commit did not judge 0.1.1 again: %+v", changed)
	}
	if got.Provenance.Outcome != audit.ProvenanceUnknown || !strings.Contains(got.Reason, "pinned version 0.0.0's") {
		t.Errorf("0.1.1 against a pin whose time the packument lacks: %s (%s), want unknown", got.Provenance.Outcome, got.Reason)
	}
}

func vuePin() audit.ProvenancePin {
	return audit.ProvenancePin{PkgType: "npm", PkgName: "vue",
		SourceRepositoryURI: "https://github.com/vuejs/core", BuilderID: npmRunnerBuilder, PinnedVersion: "3.5.35"}
}

// A version without provenance after the pin names who published it and who
// published the pinned version, in the reason and in Details, and the
// outcome stays what E14 decided: a hand publish and a stolen token look the
// same from the registry. A packument with no _npmUser says the publisher is
// not named rather than leaving it blank.
func TestNpmMismatchNamesThePublishers(t *testing.T) {
	cases := []struct {
		name, pkg, version   string
		serve                func(*testing.T, *registry)
		pin                  audit.ProvenancePin
		wantIn               []string
		publisher, pinnedPub any
	}{
		{"named", "vue", "3.5.36",
			func(t *testing.T, r *registry) { r.put("/vue", fixture(t, "npm-vue.packument.json")) },
			vuePin(),
			[]string{"published 2026-06-11T03:56:09Z by npm user daiwei1105 with no provenance", "pinned version 3.5.35 was published by GitHub Actions (2026-05-27T09:04:53Z)", "bodega pkg trust reset npm vue"},
			"daiwei1105", "GitHub Actions"},
		{"not named", "sigstore", "3.1.0",
			func(t *testing.T, r *registry) { sigstorePackument(t, r, nil) },
			sigstorePin(),
			[]string{"by a publisher the packument has not named with no provenance", "pinned version 3.0.0 was published by a publisher the packument has not named"},
			nil, nil},
	}
	for _, tc := range cases {
		for action, wantAction := range map[string]string{"warn": policy.ActionWarn, "block": policy.ActionBlock, "ignore": policy.ActionPass} {
			t.Run(tc.name+"/"+action, func(t *testing.T) {
				r := newRegistry(t)
				tc.serve(t, r)
				store := &fakeStore{actions: map[string]string{"npm": action},
					pins: map[string]audit.ProvenancePin{"npm/" + tc.pkg: tc.pin}}
				c := &Checker{Store: store, Verifier: newTestVerifier(t, r)}
				got := c.Check(context.Background(), &manifest.PackageManifest{Type: "npm", Name: tc.pkg}, &manifest.VersionEntry{Version: tc.version})
				if got.Provenance == nil || got.Provenance.Outcome != audit.ProvenanceMismatch || got.Action != wantAction {
					t.Fatalf("%+v (%s), want mismatch and %s", got, got.Reason, wantAction)
				}
				for _, w := range tc.wantIn {
					if !strings.Contains(got.Reason, w) {
						t.Errorf("reason %q does not say %q", got.Reason, w)
					}
				}
				if action == "ignore" {
					return
				}
				for key, want := range map[string]any{"publisher": tc.publisher, "pinned_publisher": tc.pinnedPub} {
					v, ok := got.Details[key]
					if !ok || v != want {
						t.Errorf("Details[%s] = %v (present %v), want %v", key, v, ok, want)
					}
				}
			})
		}
	}
}

func TestNpmPublisherComesFromThePackument(t *testing.T) {
	r := newRegistry(t)
	r.put("/vue", fixture(t, "npm-vue.packument.json"))
	ev := newTestVerifier(t, r).Npm(context.Background(), "", "vue", "3.5.36")
	if ev.Publisher == nil || *ev.Publisher != (Publisher{Name: "daiwei1105"}) {
		t.Errorf("3.5.36 publisher %+v, want npm user daiwei1105", ev.Publisher)
	}
	if p := ev.Publishers["3.5.35"]; p != (Publisher{Name: "GitHub Actions", Trusted: true}) {
		t.Errorf("3.5.35 publisher %+v, want GitHub Actions through trusted publishing", p)
	}
}

// The pypi fixtures, recorded from pypi.org on 2026-11-02:
//
//	pypi-sampleproject.simple.json
//	                   https://pypi.org/simple/sampleproject/ as PEP 691 JSON
//	pypi-sampleproject-4.0.0-py3-none-any.whl.provenance.json
//	                   https://pypi.org/integrity/sampleproject/4.0.0/sampleproject-4.0.0-py3-none-any.whl/provenance
//
// The page lists two files of 4.0.0, the wheel and the sdist, and only the
// wheel's provenance is recorded, so a test serving the version as attested
// drops the sdist or gives it no provenance.
const (
	pypiWheel       = "sampleproject-4.0.0-py3-none-any.whl"
	pypiSdist       = "sampleproject-4.0.0.tar.gz"
	pypiWheelSHA256 = "c23e447ea90d796d1e645c35c4b2de125040add12a845825546f91c93f391b6b"
	pypiRepo        = "https://github.com/pypa/sampleproject"
	pypiWheelPath   = "/integrity/sampleproject/4.0.0/" + pypiWheel + "/provenance"
	pypiPagePath    = "/simple/sampleproject/"
)

// loopbackVia is loopbackOnly over another transport: the TLS client an
// httptest server hands out, since PEP 740 provenance is read over https only.
type loopbackVia struct {
	t    *testing.T
	next http.RoundTripper
}

func (l loopbackVia) RoundTrip(r *http.Request) (*http.Response, error) {
	if ip := net.ParseIP(r.URL.Hostname()); ip == nil || !ip.IsLoopback() {
		l.t.Errorf("request to %s left the loopback interface", r.URL)
		return nil, fmt.Errorf("refused %s", r.URL.Host)
	}
	return l.next.RoundTrip(r)
}

func newTLSRegistry(t *testing.T) *registry {
	t.Helper()
	r := &registry{docs: map[string][]byte{}, hits: map[string]int{}}
	r.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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

func (r *registry) hitsOn(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[path]
}

func newPypiVerifier(t *testing.T, r *registry) *Verifier {
	return &Verifier{
		HTTP:      &http.Client{Transport: loopbackVia{t, r.Client().Transport}},
		PypiIndex: r.URL,
		Root:      recordedRoot(t),
	}
}

// pypiFiles is the recorded page's files, each provenance URL moved from
// pypi.org onto r.
func pypiFiles(t *testing.T, r *registry) []map[string]any {
	t.Helper()
	var page struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(fixture(t, "pypi-sampleproject.simple.json"), &page); err != nil {
		t.Fatal(err)
	}
	for _, f := range page.Files {
		if p, ok := f["provenance"].(string); ok {
			f["provenance"] = strings.Replace(p, "https://pypi.org", r.URL, 1)
		}
	}
	return page.Files
}

// servePypi publishes the page with edit applied to each file of 4.0.0, a
// file edit returns nil for dropped, and the recorded wheel provenance.
func servePypi(t *testing.T, r *registry, edit func(f map[string]any) map[string]any) {
	t.Helper()
	var files []map[string]any
	for _, f := range pypiFiles(t, r) {
		if strings.HasPrefix(f["filename"].(string), "sampleproject-4.0.0") {
			if f = edit(f); f == nil {
				continue
			}
		}
		files = append(files, f)
	}
	r.putJSON(t, pypiPagePath, map[string]any{"meta": map[string]any{"api-version": "1.4"}, "name": "sampleproject", "files": files})
	r.put(pypiWheelPath, fixture(t, "pypi-sampleproject-4.0.0-py3-none-any.whl.provenance.json"))
}

// wheelOnly drops the sdist, whose provenance was not recorded.
func wheelOnly(f map[string]any) map[string]any {
	if f["filename"] == pypiSdist {
		return nil
	}
	return f
}

// pypiProvenanceVariant is the recorded provenance object with edit applied.
func pypiProvenanceVariant(t *testing.T, edit func(bundle map[string]any)) []byte {
	t.Helper()
	var prov map[string]any
	if err := json.Unmarshal(fixture(t, "pypi-sampleproject-4.0.0-py3-none-any.whl.provenance.json"), &prov); err != nil {
		t.Fatal(err)
	}
	edit(prov["attestation_bundles"].([]any)[0].(map[string]any))
	b, err := json.Marshal(prov)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func checkPypi(t *testing.T, v *Verifier, version string) Evidence {
	t.Helper()
	return v.Pypi(context.Background(), "", "sampleproject", version)
}

func TestPypiAttestationVerifies(t *testing.T) {
	r := newTLSRegistry(t)
	servePypi(t, r, wheelOnly)
	ev := checkPypi(t, newPypiVerifier(t, r), "4.0.0")
	if ev.Outcome != audit.ProvenanceVerified {
		t.Fatalf("outcome %s (%s), want verified", ev.Outcome, ev.Detail)
	}
	if ev.SourceRepositoryURI != pypiRepo {
		t.Errorf("source repository %q, want %q", ev.SourceRepositoryURI, pypiRepo)
	}
	if !strings.HasPrefix(ev.WorkflowRef, pypiRepo+"/.github/workflows/release.yml@") || ev.BuilderID != ev.WorkflowRef {
		t.Errorf("workflow ref %q, builder %q: want the build signer URI in both", ev.WorkflowRef, ev.BuilderID)
	}
	sum := sha256.Sum256(fixture(t, "pypi-sampleproject-4.0.0-py3-none-any.whl.provenance.json"))
	if want := "sha256:" + hex.EncodeToString(sum[:]); ev.BundleDigest != want {
		t.Errorf("bundle digest %q, want %q over the provenance object as fetched", ev.BundleDigest, want)
	}
}

// The page is read with the PEP 691 media type, and the provenance object
// with PEP 740's.
func TestPypiSendsTheIndexMediaTypes(t *testing.T) {
	r := newTLSRegistry(t)
	servePypi(t, r, wheelOnly)
	var mu sync.Mutex
	accept := map[string]string{}
	inner := r.Config.Handler
	r.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		accept[req.URL.Path] = req.Header.Get("Accept")
		mu.Unlock()
		inner.ServeHTTP(w, req)
	})
	if ev := checkPypi(t, newPypiVerifier(t, r), "4.0.0"); ev.Outcome != audit.ProvenanceVerified {
		t.Fatalf("outcome %s (%s)", ev.Outcome, ev.Detail)
	}
	if accept[pypiPagePath] != pypiSimpleJSON || accept[pypiWheelPath] != pypiIntegrityJSON {
		t.Errorf("Accept headers %v", accept)
	}
}

// A page that cannot be read, does not parse, or lists no file of the
// version cannot say provenance is absent.
func TestPypiPageThatSaysNothingIsUnknown(t *testing.T) {
	r := newTLSRegistry(t)
	v := newPypiVerifier(t, r)
	ev := checkPypi(t, v, "4.0.0")
	if ev.Outcome != audit.ProvenanceUnknown || !strings.Contains(ev.Detail, r.URL+pypiPagePath) {
		t.Errorf("missing page: %s (%s), want unknown naming the page", ev.Outcome, ev.Detail)
	}
	r.put(pypiPagePath, []byte("<html>not json</html>"))
	if ev := checkPypi(t, v, "4.0.0"); ev.Outcome != audit.ProvenanceUnknown || !strings.Contains(ev.Detail, r.URL+pypiPagePath) {
		t.Errorf("HTML page: %s (%s), want unknown naming the page", ev.Outcome, ev.Detail)
	}
	servePypi(t, r, wheelOnly)
	if ev := checkPypi(t, v, "9.9.9"); ev.Outcome != audit.ProvenanceUnknown || !strings.Contains(ev.Detail, "lists no file") {
		t.Errorf("absent version: %s (%s), want unknown", ev.Outcome, ev.Detail)
	}
	// PEP 440 equality: 4.0 is 4.0.0.
	if ev := checkPypi(t, v, "4.0"); ev.Outcome != audit.ProvenanceVerified {
		t.Errorf("4.0 against files of 4.0.0: %s (%s), want verified", ev.Outcome, ev.Detail)
	}
}

func TestPypiWithoutProvenanceIsUnavailable(t *testing.T) {
	r := newTLSRegistry(t)
	servePypi(t, r, func(f map[string]any) map[string]any {
		f["provenance"] = nil
		return f
	})
	ev := checkPypi(t, newPypiVerifier(t, r), "4.0.0")
	if ev.Outcome != audit.ProvenanceUnavailable {
		t.Fatalf("outcome %s (%s), want unavailable", ev.Outcome, ev.Detail)
	}
	if !strings.Contains(ev.Detail, r.URL+pypiPagePath) || !strings.Contains(ev.Detail, "no attestation for any file of the version") {
		t.Errorf("detail %q does not name the page and the absence", ev.Detail)
	}
	if n := r.hitsOn(pypiWheelPath); n != 0 {
		t.Errorf("a file with null provenance was fetched %d times", n)
	}
	// An older release the recorded page lists without the key's value.
	if ev := checkPypi(t, newPypiVerifier(t, r), "3.0.0"); ev.Outcome != audit.ProvenanceUnavailable {
		t.Errorf("3.0.0: %s (%s), want unavailable", ev.Outcome, ev.Detail)
	}
}

// One file attested and one not is what an upload from somewhere other than
// the publisher's CI beside a release it built looks like.
func TestPypiPartlyAttestedVersionIsAMismatch(t *testing.T) {
	r := newTLSRegistry(t)
	servePypi(t, r, func(f map[string]any) map[string]any {
		if f["filename"] == pypiSdist {
			f["provenance"] = nil
		}
		return f
	})
	c := &Checker{Verifier: newPypiVerifier(t, r)}
	res := c.Check(context.Background(), &manifest.PackageManifest{Type: manifest.TypePypi, Name: "sampleproject"}, &manifest.VersionEntry{Version: "4.0.0"})
	if res.Provenance == nil || res.Provenance.Outcome != audit.ProvenanceMismatch {
		t.Fatalf("result %+v, want mismatch", res)
	}
	if !strings.Contains(res.Reason, pypiSdist) {
		t.Errorf("reason %q does not name the file without provenance", res.Reason)
	}
	if res.Provenance.SourceRepositoryURI != pypiRepo || res.Action != policy.ActionWarn {
		t.Errorf("a mismatch carries %+v under %s; want the attested file's identity, warned", res.Provenance, res.Action)
	}
}

// Every way the provenance object can fail to arrive is unknown: the index
// named it, so it exists, and whether it verifies is not known.
func TestPypiUnreadableProvenanceIsUnknown(t *testing.T) {
	for name, serve := range map[string]http.HandlerFunc{
		"404": http.NotFound,
		"500": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) },
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"version":1,"attestation_bundles":[],"pad":"`))
			_, _ = w.Write([]byte(strings.Repeat("a", 8<<20)))
			_, _ = w.Write([]byte(`"}`))
		},
		"not JSON": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("nope")) },
		"version 2": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"version":2,"attestation_bundles":[]}`))
		},
		"no bundle": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"version":1,"attestation_bundles":[]}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newTLSRegistry(t)
			servePypi(t, r, wheelOnly)
			inner := r.Config.Handler
			r.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == pypiWheelPath {
					serve(w, req)
					return
				}
				inner.ServeHTTP(w, req)
			})
			ev := checkPypi(t, newPypiVerifier(t, r), "4.0.0")
			if ev.Outcome != audit.ProvenanceUnknown {
				t.Fatalf("outcome %s (%s), want unknown", ev.Outcome, ev.Detail)
			}
			if !strings.Contains(ev.Detail, pypiWheel) {
				t.Errorf("detail %q does not name the file", ev.Detail)
			}
		})
	}
}

// A provenance URL on another host is not requested: the page alone cannot
// send bodega to fetch from wherever it names.
func TestPypiOffHostProvenanceIsNotRequested(t *testing.T) {
	other := newTLSRegistry(t)
	other.put(pypiWheelPath, fixture(t, "pypi-sampleproject-4.0.0-py3-none-any.whl.provenance.json"))
	r := newTLSRegistry(t)
	servePypi(t, r, func(f map[string]any) map[string]any {
		if f = wheelOnly(f); f != nil {
			f["provenance"] = other.URL + pypiWheelPath
		}
		return f
	})
	ev := checkPypi(t, newPypiVerifier(t, r), "4.0.0")
	if ev.Outcome != audit.ProvenanceUnknown || !strings.Contains(ev.Detail, strings.TrimPrefix(other.URL, "https://")) {
		t.Errorf("outcome %s (%s), want unknown naming the refused host", ev.Outcome, ev.Detail)
	}
	if n := other.hitsOn(pypiWheelPath); n != 0 {
		t.Errorf("the off-host provenance URL was requested %d times", n)
	}

	// The recorded page, unmodified, names pypi.org, which is not this index.
	r.put(pypiPagePath, fixture(t, "pypi-sampleproject.simple.json"))
	if ev := checkPypi(t, newPypiVerifier(t, r), "4.0.0"); ev.Outcome != audit.ProvenanceUnknown || !strings.Contains(ev.Detail, "pypi.org") {
		t.Errorf("recorded page: %s (%s), want unknown naming pypi.org", ev.Outcome, ev.Detail)
	}

	// Same host, but http.
	servePypi(t, r, func(f map[string]any) map[string]any {
		if f = wheelOnly(f); f != nil {
			f["provenance"] = strings.Replace(r.URL, "https://", "http://", 1) + pypiWheelPath
		}
		return f
	})
	if ev := checkPypi(t, newPypiVerifier(t, r), "4.0.0"); ev.Outcome != audit.ProvenanceUnknown {
		t.Errorf("http provenance URL: %s (%s), want unknown", ev.Outcome, ev.Detail)
	}
}

// A relative provenance URL resolves against the page.
func TestPypiRelativeProvenanceURLResolvesAgainstThePage(t *testing.T) {
	r := newTLSRegistry(t)
	servePypi(t, r, func(f map[string]any) map[string]any {
		if f = wheelOnly(f); f != nil {
			f["provenance"] = "../../integrity/sampleproject/4.0.0/" + pypiWheel + "/provenance"
		}
		return f
	})
	if ev := checkPypi(t, newPypiVerifier(t, r), "4.0.0"); ev.Outcome != audit.ProvenanceVerified {
		t.Errorf("outcome %s (%s), want verified", ev.Outcome, ev.Detail)
	}
}

func TestPypiTamperedAttestationIsInvalid(t *testing.T) {
	for name, tc := range map[string]struct {
		page  func(f map[string]any) map[string]any
		prov  func(b map[string]any)
		want  string
		cause string
	}{
		"statement subject digest": {page: wheelOnly, want: audit.ProvenanceInvalid, cause: "did not verify", prov: func(b map[string]any) {
			env := b["attestations"].([]any)[0].(map[string]any)["envelope"].(map[string]any)
			st, _ := base64.StdEncoding.DecodeString(env["statement"].(string))
			env["statement"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(st), pypiWheelSHA256, "d"+pypiWheelSHA256[1:], 1)))
		}},
		"publisher repository": {page: wheelOnly, want: audit.ProvenanceInvalid, cause: "pypa/otherproject", prov: func(b map[string]any) {
			b["publisher"].(map[string]any)["repository"] = "pypa/otherproject"
		}},
		"publisher workflow": {page: wheelOnly, want: audit.ProvenanceInvalid, cause: "nightly.yml", prov: func(b map[string]any) {
			b["publisher"].(map[string]any)["workflow"] = "nightly.yml"
		}},
		"publisher kind": {page: wheelOnly, want: audit.ProvenanceUnknown, cause: `"Google"`, prov: func(b map[string]any) {
			b["publisher"].(map[string]any)["kind"] = "Google"
		}},
		"publisher kind GitLab against a GitHub certificate": {page: wheelOnly, want: audit.ProvenanceInvalid, cause: "did not verify", prov: func(b map[string]any) {
			b["publisher"].(map[string]any)["kind"] = "GitLab"
			b["publisher"].(map[string]any)["workflow_filepath"] = ".gitlab-ci.yml"
		}},
		"page sha256": {want: audit.ProvenanceInvalid, cause: "did not verify", prov: func(map[string]any) {}, page: func(f map[string]any) map[string]any {
			if f = wheelOnly(f); f != nil {
				f["hashes"] = map[string]any{"sha256": strings.Repeat("0", 64)}
			}
			return f
		}},
		"page gives no sha256": {want: audit.ProvenanceUnknown, cause: "no sha256", prov: func(map[string]any) {}, page: func(f map[string]any) map[string]any {
			if f = wheelOnly(f); f != nil {
				f["hashes"] = map[string]any{}
			}
			return f
		}},
		"no attestation of a known predicate type": {page: wheelOnly, want: audit.ProvenanceInvalid, cause: "holds no attestation", prov: func(b map[string]any) {
			env := b["attestations"].([]any)[0].(map[string]any)["envelope"].(map[string]any)
			st, _ := base64.StdEncoding.DecodeString(env["statement"].(string))
			env["statement"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(st), PyPIPublishV1, "https://example.com/other/v1", 1)))
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newTLSRegistry(t)
			servePypi(t, r, tc.page)
			r.put(pypiWheelPath, pypiProvenanceVariant(t, tc.prov))
			ev := checkPypi(t, newPypiVerifier(t, r), "4.0.0")
			if ev.Outcome != tc.want {
				t.Fatalf("outcome %s (%s), want %s", ev.Outcome, ev.Detail, tc.want)
			}
			if !strings.Contains(ev.Detail, tc.cause) || !strings.Contains(ev.Detail, pypiWheel) {
				t.Errorf("detail %q does not name the file and %q", ev.Detail, tc.cause)
			}
			if ev.SourceRepositoryURI != "" {
				t.Errorf("a %s file recorded an identity: %+v", ev.Outcome, ev.UpstreamProvenance)
			}
		})
	}
}

func TestPypiWithoutTrustedRootIsUnknown(t *testing.T) {
	r := newTLSRegistry(t)
	servePypi(t, r, wheelOnly)
	v := newPypiVerifier(t, r)
	v.Root = func(context.Context) (root.TrustedMaterial, error) { return nil, errors.New("TUF unreachable") }
	res := (&Checker{Verifier: v}).Check(context.Background(), &manifest.PackageManifest{Type: manifest.TypePypi, Name: "sampleproject"}, &manifest.VersionEntry{Version: "4.0.0"})
	if res.Provenance == nil || res.Provenance.Outcome != audit.ProvenanceUnknown || res.Details[audit.DetailNoTrustedRoot] != true {
		t.Fatalf("result %+v, want unknown with no_trusted_root", res)
	}
}

// Two files built by different identities are a mismatch, and every file
// is verified: a later file's failure is not hidden by an earlier pass.
func TestPypiCombinesEveryFile(t *testing.T) {
	ok := audit.UpstreamProvenance{Outcome: audit.ProvenanceVerified, SourceRepositoryURI: pypiRepo, BuilderID: pypiRepo + "/.github/workflows/release.yml@refs/tags/v1"}
	other := ok
	other.SourceRepositoryURI = "https://github.com/example/sampleproject"
	file := func(name string, p audit.UpstreamProvenance) pypiFileEvidence {
		return pypiFileEvidence{filename: name, ev: Evidence{UpstreamProvenance: p, Detail: name}}
	}
	got := pypiVersion([]pypiFileEvidence{file("a.whl", ok), file("b.tar.gz", other)}, nil, "x", "1")
	if got.Outcome != audit.ProvenanceMismatch || !strings.Contains(got.Detail, "example/sampleproject") || !strings.Contains(got.Detail, pypiRepo) {
		t.Errorf("two identities: %s (%s), want mismatch naming both", got.Outcome, got.Detail)
	}
	sameAtOtherRef := ok
	sameAtOtherRef.BuilderID = pypiRepo + "/.github/workflows/release.yml@refs/tags/v2"
	if got := pypiVersion([]pypiFileEvidence{file("a.whl", ok), file("b.tar.gz", sameAtOtherRef)}, nil, "x", "1"); got.Outcome != audit.ProvenanceVerified {
		t.Errorf("one identity at two refs: %s (%s), want verified", got.Outcome, got.Detail)
	}
	bad := audit.UpstreamProvenance{Outcome: audit.ProvenanceInvalid}
	unk := audit.UpstreamProvenance{Outcome: audit.ProvenanceUnknown}
	if got := pypiVersion([]pypiFileEvidence{file("a.whl", ok), file("b.whl", unk), file("c.whl", bad)}, []string{"d.zip"}, "x", "1"); got.Outcome != audit.ProvenanceInvalid || got.Detail != "c.whl" {
		t.Errorf("an invalid file: %s (%s), want invalid from c.whl", got.Outcome, got.Detail)
	}
	if got := pypiVersion([]pypiFileEvidence{file("a.whl", unk), file("b.whl", ok), file("c.whl", unk)}, []string{"d.zip"}, "x", "1"); got.Outcome != audit.ProvenanceUnknown || got.Detail != "a.whl" {
		t.Errorf("an unknown file: %s (%s), want unknown from a.whl", got.Outcome, got.Detail)
	}
}

// A verified pypi version takes the pin through Check and Commit, and a later
// version from another repository is a mismatch.
func TestPypiFirstVerifiedVersionPinsAndAnotherRepositoryMismatches(t *testing.T) {
	r := newTLSRegistry(t)
	servePypi(t, r, wheelOnly)
	store := &fakeStore{}
	c := &Checker{Store: store, Verifier: newPypiVerifier(t, r)}
	pm := &manifest.PackageManifest{Type: manifest.TypePypi, Name: "sampleproject"}
	if got := c.Check(context.Background(), pm, &manifest.VersionEntry{Version: "4.0.0"}); got.Provenance.Outcome != audit.ProvenanceVerified || got.Action != policy.ActionPass {
		t.Fatalf("first check %+v (%s)", got, got.Reason)
	}
	c.Commit(context.Background())
	pin := store.pins["pypi/sampleproject"]
	if pin.SourceRepositoryURI != pypiRepo || pin.BuilderID != pypiRepo+"/.github/workflows/release.yml" || pin.PinnedVersion != "4.0.0" {
		t.Fatalf("pin %+v", pin)
	}

	store.pins["pypi/sampleproject"] = audit.ProvenancePin{PkgType: "pypi", PkgName: "sampleproject",
		SourceRepositoryURI: "https://github.com/example/sampleproject", BuilderID: "https://github.com/example/sampleproject/.github/workflows/release.yml", PinnedVersion: "3.9.0"}
	got := c.Check(context.Background(), pm, &manifest.VersionEntry{Version: "4.0.0", URL: r.URL})
	if got.Provenance.Outcome != audit.ProvenanceMismatch || !strings.Contains(got.Reason, "bodega pkg trust reset pypi sampleproject") {
		t.Fatalf("outcome %s (%s), want mismatch", got.Provenance.Outcome, got.Reason)
	}

	// A version without provenance is not compared with the pin.
	if got := c.Check(context.Background(), pm, &manifest.VersionEntry{Version: "3.0.0"}); got.Provenance.Outcome != audit.ProvenanceUnavailable {
		t.Errorf("3.0.0 after the pin: %s (%s), want unavailable", got.Provenance.Outcome, got.Reason)
	}
}

func TestUnpinnedPypiVersionIsNotEvaluated(t *testing.T) {
	r := newTLSRegistry(t)
	c := &Checker{Verifier: newPypiVerifier(t, r)}
	for _, version := range []string{"", "*", manifest.ConstraintAny} {
		got := c.Check(context.Background(), &manifest.PackageManifest{Type: manifest.TypePypi, Name: "x"}, &manifest.VersionEntry{Version: version})
		if got.Action != policy.ActionNotEvaluated || got.Provenance != nil {
			t.Errorf("%q: %+v, want not evaluated", version, got)
		}
	}
	if n := r.hitsOn("/simple/x/"); n != 0 {
		t.Errorf("an undatable version looked the page up %d times", n)
	}
}

// The entry's url wins over the verifier's index root, and neither's
// userinfo reaches a result.
func TestPypiIndexUserinfoReachesNoResult(t *testing.T) {
	r := newTLSRegistry(t)
	servePypi(t, r, wheelOnly)
	var auth []string
	var mu sync.Mutex
	inner := r.Config.Handler
	r.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		u, p, _ := req.BasicAuth()
		mu.Lock()
		auth = append(auth, u+":"+p)
		mu.Unlock()
		inner.ServeHTTP(w, req)
	})
	secret := strings.Replace(r.URL, "https://", "https://user:secret@", 1)
	v := newPypiVerifier(t, r)
	v.PypiIndex = secret
	c := &Checker{Verifier: v}
	pm := &manifest.PackageManifest{Type: manifest.TypePypi, Name: "sampleproject"}
	results := map[string]policy.Result{
		"verified": c.Check(context.Background(), pm, &manifest.VersionEntry{Version: "4.0.0"}),
		"absent":   c.Check(context.Background(), pm, &manifest.VersionEntry{Version: "9.9.9"}),
		"entry url": c.Check(context.Background(), &manifest.PackageManifest{Type: manifest.TypePypi, Name: "missing"},
			&manifest.VersionEntry{Version: "1.0", URL: secret + "/"}),
	}
	r.put(pypiWheelPath, []byte("nope"))
	results["unparsable provenance"] = (&Checker{Verifier: v}).Check(context.Background(), pm, &manifest.VersionEntry{Version: "4.0.0", URL: secret})
	for name, res := range results {
		b, _ := json.Marshal(res)
		if strings.Contains(string(b), "secret") || strings.Contains(string(b), "user:") {
			t.Errorf("%s: the userinfo reached the result: %s", name, b)
		}
		if res.Provenance == nil {
			t.Errorf("%s: no provenance recorded", name)
		}
	}
	if results["verified"].Provenance.Outcome != audit.ProvenanceVerified {
		t.Errorf("verified through the credentialed index: %s", results["verified"].Reason)
	}
	if !strings.Contains(results["entry url"].Reason, r.URL+"/simple/missing/") {
		t.Errorf("the entry's url was not the index read: %s", results["entry url"].Reason)
	}
	for _, a := range auth {
		if a != "user:secret" {
			t.Errorf("a request carried credentials %q, want the index's", a)
		}
	}
}

func TestPypiFileVersion(t *testing.T) {
	for _, tc := range []struct{ project, file, want string }{
		{"sampleproject", "sampleproject-4.0.0-py3-none-any.whl", "4.0.0"},
		{"sampleproject", "sampleproject-4.0.0.tar.gz", "4.0.0"},
		{"python-3parclient", "python-3parclient-4.2.10.tar.gz", "4.2.10"},
		{"Foo.Bar", "foo_bar-1.0-1-py3-none-any.whl", "1.0"},
		{"sampleproject", "sampleproject-4.0.0.exe", ""},
		{"sampleproject", "otherproject-4.0.0.tar.gz", ""},
	} {
		if got := pypiFileVersion(tc.project, tc.file); got != tc.want {
			t.Errorf("pypiFileVersion(%q, %q) = %q, want %q", tc.project, tc.file, got, tc.want)
		}
	}
}

// PyPI's publish attestation carries a null predicate, so the builder comes
// from the certificate for pypi alone: the npm and GitHub callers, reading
// the predicate, still refuse a statement naming no builder.
func TestVerifyBundleBuilderSource(t *testing.T) {
	var prov pypiProvenance
	if err := json.Unmarshal(fixture(t, "pypi-sampleproject-4.0.0-py3-none-any.whl.provenance.json"), &prov); err != nil {
		t.Fatal(err)
	}
	raw, _, err := pypiSigstoreBundle(prov.AttestationBundles[0].Attestations[0])
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := hex.DecodeString(pypiWheelSHA256)
	tm, _ := recordedRoot(t)(context.Background())
	if _, _, err := verifyBundle(tm, raw, githubIssuer, "sha256", digest, builderFromPredicate); err == nil || !strings.Contains(err.Error(), "names no builder") {
		t.Errorf("builder from the predicate: %v, want the no-builder refusal", err)
	}
	id, _, err := verifyBundle(tm, raw, githubIssuer, "sha256", digest, builderFromSigner)
	if err != nil || id.BuilderID != id.WorkflowRef || id.BuilderID == "" {
		t.Errorf("builder from the signer: %+v, %v", id, err)
	}
}
