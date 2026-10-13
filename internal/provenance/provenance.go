// Package provenance verifies what a publisher signed about who built a
// dependency: the Sigstore bundles npm serves beside a version built in CI,
// and the GitHub artifact attestations a release asset built with
// actions/attest carries. A checksum says which bytes; this says which
// repository and which CI workflow produced them, so a version published
// with a stolen maintainer token from somewhere other than the project's CI
// stops looking the same as one that was not.
package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/ravinald/bodega/internal/audit"
)

// SLSA provenance predicate types. npm has published both; GitHub artifact
// attestations use v1.
const (
	SLSAProvenanceV1  = "https://slsa.dev/provenance/v1"
	SLSAProvenanceV02 = "https://slsa.dev/provenance/v0.2"
)

// OIDC issuers whose certificates name a CI identity. npm accepts provenance
// from GitHub Actions and GitLab CI; GitHub attestations come from Actions.
const (
	issuerGitHubActions = "https://token.actions.githubusercontent.com"
	issuerGitLab        = "https://gitlab.com"
)

// Evidence is what verifying one version concluded.
type Evidence struct {
	audit.UpstreamProvenance
	// Detail says why, in words an operator acts on.
	Detail string
	// PublishedAt is when the registry says the version checked was
	// published, nil when it does not say. Published is the same for every
	// version it lists; a version absent from it has an unknown time. Only
	// npm fills either.
	PublishedAt *time.Time
	Published   map[string]time.Time
	// Publisher is who the registry says published the version checked, nil
	// when it does not say; Publishers is the same for every version it
	// names. PinnedPublisher is Publishers' entry for the pinned version,
	// set when a version without provenance is judged against a pin. Only
	// npm fills any of them.
	Publisher       *Publisher
	Publishers      map[string]Publisher
	PinnedPublisher *Publisher
}

// Publisher is the account a registry says published a version: npm's
// _npmUser. A trusted-publishing release is published by the CI system's
// OIDC identity rather than an npm account, and npm names that identity
// ("GitHub Actions") in the same field.
type Publisher struct {
	Name    string
	Trusted bool
}

func (p *Publisher) String() string {
	switch {
	case p == nil:
		return "a publisher the packument has not named"
	case p.Trusted:
		return p.Name
	}
	return "npm user " + p.Name
}

func unavailable(format string, a ...any) Evidence {
	return Evidence{UpstreamProvenance: audit.UpstreamProvenance{Outcome: audit.ProvenanceUnavailable}, Detail: fmt.Sprintf(format, a...)}
}

func invalid(format string, a ...any) Evidence {
	return Evidence{UpstreamProvenance: audit.UpstreamProvenance{Outcome: audit.ProvenanceInvalid}, Detail: fmt.Sprintf(format, a...)}
}

// RootFunc returns the Sigstore trusted root bundles are verified against.
type RootFunc func(ctx context.Context) (root.TrustedMaterial, error)

// Verifier fetches and verifies upstream provenance.
type Verifier struct {
	HTTP *http.Client
	// NpmRegistry is the registry read when a version names none.
	NpmRegistry string
	// GitHubWeb and GitHubAPI are the GitHub hosts a release URL is matched
	// against and the API attestations are read from.
	GitHubWeb string
	GitHubAPI string
	Root      RootFunc
}

// NewVerifier returns a verifier against the public registries, with the
// trusted root from trustedRootPath, or from Sigstore's TUF repository when
// that is empty.
func NewVerifier(trustedRootPath string) *Verifier {
	return &Verifier{
		HTTP:        &http.Client{Timeout: 20 * time.Second},
		NpmRegistry: "https://registry.npmjs.org",
		GitHubWeb:   "https://github.com",
		GitHubAPI:   "https://api.github.com",
		Root:        SharedRoot(trustedRootPath),
	}
}

// LoadTrustedRootFile reads a Sigstore trusted_root.json, saying which file
// and why when it cannot.
func LoadTrustedRootFile(path string) (*root.TrustedRoot, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: an operator-configured path.
	if err != nil {
		return nil, fmt.Errorf("sigstore_trusted_root %s: %w", path, err)
	}
	tr, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("sigstore_trusted_root %s is not a Sigstore trusted root: %w", path, err)
	}
	return tr, nil
}

// tufRefresh is how long a trusted root fetched through TUF is used before
// the next fetch, and tufRetry how long a failed fetch is remembered. Without
// the second, a host that cannot reach TUF pays the timeout on every version
// that publishes provenance.
const (
	tufRefresh = 24 * time.Hour
	tufRetry   = 5 * time.Minute
)

var sharedRoots sync.Map // path > *rootCache

// SharedRoot returns the process-wide trusted root source for path. Every
// admission builds its checkers afresh, so the TUF client's answer is held
// here rather than on a checker. A file is re-read on every call: it is a few
// kilobytes, and an operator who replaces it expects the next admission to
// see the replacement.
func SharedRoot(path string) RootFunc {
	v, _ := sharedRoots.LoadOrStore(path, &rootCache{path: path})
	return v.(*rootCache).get
}

type rootCache struct {
	path  string
	mu    sync.Mutex
	tm    root.TrustedMaterial
	at    time.Time
	err   error
	errAt time.Time
}

func (c *rootCache) get(ctx context.Context) (root.TrustedMaterial, error) {
	if c.path != "" {
		return LoadTrustedRootFile(c.path)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tm != nil && time.Since(c.at) < tufRefresh {
		return c.tm, nil
	}
	if c.err != nil && time.Since(c.errAt) < tufRetry {
		return nil, c.err
	}
	// In memory: the TUF client's default cache is under $HOME, which the
	// user a hardened service runs as may not be able to write, and a cache
	// only saves the fetch this already makes once a day.
	tr, err := root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithContext(ctx).WithDisableLocalCache())
	if err != nil {
		c.err, c.errAt = fmt.Errorf("fetch the Sigstore trusted root through TUF (set sigstore_trusted_root on a host that cannot reach it): %w", err), time.Now()
		if c.tm != nil {
			// A stale root still verifies everything signed before it
			// rotated; refusing every bundle over one failed refresh would
			// not.
			return c.tm, nil
		}
		return nil, c.err
	}
	c.tm, c.at, c.err = tr, time.Now(), nil
	return tr, nil
}

// statement is the part of a verified in-toto statement this package reads.
type statement struct {
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`
}

// predicateTypeOf reads a bundle's predicate type before it is verified, to
// choose which bundles to verify. Nothing is concluded from it.
func predicateTypeOf(raw []byte) string {
	var b struct {
		DSSEEnvelope struct {
			Payload []byte `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if json.Unmarshal(raw, &b) != nil {
		return ""
	}
	var st statement
	if json.Unmarshal(b.DSSEEnvelope.Payload, &st) != nil {
		return ""
	}
	return st.PredicateType
}

// verifyBundle verifies one Sigstore bundle against tm: the certificate chain
// to Fulcio, the transparency log entry, the signature over the DSSE envelope,
// an issuer matching issuerRegex, and a statement subject carrying digest
// under alg. It returns the identity the certificate binds and the statement.
func verifyBundle(tm root.TrustedMaterial, raw []byte, issuerRegex, alg string, digest []byte) (audit.UpstreamProvenance, *statement, error) {
	var id audit.UpstreamProvenance
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return id, nil, fmt.Errorf("not a Sigstore bundle: %w", err)
	}
	v, err := verify.NewVerifier(tm,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
		verify.WithSignedCertificateTimestamps(1))
	if err != nil {
		return id, nil, err
	}
	certID, err := verify.NewShortCertificateIdentity("", issuerRegex, "", ".+")
	if err != nil {
		return id, nil, err
	}
	res, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest(alg, digest), verify.WithCertificateIdentity(certID)))
	if err != nil {
		return id, nil, err
	}
	if res.Signature == nil || res.Signature.Certificate == nil {
		return id, nil, errors.New("signed by a key, not a CI identity certificate")
	}
	cert := res.Signature.Certificate
	if cert.SourceRepositoryURI == "" {
		return id, nil, errors.New("the signing certificate names no source repository")
	}
	env, err := b.Envelope()
	if err != nil {
		return id, nil, err
	}
	payload, err := env.RawEnvelope().DecodeB64Payload()
	if err != nil {
		return id, nil, err
	}
	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return id, nil, fmt.Errorf("decode the verified statement: %w", err)
	}
	sum := sha256.Sum256(raw)
	id = audit.UpstreamProvenance{
		SourceRepositoryURI: cert.SourceRepositoryURI,
		WorkflowRef:         cert.BuildSignerURI,
		BuilderID:           builderID(&st),
		BundleDigest:        "sha256:" + hex.EncodeToString(sum[:]),
	}
	if id.BuilderID == "" {
		return id, nil, errors.New("the provenance names no builder")
	}
	return id, &st, nil
}

// builderID is runDetails.builder.id in SLSA v1 and builder.id in v0.2.
func builderID(st *statement) string {
	var p struct {
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
		} `json:"runDetails"`
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
	}
	if json.Unmarshal(st.Predicate, &p) != nil {
		return ""
	}
	if p.RunDetails.Builder.ID != "" {
		return p.RunDetails.Builder.ID
	}
	return p.Builder.ID
}

// PinnedBuilder is the part of a builder ID a pin compares: the ID with any
// "@<ref>" suffix removed. A GitHub Actions builder ID names the workflow at
// the ref that ran it, and a release workflow runs at a new tag every time.
func PinnedBuilder(builderID string) string {
	_, rest, ok := strings.Cut(builderID, "://")
	if !ok {
		rest = builderID
	}
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		return builderID[:len(builderID)-len(rest)+i]
	}
	return builderID
}

func (v *Verifier) client() *http.Client {
	if v.HTTP != nil {
		return v.HTTP
	}
	return http.DefaultClient
}

// errNotFound is a 404, which for an attestation lookup means "none
// published" rather than "could not tell".
var errNotFound = errors.New("not found")

// get reads url, refusing a body over limit bytes rather than returning a
// truncated one, which would parse as a document that is not there.
func (v *Verifier) get(ctx context.Context, url string, header http.Header, limit int64) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return nil, fmt.Errorf("refusing to fetch %q: not an http(s) URL", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	req.Header.Set("User-Agent", "bodega")
	resp, err := v.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("GET %s: %w", url, errNotFound)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: the body is larger than the %d MiB cap", url, limit>>20)
	}
	return body, nil
}
