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
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
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
	// NoTrustedRoot is set on an unknown outcome reached because no Sigstore
	// trusted root could be had, so no bundle was checked. The fix is the
	// operator's, not the package's, and a refusal says so.
	NoTrustedRoot bool
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

func unknown(format string, a ...any) Evidence {
	return Evidence{UpstreamProvenance: audit.UpstreamProvenance{Outcome: audit.ProvenanceUnknown}, Detail: fmt.Sprintf(format, a...)}
}

// noRoot is published provenance that was not checked because the trusted
// root could not be had: through TUF, or from sigstore_trusted_root.
func noRoot(err error, format string, a ...any) Evidence {
	ev := unknown(format+", but it was not checked, because there is no Sigstore trusted root to check it against: %v", append(a, err)...)
	ev.NoTrustedRoot = true
	return ev
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
	// PypiIndex is the PEP 503 index root read when a version names none.
	PypiIndex string
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
		PypiIndex:   "https://pypi.org",
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

// builderSource says where verifyBundle reads a builder ID from.
type builderSource int

const (
	// builderFromPredicate is the SLSA predicate's builder, and a statement
	// naming none is refused: SLSA provenance without one says nothing.
	builderFromPredicate builderSource = iota
	// builderFromSigner is the certificate's build signer URI, for a
	// statement whose predicate carries no builder by design, as PyPI's
	// publish attestation does.
	builderFromSigner
)

// verifyBundle verifies one Sigstore bundle against tm: the certificate chain
// to Fulcio, the transparency log entry, the signature over the DSSE envelope,
// an issuer matching issuerRegex, and a statement subject carrying digest
// under alg. It returns the identity the certificate binds and the statement.
func verifyBundle(tm root.TrustedMaterial, raw []byte, issuerRegex, alg string, digest []byte, from builderSource) (audit.UpstreamProvenance, *statement, error) {
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
	if from == builderFromSigner {
		id.BuilderID = cert.BuildSignerURI
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

// get reads raw, refusing a body over limit bytes rather than returning a
// truncated one, which would parse as a document that is not there.
func (v *Verifier) get(ctx context.Context, raw string, header http.Header, limit int64) ([]byte, error) {
	body, _, err := v.getWithin(ctx, raw, header, limit, nil)
	return body, err
}

// getWithin is get with every redirect hop put to allow before it is sent; a
// hop allow refuses is never requested. It also returns the URL of the
// response the body came from, which after a redirect is the one a relative
// reference in the body resolves against. Userinfo in raw stays on the request
// URL, where the client turns it into Basic credentials for that request
// alone: set as a header here instead, it would be copied onto a redirect to
// another port of the same host. Every error it returns is a *fetchError.
func (v *Verifier) getWithin(ctx context.Context, raw string, header http.Header, limit int64, allow func(*url.URL) error) ([]byte, *url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, nil, &fetchError{what: "refusing to fetch it: not an http(s) URL", err: err}
	}
	at := (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
	fail := func(what string, err error) ([]byte, *url.URL, error) {
		return nil, nil, &fetchError{at: manifest.PublicURL(at), what: what, err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fail("the request could not be built", err)
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	req.Header.Set("User-Agent", policy.UserAgent)
	client := v.client()
	if allow != nil {
		c := *client
		prior := c.CheckRedirect
		c.CheckRedirect = func(next *http.Request, via []*http.Request) error {
			if err := allow(next.URL); err != nil {
				return err
			}
			if prior != nil {
				return prior(next, via)
			}
			if len(via) >= 10 {
				return errTooManyRedirects
			}
			return nil
		}
		client = &c
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail(transportFailure(err), err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fail("HTTP 404", errNotFound)
	case resp.StatusCode != http.StatusOK:
		return fail(fmt.Sprintf("HTTP %d", resp.StatusCode), nil)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fail("the body could not be read", err)
	}
	if int64(len(body)) > limit {
		return fail(fmt.Sprintf("the body is larger than the %d MiB cap", limit>>20), nil)
	}
	return body, resp.Request.URL, nil
}

var errTooManyRedirects = errors.New("stopped after 10 redirects")

// transportFailure names the class of a client.Do error without rendering its
// text. net/http quotes a Location header it could not parse verbatim, and no
// rewrite of that text can find every spelling of userinfo in it (a literal
// or percent-encoded @, a network-path reference, a parser quoting only the
// port it choked on), so the text is read to classify and never repeated.
func transportFailure(err error) string {
	var off *offIndexError
	switch {
	case errors.As(err, &off):
		return off.Error()
	case errors.Is(err, errTooManyRedirects):
		return "it redirected more than 10 times"
	case errors.Is(err, context.DeadlineExceeded):
		return "the request timed out"
	case errors.Is(err, context.Canceled):
		return "the request was canceled"
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		if strings.Contains(ue.Err.Error(), "Location header") {
			return "it redirected to a Location that is not a valid URL, so the redirect was not followed"
		}
		if ue.Timeout() {
			return "the request timed out"
		}
	}
	return "the connection failed"
}

// fetchError is a failed provenance fetch. Its text is a fixed sentence for
// the failure's class and the scheme and host of the URL requested, both
// known not to carry credentials, and err keeps the original chain for
// errors.Is and errors.As without ever being rendered.
type fetchError struct {
	at   string
	what string
	err  error
}

func (e *fetchError) Error() string {
	if e.at == "" {
		return e.what
	}
	return "GET " + e.at + ": " + e.what
}

func (e *fetchError) Unwrap() error { return e.err }
