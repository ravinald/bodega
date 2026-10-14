// Package idp verifies OIDC ID tokens from the providers oidc_providers
// configures and maps their claims onto bodega token scopes.
//
// It is the verification half of POST /api/v1/auth/exchange. Minting and
// storing the bodega token is the server's; this package answers "who is this
// and what may they do", or refuses with a reason fit to send back to the
// caller. A reason never carries the token itself.
package idp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

// rediscoverAfter is how long a provider that failed discovery waits before
// the next exchange tries it again. Without a floor, every CI job naming an
// unreachable issuer would hold a request open for the full client timeout.
const rediscoverAfter = time.Minute

// Registry holds one verifier per configured provider.
type Registry struct {
	providers []*provider
	client    *http.Client
	logger    *slog.Logger
	now       func() time.Time
}

type provider struct {
	cfg config.OIDCProvider

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
	endpoint ProviderInfo
	lastErr  error
	lastTry  time.Time
}

// ProviderInfo is what a client needs to sign in through a provider with the
// device authorization flow. DeviceAuthURL is empty for an issuer that offers
// no device flow, which is every CI issuer.
type ProviderInfo struct {
	Name          string `json:"name"`
	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id,omitempty"`
	DeviceAuthURL string `json:"device_authorization_endpoint,omitempty"`
	TokenURL      string `json:"token_endpoint,omitempty"`
}

// Result is a verified ID token mapped onto bodega scopes.
type Result struct {
	Provider string
	Issuer   string
	Subject  string
	Scopes   audit.Scopes
	Rule     int // index of the rule that matched
}

// Refusal is an exchange refused for a reason the caller may read. Status is
// the HTTP status to answer with.
type Refusal struct {
	Status int
	Reason string
}

func (r *Refusal) Error() string { return r.Reason }

func refuse(format string, args ...any) error {
	return &Refusal{Status: http.StatusUnauthorized, Reason: fmt.Sprintf(format, args...)}
}

// New discovers every provider. One that cannot be reached is logged at ERROR
// and its tokens are refused until a later exchange reaches it; the others,
// and everything else the server does, carry on. client may be nil.
func New(ctx context.Context, providers []config.OIDCProvider, client *http.Client, logger *slog.Logger) *Registry {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	r := &Registry{client: client, logger: logger, now: time.Now}
	var wg sync.WaitGroup
	for _, pc := range providers {
		p := &provider{cfg: pc}
		r.providers = append(r.providers, p)
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.mu.Lock()
			defer p.mu.Unlock()
			r.discoverLocked(ctx, p)
		}()
	}
	wg.Wait()
	return r
}

// SetNow replaces the clock expiry is judged against. For tests.
func (r *Registry) SetNow(now func() time.Time) { r.now = now }

// Len is the number of configured providers.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.providers)
}

// discoverLocked fetches p's discovery document and builds its verifier. The
// key set behind the verifier caches the issuer's keys and refetches them
// when a token names a key it does not hold, which is how a rotation lands.
func (r *Registry) discoverLocked(ctx context.Context, p *provider) {
	p.lastTry = r.now()
	dctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, r.client), r.client.Timeout+time.Second)
	defer cancel()
	op, err := oidc.NewProvider(dctx, p.cfg.Issuer)
	if err != nil {
		p.lastErr = err
		r.logger.Error("OIDC provider unreachable; tokens it issues are refused until it answers",
			"provider", p.cfg.DisplayName(), "issuer", p.cfg.Issuer, "error", err)
		return
	}
	var extra struct {
		DeviceAuthURL string `json:"device_authorization_endpoint"`
	}
	_ = op.Claims(&extra)
	p.verifier = op.VerifierContext(oidc.ClientContext(context.Background(), r.client), &oidc.Config{
		SkipClientIDCheck: true, // aud is checked against audience and client_id below
		Now:               func() time.Time { return r.now() },
	})
	p.endpoint = ProviderInfo{
		Name: p.cfg.DisplayName(), Issuer: p.cfg.Issuer, ClientID: p.cfg.ClientID,
		DeviceAuthURL: extra.DeviceAuthURL, TokenURL: op.Endpoint().TokenURL,
	}
	p.lastErr = nil
	r.logger.Info("OIDC provider discovered", "provider", p.cfg.DisplayName(), "issuer", p.cfg.Issuer)
}

// ready returns p's verifier, retrying discovery once the floor has passed.
func (r *Registry) ready(ctx context.Context, p *provider) (*oidc.IDTokenVerifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.verifier == nil && r.now().Sub(p.lastTry) >= rediscoverAfter {
		r.discoverLocked(ctx, p)
	}
	if p.verifier == nil {
		return nil, p.lastErr
	}
	return p.verifier, nil
}

// Providers lists every provider bodega login can sign in through: those with
// a client_id and a device authorization endpoint. A provider whose discovery
// has not succeeded is retried here on the same floor an exchange uses.
func (r *Registry) Providers(ctx context.Context) []ProviderInfo {
	if r == nil {
		return nil
	}
	var out []ProviderInfo
	for _, p := range r.providers {
		if p.cfg.ClientID == "" {
			continue
		}
		if _, err := r.ready(ctx, p); err != nil {
			continue
		}
		p.mu.Lock()
		info := p.endpoint
		p.mu.Unlock()
		if info.DeviceAuthURL != "" {
			out = append(out, info)
		}
	}
	return out
}

// Exchange verifies rawIDToken against the provider its issuer names and
// returns the scopes the first matching rule grants. Every failure is a
// *Refusal naming the issuer, and never the token.
func (r *Registry) Exchange(ctx context.Context, rawIDToken string) (Result, error) {
	if r == nil || len(r.providers) == 0 {
		return Result{}, &Refusal{Status: http.StatusNotFound, Reason: "no oidc_providers are configured on this server"}
	}
	iss, err := unverifiedIssuer(rawIDToken)
	if err != nil {
		return Result{}, refuse("the ID token does not parse as a JWT: %v", err)
	}
	var p *provider
	for _, c := range r.providers {
		if c.cfg.Issuer == iss {
			p = c
			break
		}
	}
	if p == nil {
		return Result{}, refuse("issuer %q is not one of this server's oidc_providers", iss)
	}
	v, err := r.ready(ctx, p)
	if err != nil {
		return Result{}, refuse("issuer %s could not be reached for its signing keys, so its tokens are refused: %v", iss, err)
	}
	tok, err := v.Verify(ctx, rawIDToken)
	if err != nil {
		var exp *oidc.TokenExpiredError
		if errors.As(err, &exp) {
			return Result{}, refuse("ID token from %s expired at %s", iss, exp.Expiry.UTC().Format(time.RFC3339))
		}
		return Result{}, refuse("ID token from %s failed verification: %v", iss, err)
	}
	want := p.cfg.Audiences()
	if !slices.ContainsFunc(tok.Audience, func(a string) bool { return slices.Contains(want, a) }) {
		return Result{}, refuse("ID token from %s is for audience %q; this server accepts %q", iss, tok.Audience, want)
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return Result{}, refuse("ID token from %s carries claims that do not decode: %v", iss, err)
	}
	for i, rule := range p.cfg.Rules {
		if len(unmatched(rule, claims)) > 0 {
			continue
		}
		sc, err := audit.ParseScopes(rule.Scopes)
		if err != nil {
			return Result{}, &Refusal{Status: http.StatusInternalServerError, Reason: fmt.Sprintf("rule %d for %s has scopes that do not parse: %v", i, iss, err)}
		}
		return Result{Provider: p.cfg.DisplayName(), Issuer: iss, Subject: tok.Subject, Scopes: sc, Rule: i}, nil
	}
	return Result{}, refuse("no rule for issuer %s matched: %s", iss, describeMisses(p.cfg.Rules, claims))
}

// unverifiedIssuer reads iss from a JWT payload without checking anything.
// It picks which provider verifies the token, and nothing else trusts it.
func unverifiedIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("want 3 dot-separated parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("payload: %w", err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("payload: %w", err)
	}
	if c.Iss == "" {
		return "", errors.New("no iss claim")
	}
	return c.Iss, nil
}

// unmatched returns the claim names in rule that claims does not satisfy.
func unmatched(rule config.OIDCRule, claims map[string]any) []string {
	var out []string
	for k, want := range rule.Claims {
		if !claimMatches(claims[k], want) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func claimMatches(got any, want string) bool {
	switch v := got.(type) {
	case string:
		return globMatch(want, v)
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && globMatch(want, s) {
				return true
			}
		}
	case bool, float64:
		return globMatch(want, fmt.Sprint(v))
	}
	return false
}

// globMatch matches s against pattern, where * spans any run of characters
// including "/". path.Match would stop * at a slash, and every CI claim worth
// matching (repository, ref, job_workflow_ref) is made of slashes.
func globMatch(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$").MatchString(s)
}

// describeMisses names, per rule, each claim that failed and what the token
// carried for it. Claim values are not secrets, and an operator fixing a rule
// needs to see what the job presented.
func describeMisses(rules []config.OIDCRule, claims map[string]any) string {
	var b strings.Builder
	for i, rule := range rules {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "rule %d:", i)
		for _, k := range unmatched(rule, claims) {
			got, present := claims[k]
			if !present {
				fmt.Fprintf(&b, " %s absent (want %q)", k, rule.Claims[k])
				continue
			}
			fmt.Fprintf(&b, " %s=%s (want %q)", k, claimString(got), rule.Claims[k])
		}
	}
	return b.String()
}

func claimString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}
