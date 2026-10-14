package idp_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/idp"
	"github.com/ravinald/bodega/internal/idp/idptest"
)

const audience = "https://bodega.example"

func ciProvider(issuer string) config.OIDCProvider {
	return config.OIDCProvider{
		Name: "ci", Issuer: issuer, Audience: audience, ClientID: "bodega-cli",
		Rules: []config.OIDCRule{
			{Claims: map[string]string{"repository": "acme/app", "ref": "refs/heads/main"}, Scopes: "read,write:npm"},
			{Claims: map[string]string{"job_workflow_ref": "acme/ops/.github/workflows/*@refs/heads/main"}, Scopes: "admin"},
			{Claims: map[string]string{"groups": "bodega-readers"}, Scopes: "read"},
		},
	}
}

func newRegistry(t *testing.T, is *idptest.Issuer) *idp.Registry {
	t.Helper()
	return idp.New(context.Background(), []config.OIDCProvider{ciProvider(is.URL)}, nil, nil)
}

func refusal(t *testing.T, err error) *idp.Refusal {
	t.Helper()
	var ref *idp.Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("err = %v, want an *idp.Refusal", err)
	}
	return ref
}

func TestExchangeValidTokenMapsFirstMatchingRule(t *testing.T) {
	is := idptest.New(t)
	r := newRegistry(t, is)
	raw := is.Token(t, map[string]any{
		"aud": audience, "sub": "repo:acme/app:ref:refs/heads/main",
		"repository": "acme/app", "ref": "refs/heads/main",
	})
	res, err := r.Exchange(context.Background(), raw)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if res.Subject != "repo:acme/app:ref:refs/heads/main" || res.Issuer != is.URL || res.Provider != "ci" {
		t.Errorf("result = %+v", res)
	}
	if got := res.Scopes.String(); got != "read,write:npm" || res.Rule != 0 {
		t.Errorf("scopes = %q from rule %d, want read,write:npm from rule 0", got, res.Rule)
	}
}

// A glob spans slashes, and a list claim matches on any element: the two
// shapes job_workflow_ref and groups need.
func TestExchangeGlobAndListClaims(t *testing.T) {
	is := idptest.New(t)
	r := newRegistry(t, is)
	wf, err := r.Exchange(context.Background(), is.Token(t, map[string]any{
		"aud": audience, "sub": "w",
		"job_workflow_ref": "acme/ops/.github/workflows/release.yml@refs/heads/main",
	}))
	if err != nil || wf.Scopes.String() != "admin" {
		t.Errorf("workflow glob: %+v, %v; want admin", wf, err)
	}
	// client_id is an accepted audience: it is what a device-flow ID token carries.
	person, err := r.Exchange(context.Background(), is.Token(t, map[string]any{
		"aud": "bodega-cli", "sub": "alice", "groups": []string{"staff", "bodega-readers"},
	}))
	if err != nil || person.Scopes.String() != "read" {
		t.Errorf("groups list: %+v, %v; want read", person, err)
	}
}

func TestExchangeRefusesExpiredToken(t *testing.T) {
	is := idptest.New(t)
	r := newRegistry(t, is)
	raw := is.Token(t, map[string]any{
		"aud": audience, "sub": "s", "repository": "acme/app", "ref": "refs/heads/main",
		"iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix(),
	})
	_, err := r.Exchange(context.Background(), raw)
	ref := refusal(t, err)
	if ref.Status != http.StatusUnauthorized || !strings.Contains(ref.Reason, "expired") || !strings.Contains(ref.Reason, is.URL) {
		t.Errorf("refusal = %+v, want a 401 naming the issuer and the expiry", ref)
	}
	if strings.Contains(ref.Reason, raw) {
		t.Error("refusal echoes the token")
	}
}

func TestExchangeRefusesWrongAudience(t *testing.T) {
	is := idptest.New(t)
	r := newRegistry(t, is)
	_, err := r.Exchange(context.Background(), is.Token(t, map[string]any{
		"aud": "https://someone-else.example", "sub": "s", "repository": "acme/app", "ref": "refs/heads/main",
	}))
	ref := refusal(t, err)
	if ref.Status != http.StatusUnauthorized || !strings.Contains(ref.Reason, "someone-else") || !strings.Contains(ref.Reason, audience) {
		t.Errorf("refusal = %+v, want a 401 naming both audiences", ref)
	}
}

// A token signed by a key the issuer rotated to verifies without a restart:
// the key set refetches on a kid it does not hold. One signed by a key the
// issuer has since withdrawn does not.
func TestExchangeHonorsKeyRotation(t *testing.T) {
	is := idptest.New(t)
	r := newRegistry(t, is)
	claims := map[string]any{"aud": audience, "sub": "s", "repository": "acme/app", "ref": "refs/heads/main"}
	old := is.Token(t, claims)
	if _, err := r.Exchange(context.Background(), old); err != nil {
		t.Fatalf("first key: %v", err)
	}
	before := is.JWKSFetches()

	is.Rotate(false)
	if _, err := r.Exchange(context.Background(), is.Token(t, claims)); err != nil {
		t.Fatalf("token from the rotated key refused: %v", err)
	}
	if is.JWKSFetches() <= before {
		t.Error("the rotated key verified without the JWKS being refetched")
	}
	if _, err := r.Exchange(context.Background(), old); err == nil {
		t.Error("a token signed by the withdrawn key still verified")
	}
}

// No rule matched: 401, the reason names the issuer and each unmatched claim
// with what the token carried, and never the token.
func TestExchangeRefusesUnmatchedClaims(t *testing.T) {
	is := idptest.New(t)
	r := newRegistry(t, is)
	raw := is.Token(t, map[string]any{
		"aud": audience, "sub": "s", "repository": "acme/fork", "ref": "refs/heads/main",
	})
	_, err := r.Exchange(context.Background(), raw)
	ref := refusal(t, err)
	if ref.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", ref.Status)
	}
	for _, want := range []string{is.URL, `repository="acme/fork"`, `want "acme/app"`, "job_workflow_ref absent", "groups absent"} {
		if !strings.Contains(ref.Reason, want) {
			t.Errorf("reason %q does not name %q", ref.Reason, want)
		}
	}
	if strings.Contains(ref.Reason, raw) || strings.Contains(ref.Reason, strings.Split(raw, ".")[2]) {
		t.Error("reason carries the token")
	}
}

func TestExchangeRefusesUnknownIssuerAndForgedSignature(t *testing.T) {
	is := idptest.New(t)
	other := idptest.New(t)
	r := newRegistry(t, is)
	_, err := r.Exchange(context.Background(), other.Token(t, map[string]any{"aud": audience, "sub": "s"}))
	if ref := refusal(t, err); !strings.Contains(ref.Reason, other.URL) || !strings.Contains(ref.Reason, "not one of") {
		t.Errorf("unknown issuer: %q", ref.Reason)
	}
	// Signed by another issuer's key but claiming this one.
	forged := other.Token(t, map[string]any{"iss": is.URL, "aud": audience, "sub": "s", "repository": "acme/app", "ref": "refs/heads/main"})
	if _, err := r.Exchange(context.Background(), forged); err == nil {
		t.Error("a token signed by a key the issuer never published verified")
	}
}

// An issuer down at start is logged at ERROR and its tokens refused; the
// registry still answers for the provider that is up, and the down one is
// rediscovered once it answers.
func TestUnreachableProviderIsRefusedNotFatal(t *testing.T) {
	up := idptest.New(t)
	down := idptest.New(t)
	downURL := down.URL
	down.Server.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	p2 := ciProvider(downURL)
	p2.Name = "down"
	r := idp.New(context.Background(), []config.OIDCProvider{ciProvider(up.URL), p2}, &http.Client{Timeout: 2 * time.Second}, logger)
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), downURL) {
		t.Errorf("no ERROR naming the unreachable issuer; logs:\n%s", logs.String())
	}

	claims := map[string]any{"aud": audience, "sub": "s", "repository": "acme/app", "ref": "refs/heads/main"}
	if _, err := r.Exchange(context.Background(), up.Token(t, claims)); err != nil {
		t.Errorf("the reachable provider stopped working: %v", err)
	}
	claims["iss"] = downURL
	_, err := r.Exchange(context.Background(), up.Token(t, claims))
	if ref := refusal(t, err); !strings.Contains(ref.Reason, "could not be reached") || !strings.Contains(ref.Reason, downURL) {
		t.Errorf("refusal = %q, want one naming the unreachable issuer", ref.Reason)
	}
}

func TestProvidersListsDeviceFlowProviders(t *testing.T) {
	is := idptest.New(t)
	ciOnly := ciProvider(idptest.New(t).URL)
	ciOnly.Name, ciOnly.ClientID = "ci-only", ""
	r := idp.New(context.Background(), []config.OIDCProvider{ciProvider(is.URL), ciOnly}, nil, nil)
	got := r.Providers(context.Background())
	if len(got) != 1 || got[0].Name != "ci" || got[0].DeviceAuthURL != is.URL+"/device" || got[0].TokenURL != is.URL+"/token" || got[0].ClientID != "bodega-cli" {
		t.Errorf("providers = %+v", got)
	}
	var nilReg *idp.Registry
	if _, err := nilReg.Exchange(context.Background(), "x.y.z"); refusal(t, err).Status != http.StatusNotFound {
		t.Error("a server with no providers should answer 404")
	}
}
