package server

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

const testPepper = "pepper-for-tests"

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// Requirement 7's first item. docs/DESIGN.md used to claim package-manager
// clients cannot send auth headers; all eight can, and this is the header each
// one puts on the wire once bodega doctor has written its credential.
func TestEveryClientCredentialFormParses(t *testing.T) {
	const tok = "bodega_ak_deadbeef"

	for _, tc := range []struct {
		client string
		how    string
		header string
		want   credentialForm
	}{
		{"apt", "/etc/apt/auth.conf.d/bodega.conf, netrc login+password", basicAuth("bodega", tok), formBasic},
		{"pip", "index URL with the token in the user half", basicAuth(tok, ""), formBasic},
		{"npm", "_authToken in .npmrc", "Bearer " + tok, formBearer},
		{"gomod", ".netrc for the GOPROXY host", basicAuth("bodega", tok), formBasic},
		{"cargo", "credentials.toml token, sent with no scheme", tok, formRaw},
		{"helm", "--username bodega --password <token>", basicAuth("bodega", tok), formBasic},
		{"git", "libcurl reading .netrc", basicAuth("bodega", tok), formBasic},
		{"binary", "curl --netrc / wget", basicAuth("bodega", tok), formBasic},
	} {
		t.Run(tc.client, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/npm/left-pad", nil)
			r.Header.Set("Authorization", tc.header)
			got, form := credentialFrom(r)
			if got != tok {
				t.Fatalf("%s (%s) parsed to %q, want the token", tc.client, tc.how, got)
			}
			if form != tc.want {
				t.Fatalf("%s parsed as form %q, want %q", tc.client, form, tc.want)
			}
		})
	}
}

// A scheme bodega does not speak must yield nothing. Reading the remainder as
// a token would attribute a request to whichever identity collided with a
// base64 blob, and the caller never claimed to be that host.
func TestUnknownAuthSchemesYieldNoCredential(t *testing.T) {
	for _, h := range []string{
		"",
		"Digest username=\"bodega\", realm=\"x\"",
		"Negotiate YIIC...",
		"Bearer ",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte(":")),
	} {
		r := httptest.NewRequest(http.MethodGet, "/npm/left-pad", nil)
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		if got, form := credentialFrom(r); got != "" || form != formNone {
			t.Fatalf("Authorization %q parsed to (%q, %q), want no credential", h, got, form)
		}
	}
}

// identityFor builds the set once and answers one request through it, which is
// what the middleware does per request.
func identityFor(t *testing.T, bindings []audit.IdentityBinding, tokens []audit.TokenHash, header, ip string) string {
	t.Helper()
	set := newIdentitySet(bindings, tokens)
	r := httptest.NewRequest(http.MethodGet, "/npm/left-pad", nil)
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	cred, _ := credentialFrom(r)
	return set.resolve(cred, ip, testPepper, time.Now())
}

// The order in requirement 3, and the case that makes it observable: an
// operator issued a credential to one host, and the subnet it sits in says
// something else. The credential is the more specific statement.
func TestTokenBeatsACIDRThatDisagrees(t *testing.T) {
	const tok = "bodega_ak_build07"
	bindings := []audit.IdentityBinding{
		{Kind: audit.BindCIDR, Key: "10.20.0.0/16", Identity: "devbox"},
		{Kind: audit.BindToken, Key: "tok-1", Identity: "build-07"},
	}
	tokens := []audit.TokenHash{{ID: "tok-1", Hash: audit.HashToken(tok, testPepper)}}

	if got := identityFor(t, bindings, tokens, "Bearer "+tok, "10.20.0.9"); got != "build-07" {
		t.Fatalf("token + disagreeing CIDR resolved to %q, want build-07", got)
	}
	// Same address, no credential: the CIDR is the only thing left to answer.
	if got := identityFor(t, bindings, tokens, "", "10.20.0.9"); got != "devbox" {
		t.Fatalf("no credential resolved to %q, want the CIDR's devbox", got)
	}
	// A credential nothing knows falls through rather than refusing. This path
	// adds attribution, never admission.
	if got := identityFor(t, bindings, tokens, "Bearer bodega_ak_unknown", "10.20.0.9"); got != "devbox" {
		t.Fatalf("an unknown token resolved to %q, want the CIDR fallback devbox", got)
	}
}

func TestLongestPrefixCIDRWins(t *testing.T) {
	bindings := []audit.IdentityBinding{
		{Kind: audit.BindCIDR, Key: "10.0.0.0/8", Identity: "fleet"},
		{Kind: audit.BindCIDR, Key: "10.20.0.0/16", Identity: "devbox"},
		{Kind: audit.BindCIDR, Key: "10.20.5.7/32", Identity: "devbox-7"},
	}
	for ip, want := range map[string]string{
		"10.20.5.7": "devbox-7",
		"10.20.9.1": "devbox",
		"10.99.0.1": "fleet",
		"192.0.2.1": "",
	} {
		if got := identityFor(t, bindings, nil, "", ip); got != want {
			t.Fatalf("%s resolved to %q, want %q", ip, got, want)
		}
	}
}

// A revoked-by-expiry token identifies nobody. The expiry row is the operator
// saying this host is no longer that host.
func TestExpiredTokenFallsThroughToTheCIDR(t *testing.T) {
	const tok = "bodega_ak_stale"
	past := time.Now().Add(-time.Hour)
	bindings := []audit.IdentityBinding{
		{Kind: audit.BindCIDR, Key: "10.20.0.0/16", Identity: "devbox"},
		{Kind: audit.BindToken, Key: "tok-1", Identity: "build-07"},
	}
	tokens := []audit.TokenHash{{ID: "tok-1", Hash: audit.HashToken(tok, testPepper), ExpiresAt: &past}}
	if got := identityFor(t, bindings, tokens, "Bearer "+tok, "10.20.0.9"); got != "devbox" {
		t.Fatalf("expired token resolved to %q, want the CIDR fallback devbox", got)
	}
}

// Requirement 1's second half, and the one that would make this item a
// regression if it failed: a request with no credential is served as it is
// today, with an audit row that names nobody rather than no audit row.
func TestUnidentifiedRequestIsStillServedAndStillRecorded(t *testing.T) {
	ctx := context.Background()
	s := newACLServer(t, &config.Config{})
	s.pepper = testPepper
	if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{
		Kind: audit.BindCIDR, Key: "10.20.0.0/16", Identity: "devbox",
	}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	s.refreshIdentities(ctx)

	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Identity", Identity(r))
		w.WriteHeader(http.StatusOK)
	})
	h = AuditMiddleware(s.auditDB)(h)
	h = IdentityMiddleware(s.identityFunc())(h)

	for _, tc := range []struct{ name, ip, want string }{
		{"unidentified", "203.0.113.9:5000", ""},
		{"bound by cidr", "10.20.0.9:5000", "devbox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/npm/left-pad", nil)
			req.RemoteAddr = tc.ip
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, want 200: identity resolution must not gate a fetch", rec.Code)
			}
			if got := rec.Header().Get("X-Seen-Identity"); got != tc.want {
				t.Fatalf("handler saw identity %q, want %q", got, tc.want)
			}
		})
	}

	// Requirement 5: the row carries both, and the unidentified fetch is on it.
	events, err := s.auditDB.Query(ctx, audit.Filter{EventType: audit.EventServeFetch})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("recorded %d serve_fetch rows, want 2 (the unidentified one is not dropped)", len(events))
	}
	byIP := map[string]audit.StoredEvent{}
	for _, e := range events {
		byIP[e.ClientIP] = e
	}
	if e := byIP["10.20.0.9"]; e.Identity != "devbox" {
		t.Fatalf("bound request recorded identity %q, want devbox", e.Identity)
	}
	if e := byIP["203.0.113.9"]; e.Identity != "" {
		t.Fatalf("unidentified request recorded identity %q, want empty", e.Identity)
	}
}

// Requirement 4. trusted_proxies defaults to loopback + RFC 1918 and bodega
// returns X-Real-IP verbatim from any peer in that set, so a CIDR binding on a
// default-configured instance is assertable by whoever sends a header.
func TestStartRefusesACIDRBindingUnderDefaultTrustedProxies(t *testing.T) {
	ctx := context.Background()

	t.Run("default trusted_proxies refuses", func(t *testing.T) {
		s := newACLServer(t, &config.Config{AllowPlaintext: true})
		if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{
			Kind: audit.BindCIDR, Key: "10.20.0.0/16", Identity: "devbox",
		}); err != nil {
			t.Fatalf("bind: %v", err)
		}
		err := s.guardCIDRBindings(ctx)
		var want *cidrBindingTrustError
		if !errors.As(err, &want) {
			t.Fatalf("guard returned %v, want the startup refusal", err)
		}
		for _, phrase := range []string{
			"bodega acl proxies add",  // name the proxy
			"\"trusted_proxies\": []", // or write an empty list
			"trusted_proxies is still the built-in default",
		} {
			if !strings.Contains(err.Error(), phrase) {
				t.Fatalf("refusal does not carry %q:\n%s", phrase, err)
			}
		}
	})

	t.Run("a token binding alone is fine", func(t *testing.T) {
		s := newACLServer(t, &config.Config{AllowPlaintext: true})
		if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{
			Kind: audit.BindToken, Key: "tok-1", Identity: "build-07",
		}); err != nil {
			t.Fatalf("bind: %v", err)
		}
		if err := s.guardCIDRBindings(ctx); err != nil {
			t.Fatalf("a token binding needs no proxy answer, but startup refused: %v", err)
		}
	})

	for _, tc := range []struct {
		name    string
		entries []string
	}{
		{"named proxy", []string{"192.0.2.7/32"}},
		{"explicitly empty", nil},
	} {
		t.Run("answered: "+tc.name, func(t *testing.T) {
			s := newACLServer(t, &config.Config{AllowPlaintext: true})
			if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{
				Kind: audit.BindCIDR, Key: "10.20.0.0/16", Identity: "devbox",
			}); err != nil {
				t.Fatalf("bind: %v", err)
			}
			if _, err := s.auditDB.SeedACL(ctx, audit.ACLProxies, tc.entries, "ravi"); err != nil {
				t.Fatalf("seed proxies: %v", err)
			}
			s.refreshACLs(ctx)
			if err := s.guardCIDRBindings(ctx); err != nil {
				t.Fatalf("trusted_proxies answered (%s) and startup still refused: %v", tc.name, err)
			}
		})
	}
}
