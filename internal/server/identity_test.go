package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/host"
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
// what the middleware does per request. trusted_proxies is answered here: these
// cases are about resolution order, and the unanswered case is its own test.
func identityFor(t *testing.T, bindings []audit.IdentityBinding, tokens []audit.TokenHash, header, ip string) string {
	t.Helper()
	set := newIdentitySet(bindings, tokens)
	r := httptest.NewRequest(http.MethodGet, "/npm/left-pad", nil)
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	cred, _ := credentialFrom(r)
	return set.resolve(cred, ip, testPepper, time.Now(), true)
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
	s := newACLServer(t, &config.Config{TrustedProxies: []string{}})
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

// The seam nothing asserted: what bodega doctor writes is what its client
// sends. TestEveryClientCredentialFormParses drives headers written by hand,
// so both halves could drift the same way and stay green. This one renders
// each target through the writer, reads it back the way its client does, and
// puts the result on the wire.
//
// The readers below are deliberately small and literal. They are not a claim
// that this is how apt or cargo parse their files; they are a claim about
// where the credential sits in the file bodega wrote, which is the half of the
// contract bodega owns.
func TestDoctorWritesWhatEachClientSends(t *testing.T) {
	const tok = "bodega_ak_deadbeef"
	base, err := url.Parse("https://bodega.internal")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}

	readers := map[string]func(*testing.T, string) string{
		"apt":    netrcHeader,
		"pip":    netrcHeader,
		"npm":    npmHeader,
		"gomod":  netrcHeader,
		"cargo":  cargoHeader,
		"helm":   helmHeader,
		"git":    netrcHeader,
		"binary": netrcHeader,
	}
	forms := map[string]credentialForm{
		"apt": formBasic, "pip": formBasic, "npm": formBearer, "gomod": formBasic,
		"cargo": formRaw, "helm": formBasic, "git": formBasic, "binary": formBasic,
	}

	targets := host.CredentialTargets(t.TempDir())
	if len(targets) != len(readers) {
		t.Fatalf("%d targets, %d readers; every client bodega writes for must be read back", len(targets), len(readers))
	}
	for _, target := range targets {
		t.Run(target.Client, func(t *testing.T) {
			read, ok := readers[target.Client]
			if !ok {
				t.Fatalf("no reader for %q", target.Client)
			}
			header := read(t, target.Render(base, tok))

			r := httptest.NewRequest(http.MethodGet, "/apt/dists/noble/Release", nil)
			r.Header.Set("Authorization", header)
			got, form := credentialFrom(r)
			if got != tok {
				t.Fatalf("%s: the file doctor wrote yields %q on the wire, not the token", target.Client, got)
			}
			if form != forms[target.Client] {
				t.Fatalf("%s: parsed as form %q, want %q", target.Client, form, forms[target.Client])
			}
		})
	}
}

// netrcHeader reads the login and password for the one machine in the file and
// sends them as Basic, which is what libcurl, requests and the go toolchain
// each do with a netrc entry.
//
// It refuses a comment preceded by a blank line first, because a Fields scan
// reads such a file exactly as happily as a good one and pip does not: Python's
// netrc module rejects that placement, and rejects the whole file for it, so
// requests hands back no credential at all. libcurl parses it regardless, which
// is why a reader modeled on curl alone let the shape through.
func netrcHeader(t *testing.T, file string) string {
	t.Helper()
	lines := strings.Split(file, "\n")
	for i, l := range lines {
		if i > 0 && strings.HasPrefix(strings.TrimSpace(l), "#") && strings.TrimSpace(lines[i-1]) == "" {
			t.Fatalf("line %d is a comment after a blank line, which Python's netrc refuses,\n"+
				"taking every other credential in the file with it:\n%s", i+1, file)
		}
	}
	fields := strings.Fields(file)
	var login, password string
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "login":
			login = fields[i+1]
		case "password":
			password = fields[i+1]
		}
	}
	if login == "" || password == "" {
		t.Fatalf("no netrc login/password in:\n%s", file)
	}
	return basicAuth(login, password)
}

// npmHeader takes the _authToken npm keys on the registry path and sends it as
// Bearer, which is npm's own wire form.
func npmHeader(t *testing.T, file string) string {
	t.Helper()
	for _, line := range strings.Split(file, "\n") {
		_, value, ok := strings.Cut(line, ":_authToken=")
		if ok {
			return "Bearer " + strings.TrimSpace(value)
		}
	}
	t.Fatalf("no _authToken in:\n%s", file)
	return ""
}

// cargoHeader takes the registry token and sends it as the whole Authorization
// value, with no scheme. Cargo is the only client bodega serves that does this.
func cargoHeader(t *testing.T, file string) string {
	t.Helper()
	inRegistry := false
	for _, line := range strings.Split(file, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inRegistry = line == "[registries.bodega]"
			continue
		}
		if !inRegistry {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "token = "); ok {
			return strings.Trim(rest, `"`)
		}
	}
	t.Fatalf("no [registries.bodega] token in:\n%s", file)
	return ""
}

// helmHeader takes the username and password off the bodega repository entry
// and sends them as Basic, which is what helm does with a repo that carries
// credentials.
//
// First entry wins, not last: helm resolves a chart reference through the
// first repository matching the name, so a file carrying two bodega entries
// puts the older one on the wire.
func helmHeader(t *testing.T, file string) string {
	t.Helper()
	var user, pass string
	for _, line := range strings.Split(file, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "username: "); ok && user == "" {
			user = rest
		}
		if rest, ok := strings.CutPrefix(line, "password: "); ok && pass == "" {
			pass = rest
		}
	}
	if user == "" || pass == "" {
		t.Fatalf("no credential on the helm repository entry:\n%s", file)
	}
	return basicAuth(user, pass)
}

// The other half of that seam: what goes on the wire after a rotation, when
// the file bodega rewrites is the one its client re-serialized rather than the
// one bodega left. cargo, helm and npm all drop the marker comment when they
// write their own configuration, so anchoring on the fence alone stacked a
// second entry and the stale token was what the client sent.
func TestRotatedCredentialIsWhatTheClientSends(t *testing.T) {
	const stale, fresh = "bodega_ak_stale", "bodega_ak_fresh"
	base, err := url.Parse("https://bodega.internal")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}

	cases := []struct {
		client string
		seed   string
		read   func(*testing.T, string) string
		form   credentialForm
	}{
		{
			client: "cargo",
			seed:   "[registries.bodega]\ntoken = \"" + stale + "\"\n\n[registry]\ntoken = \"crates-io\"\n",
			read:   cargoHeader,
			form:   formRaw,
		},
		{
			client: "helm",
			seed: "apiVersion: \"\"\ngenerated: \"2026-01-01T00:00:00Z\"\nrepositories:\n" +
				"- name: bodega\n  url: https://bodega.internal/helm\n  username: bodega\n  password: " + stale + "\n" +
				"- name: bitnami\n  url: https://charts.bitnami.com/bitnami\n",
			read: helmHeader,
			form: formBasic,
		},
		{
			client: "npm",
			seed:   "registry=https://registry.internal/\n//bodega.internal/npm/:_authToken=" + stale + "\n",
			read:   npmHeader,
			form:   formBearer,
		},
	}

	for _, tc := range cases {
		t.Run(tc.client, func(t *testing.T) {
			t.Setenv("HELM_REPOSITORY_CONFIG", "")
			t.Setenv("XDG_CONFIG_HOME", "")
			home := t.TempDir()

			var target host.CredentialTarget
			for _, candidate := range host.CredentialTargets(home) {
				if candidate.Client == tc.client {
					target = candidate
				}
			}
			if target.Client == "" {
				t.Fatalf("no credential target for %q", tc.client)
			}
			if err := os.MkdirAll(filepath.Dir(target.Path), 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(target.Path, []byte(tc.seed), 0o600); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if _, err := host.WriteCredential(target, base, fresh); err != nil {
				t.Fatalf("rotate: %v", err)
			}
			data, err := os.ReadFile(target.Path)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}

			r := httptest.NewRequest(http.MethodGet, "/apt/dists/noble/Release", nil)
			r.Header.Set("Authorization", tc.read(t, string(data)))
			got, form := credentialFrom(r)
			if got != fresh {
				t.Fatalf("after rotation %s sends %q, not the new token:\n%s", tc.client, got, data)
			}
			if form != tc.form {
				t.Fatalf("%s: credential form %v, want %v", tc.client, form, tc.form)
			}
		})
	}
}

// A CIDR binding names the connection, not a header. The hazard it carries is
// X-Real-IP: with trusted_proxies left at the built-in default, loopback plus
// RFC 1918, bodega believes that header verbatim from any peer in that range,
// so one of them could claim an address inside a bound network and collect the
// identity. An address read off the connection carries no such claim.
//
// So the gate is on provenance rather than on config state. Every case drives
// the real RealIPMiddleware, because the provenance is what that middleware
// settles and a chain without it would assert nothing.
func TestACIDRBindingResolvesAConnectionAndNotAForgedHeader(t *testing.T) {
	ctx := context.Background()
	const tok = "bodega_ak_build07"

	// serve builds the chain in handler()'s order for the three middlewares
	// that matter here, and returns the identity the handler saw.
	serve := func(t *testing.T, s *Server, remote, realIP, auth string) (int, string) {
		t.Helper()
		var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Seen-Identity", Identity(r))
			w.WriteHeader(http.StatusOK)
		})
		h = AuditMiddleware(s.auditDB)(h)
		h = IdentityMiddleware(s.identityFunc())(h)
		h = RealIPMiddleware(s.trustedNetsFunc())(h)
		req := httptest.NewRequest(http.MethodGet, "/cargo/config.json", nil)
		req.RemoteAddr = remote
		if realIP != "" {
			req.Header.Set("X-Real-IP", realIP)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Header().Get("X-Seen-Identity")
	}

	// bound is an instance with one CIDR binding and trusted_proxies still at
	// the built-in default, which is where every install starts.
	bound := func(t *testing.T) *Server {
		t.Helper()
		s := newACLServer(t, &config.Config{AllowPlaintext: true})
		s.pepper = testPepper
		if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{
			Kind: audit.BindCIDR, Key: "10.20.0.0/16", Identity: "devbox",
		}); err != nil {
			t.Fatalf("bind cidr: %v", err)
		}
		s.refreshIdentities(ctx)
		return s
	}

	t.Run("a direct peer inside the binding resolves", func(t *testing.T) {
		s := bound(t)
		code, id := serve(t, s, "10.20.0.9:5000", "", "")
		if code != http.StatusOK {
			t.Fatalf("status %d, want 200: attribution never gates a fetch", code)
		}
		if id != "devbox" {
			t.Fatalf("resolved %q, want devbox: the address completed a handshake and nothing a client writes changes it", id)
		}
		events, err := s.auditDB.Query(ctx, audit.Filter{EventType: audit.EventServeFetch})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(events) != 1 || events[0].Identity != "devbox" || events[0].ClientIP != "10.20.0.9" {
			t.Fatalf("rows = %+v, want one naming devbox at 10.20.0.9", events)
		}
	})

	t.Run("an RFC 1918 peer cannot claim the network by header", func(t *testing.T) {
		s := bound(t)
		// 10.99.0.1 is inside the built-in trusted set, so RealIPMiddleware
		// believes its X-Real-IP. That is the forge the gate exists for.
		code, id := serve(t, s, "10.99.0.1:5000", "10.20.0.9", "")
		if code != http.StatusOK {
			t.Fatalf("status %d, want 200", code)
		}
		if id != "" {
			t.Fatalf("resolved %q from a header on a default-trusted_proxies instance; the binding must name nobody", id)
		}
	})

	t.Run("a peer outside the trusted set has its header ignored", func(t *testing.T) {
		s := bound(t)
		if _, id := serve(t, s, "203.0.113.9:5000", "10.20.0.9", ""); id != "" {
			t.Fatalf("resolved %q: RealIPMiddleware does not believe this peer, so the address is 203.0.113.9", id)
		}
	})

	t.Run("answering trusted_proxies admits the proxy's header", func(t *testing.T) {
		s := bound(t)
		if _, err := s.auditDB.SeedACL(ctx, audit.ACLProxies, []string{"10.99.0.0/16"}, "ravi"); err != nil {
			t.Fatalf("seed proxies: %v", err)
		}
		s.reload(ctx)
		if _, id := serve(t, s, "10.99.0.1:5000", "10.20.0.9", ""); id != "devbox" {
			t.Fatalf("resolved %q with the proxy named, want devbox", id)
		}
	})

	// Requirement 2. A credential is the precise answer and wins over the
	// subnet, on every request and from either address, because resolve walks
	// the token first rather than reading a map in range order.
	t.Run("a token beats the address it arrives from", func(t *testing.T) {
		s := bound(t)
		const id = "tok-1"
		if err := s.auditDB.InsertToken(ctx, id, "build-07", audit.HashToken(tok, testPepper), "", nil); err != nil {
			t.Fatalf("insert token: %v", err)
		}
		if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{
			Kind: audit.BindToken, Key: id, Identity: "build-07",
		}); err != nil {
			t.Fatalf("bind token: %v", err)
		}
		s.refreshIdentities(ctx)

		for i := range 20 {
			if _, got := serve(t, s, "10.20.0.9:5000", "", "Bearer "+tok); got != "build-07" {
				t.Fatalf("request %d resolved %q, want build-07 on every one of them", i, got)
			}
		}
	})
}

// A reload is not instantaneous from a request's point of view: RealIPMiddleware
// decides whether to believe a header, and IdentityMiddleware runs after it.
// Both must answer to the same trusted set, or an operator narrowing
// trusted_proxies hands the in-flight request a decision made under the old set
// and a verdict made under the new one. The peer excluded by the reload is the
// one that collects an identity it was never granted.
func TestCIDRForwardedTrustUsesRealIPSnapshot(t *testing.T) {
	ctx := context.Background()

	// serve drives the two middlewares in handler()'s order with an ACL
	// refresh wedged between them, which is where a SIGHUP can land.
	serve := func(t *testing.T, s *Server, remote, realIP string, betweenACLs []string) string {
		t.Helper()
		var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Seen-Identity", Identity(r))
		})
		h = IdentityMiddleware(s.identityFunc())(h)
		reloadBetween := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := s.auditDB.SeedACL(ctx, audit.ACLProxies, betweenACLs, "ravi"); err != nil {
					t.Errorf("seed proxies mid-chain: %v", err)
				}
				s.refreshACLs(ctx)
				next.ServeHTTP(w, r)
			})
		}
		h = reloadBetween(h)
		h = RealIPMiddleware(s.trustedNetsFunc())(h)
		req := httptest.NewRequest(http.MethodGet, "/cargo/config.json", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Real-IP", realIP)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Header().Get("X-Seen-Identity")
	}

	bound := func(t *testing.T, seed []string) *Server {
		t.Helper()
		s := newACLServer(t, &config.Config{AllowPlaintext: true})
		s.pepper = testPepper
		if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{
			Kind: audit.BindCIDR, Key: "10.20.0.0/16", Identity: "devbox",
		}); err != nil {
			t.Fatalf("bind cidr: %v", err)
		}
		if seed != nil {
			if _, err := s.auditDB.SeedACL(ctx, audit.ACLProxies, seed, "ravi"); err != nil {
				t.Fatalf("seed proxies: %v", err)
			}
		}
		s.refreshACLs(ctx)
		s.refreshIdentities(ctx)
		return s
	}

	// The header was believed under the built-in default, and the reload
	// excludes the peer that sent it. The answer belongs to the snapshot the
	// header was read against, so this peer names nobody.
	t.Run("a reload excluding the peer does not bless a header already read", func(t *testing.T) {
		s := bound(t, nil)
		if id := serve(t, s, "10.99.0.1:5000", "10.20.0.9", []string{"192.168.50.0/24"}); id != "" {
			t.Fatalf("resolved %q from a header believed under the built-in default; 10.99.0.1 is not a configured proxy", id)
		}
	})

	// The inverse transition, so the assertion is about the snapshot rather
	// than about one direction of change: the peer was a named proxy when its
	// header was read, and a reload that drops trusted_proxies afterwards does
	// not retract that.
	t.Run("a reload after the header was read does not retract the proxy", func(t *testing.T) {
		s := bound(t, []string{"10.99.0.0/16"})
		if id := serve(t, s, "10.99.0.1:5000", "10.20.0.9", nil); id != "devbox" {
			t.Fatalf("resolved %q, want devbox: the header was read while this peer was a named proxy", id)
		}
	})
}
