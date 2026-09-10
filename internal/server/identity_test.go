package server

import (
	"context"
	"encoding/base64"
	"errors"
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
	// trusted_proxies answered, so the CIDR binding resolves at all. Unanswered
	// is TestCIDRBindingsAreInertUntilTrustedProxiesIsAnswered.
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
			// One binding is the common first state, so the singular branch is
			// the one most operators meet. docs/USAGE.md quotes this line.
			"1 CIDR identity binding exists while",
		} {
			if !strings.Contains(err.Error(), phrase) {
				t.Fatalf("refusal does not carry %q:\n%s", phrase, err)
			}
		}

		if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{
			Kind: audit.BindCIDR, Key: "192.168.0.0/16", Identity: "office",
		}); err != nil {
			t.Fatalf("second bind: %v", err)
		}
		if got := s.guardCIDRBindings(ctx).Error(); !strings.Contains(got, "2 CIDR identity bindings exist while") {
			t.Fatalf("plural branch reads wrong:\n%s", got)
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

// The hole the startup refusal alone leaves open: an operator binds a CIDR on
// a server that is already running. guardCIDRBindings ran at boot with nothing
// bound and passed, and both paths that install a binding afterwards — SIGHUP
// and the cache TTL — reach the read path with no guard between them. So the
// instance would serve, header-assertable by any RFC 1918 peer, the exact
// arrangement it refuses to start carrying.
//
// Every case here drives a request through and records a row, so none of them
// can be satisfied by refusing the request. Attribution is what changes.
func TestCIDRBindingsAreInertUntilTrustedProxiesIsAnswered(t *testing.T) {
	ctx := context.Background()
	const tok = "bodega_ak_build07"

	// serve builds the chain the way handler() does for these two middlewares
	// and returns the identity the handler saw.
	serve := func(t *testing.T, s *Server, remote, header string) (int, string) {
		t.Helper()
		var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Seen-Identity", Identity(r))
			w.WriteHeader(http.StatusOK)
		})
		h = AuditMiddleware(s.auditDB)(h)
		h = IdentityMiddleware(s.identityFunc())(h)
		req := httptest.NewRequest(http.MethodGet, "/cargo/config.json", nil)
		req.RemoteAddr = remote
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Header().Get("X-Seen-Identity")
	}

	// running starts from the state guardCIDRBindings passes: no bindings, and
	// trusted_proxies left at the built-in default.
	running := func(t *testing.T) *Server {
		t.Helper()
		s := newACLServer(t, &config.Config{AllowPlaintext: true})
		s.pepper = testPepper
		if err := s.guardCIDRBindings(ctx); err != nil {
			t.Fatalf("startup refused with nothing bound: %v", err)
		}
		return s
	}

	bindCIDR := func(t *testing.T, s *Server) {
		t.Helper()
		if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{
			Kind: audit.BindCIDR, Key: "10.20.0.0/16", Identity: "sneaky-fleet",
		}); err != nil {
			t.Fatalf("bind cidr: %v", err)
		}
	}

	t.Run("bound after start", func(t *testing.T) {
		s := running(t)
		bindCIDR(t, s)
		s.refreshIdentities(ctx) // what the 30-second TTL does on its own

		code, id := serve(t, s, "10.20.0.9:5000", "")
		if code != http.StatusOK {
			t.Fatalf("status %d, want 200: the guard withholds a name, never a package", code)
		}
		if id != "" {
			t.Fatalf("resolved %q from an address on a default-trusted_proxies instance; "+
				"the binding is assertable by any RFC 1918 peer and must name nobody", id)
		}
		events, err := s.auditDB.Query(ctx, audit.Filter{EventType: audit.EventServeFetch})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("recorded %d serve_fetch rows, want 1", len(events))
		}
		if events[0].Identity != "" || events[0].ClientIP != "10.20.0.9" {
			t.Fatalf("row = (ip %q, identity %q), want (10.20.0.9, empty)",
				events[0].ClientIP, events[0].Identity)
		}
	})

	t.Run("bound then SIGHUP", func(t *testing.T) {
		s := running(t)
		bindCIDR(t, s)
		s.reload(ctx) // the whole reload, not refreshIdentities alone

		if code, id := serve(t, s, "10.20.0.9:5000", ""); code != http.StatusOK || id != "" {
			t.Fatalf("after reload: status %d, identity %q; want 200 and no identity", code, id)
		}
	})

	t.Run("token bindings still resolve", func(t *testing.T) {
		s := running(t)
		bindCIDR(t, s)
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

		// A credential is a claim the caller had to hold. An address is a claim
		// anyone inside RFC 1918 can make with a header, which is the whole
		// difference the guard turns on.
		if _, got := serve(t, s, "10.20.0.9:5000", "Bearer "+tok); got != "build-07" {
			t.Fatalf("token resolved to %q, want build-07: the guard is on the CIDR half alone", got)
		}
		if _, got := serve(t, s, "10.20.0.9:5000", ""); got != "" {
			t.Fatalf("address alone resolved to %q, want no identity", got)
		}
	})

	t.Run("answered proxies bring the binding back", func(t *testing.T) {
		s := running(t)
		bindCIDR(t, s)
		if _, err := s.auditDB.SeedACL(ctx, audit.ACLProxies, nil, "ravi"); err != nil {
			t.Fatalf("seed proxies: %v", err)
		}
		s.reload(ctx)

		if _, got := serve(t, s, "10.20.0.9:5000", ""); got != "sneaky-fleet" {
			t.Fatalf("resolved %q with trusted_proxies answered, want sneaky-fleet", got)
		}
	})
}
