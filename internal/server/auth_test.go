package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/idp/idptest"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

const oidcAudience = "https://bodega.example"

// newOIDCServer builds a server whose admin_permit_cidr is 10.0.0.0/8, so a
// token is required there, with one provider at a local test issuer:
//
//	acme/app on main      -> read,write:npm
//	acme/ops              -> read,admin
//	acme/oncall           -> read,approve
//	acme/root             -> superadmin
//	acme/publisher        -> write:pypi (no read)
func newOIDCServer(t *testing.T) (*Server, *idptest.Issuer) {
	t.Helper()
	return newOIDCServerAt(t, "10.0.0.0/8", nil)
}

// newOIDCServerAt is newOIDCServer with admin_permit_cidr set to adminCIDR,
// and edit applied to the config before the server is built.
func newOIDCServerAt(t *testing.T, adminCIDR string, edit func(*config.Config)) (*Server, *idptest.Issuer) {
	t.Helper()
	is := idptest.New(t)
	dir := t.TempDir()
	cfg := &config.Config{
		AptCodename:     "noble",
		LogDir:          dir,
		StoragePath:     dir,
		AuditDB:         filepath.Join(dir, "audit.db"),
		AdminPermitCIDR: []string{adminCIDR},
		AllowPlaintext:  true,
		OIDCTokenTTL:    "10m",
		OIDCProviders: []config.OIDCProvider{{
			Name: "ci", Issuer: is.URL, Audience: oidcAudience,
			Rules: []config.OIDCRule{
				{Claims: map[string]string{"repository": "acme/app", "ref": "refs/heads/main"}, Scopes: "read,write:npm"},
				{Claims: map[string]string{"repository": "acme/ops"}, Scopes: "read,admin"},
				{Claims: map[string]string{"repository": "acme/oncall"}, Scopes: "read,approve"},
				{Claims: map[string]string{"repository": "acme/root"}, Scopes: "superadmin"},
				{Claims: map[string]string{"repository": "acme/publisher"}, Scopes: "write:pypi"},
			},
		}},
	}
	if edit != nil {
		edit(cfg)
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB == nil || s.oidc == nil {
		t.Fatal("server built without audit db or OIDC registry")
	}
	t.Cleanup(func() { _ = s.auditDB.Close() })
	s.pepper = invPepper
	return s, is
}

func ciToken(t *testing.T, is *idptest.Issuer, repo string, extra map[string]any) string {
	t.Helper()
	c := map[string]any{"aud": oidcAudience, "sub": "repo:" + repo + ":ref:refs/heads/main", "repository": repo, "ref": "refs/heads/main"}
	for k, v := range extra {
		c[k] = v
	}
	return is.Token(t, c)
}

func exchange(t *testing.T, s *Server, idToken string) (*exchangeResponse, int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"id_token": idToken})
	rec := send(s, http.MethodPost, authExchangePath, outsideAddr, "", string(body))
	if rec.Code != http.StatusOK {
		return nil, rec.Code, rec.Body.String()
	}
	var out exchangeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode exchange: %v", err)
	}
	return &out, rec.Code, rec.Body.String()
}

// The exchange is reachable from outside admin_permit_cidr, mints a token
// carrying the rule's scopes for no longer than oidc_token_ttl, and the token
// is usable by the very next request.
func TestAuthExchangeMintsScopedShortLivedToken(t *testing.T) {
	s, is := newOIDCServer(t)
	// One handler for every request here, so the gate's hash cache lives
	// across them: warmed before the exchange, it must still see the token
	// the exchange minted.
	h := s.handler()
	do := func(method, path, remote, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = remote
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if err := s.auditDB.InsertScopedToken(context.Background(), "pre", "reader", audit.HashToken("bodega_ak_pre", invPepper), "", "read", "test-operator", nil); err != nil {
		t.Fatal(err)
	}
	do(http.MethodGet, "/api/v1/packages/npm", adminAddr, "bodega_ak_pre", "")
	before := time.Now()
	rec := do(http.MethodPost, authExchangePath, outsideAddr, "", `{"id_token":"`+ciToken(t, is, "acme/app", nil)+`"}`)
	var got exchangeResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body)
	}
	if got.Scopes != "read,write:npm" || got.Subject != "repo:acme/app:ref:refs/heads/main" || got.Issuer != is.URL {
		t.Errorf("exchange = %+v", got)
	}
	exp, err := time.Parse(time.RFC3339, got.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if exp.After(before.Add(10*time.Minute+time.Second)) || exp.Before(before.Add(9*time.Minute)) {
		t.Errorf("expires_at %s, want about now+10m (oidc_token_ttl)", exp)
	}
	tokens, _ := s.auditDB.ListTokens(context.Background())
	if len(tokens) != 2 || tokens[0].Subject != got.Subject || tokens[0].Issuer != is.URL || tokens[0].Scope != "read,write:npm" {
		t.Errorf("stored tokens = %+v", tokens)
	}
	// Within the hash cache's TTL: the token must work at once.
	rec = do(http.MethodPost, "/api/v1/packages/npm", adminAddr, got.Token, `{}`)
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Errorf("fresh token on an in-scope write: %d %s", rec.Code, rec.Body)
	}
}

func TestAuthExchangeRefusals(t *testing.T) {
	s, is := newOIDCServer(t)
	expired := ciToken(t, is, "acme/app", map[string]any{
		"iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix(),
	})
	cases := []struct {
		name, idToken string
		want          []string
	}{
		{"expired", expired, []string{is.URL, "expired"}},
		{"wrong audience", ciToken(t, is, "acme/app", map[string]any{"aud": "https://elsewhere"}), []string{is.URL, "https://elsewhere"}},
		{"unmatched claims", ciToken(t, is, "acme/fork", nil), []string{is.URL, `repository=\"acme/fork\"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, code, body := exchange(t, s, tc.idToken)
			if got != nil || code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", code)
			}
			for _, w := range tc.want {
				if !strings.Contains(body, w) {
					t.Errorf("body %s does not name %q", body, w)
				}
			}
			if strings.Contains(body, tc.idToken) {
				t.Error("refusal echoes the ID token")
			}
		})
	}
	rows, _ := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventDenied})
	n := 0
	for _, r := range rows {
		if r.Status == audit.DenialOIDCRefused {
			n++
		}
	}
	if n != len(cases) {
		t.Errorf("%d oidc_refused rows, want %d", n, len(cases))
	}
	if toks, _ := s.auditDB.ListTokens(context.Background()); len(toks) != 0 {
		t.Errorf("a refused exchange stored a token: %+v", toks)
	}
}

// A token outside its scopes is refused with 403 naming the missing scope, on
// read, write, admin, approve and superadmin routes alike. admin reaches
// neither the votes nor token management, and approve and superadmin reach
// nothing of admin's.
func TestScopeRefusalOnReadWriteAndAdminRoutes(t *testing.T) {
	s, is := newOIDCServer(t)
	app, _, _ := exchange(t, s, ciToken(t, is, "acme/app", nil))
	ops, _, _ := exchange(t, s, ciToken(t, is, "acme/ops", nil))
	pub, _, _ := exchange(t, s, ciToken(t, is, "acme/publisher", nil))
	oncall, _, _ := exchange(t, s, ciToken(t, is, "acme/oncall", nil))
	root, _, _ := exchange(t, s, ciToken(t, is, "acme/root", nil))
	if app == nil || ops == nil || pub == nil || oncall == nil || root == nil {
		t.Fatal("exchange failed")
	}
	cases := []struct {
		name, method, path, token, missing string
	}{
		{"read without read", http.MethodGet, "/npm/left-pad", pub.Token, "read:npm"},
		{"read api without read", http.MethodGet, "/api/v1/packages/npm", pub.Token, "read:npm"},
		{"write other type", http.MethodPost, "/api/v1/packages/pypi", app.Token, "write:pypi"},
		{"write without write", http.MethodDelete, "/api/v1/packages/npm/left-pad", ops.Token, "write:npm"},
		{"admin read", http.MethodGet, "/api/v1/audit", app.Token, "admin"},
		{"admin mutation", http.MethodPost, "/api/v1/policies", app.Token, "admin"},
		{"admin read as approver", http.MethodGet, "/api/v1/audit", oncall.Token, "admin"},
		{"admin read as superadmin", http.MethodGet, "/api/v1/config", root.Token, "admin"},
		{"token mint", http.MethodPost, "/api/v1/tokens", app.Token, "superadmin"},
		{"token mint as admin", http.MethodPost, "/api/v1/tokens", ops.Token, "superadmin"},
		{"token list as admin", http.MethodGet, "/api/v1/tokens", ops.Token, "superadmin"},
		{"token revoke as admin", http.MethodDelete, "/api/v1/tokens/x", ops.Token, "superadmin"},
		{"token mint as approver", http.MethodPost, "/api/v1/tokens", oncall.Token, "superadmin"},
		{"queue list", http.MethodGet, "/api/v1/queue", app.Token, "admin or approve"},
		{"queue list as superadmin", http.MethodGet, "/api/v1/queue", root.Token, "admin or approve"},
		{"queue approve", http.MethodPost, "/api/v1/queue/1/approve", app.Token, "approve"},
		{"queue approve as admin", http.MethodPost, "/api/v1/queue/1/approve", ops.Token, "approve"},
		{"queue dismiss as admin", http.MethodPost, "/api/v1/queue/1/dismiss", ops.Token, "approve"},
		{"override list", http.MethodGet, "/api/v1/overrides", app.Token, "admin or approve"},
		{"override approve as admin", http.MethodPost, "/api/v1/overrides/x/approve", ops.Token, "approve"},
		{"override reject as admin", http.MethodPost, "/api/v1/overrides/x/reject", ops.Token, "approve"},
		{"override approve as superadmin", http.MethodPost, "/api/v1/overrides/x/approve", root.Token, "approve"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := send(s, tc.method, tc.path, adminAddr, tc.token, `{"label":"x","scope":"read"}`)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d (%s), want 403", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), `"`+tc.missing+`"`) {
				t.Errorf("body %q does not name the missing scope %q", rec.Body, tc.missing)
			}
		})
	}
	// The same tokens inside their scopes pass the gate.
	for _, ok := range []struct{ method, path, token string }{
		{http.MethodGet, "/api/v1/packages/npm", app.Token},
		{http.MethodGet, "/api/v1/audit", ops.Token},
		{http.MethodGet, "/api/v1/queue", ops.Token},
		{http.MethodGet, "/api/v1/queue", oncall.Token},
		{http.MethodPost, "/api/v1/queue/1/approve", oncall.Token},
		{http.MethodPost, "/api/v1/queue/1/dismiss", oncall.Token},
		{http.MethodGet, "/api/v1/overrides", ops.Token},
		{http.MethodGet, "/api/v1/overrides", oncall.Token},
		{http.MethodPost, "/api/v1/overrides/x/approve", oncall.Token},
		{http.MethodPost, "/api/v1/overrides/x/reject", oncall.Token},
		{http.MethodGet, "/api/v1/tokens", root.Token},
		{http.MethodPost, "/api/v1/tokens", root.Token},
		{http.MethodDelete, "/api/v1/tokens/x", root.Token},
		{http.MethodPost, "/api/v1/overrides", app.Token},
		{http.MethodGet, "/healthz", pub.Token},
	} {
		if rec := send(s, ok.method, ok.path, adminAddr, ok.token, ""); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
			t.Errorf("%s %s in scope: %d %s", ok.method, ok.path, rec.Code, rec.Body)
		}
	}
}

// Every row a request carrying an exchanged token writes names the ID
// token's subject as actor and its issuer as identity, so a filter on either
// finds a workflow rather than a token id.
func TestExchangedTokenAttributesAuditRows(t *testing.T) {
	s, is := newOIDCServer(t)
	app, _, _ := exchange(t, s, ciToken(t, is, "acme/app", nil))
	if app == nil {
		t.Fatal("exchange failed")
	}
	if rec := send(s, http.MethodPost, "/api/v1/packages/pypi", adminAddr, app.Token, `{}`); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	rows, err := s.auditDB.Query(context.Background(), audit.Filter{Actor: app.Subject})
	if err != nil {
		t.Fatal(err)
	}
	var created, denied bool
	for _, r := range rows {
		if r.Identity != is.URL {
			t.Errorf("row %s/%s identity = %q, want the issuer", r.EventType, r.Status, r.Identity)
		}
		created = created || (r.EventType == audit.EventCreate && r.PkgType == "token")
		denied = denied || (r.EventType == audit.EventDenied && r.Status == audit.DenialTokenScope)
	}
	if !created || !denied {
		t.Errorf("rows for actor %q = %+v; want the exchange and the scope refusal", app.Subject, rows)
	}
	byIdentity, _ := s.auditDB.Query(context.Background(), audit.Filter{Identity: is.URL})
	if len(byIdentity) != len(rows) {
		t.Errorf("--identity %s finds %d rows, --actor finds %d", is.URL, len(byIdentity), len(rows))
	}
}

// Rows written before the gate reads the token still name the subject: the
// /client/ boundary's refusal, and the gate's own admin_permit_cidr refusal,
// which it writes before it looks at any token.
func TestExchangedTokenAttributesRowsWrittenBeforeTheGate(t *testing.T) {
	s, is := newOIDCServer(t)
	app, _, _ := exchange(t, s, ciToken(t, is, "acme/app", nil))
	if app == nil {
		t.Fatal("exchange failed")
	}
	cases := []struct {
		name, method, path, remote, status string
	}{
		{"client refusal", http.MethodGet, "/client/plan", adminAddr, audit.DenialClientUnidentified},
		{"cidr refusal", http.MethodPost, "/api/v1/packages/import", outsideAddr, audit.DenialIPNotPermitted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rec := send(s, tc.method, tc.path, tc.remote, app.Token, `{}`); rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			rows, err := s.auditDB.Query(context.Background(), audit.Filter{})
			if err != nil || len(rows) == 0 {
				t.Fatalf("query: %d rows, %v", len(rows), err)
			}
			r := rows[0]
			if r.EventType != audit.EventDenied || r.Status != tc.status {
				t.Fatalf("newest row = %s/%s, want denied/%s", r.EventType, r.Status, tc.status)
			}
			if r.Actor != app.Subject || r.Identity != is.URL {
				t.Errorf("row actor=%q identity=%q, want %q and %q", r.Actor, r.Identity, app.Subject, is.URL)
			}
		})
	}
}

// A narrowed token on bulk import lands the entries its types reach and
// refuses the rest by name.
func TestBulkImportHoldsEachEntryToTokenTypes(t *testing.T) {
	s, is := newOIDCServer(t)
	app, _, _ := exchange(t, s, ciToken(t, is, "acme/app", nil))
	body := `[{"type":"pypi","name":"requests","mode":"proxy"}]`
	rec := send(s, http.MethodPost, "/api/v1/packages/import", adminAddr, app.Token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	var resp ImportResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Results) != 1 || resp.Results[0].Outcome != ImportFailed || !strings.Contains(resp.Results[0].Reason, `"write:pypi"`) {
		t.Errorf("results = %+v, want pypi refused naming write:pypi", resp.Results)
	}
	if pm, _ := s.store.GetPackage(context.Background(), "pypi", "requests"); pm != nil {
		t.Error("an out-of-scope entry was stored")
	}
}

// Legacy and operator-minted tokens keep working: a pre-scope token holds
// read, write and admin; an inventory token still reads.
func TestMintedTokenScopes(t *testing.T) {
	s := newInventoryServer(t, []string{"10.0.0.0/8"})
	if rec := send(s, http.MethodGet, "/api/v1/audit", adminAddr, fullToken, ""); rec.Code != http.StatusOK {
		t.Errorf("full token on an admin read: %d", rec.Code)
	}
	if rec := send(s, http.MethodGet, "/api/v1/packages/apt", adminAddr, invToken, ""); rec.Code == http.StatusForbidden {
		t.Errorf("inventory token refused a read: %s", rec.Body)
	}
	rec := send(s, http.MethodPost, "/api/v1/tokens", adminAddr, fullToken, `{"label":"ci"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "scope") {
		t.Errorf("token minted with no scope: %d %s", rec.Code, rec.Body)
	}
	rec = send(s, http.MethodPost, "/api/v1/tokens", adminAddr, fullToken, `{"label":"ci","scope":"write:npm, read"}`)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"read,write:npm"`) {
		t.Errorf("scoped mint: %d %s", rec.Code, rec.Body)
	}
	var minted struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &minted)
	tokens, _ := s.auditDB.ListTokens(context.Background())
	var createdBy string
	for _, tk := range tokens {
		if tk.ID == minted.ID {
			createdBy = tk.CreatedBy
		}
	}
	if createdBy != "ops" {
		t.Errorf("API-minted token created_by = %q, want ops, the identity the minting token is bound to", createdBy)
	}
}

// Minting over the API needs a caller with an identity to record as the new
// token's creator, on a localhost-only server too, where the gate asks for no
// token at all.
func TestAPIMintRefusesACallerWithNoIdentity(t *testing.T) {
	s := newInventoryServer(t, []string{"127.0.0.0/8"})
	if err := s.auditDB.InsertToken(context.Background(), "unbound", "unbound", audit.HashToken(unboundToken, invPepper), "", nil); err != nil {
		t.Fatal(err)
	}
	rec := send(s, http.MethodPost, "/api/v1/tokens", localAddr, unboundToken, `{"label":"x","scope":"read"}`)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "bound to an identity") {
		t.Errorf("unbound superadmin token on localhost mint = %d %s, want 401 naming the identity it lacks", rec.Code, rec.Body)
	}
	if rec := send(s, http.MethodPost, "/api/v1/tokens", localAddr, fullToken, `{"label":"x","scope":"read"}`); rec.Code != http.StatusCreated {
		t.Errorf("bound full token on localhost = %d %s, want 201", rec.Code, rec.Body)
	}
}

// The token routes need a presented, unexpired token holding superadmin in
// both postures: neither a tokenless host in admin_permit_cidr nor a
// tokenless localhost caller on a loopback-only server reaches them.
func TestTokenRoutesRequireSuperadminToken(t *testing.T) {
	//nolint:gosec // G101: test fixtures, not credentials.
	const (
		noSuperToken  = "bodega_ak_nosuper"
		expiredToken  = "bodega_ak_expired"
		unmatchedCred = "bodega_ak_matches_nothing"
	)
	routes := []struct {
		name, method, path, body string
		ok                       int
	}{
		{"list", http.MethodGet, "/api/v1/tokens", "", http.StatusOK},
		{"revoke", http.MethodDelete, "/api/v1/tokens/target", "", http.StatusOK},
		{"mint", http.MethodPost, "/api/v1/tokens", `{"label":"x","scope":"read"}`, http.StatusCreated},
	}
	postures := []struct {
		name, cidr, addr, ip string
	}{
		{"loopback only", "127.0.0.1/32", localAddr, "127.0.0.1"},
		{"widened", "10.0.0.0/8", adminAddr, "10.0.0.5"},
	}
	creds := []struct {
		name, token string
		want        int
		denial      string
	}{
		{"none", "", http.StatusUnauthorized, audit.DenialTokenMissing},
		{"unmatched", unmatchedCred, http.StatusUnauthorized, audit.DenialTokenInvalid},
		{"expired", expiredToken, http.StatusUnauthorized, audit.DenialTokenExpired},
		{"without superadmin", noSuperToken, http.StatusForbidden, audit.DenialTokenScope},
		{"superadmin", fullToken, 0, ""},
	}
	for _, p := range postures {
		for _, rt := range routes {
			for _, c := range creds {
				t.Run(p.name+"/"+rt.name+"/"+c.name, func(t *testing.T) {
					s := newInventoryServer(t, []string{p.cidr})
					ctx := context.Background()
					past := time.Now().Add(-time.Hour)
					for _, tk := range []struct {
						id, token, scope string
						exp              *time.Time
					}{
						{"nosuper", noSuperToken, "write,admin,approve", nil},
						{"expired", expiredToken, audit.ScopeFull, &past},
						{"target", "bodega_ak_target", audit.ScopeFull, nil},
					} {
						if err := s.auditDB.InsertScopedToken(ctx, tk.id, tk.id, audit.HashToken(tk.token, invPepper), "", tk.scope, "test-operator", tk.exp); err != nil {
							t.Fatal(err)
						}
					}

					rec := send(s, rt.method, rt.path, p.addr, c.token, rt.body)
					want := c.want
					if want == 0 {
						want = rt.ok
					}
					if rec.Code != want {
						t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body, want)
					}
					if c.denial == "" {
						return
					}
					if c.name == "none" {
						for _, part := range []string{"superadmin", "Authorization: Bearer <token>", "bodega token list|generate|revoke"} {
							if !strings.Contains(rec.Body.String(), part) {
								t.Errorf("body %q does not say %q", rec.Body, part)
							}
						}
					}
					if rt.name == "revoke" {
						toks, _ := s.auditDB.ListTokens(ctx)
						if !slices.ContainsFunc(toks, func(tk audit.TokenInfo) bool { return tk.ID == "target" }) {
							t.Error("a refused revoke deleted the target token")
						}
					}
					rows := denials(t, s)
					if len(rows) != 1 || rows[0].Status != c.denial || rows[0].ClientIP != p.ip {
						t.Fatalf("denials = %+v, want one %s from %s", rows, c.denial, p.ip)
					}
					details := denialDetails(t, rows[0])
					switch c.denial {
					case audit.DenialTokenMissing:
						if details["route"] != "tokens" {
							t.Errorf("details = %v, want route tokens", details)
						}
					case audit.DenialTokenInvalid:
						if details["hash_prefix"] == "" || strings.Contains(rows[0].Details, unmatchedCred) {
							t.Errorf("details = %s, want a hash prefix and never the credential", rows[0].Details)
						}
					case audit.DenialTokenExpired:
						if details["token_id"] != "expired" {
							t.Errorf("details = %v, want token_id expired", details)
						}
					case audit.DenialTokenScope:
						if details["missing_scope"] != audit.ScopeSuperadmin {
							t.Errorf("details = %v, want missing_scope superadmin", details)
						}
					}
				})
			}
		}
	}

	// The other admin reads keep their posture: a tokenless host in range
	// still reads the audit trail.
	s := newInventoryServer(t, []string{"10.0.0.0/8"})
	if rec := send(s, http.MethodGet, "/api/v1/audit", adminAddr, "", ""); rec.Code != http.StatusOK {
		t.Errorf("tokenless GET /api/v1/audit in range = %d %s, want 200", rec.Code, rec.Body)
	}
}

// An exchanged token requests and votes on overrides under its principal's
// identity, held to the route's scope, in both postures: on a localhost-only
// server the gate asks for no token and checks only a Bearer credential, so
// overrideCaller is the only scope check a Basic credential meets.
func TestOverrideRoutesAcceptExchangedTokens(t *testing.T) {
	for _, posture := range []struct {
		name, cidr, addr string
		basic            bool
	}{
		{"token required", "10.0.0.0/8", adminAddr, false},
		{"localhost only", "127.0.0.1/32", localAddr, true},
	} {
		t.Run(posture.name, func(t *testing.T) {
			s, is := newOIDCServerAt(t, posture.cidr, func(c *config.Config) { c.OverrideQuorum = 3 })
			app, _, _ := exchange(t, s, ciToken(t, is, "acme/app", nil))
			ops, _, _ := exchange(t, s, ciToken(t, is, "acme/oncall", nil))
			opsAgain, _, _ := exchange(t, s, ciToken(t, is, "acme/oncall", nil))
			if app == nil || ops == nil || opsAgain == nil {
				t.Fatal("exchange failed")
			}
			appID := is.URL + "#repo:acme/app:ref:refs/heads/main"
			opsID := is.URL + "#repo:acme/oncall:ref:refs/heads/main"

			rec := send(s, http.MethodPost, "/api/v1/overrides", posture.addr, app.Token, overrideBody)
			if rec.Code != http.StatusCreated {
				t.Fatalf("write token requesting = %d %s, want 201", rec.Code, rec.Body)
			}
			o := decodeOverride(t, rec.Body.Bytes())
			if o.RequestedBy != appID || o.RequesterCounts || o.ApprovalsNeeded != 3 {
				t.Errorf("requested = by %q, counted %v, needs %d; want by %q, not counted, needs 3",
					o.RequestedBy, o.RequesterCounts, o.ApprovalsNeeded, appID)
			}
			approve := "/api/v1/overrides/" + o.ID + "/approve"

			basic := func(token string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, approve, nil)
				req.RemoteAddr = posture.addr
				req.SetBasicAuth("ci", token)
				rec := httptest.NewRecorder()
				s.handler().ServeHTTP(rec, req)
				return rec
			}
			tries := map[string]*httptest.ResponseRecorder{"Bearer": send(s, http.MethodPost, approve, posture.addr, app.Token, "")}
			if posture.basic {
				tries["Basic"] = basic(app.Token)
			}
			for name, rec := range tries {
				if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `lacks scope "approve"`) {
					t.Errorf("write token approving over %s = %d %s, want 403 naming approve", name, rec.Code, rec.Body)
				}
			}

			rec = send(s, http.MethodPost, approve, posture.addr, ops.Token, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("approve token approving = %d %s, want 200", rec.Code, rec.Body)
			}
			got := decodeOverride(t, rec.Body.Bytes())
			if len(got.Votes) != 1 || got.Votes[0].Identity != opsID {
				t.Errorf("votes = %+v, want one under %q", got.Votes, opsID)
			}
			// A second exchange for the same subject is the same voter.
			if rec := send(s, http.MethodPost, approve, posture.addr, opsAgain.Token, ""); rec.Code != http.StatusConflict {
				t.Errorf("second exchange approving = %d %s, want 409", rec.Code, rec.Body)
			}
			if rec := send(s, http.MethodGet, "/api/v1/overrides", posture.addr, ops.Token, ""); rec.Code != http.StatusOK {
				t.Errorf("approve token listing = %d %s, want 200", rec.Code, rec.Body)
			}

			// A binding on the exchanged token wins over its principal.
			if _, err := s.auditDB.AddIdentityBinding(context.Background(),
				audit.IdentityBinding{Kind: audit.BindToken, Key: opsAgain.ID, Identity: "erin"}); err != nil {
				t.Fatal(err)
			}
			s.refreshIdentities(context.Background())
			rec = send(s, http.MethodPost, approve, posture.addr, opsAgain.Token, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("bound exchanged token approving = %d %s, want 200", rec.Code, rec.Body)
			}
			// The requester's token holds write, not approve, so it does not
			// count: two approvers leave a quorum of 3 one short.
			if got := decodeOverride(t, rec.Body.Bytes()); got.Status != audit.OverrideStatusPending || got.RequesterCounts ||
				got.ApprovalsNeeded != 1 || len(got.Votes) != 2 || got.Votes[1].Identity != "erin" || !got.Votes[1].Counted {
				t.Errorf("after the bound vote = %+v", got)
			}
		})
	}
}

// Every /api/v1/ route the mux registers has a scope somebody chose, and the
// gate computes that scope. routeScope falls back on the method alone, so a
// route merged in without an adminPrefixes entry reads as write or read and a
// CI token reaches it. A route missing from want fails here until it is
// classified.
func TestEveryAPIRouteHasAChosenScope(t *testing.T) {
	const adminOrApprove = audit.ScopeAdmin + "|" + audit.ScopeApprove
	want := map[string]string{
		"GET /api/v1/packages":                                     audit.ScopeRead,
		"GET /api/v1/packages/{type}":                              audit.ScopeRead,
		"GET /api/v1/packages/{type}/{name}":                       audit.ScopeRead,
		"GET /api/v1/packages/{type}/{name}/{version}":             audit.ScopeRead,
		"GET /api/v1/packages/{type}/{name}/{version}/attestation": audit.ScopeRead,
		"GET /api/v1/attestation/keys":                             audit.ScopeRead,
		"GET /api/v1/status":                                       audit.ScopeRead,
		"GET /api/v1/config":                                       audit.ScopeAdmin,
		"GET /api/v1/metrics":                                      audit.ScopeRead,
		"POST /api/v1/packages/import":                             audit.ScopeWrite,
		"POST /api/v1/packages/{type}":                             audit.ScopeWrite,
		"DELETE /api/v1/packages/{type}/{name}":                    audit.ScopeWrite,
		"PATCH /api/v1/packages/{type}/{name}/hide":                audit.ScopeWrite,
		"PATCH /api/v1/packages/{type}/{name}/hide/{version}":      audit.ScopeWrite,
		"PATCH /api/v1/packages/{type}/{name}/freeze":              audit.ScopeWrite,
		"PATCH /api/v1/packages/{type}/{name}/freeze/{version}":    audit.ScopeWrite,
		"GET /api/v1/audit":                                        audit.ScopeAdmin,
		"GET /api/v1/tokens":                                       audit.ScopeSuperadmin,
		"POST /api/v1/tokens":                                      audit.ScopeSuperadmin,
		"DELETE /api/v1/tokens/{id}":                               audit.ScopeSuperadmin,
		"GET /api/v1/profiles/{name}/pins":                         audit.ScopeAdmin,
		"POST /api/v1/inventory/sources/{instance}/{route...}":     audit.ScopeAdmin,
		"GET /api/v1/inventory/{identity}":                         audit.ScopeAdmin,
		"GET /api/v1/policies":                                     audit.ScopeAdmin,
		"POST /api/v1/policies":                                    audit.ScopeAdmin,
		"DELETE /api/v1/policies/{id}":                             audit.ScopeAdmin,
		"GET /api/v1/overrides":                                    adminOrApprove,
		"POST /api/v1/overrides":                                   audit.ScopeWrite,
		"POST /api/v1/overrides/{id}/approve":                      audit.ScopeApprove,
		"POST /api/v1/overrides/{id}/reject":                       audit.ScopeApprove,
		"GET /api/v1/queue":                                        adminOrApprove,
		"POST /api/v1/queue/{id}/approve":                          audit.ScopeApprove,
		"POST /api/v1/queue/{id}/dismiss":                          audit.ScopeApprove,
		// HMAC over the body, not a token: the gate passes it as a push route.
		"POST " + RevetWebhookPath:            audit.ScopeWrite,
		"POST " + authExchangePath:            "",
		"GET " + authPathPrefix + "providers": "",
	}
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	consts := map[string]string{"RevetWebhookPath": RevetWebhookPath, "authExchangePath": authExchangePath, "authPathPrefix": authPathPrefix}
	re := regexp.MustCompile(`m\.HandleFunc\("([A-Z]+ [^"]*)"((?:\s*\+\s*(?:\w+|"[^"]*"))*)`)
	sample := regexp.MustCompile(`\{type\}|\{[^}]*\}`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		pattern := m[1]
		for _, part := range regexp.MustCompile(`\w+|"[^"]*"`).FindAllString(m[2], -1) {
			if lit, ok := strings.CutPrefix(part, `"`); ok {
				pattern += strings.TrimSuffix(lit, `"`)
			} else if v, ok := consts[part]; ok {
				pattern += v
			} else {
				t.Fatalf("route %q concatenates %s, which this test cannot resolve", m[0], part)
			}
		}
		method, path, _ := strings.Cut(pattern, " ")
		if !strings.HasPrefix(path, "/api/v1/") {
			continue
		}
		seen[pattern] = true
		scope, ok := want[pattern]
		if !ok {
			t.Errorf("%s is registered with no chosen scope; add it to want, and to adminPrefixes if it reaches admin surface", pattern)
			continue
		}
		concrete := sample.ReplaceAllStringFunc(path, func(seg string) string {
			if seg == "{type}" {
				return manifest.TypeNpm
			}
			return "x"
		})
		if got, _ := routeScope(httptest.NewRequest(method, concrete, nil)); strings.Join(got, "|") != scope {
			t.Errorf("%s: routeScope = %q, want %q", pattern, got, scope)
		}
	}
	for pattern := range want {
		if !seen[pattern] {
			t.Errorf("%s is in want but server.go registers no such route", pattern)
		}
	}
}

// Every row naming who asked names an exchanged token's caller by its
// principal: a refused fetch lands in the review queue and in discovery under
// <issuer>#<subject>, the name the override quorum counts.
func TestExchangedCallerNamedInQueueAndDiscovery(t *testing.T) {
	s := newDiscoveryServer(t)
	p := audit.Principal{Subject: "repo:acme/app:ref:refs/heads/main", Issuer: "https://token.actions.githubusercontent.com"}
	if err := s.auditDB.InsertExchangedToken(t.Context(), "ex1", "ci", audit.HashToken("bodega_ex_1", s.pepper), "read",
		time.Now().Add(10*time.Minute), p); err != nil {
		t.Fatal(err)
	}
	if err := s.store.AddVersion(t.Context(), manifest.TypeNpm, "leftpad", manifest.VersionEntry{
		Version: "1.2.0", Mode: manifest.ModeProxy,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID: "npm-elsewhere", RegistryType: manifest.TypeNpm, RuleKind: policy.KindPackage, Pattern: "rightpad",
	}); err != nil {
		t.Fatal(err)
	}
	s.policy.Invalidate()
	rec := doRequest(s, http.MethodGet, "/npm/leftpad/-/leftpad-1.2.0.tgz", map[string]string{"Authorization": "Bearer bodega_ex_1"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body)
	}
	q := oneQueueRow(t, s)
	if len(q.Requesters) != 1 || q.Requesters[0].Identity != p.Identity() {
		t.Errorf("queue requesters = %+v, want identity %q", q.Requesters, p.Identity())
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, _ := s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{RegistryType: manifest.TypeNpm})
		if len(rows) > 0 {
			if rows[0].LastIdentity != p.Identity() {
				t.Errorf("discovery last_identity = %q, want %q", rows[0].LastIdentity, p.Identity())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no discovery row recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// callerName ranks a token binding over a principal and a principal over any
// other binding, the order overrideIdentity votes in.
func TestCallerNamePrecedence(t *testing.T) {
	p := audit.Principal{Subject: "alice", Issuer: "https://idp.example"}
	cases := []struct {
		name      string
		match     identityMatch
		principal bool
		want      string
	}{
		{"nothing", identityMatch{}, false, ""},
		{"cidr binding alone", identityMatch{Identity: "rack-4", Kind: audit.BindCIDR}, false, "rack-4"},
		{"principal over cidr binding", identityMatch{Identity: "rack-4", Kind: audit.BindCIDR}, true, p.Identity()},
		{"token binding over principal", identityMatch{Identity: "build-07", Kind: audit.BindToken}, true, "build-07"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/npm/leftpad", nil)
			ctx := context.WithValue(r.Context(), identityKey, tc.match)
			if tc.principal {
				ctx = audit.WithPrincipal(ctx, p)
			}
			r = r.WithContext(ctx)
			if got := callerName(r); got != tc.want {
				t.Errorf("callerName = %q, want %q", got, tc.want)
			}
			if Identity(r) != tc.match.Identity {
				t.Errorf("Identity = %q, want the binding alone", Identity(r))
			}
		})
	}
}
