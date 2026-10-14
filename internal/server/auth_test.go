package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/idp/idptest"
	"github.com/ravinald/bodega/internal/manifest"
)

const oidcAudience = "https://bodega.example"

// newOIDCServer builds a server whose admin_permit_cidr is 10.0.0.0/8, so a
// token is required there, with one provider at a local test issuer:
//
//	acme/app on main      -> read,write:npm
//	acme/ops              -> read,admin
//	acme/publisher        -> write:pypi (no read)
func newOIDCServer(t *testing.T) (*Server, *idptest.Issuer) {
	t.Helper()
	is := idptest.New(t)
	dir := t.TempDir()
	cfg := &config.Config{
		AptCodename:     "noble",
		LogDir:          dir,
		StoragePath:     dir,
		AuditDB:         filepath.Join(dir, "audit.db"),
		AdminPermitCIDR: []string{"10.0.0.0/8"},
		AllowPlaintext:  true,
		OIDCTokenTTL:    "10m",
		OIDCProviders: []config.OIDCProvider{{
			Name: "ci", Issuer: is.URL, Audience: oidcAudience,
			Rules: []config.OIDCRule{
				{Claims: map[string]string{"repository": "acme/app", "ref": "refs/heads/main"}, Scopes: "read,write:npm"},
				{Claims: map[string]string{"repository": "acme/ops"}, Scopes: "read,admin"},
				{Claims: map[string]string{"repository": "acme/publisher"}, Scopes: "write:pypi"},
			},
		}},
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
	if err := s.auditDB.InsertScopedToken(context.Background(), "pre", "reader", audit.HashToken("bodega_ak_pre", invPepper), "", "read", nil); err != nil {
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
// read, write and admin routes alike.
func TestScopeRefusalOnReadWriteAndAdminRoutes(t *testing.T) {
	s, is := newOIDCServer(t)
	app, _, _ := exchange(t, s, ciToken(t, is, "acme/app", nil))
	ops, _, _ := exchange(t, s, ciToken(t, is, "acme/ops", nil))
	pub, _, _ := exchange(t, s, ciToken(t, is, "acme/publisher", nil))
	if app == nil || ops == nil || pub == nil {
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
		{"admin mutation", http.MethodPost, "/api/v1/tokens", app.Token, "admin"},
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
}
