package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

//nolint:gosec // G101: test fixtures, not credentials.
const (
	aliceToken   = "bodega_ak_alice"
	bobToken     = "bodega_ak_bob"
	unboundToken = "bodega_ak_unbound"
	scopedToken  = "bodega_ak_scoped"
	localAddr    = "127.0.0.1:40000"
)

// newOverrideServer is a localhost-only server, the posture in which the
// mutation gate asks for no token at all, with tokens bound to alice and bob,
// one bound to nothing, an inventory token bound to web-01, and a CIDR
// binding that names every local caller "lab".
func newOverrideServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{AptCodename: "noble", LogDir: dir, StoragePath: dir,
		AuditDB: filepath.Join(dir, "audit.db"), AdminPermitCIDR: []string{"127.0.0.1/32"}, AllowPlaintext: true}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB == nil {
		t.Fatal("server built without an audit db")
	}
	t.Cleanup(func() { _ = s.auditDB.Close() })
	s.pepper = invPepper
	ctx := context.Background()
	for id, tok := range map[string]string{"a1": aliceToken, "b1": bobToken, "u1": unboundToken} {
		if err := s.auditDB.InsertToken(ctx, id, id, audit.HashToken(tok, invPepper), "", nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.auditDB.InsertScopedToken(ctx, "s1", "web-01", audit.HashToken(scopedToken, invPepper), "", audit.ScopeInventory, nil); err != nil {
		t.Fatal(err)
	}
	for _, b := range []audit.IdentityBinding{
		{Kind: audit.BindToken, Key: "a1", Identity: "alice"},
		{Kind: audit.BindToken, Key: "b1", Identity: "bob"},
		{Kind: audit.BindToken, Key: "s1", Identity: "web-01"},
		{Kind: audit.BindCIDR, Key: "127.0.0.0/8", Identity: "lab"},
	} {
		if _, err := s.auditDB.AddIdentityBinding(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	s.refreshIdentities(ctx)
	return s
}

const overrideBody = `{"type":"npm","name":"minimist","version":"1.2.0","check":"osv","reason":"vendored fix","expires":"7d"}`

func decodeOverride(t *testing.T, body []byte) audit.Override {
	t.Helper()
	var o audit.Override
	if err := json.Unmarshal(body, &o); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return o
}

// Every override route takes a token bound to an identity, on a server whose
// mutation gate would let an anonymous localhost POST through. A CIDR
// binding does not count, and an inventory token is refused by scope.
func TestOverrideRoutesRequireABoundToken(t *testing.T) {
	s := newOverrideServer(t)
	for _, tc := range []struct {
		name, token string
		want        int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"token bound to nothing, address bound by CIDR", unboundToken, http.StatusUnauthorized},
		{"inventory token", scopedToken, http.StatusForbidden},
	} {
		for _, r := range []struct{ method, path, body string }{
			{http.MethodGet, "/api/v1/overrides", ""},
			{http.MethodPost, "/api/v1/overrides", overrideBody},
			{http.MethodPost, "/api/v1/overrides/abc/approve", ""},
			{http.MethodPost, "/api/v1/overrides/abc/reject", ""},
		} {
			if rec := send(s, r.method, r.path, localAddr, tc.token, r.body); rec.Code != tc.want {
				t.Errorf("%s: %s %s = %d (%s), want %d", tc.name, r.method, r.path, rec.Code, rec.Body, tc.want)
			}
		}
	}
	list, err := s.auditDB.ListOverrides(context.Background(), audit.OverrideFilter{})
	if err != nil || len(list) != 0 {
		t.Errorf("refused requests left %d override(s): %v", len(list), err)
	}
}

// The API applies the CLI's rules under the token's identity: the requester
// cannot approve, a second identity approves once, and the listing filters.
func TestOverrideAPIFlow(t *testing.T) {
	s := newOverrideServer(t)
	rec := send(s, http.MethodPost, "/api/v1/overrides", localAddr, aliceToken, overrideBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("request = %d %s", rec.Code, rec.Body)
	}
	o := decodeOverride(t, rec.Body.Bytes())
	if o.RequestedBy != "alice" || o.Status != audit.OverrideStatusPending {
		t.Fatalf("requested = %+v", o)
	}

	if rec := send(s, http.MethodPost, "/api/v1/overrides/"+o.ID+"/approve", localAddr, aliceToken, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval = %d %s, want 403", rec.Code, rec.Body)
	}
	rec = send(s, http.MethodPost, "/api/v1/overrides/"+o.ID+"/approve", localAddr, bobToken, `{"comment":"checked the diff"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("bob approving = %d %s", rec.Code, rec.Body)
	}
	if got := decodeOverride(t, rec.Body.Bytes()); got.Status != audit.OverrideStatusActive || len(got.Votes) != 1 || got.Votes[0].Comment != "checked the diff" {
		t.Errorf("approved = %+v", got)
	}
	if rec := send(s, http.MethodPost, "/api/v1/overrides/"+o.ID+"/approve", localAddr, bobToken, ""); rec.Code != http.StatusConflict {
		t.Errorf("approving an approved override = %d, want 409", rec.Code)
	}
	if rec := send(s, http.MethodPost, "/api/v1/overrides/nope/reject", localAddr, bobToken, ""); rec.Code != http.StatusNotFound {
		t.Errorf("rejecting an unknown id = %d, want 404", rec.Code)
	}
	if rec := send(s, http.MethodPost, "/api/v1/overrides", localAddr, aliceToken,
		`{"type":"npm","name":"minimist","version":"1.2.0","check":"osv","reason":"x","expires":"90d"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("expiry past the cap = %d %s, want 400", rec.Code, rec.Body)
	}

	for status, want := range map[string]int{"active": 1, "pending": 0, "": 1} {
		rec := send(s, http.MethodGet, "/api/v1/overrides?status="+status, localAddr, bobToken, "")
		var list []audit.Override
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list) != want {
			t.Errorf("list status=%q = %d %s, want %d override(s)", status, rec.Code, rec.Body, want)
		}
	}
}
