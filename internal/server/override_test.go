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
	writerToken  = "bodega_ak_writer"
	readerToken  = "bodega_ak_reader"
	localAddr    = "127.0.0.1:40000"
)

// newOverrideServer is a localhost-only server, the posture in which the
// mutation gate asks for no token at all, with tokens bound to alice and bob,
// one bound to nothing, an inventory token bound to web-01, a write-only
// token bound to carol, a read-only one bound to dave, and a CIDR binding that
// names every local caller "lab".
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
	for id, st := range map[string]struct{ tok, scope string }{
		"s1": {scopedToken, audit.ScopeInventory},
		"w1": {writerToken, audit.ScopeWrite},
		"r1": {readerToken, audit.ScopeRead},
	} {
		if err := s.auditDB.InsertScopedToken(ctx, id, id, audit.HashToken(st.tok, invPepper), "", st.scope, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, b := range []audit.IdentityBinding{
		{Kind: audit.BindToken, Key: "a1", Identity: "alice"},
		{Kind: audit.BindToken, Key: "b1", Identity: "bob"},
		{Kind: audit.BindToken, Key: "s1", Identity: "web-01"},
		{Kind: audit.BindToken, Key: "w1", Identity: "carol"},
		{Kind: audit.BindToken, Key: "r1", Identity: "dave"},
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
// binding does not count.
func TestOverrideRoutesRequireABoundToken(t *testing.T) {
	s := newOverrideServer(t)
	for _, tc := range []struct{ name, token string }{
		{"no token", ""},
		{"token bound to nothing, address bound by CIDR", unboundToken},
	} {
		for _, r := range []struct{ method, path, body string }{
			{http.MethodGet, "/api/v1/overrides", ""},
			{http.MethodPost, "/api/v1/overrides", overrideBody},
			{http.MethodPost, "/api/v1/overrides/abc/approve", ""},
			{http.MethodPost, "/api/v1/overrides/abc/reject", ""},
		} {
			if rec := send(s, r.method, r.path, localAddr, tc.token, r.body); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s: %s %s = %d (%s), want 401", tc.name, r.method, r.path, rec.Code, rec.Body)
			}
		}
	}
	list, err := s.auditDB.ListOverrides(context.Background(), audit.OverrideFilter{})
	if err != nil || len(list) != 0 {
		t.Errorf("refused requests left %d override(s): %v", len(list), err)
	}
}

// Requesting an override needs write, voting on one needs admin and listing
// needs read, whichever header form carries the token. The Basic form matters
// on its own: the localhost-only gate scope-checks a Bearer credential only,
// so overrideCaller is what refuses it.
func TestOverrideRoutesCheckScope(t *testing.T) {
	s := newOverrideServer(t)
	rec := send(s, http.MethodPost, "/api/v1/overrides", localAddr, writerToken, overrideBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("write token requesting = %d %s, want 201", rec.Code, rec.Body)
	}
	id := decodeOverride(t, rec.Body.Bytes()).ID

	basic := func(method, path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = localAddr
		req.SetBasicAuth("ci", token)
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, req)
		return rec
	}
	for _, tc := range []struct {
		name, method, path, token, body string
		basic                           bool
		want                            int
		missing                         string
	}{
		{"write token approving", http.MethodPost, "/api/v1/overrides/" + id + "/approve", writerToken, "", false, http.StatusForbidden, "admin"},
		{"write token rejecting", http.MethodPost, "/api/v1/overrides/" + id + "/reject", writerToken, "", false, http.StatusForbidden, "admin"},
		{"write token approving over Basic", http.MethodPost, "/api/v1/overrides/" + id + "/approve", writerToken, "", true, http.StatusForbidden, "admin"},
		{"inventory token requesting", http.MethodPost, "/api/v1/overrides", scopedToken, overrideBody, false, http.StatusForbidden, "write"},
		{"inventory token requesting over Basic", http.MethodPost, "/api/v1/overrides", scopedToken, "", true, http.StatusForbidden, "write"},
		{"inventory token approving", http.MethodPost, "/api/v1/overrides/" + id + "/approve", scopedToken, "", false, http.StatusForbidden, "admin"},
		{"read token requesting", http.MethodPost, "/api/v1/overrides", readerToken, overrideBody, false, http.StatusForbidden, "write"},
		{"read token listing", http.MethodGet, "/api/v1/overrides", readerToken, "", false, http.StatusOK, ""},
	} {
		var rec *httptest.ResponseRecorder
		if tc.basic {
			rec = basic(tc.method, tc.path, tc.token)
		} else {
			rec = send(s, tc.method, tc.path, localAddr, tc.token, tc.body)
		}
		if rec.Code != tc.want {
			t.Errorf("%s = %d (%s), want %d", tc.name, rec.Code, rec.Body, tc.want)
			continue
		}
		if tc.missing != "" && !strings.Contains(rec.Body.String(), `lacks scope "`+tc.missing+`"`) {
			t.Errorf("%s: body %q does not name the missing scope %q", tc.name, rec.Body, tc.missing)
		}
	}

	o, err := s.auditDB.GetOverride(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if o.State != audit.OverrideStatusPending || len(o.Votes) != 0 {
		t.Errorf("refused votes changed the override: %+v", o)
	}
	rows, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventDenied})
	if err != nil {
		t.Fatal(err)
	}
	var admin int
	for _, r := range rows {
		if r.Status == audit.DenialTokenScope && strings.Contains(r.Details, `"missing_scope":"admin"`) {
			admin++
		}
	}
	if admin != 4 {
		t.Errorf("%d token_scope denials name missing_scope admin, want 4: %+v", admin, rows)
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
