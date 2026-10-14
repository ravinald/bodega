package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const tokenScopesVersion = 32

func TestParseScopes(t *testing.T) {
	cases := []struct{ in, want, err string }{
		{in: "read", want: "read"},
		{in: "admin, write ,read", want: "read,write,admin"},
		{in: "write:npm,pypi", want: "write:npm,pypi"},
		{in: "write:pypi,npm,admin", want: "write:npm,pypi,admin"},
		{in: "read write:npm write:cargo", want: "read,write:cargo,npm"},
		{in: "write:npm,write", want: "write"}, // unrestricted wins
		{in: "full", want: ScopeFull},
		{in: "inventory", want: "inventory"},
		{in: "", err: "no scope"},
		{in: "root", err: "unknown scope"},
		{in: "read,npm", err: "unknown scope"},
		{in: "write:rubygems", err: "unknown package type"},
		{in: "admin:npm", err: "takes no package types"},
		{in: "inventory,read", err: "combines with no other"},
	}
	for _, tc := range cases {
		got, err := CanonicalScopes(tc.in)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q: err = %v, want one containing %q", tc.in, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestScopesAllows(t *testing.T) {
	sc, err := ParseScopes("read,write:npm,pypi")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, typ string
		want      bool
	}{
		{ScopeRead, "apt", true},
		{ScopeRead, "", true},
		{ScopeWrite, "npm", true},
		{ScopeWrite, "cargo", false},
		{ScopeWrite, "", true}, // a route tied to no type
		{ScopeAdmin, "", false},
	} {
		if got := sc.Allows(c.name, c.typ); got != c.want {
			t.Errorf("Allows(%s, %q) = %v, want %v", c.name, c.typ, got, c.want)
		}
	}
	inv, _ := ParseScopes(ScopeInventory)
	if !inv.Allows(ScopeRead, "apt") || inv.Allows(ScopeWrite, "apt") || inv.Allows(ScopeAdmin, "") {
		t.Error("inventory should read and do nothing else here")
	}
	all, _ := ParseScopes(ScopeFull)
	narrow, _ := ParseScopes("read,write:npm,admin")
	if !all.HoldsAll() || narrow.HoldsAll() || inv.HoldsAll() {
		t.Error("HoldsAll should be true only for unrestricted read, write and admin")
	}
}

// A token stored as full before scopes migrates to read,write,admin; an
// inventory token keeps its scope; the down migration drops anything an
// older binary would widen.
func TestTokenScopesMigration(t *testing.T) {
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() { _ = raw.Close() }()
	m := migrator(t, raw)
	if err := m.Migrate(tokenScopesVersion - 1); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO api_tokens (id, label, hash, scope) VALUES ('old', 'ci', 'h1', 'full'), ('inv', 'web', 'h2', 'inventory')`); err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(tokenScopesVersion); err != nil {
		t.Fatalf("migrate to %d: %v", tokenScopesVersion, err)
	}
	got := map[string]string{}
	rows, err := raw.Query(`SELECT id, scope, subject, issuer FROM api_tokens`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, scope, sub, iss string
		if err := rows.Scan(&id, &scope, &sub, &iss); err != nil {
			t.Fatal(err)
		}
		got[id] = scope
		if sub != "" || iss != "" {
			t.Errorf("%s migrated with subject %q issuer %q, want empty", id, sub, iss)
		}
	}
	_ = rows.Close()
	if got["old"] != ScopeFull || got["inv"] != ScopeInventory {
		t.Errorf("migrated scopes = %v, want old=%s inv=inventory", got, ScopeFull)
	}
	if _, err := raw.Exec(`INSERT INTO api_tokens (id, label, hash, scope) VALUES ('n', 'n', 'h3', 'write:npm'), ('x', 'x', 'h4', 'read,write,admin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO api_tokens (id, label, hash, scope, subject, issuer) VALUES ('e', 'e', 'h5', 'read,write,admin', 's', 'https://i')`); err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(tokenScopesVersion - 1); err != nil {
		t.Fatalf("down: %v", err)
	}
	var ids []string
	rows, _ = raw.Query(`SELECT id || '=' || scope FROM api_tokens ORDER BY id`)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		ids = append(ids, s)
	}
	_ = rows.Close()
	if strings.Join(ids, " ") != "inv=inventory old=full x=full" {
		t.Errorf("after down: %v, want the narrowed and exchanged tokens gone", ids)
	}
}

func TestExchangedTokenRoundTripAndPrune(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	p := Principal{Subject: "repo:acme/app:ref:refs/heads/main", Issuer: "https://token.actions.githubusercontent.com"}
	past := time.Now().Add(-time.Minute)
	if err := db.InsertExchangedToken(ctx, "live", "oidc", "h1", "write:npm", time.Now().Add(time.Hour), p); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertExchangedToken(ctx, "dead", "oidc", "h2", "read", past, p); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertScopedToken(ctx, "op", "ops", "h3", "", "admin", &past); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertExchangedToken(ctx, "x", "oidc", "h4", "read", time.Now(), Principal{}); err == nil {
		t.Error("an exchanged token with no subject was stored")
	}
	if n, err := db.DeleteExpiredExchangedTokens(ctx, time.Now()); err != nil || n != 1 {
		t.Errorf("pruned %d, %v; want 1 (the expired exchanged token only)", n, err)
	}
	hashes, _ := db.GetTokenHashes(ctx)
	byID := map[string]TokenHash{}
	for _, h := range hashes {
		byID[h.ID] = h
	}
	if _, ok := byID["op"]; !ok {
		t.Error("an expired operator token was pruned; token list should show it as EXPIRED")
	}
	if pr, ok := byID["live"].Principal(); !ok || pr != p {
		t.Errorf("principal = %+v, %v", pr, ok)
	}
	if _, ok := byID["op"].Principal(); ok {
		t.Error("an operator token reported a principal")
	}
}

// A principal in the context names actor and identity on every row, whatever
// the caller filled in.
func TestRecordStampsPrincipal(t *testing.T) {
	db := newIdentityTestDB(t)
	ctx := WithPrincipal(context.Background(), Principal{Subject: "alice", Issuer: "https://idp.example"})
	if err := db.Record(ctx, Event{EventType: EventCreate, PkgType: "npm", PkgName: "x", Identity: "web-01"}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(context.Background(), Filter{Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Identity != "https://idp.example" {
		t.Errorf("rows = %+v, want one with identity https://idp.example", rows)
	}
}
