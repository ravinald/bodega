package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4/source/iofs"
)

const (
	tokenScopesVersion     = 36
	approveScopesVersion   = 37
	requesterCountsVersion = 38
)

// migrationBefore is the version the source holds immediately below v. The
// numbering has gaps where another branch reserved a version, so v-1 can
// name no migration at all.
func migrationBefore(t *testing.T, v uint) uint {
	t.Helper()
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("iofs source: %v", err)
	}
	prev, err := src.Prev(v)
	if err != nil {
		t.Fatalf("no migration before %d: %v", v, err)
	}
	return prev
}

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
		{in: "superadmin approve admin read", want: "read,admin,approve,superadmin"},
		{in: "approve", want: "approve"},
		{in: "superadmin", want: "superadmin"},
		{in: "approve:npm", err: "takes no package types"},
		{in: "superadmin:npm", err: "takes no package types"},
		{in: "inventory,approve", err: "combines with no other"},
		{in: "superadmin,inventory", err: "combines with no other"},
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

// admin, approve and superadmin are granted independently: none reaches a
// route needing another.
func TestAdminApproveSuperadminAreIndependent(t *testing.T) {
	names := []string{ScopeAdmin, ScopeApprove, ScopeSuperadmin}
	for _, held := range names {
		sc, err := ParseScopes("read,write," + held)
		if err != nil {
			t.Fatal(err)
		}
		for _, need := range names {
			if got := sc.Allows(need, ""); got != (need == held) {
				t.Errorf("a token holding %s: Allows(%s) = %v", held, need, got)
			}
		}
	}
}

// Migration 037 widens every admin token to hold approve and superadmin, so
// an upgrade takes no capability away, and leaves every other token alone.
// The down migration narrows the widened ones back and deletes any token an
// older binary would read as more than it was issued.
func TestApproveScopesMigration(t *testing.T) {
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() { _ = raw.Close() }()
	m := migrator(t, raw)
	before := migrationBefore(t, approveScopesVersion)
	if err := m.Migrate(before); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO api_tokens (id, label, hash, scope) VALUES
		('full', 'ops', 'h1', 'read,write,admin'),
		('narrow', 'ops', 'h2', 'read:npm,admin'),
		('adm', 'ops', 'h3', 'admin'),
		('ci', 'ci', 'h4', 'read,write:npm'),
		('inv', 'web', 'h5', 'inventory')`); err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(approveScopesVersion); err != nil {
		t.Fatalf("migrate to %d: %v", approveScopesVersion, err)
	}
	scopes := func() string {
		t.Helper()
		rows, err := raw.Query(`SELECT id || '=' || scope || '/' || created_by FROM api_tokens ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		return strings.Join(out, " ")
	}
	want := "adm=admin,approve,superadmin/ ci=read,write:npm/ full=read,write,admin,approve,superadmin/ " +
		"inv=inventory/ narrow=read:npm,admin,approve,superadmin/"
	if got := scopes(); got != want {
		t.Errorf("after 037:\n got %s\nwant %s", got, want)
	}
	for _, id := range []string{"full", "narrow", "adm"} {
		var s string
		_ = raw.QueryRow(`SELECT scope FROM api_tokens WHERE id = ?`, id).Scan(&s)
		if canon, err := CanonicalScopes(s); err != nil || canon != s {
			t.Errorf("%s migrated to %q, which is not canonical (%q, %v)", id, s, canon, err)
		}
	}

	if _, err := raw.Exec(`INSERT INTO api_tokens (id, label, hash, scope, created_by) VALUES
		('oncall', 'o', 'h6', 'read,approve', 'alice'),
		('root', 'r', 'h7', 'superadmin', 'alice'),
		('plain', 'p', 'h8', 'read,admin', 'alice')`); err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(before); err != nil {
		t.Fatalf("down: %v", err)
	}
	var ids []string
	rows, _ := raw.Query(`SELECT id || '=' || scope FROM api_tokens ORDER BY id`)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		ids = append(ids, s)
	}
	_ = rows.Close()
	if got := strings.Join(ids, " "); got != "adm=admin ci=read,write:npm full=read,write,admin inv=inventory narrow=read:npm,admin" {
		t.Errorf("after down: %s, want the widened tokens narrowed and oncall, root and plain gone", got)
	}
	if _, err := raw.Exec(`SELECT created_by FROM api_tokens`); err == nil {
		t.Error("created_by survived the down migration")
	}
}

// Every token row names its creator: an exchanged token the principal it acts
// for, any other the caller's identity, and no token is stored without one.
func TestTokenRecordsCreator(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	p := Principal{Subject: "alice", Issuer: "https://idp.example"}
	if err := db.InsertExchangedToken(ctx, "ex", "oidc", "h1", "read,approve", time.Now().Add(time.Hour), p); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertScopedToken(ctx, "op", "ops", "h2", "", "superadmin", "bob", nil); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertScopedToken(ctx, "anon", "x", "h3", "", "read", " ", nil); err == nil {
		t.Error("a token with no creator was stored")
	}
	tokens, err := db.ListTokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, tk := range tokens {
		got[tk.ID] = tk.CreatedBy
	}
	if len(got) != 2 || got["ex"] != p.Identity() || got["op"] != "bob" {
		t.Errorf("created_by = %v, want ex=%s op=bob", got, p.Identity())
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
	before := migrationBefore(t, tokenScopesVersion)
	if err := m.Migrate(before); err != nil {
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
	if got["old"] != "read,write,admin" || got["inv"] != ScopeInventory {
		t.Errorf("migrated scopes = %v, want old=read,write,admin inv=inventory", got)
	}
	if _, err := raw.Exec(`INSERT INTO api_tokens (id, label, hash, scope) VALUES ('n', 'n', 'h3', 'write:npm'), ('x', 'x', 'h4', 'read,write,admin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO api_tokens (id, label, hash, scope, subject, issuer) VALUES ('e', 'e', 'h5', 'read,write,admin', 's', 'https://i')`); err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(before); err != nil {
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
	if err := db.InsertScopedToken(ctx, "op", "ops", "h3", "", "admin", "test-operator", &past); err != nil {
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

// A request pending when migration 038 runs keeps the rule it was made
// under: its requester counts, as do the votes already cast, so one more
// approval still meets a quorum of 2. Going back down deletes a vote that
// did not count and rejects a pending request whose requester did not, since
// the older binary would count both.
func TestRequesterCountsMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	m := migrator(t, raw)
	before := migrationBefore(t, requesterCountsVersion)
	if err := m.Migrate(before); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	at, until := formatOverrideTime(now), formatOverrideTime(now.Add(time.Hour))
	if _, err := raw.Exec(`INSERT INTO overrides (id, pkg_type, pkg_name, pkg_version, check_name, reason,
		requested_by, requested_at, expires_at, quorum, state) VALUES
		('old', 'npm', 'minimist', '1.2.0', 'osv', 'r', 'f46-ci', ?, ?, 3, 'pending')`, at, until); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO override_votes (override_id, identity, vote, voted_at) VALUES ('old', 'alice', 'approve', ?)`, at); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	adb, err := Open(path)
	if err != nil {
		t.Fatalf("open (migrates to latest): %v", err)
	}
	o, err := adb.GetOverride(t.Context(), "old")
	if err != nil {
		t.Fatal(err)
	}
	if !o.RequesterCounts || len(o.Votes) != 1 || !o.Votes[0].Counted || o.Remaining() != 1 {
		t.Fatalf("after 038: %+v, want the requester and alice counted, one approval remaining", o)
	}
	o, err = adb.VoteOverride(t.Context(), "old", OverrideCaller{Identity: "bob", Scope: "approve"}, VoteApprove, "", now)
	if err != nil || o.State != OverrideApproved {
		t.Fatalf("bob's approval = %v, %v; want approved by f46-ci, alice and bob", o.State, err)
	}

	newer := Override{ID: "new", PkgType: "npm", PkgName: "minimist", PkgVersion: "1.2.1", Check: CheckOSV, Reason: "r",
		RequestedBy: "f46-ci", RequestedAt: now, ExpiresAt: now.Add(time.Hour), Quorum: 2}
	if err := adb.InsertOverride(t.Context(), newer); err != nil {
		t.Fatal(err)
	}
	if _, err := adb.VoteOverride(t.Context(), "new", OverrideCaller{Identity: "sock", Scope: "approve", TokenCreatedBy: "f46-ci"}, VoteApprove, "", now); err != nil {
		t.Fatal(err)
	}
	if err := adb.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if err := migrator(t, raw).Migrate(before); err != nil {
		t.Fatalf("down: %v", err)
	}
	var state string
	var votes int
	if err := raw.QueryRow(`SELECT state, (SELECT count(*) FROM override_votes WHERE override_id = 'new') FROM overrides WHERE id = 'new'`).
		Scan(&state, &votes); err != nil {
		t.Fatal(err)
	}
	if state != OverrideRejected || votes != 0 {
		t.Errorf("after down: new is %s with %d vote(s), want rejected with none", state, votes)
	}
	if err := raw.QueryRow(`SELECT state FROM overrides WHERE id = 'old'`).Scan(&state); err != nil || state != OverrideApproved {
		t.Errorf("after down: old is %s (%v), want approved, untouched", state, err)
	}
}
