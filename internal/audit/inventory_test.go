package audit

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const tokenScopeVersion = 26

// A token minted before scopes existed was an admin credential, and the
// migration must not quietly demote it: it migrates as full.
func TestTokenScopeMigrationKeepsExistingTokensFull(t *testing.T) {
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() { _ = raw.Close() }()

	m := migrator(t, raw)
	if err := m.Migrate(tokenScopeVersion - 1); err != nil {
		t.Fatalf("migrate to %d: %v", tokenScopeVersion-1, err)
	}
	if _, err := raw.Exec(`INSERT INTO api_tokens (id, label, hash) VALUES ('old', 'ci', 'h')`); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	if err := m.Migrate(tokenScopeVersion); err != nil {
		t.Fatalf("migrate to %d: %v", tokenScopeVersion, err)
	}
	var scope string
	if err := raw.QueryRow(`SELECT scope FROM api_tokens WHERE id = 'old'`).Scan(&scope); err != nil {
		t.Fatalf("read scope: %v", err)
	}
	if scope != ScopeFull {
		t.Errorf("pre-existing token scope = %q, want %q", scope, ScopeFull)
	}
	if _, err := raw.Exec(`INSERT INTO api_tokens (id, label, hash, scope) VALUES ('x', 'x', 'x', 'admin')`); err == nil {
		t.Error("a scope outside full/inventory was stored; the CHECK constraint is missing")
	}
}

func TestScopedTokenRoundTrips(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	if err := db.InsertToken(ctx, "a", "admin", "ha", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertScopedToken(ctx, "b", "host", "hb", "", ScopeInventory, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertScopedToken(ctx, "c", "bad", "hc", "", "root", nil); err == nil {
		t.Error("InsertScopedToken accepted an unknown scope")
	}
	hashes, err := db.GetTokenHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, h := range hashes {
		got[h.ID] = h.Scope
	}
	if got["a"] != ScopeFull || got["b"] != ScopeInventory {
		t.Errorf("scopes = %v, want a=full b=inventory", got)
	}
	infos, err := db.ListTokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range infos {
		if i.Scope != got[i.ID] {
			t.Errorf("ListTokens scope for %s = %q, GetTokenHashes says %q", i.ID, i.Scope, got[i.ID])
		}
	}
}

func TestInventoryHostMapping(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)

	added, err := db.BindInventoryHost(ctx, "osq", "node-1", "web-01")
	if err != nil || !added {
		t.Fatalf("bind = %v, %v; want added", added, err)
	}
	if added, err := db.BindInventoryHost(ctx, "osq", "node-1", "web-01"); err != nil || added {
		t.Errorf("rebinding to the same identity = %v, %v; want a no-op", added, err)
	}
	_, err = db.BindInventoryHost(ctx, "osq", "node-1", "web-02")
	var conflict *InventoryHostConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("rebinding to another identity: err = %v, want *InventoryHostConflict", err)
	}
	// The same external id under another instance is another host.
	if added, err := db.BindInventoryHost(ctx, "osq-b", "node-1", "web-02"); err != nil || !added {
		t.Errorf("same id under a second instance = %v, %v; want added", added, err)
	}
	if id, _ := db.InventoryHostIdentity(ctx, "osq", "node-1"); id != "web-01" {
		t.Errorf("identity = %q, want web-01", id)
	}
	if removed, err := db.UnbindInventoryHost(ctx, "osq", "node-1"); err != nil || !removed {
		t.Errorf("unbind = %v, %v", removed, err)
	}
	if id, _ := db.InventoryHostIdentity(ctx, "osq", "node-1"); id != "" {
		t.Errorf("identity after unbind = %q, want none", id)
	}
}

func TestInventoryReportsChainAndStayUnbound(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

	rep := InventoryReport{Source: "cdx", ExternalID: "ghost", ObservedAt: now, ReceivedAt: now,
		Components: []InventoryComponent{{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}}}
	first, err := db.AppendInventoryReport(ctx, rep)
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.AppendInventoryReport(ctx, rep)
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq != 1 || second.Seq != 2 {
		t.Errorf("seq = %d, %d; want 1, 2", first.Seq, second.Seq)
	}
	if first.PrevSHA256 != "" || second.PrevSHA256 != first.SHA256 || second.SHA256 == first.SHA256 {
		t.Errorf("chain broken: first=%+v second=%+v", first, second)
	}

	unbound, err := db.ListUnboundInventoryHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(unbound) != 1 || unbound[0].ExternalID != "ghost" || unbound[0].Reports != 2 {
		t.Fatalf("unbound = %+v, want ghost with 2 reports", unbound)
	}

	// Binding takes the id off the unbound list and leaves the stored rows
	// exactly as they were written.
	if _, err := db.BindInventoryHost(ctx, "cdx", "ghost", "web-03"); err != nil {
		t.Fatal(err)
	}
	if unbound, _ := db.ListUnboundInventoryHosts(ctx); len(unbound) != 0 {
		t.Errorf("unbound after bind = %+v, want none", unbound)
	}
	stored, err := db.InventoryReports(ctx, "cdx")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 || stored[0].Identity != "" || len(stored[0].Components) != 1 {
		t.Errorf("stored = %+v, want two unbound reports with one component each", stored)
	}
	hosts, _ := db.ListInventoryHosts(ctx)
	if len(hosts) != 1 || !hosts[0].FirstSeen.Equal(now) {
		t.Errorf("hosts = %+v, want first_seen carried from the unbound reports", hosts)
	}
}

// One host reporting through two instances keeps both histories, each
// chained on its own.
func TestInventoryReportsKeptPerSource(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	now := time.Now()
	for _, src := range []string{"osq", "falcon-a"} {
		if _, err := db.AppendInventoryReport(ctx, InventoryReport{
			Source: src, ExternalID: "h", Identity: "web-01", ObservedAt: now, ReceivedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := db.InventoryReports(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].Seq != 1 || all[1].Seq != 1 {
		t.Errorf("reports = %+v, want one per source, each starting its own chain", all)
	}
}

func TestInventoryTablesRefuseUpdates(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	now := time.Now()
	if _, err := db.AppendInventoryReport(ctx, InventoryReport{Source: "s", ExternalID: "h", ObservedAt: now, ReceivedAt: now,
		Components: []InventoryComponent{{Ecosystem: "apt", Name: "curl"}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.AppendInventoryAttempts(ctx, []InventoryAttempt{{Source: "s", ExternalID: "h", Destination: "pypi.org",
		ObservedAt: now, ReceivedAt: now}}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE inventory_reports SET identity = 'x'`,
		`UPDATE inventory_components SET name = 'x'`,
		`UPDATE inventory_attempts SET destination = 'x'`,
	} {
		_, err := db.writer().ExecContext(ctx, q)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: err = %v, want the append-only refusal", q, err)
		}
	}
}

func TestPruneInventoryRemovesOnlyOlderRowsOfOneSource(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now()
	for _, r := range []InventoryReport{
		{Source: "a", ExternalID: "h", ObservedAt: old, ReceivedAt: old, Components: []InventoryComponent{{Ecosystem: "apt", Name: "x"}}},
		{Source: "a", ExternalID: "h", ObservedAt: recent, ReceivedAt: recent},
		{Source: "b", ExternalID: "h", ObservedAt: old, ReceivedAt: old},
	} {
		if _, err := db.AppendInventoryReport(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AppendInventoryAttempts(ctx, []InventoryAttempt{{Source: "a", ExternalID: "h", Destination: "d", ObservedAt: old, ReceivedAt: old}}); err != nil {
		t.Fatal(err)
	}
	n, err := db.PruneInventory(ctx, "a", time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("pruned %d rows, want the old report and the old attempt", n)
	}
	a, _ := db.InventoryReports(ctx, "a")
	b, _ := db.InventoryReports(ctx, "b")
	if len(a) != 1 || len(b) != 1 {
		t.Errorf("after prune: a=%d b=%d reports, want 1 and 1", len(a), len(b))
	}
	var orphans int
	_ = db.db.QueryRow(`SELECT COUNT(*) FROM inventory_components WHERE report_id NOT IN (SELECT id FROM inventory_reports)`).Scan(&orphans)
	if orphans != 0 {
		t.Errorf("%d components outlived their report", orphans)
	}
}

func TestRecordInventoryPollKeepsLastSuccess(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	ok := time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC)
	if err := db.RecordInventoryPoll(ctx, "falcon", ok, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordInventoryPoll(ctx, "falcon", ok.Add(time.Hour), errors.New("401 from upstream")); err != nil {
		t.Fatal(err)
	}
	st, err := db.InventorySourceStats(ctx, "falcon")
	if err != nil {
		t.Fatal(err)
	}
	if !st.LastSuccess.Equal(ok) || !st.LastAttempt.Equal(ok.Add(time.Hour)) || st.LastError != "401 from upstream" {
		t.Errorf("stats = %+v", st)
	}
}

// A reader verifying the chain has only the stored rows, so every row has to
// recompute to its own sha256 from what InventoryReports returns, whatever
// precision the writer's clock had and whatever the strings carry.
func TestInventoryReportChainRecomputesFromStoredRows(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	now := time.Date(2026, 10, 8, 12, 0, 0, 123456789, time.FixedZone("x", 5*3600))

	reps := []InventoryReport{
		{Source: "cdx", ExternalID: "h", ObservedAt: now, ReceivedAt: now.Add(987654 * time.Nanosecond),
			Components: []InventoryComponent{{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}}},
		{Source: "cdx", ExternalID: "h", ObservedAt: now.Add(time.Second), ReceivedAt: now.Add(time.Second),
			Components: []InventoryComponent{}},
		{Source: "cdx", ExternalID: "h", ReceivedAt: now.Add(2 * time.Second),
			Components: []InventoryComponent{
				{Ecosystem: "other", Name: "bad\xffutf8\x00nul", Path: "/opt/<a>&b", PURL: "pkg:generic/x"},
				{Ecosystem: "npm", Name: "a"},
			}},
	}
	var returned []InventoryReport
	for _, r := range reps {
		got, err := db.AppendInventoryReport(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		returned = append(returned, got)
	}
	stored, err := db.InventoryReports(ctx, "cdx")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != len(reps) {
		t.Fatalf("stored %d reports, want %d", len(stored), len(reps))
	}
	prev := ""
	for i, s := range stored {
		sum, err := reportDigest(s)
		if err != nil {
			t.Fatal(err)
		}
		if sum != s.SHA256 {
			t.Errorf("report %d: stored sha256 %s, recomputed %s", i, s.SHA256, sum)
		}
		if s.PrevSHA256 != prev {
			t.Errorf("report %d: prev_sha256 %q, want recomputed predecessor %q", i, s.PrevSHA256, prev)
		}
		prev = sum
		if returned[i].SHA256 != s.SHA256 || !returned[i].ObservedAt.Equal(s.ObservedAt) || !returned[i].ReceivedAt.Equal(s.ReceivedAt) {
			t.Errorf("report %d: returned %+v differs from stored %+v", i, returned[i], s)
		}
	}
}

// A report is classified once. The record of what bodega knew when it
// arrived can be neither replaced nor edited, and retention removes it with
// the report it belongs to.
func TestInventoryClassificationIsWriteOnceAndPrunedWithItsReport(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rep, err := db.AppendInventoryReport(ctx, InventoryReport{Source: "cdx", ExternalID: "web-01", Identity: "web-01",
		ObservedAt: old, ReceivedAt: old, Components: []InventoryComponent{{Ecosystem: "npm", Name: "x", Version: "1"}}})
	if err != nil {
		t.Fatal(err)
	}
	c := InventoryClassification{ReportID: rep.ID, Source: "cdx", Identity: "web-01", ClassifiedAt: old,
		Components: []ClassifiedComponent{{Ecosystem: "npm", Name: "x", Version: "1", Class: "unknown", Reason: "r"}}}
	if err := db.RecordInventoryClassification(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.Components[0].Class = "served"
	if err := db.RecordInventoryClassification(ctx, c); err == nil {
		t.Error("a second classification of one report was stored")
	}
	if _, err := db.writer().ExecContext(ctx, `UPDATE inventory_classifications SET components = '[]'`); err == nil {
		t.Error("UPDATE on inventory_classifications succeeded; the append-only trigger is missing")
	}
	got, err := db.InventoryClassifications(ctx, []int64{rep.ID})
	if err != nil || got[rep.ID].Components[0].Class != "unknown" || got[rep.ID].Disagreements == nil {
		t.Errorf("stored classification = %+v, %v; want the first one, with an empty (not null) disagreement list", got, err)
	}
	if _, err := db.PruneInventory(ctx, "cdx", old.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.InventoryClassifications(ctx, []int64{rep.ID}); len(got) != 0 {
		t.Errorf("classification of a pruned report survived: %+v", got)
	}
}

func TestInventoryBaselineNamesOneSubject(t *testing.T) {
	ctx := context.Background()
	db := newIdentityTestDB(t)
	for _, b := range []InventoryBaseline{{}, {Identity: "a", Profile: "p"}} {
		if _, err := db.AcceptInventoryBaseline(ctx, b); err == nil {
			t.Errorf("baseline %+v was accepted", b)
		}
	}
	first, err := db.AcceptInventoryBaseline(ctx, InventoryBaseline{Identity: "a", ReportIDs: []int64{3, 4}, Actor: "ops",
		Components: []BaselineComponent{{Ecosystem: "apt", Name: "bash", Version: "5"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AcceptInventoryBaseline(ctx, InventoryBaseline{Identity: "a", Comment: "second"}); err != nil {
		t.Fatal(err)
	}
	cur, err := db.CurrentInventoryBaseline(ctx, "a", "")
	if err != nil || cur == nil || cur.Comment != "second" || cur.ID == first.ID {
		t.Errorf("current = %+v, %v; want the newer baseline in force", cur, err)
	}
	if none, err := db.CurrentInventoryBaseline(ctx, "", "a"); err != nil || none != nil {
		t.Errorf("an identity's baseline answered as a profile's: %+v, %v", none, err)
	}
}
