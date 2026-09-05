package audit

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

func TestMigrationsFreshOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("fresh open: %v", err)
	}
	defer db.Close()

	// Core tables should exist.
	for _, tbl := range []string{"events", "checksums", "api_tokens", "upstream_policies", "schema_migrations"} {
		var name string
		if err := db.db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl,
		).Scan(&name); err != nil {
			t.Errorf("missing table %s: %v", tbl, err)
		}
	}

	// schema_migrations version should reflect the highest migration in the FS.
	maxV, err := maxMigrationVersion(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("maxMigrationVersion: %v", err)
	}
	var version int
	var dirty bool
	if err := db.db.QueryRow(`SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if uint(version) != maxV {
		t.Errorf("schema_migrations version = %d, want %d", version, maxV)
	}
	if dirty {
		t.Error("schema_migrations dirty after clean migrate")
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db1, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	db1.Close()

	db2, err := Open(path)
	if err != nil {
		t.Fatalf("second open (idempotent): %v", err)
	}
	db2.Close()
}

func TestMigrationsRefusesNewerDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")

	// First open at current schema.
	db, err := Open(path)
	if err != nil {
		t.Fatalf("fresh open: %v", err)
	}
	db.Close()

	// Fabricate a "future" schema version in schema_migrations.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := raw.Exec(`UPDATE schema_migrations SET version = 9999`); err != nil {
		t.Fatalf("bump version: %v", err)
	}
	raw.Close()

	// Re-open should refuse with a clear error.
	if _, err := Open(path); err == nil {
		t.Fatal("expected error opening DB with schema version > binary max, got nil")
	}
}

func TestMigrationsAppliedToLegacyDB(t *testing.T) {
	// Simulate a pre-0.2.0 install: tables created by the old inline schema,
	// but no schema_migrations row. Migration 001 should recognize existing
	// tables (CREATE ... IF NOT EXISTS) and 002 should add upstream_policies.
	path := filepath.Join(t.TempDir(), "audit.db")

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE events (
		    id          INTEGER PRIMARY KEY AUTOINCREMENT,
		    timestamp   TEXT    NOT NULL,
		    event_type  TEXT    NOT NULL,
		    pkg_type    TEXT    NOT NULL,
		    pkg_name    TEXT    NOT NULL,
		    pkg_version TEXT    DEFAULT '',
		    client_ip   TEXT    DEFAULT '',
		    user_agent  TEXT    DEFAULT '',
		    status      TEXT    DEFAULT '',
		    duration_ms INTEGER DEFAULT 0,
		    details     TEXT    DEFAULT ''
		);
		CREATE TABLE checksums (
		    id INTEGER PRIMARY KEY, s3_key TEXT UNIQUE, pkg_type TEXT, pkg_name TEXT, pkg_version TEXT, algorithm TEXT, value TEXT, source TEXT, created_at TEXT, updated_at TEXT
		);
		CREATE TABLE api_tokens (id TEXT PRIMARY KEY, label TEXT, hash TEXT, comment TEXT, created_at TEXT, expires_at TEXT, last_used TEXT);
	`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	// Seed a row so we can verify data survives.
	if _, err := raw.Exec(`INSERT INTO api_tokens (id, label, hash) VALUES ('seed', 'legacy', 'x')`); err != nil {
		t.Fatalf("seed row: %v", err)
	}
	raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("migrate legacy: %v", err)
	}
	defer db.Close()

	// Existing row should still be there.
	var label string
	if err := db.db.QueryRow(`SELECT label FROM api_tokens WHERE id='seed'`).Scan(&label); err != nil {
		t.Fatalf("row lost during migration: %v", err)
	}
	if label != "legacy" {
		t.Errorf("label = %q, want legacy", label)
	}

	// upstream_policies from migration 002 must now exist.
	var tblName string
	if err := db.db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='upstream_policies'`,
	).Scan(&tblName); err != nil {
		t.Fatalf("upstream_policies missing after legacy migrate: %v", err)
	}

	// Insert/list round trip.
	ctx := context.Background()
	if err := db.InsertPolicy(ctx, PolicyInfo{
		ID: "abc", RegistryType: "pypi", RuleKind: "package", Pattern: "django", CreatedBy: "test",
	}); err != nil {
		t.Fatalf("InsertPolicy: %v", err)
	}
	rules, err := db.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(rules) != 1 || rules[0].Pattern != "django" {
		t.Errorf("ListPolicies = %+v", rules)
	}
}

// Migrations 009 and 010 move the decision CHECK. A value the constraint
// rejects fails at write time inside the recorder's worker goroutine, where
// the only evidence is a warn line nobody reads, so the constraint is
// asserted here.
func TestDiscoveryDecisionsSurviveTheCheckConstraint(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	for _, decision := range []string{
		DecisionAllowed, DecisionDenied, DecisionNoPolicy,
		DecisionNoManifest, DecisionNoNamespace,
	} {
		row := DiscoveryRow{
			RegistryType: "gomod",
			PatternHint:  "github.com/aws/",
			PkgName:      "github.com/aws/aws-sdk-go-v2",
			PkgVersion:   "v1.30.0",
			Decision:     decision,
			UpstreamURL:  "https://proxy.golang.org/x",
		}
		if err := db.RecordDiscovery(ctx, row); err != nil {
			t.Errorf("record decision %q: %v", decision, err)
		}
	}

	rows, err := db.ListDiscovery(ctx, DiscoveryFilter{RegistryType: "gomod"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 5 {
		t.Errorf("rows = %d, want 5 — the decision column is part of the primary key, so each value is its own row", len(rows))
	}

	// The retired value has to be refused rather than silently stored: a
	// constraint that still accepted it would let a stale binary keep writing
	// rows nothing reads back.
	err = db.RecordDiscovery(ctx, DiscoveryRow{
		RegistryType: "gomod",
		PatternHint:  "github.com/aws/",
		PkgName:      "github.com/aws/aws-sdk-go-v2",
		PkgVersion:   "v1.31.0",
		Decision:     "would_deny",
	})
	if err == nil {
		t.Error("RecordDiscovery accepted would_deny; migration 010 did not narrow the CHECK")
	}
}

// The rename-copy-drop in 009 has to carry the pre-existing rows across and
// rebuild both indexes. The test migrates to 008, writes a row through the
// pre-009 schema, then steps up: a migration that silently emptied the table
// would otherwise surface only as a discovery log that reset itself on
// upgrade.
func TestMigration009PreservesRowsAndIndexes(t *testing.T) {
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() { _ = raw.Close() }()

	m := migrator(t, raw)
	if err := m.Migrate(8); err != nil {
		t.Fatalf("migrate to 008: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO upstream_discovery (registry_type, pattern_hint, pkg_name, pkg_version, decision, upstream_url)
		 VALUES ('npm','lodash','lodash','4.17.21','no_policy','https://registry.npmjs.org/lodash')`,
	); err != nil {
		t.Fatalf("seed row at 008: %v", err)
	}

	if err := m.Migrate(9); err != nil {
		t.Fatalf("migrate to 009: %v", err)
	}

	var upstream string
	if err := raw.QueryRow(
		`SELECT upstream_url FROM upstream_discovery WHERE pkg_name = 'lodash'`,
	).Scan(&upstream); err != nil {
		t.Fatalf("row did not survive 009: %v", err)
	}
	if upstream != "https://registry.npmjs.org/lodash" {
		t.Errorf("upstream_url = %q after 009; the copy mismatched its columns", upstream)
	}

	for _, idx := range []string{"idx_discovery_type_pattern", "idx_discovery_last_seen"} {
		var name string
		if err := raw.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx,
		).Scan(&name); err != nil {
			t.Errorf("index %s missing after 009: %v", idx, err)
		}
	}
	var leftover string
	err = raw.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'upstream_discovery!_%' ESCAPE '!'`,
	).Scan(&leftover)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("migration left a scratch table behind: %q (%v)", leftover, err)
	}

	// Rolling back drops what the narrower constraint cannot hold, and keeps
	// everything it can. A down migration that aborted instead would strand
	// the operator on a schema they cannot leave.
	if _, err := raw.Exec(
		`INSERT INTO upstream_discovery (registry_type, pattern_hint, pkg_name, pkg_version, decision)
		 VALUES ('gomod','github.com/aws/','github.com/aws/aws-sdk-go-v2','v1.30.0','no_manifest')`,
	); err != nil {
		t.Fatalf("seed no_manifest row at 009: %v", err)
	}
	if err := m.Migrate(8); err != nil {
		t.Fatalf("migrate down to 008: %v", err)
	}
	var kept, dropped int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM upstream_discovery`).Scan(&kept); err != nil {
		t.Fatalf("count after down: %v", err)
	}
	if kept != 1 {
		t.Errorf("rows after down = %d, want 1 (the no_policy row survives)", kept)
	}
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM upstream_discovery WHERE decision = 'no_manifest'`,
	).Scan(&dropped); err != nil {
		t.Fatalf("count no_manifest after down: %v", err)
	}
	if dropped != 0 {
		t.Errorf("no_manifest rows after down = %d, want 0", dropped)
	}
}

// Migration 010 retires would_deny by relabeling, not by deleting. decision is
// part of the primary key, so a would_deny row can collide with the denied row
// for the same package; the merge is the half that a plain UPDATE would fail
// on and a plain DELETE would hide. Both cases are seeded here.
func TestMigration010RelabelsWouldDeny(t *testing.T) {
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() { _ = raw.Close() }()

	m := migrator(t, raw)
	if err := m.Migrate(9); err != nil {
		t.Fatalf("migrate to 009: %v", err)
	}

	// Explicit timestamps: the merge has to widen the window to cover both
	// rows and carry the later row's client, which a defaulted `now` on every
	// insert would make unobservable.
	const seed = `INSERT INTO upstream_discovery
	   (registry_type, pattern_hint, pkg_name, pkg_version, decision,
	    first_seen, last_seen, last_client, request_count, upstream_url)
	 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	for _, row := range [][]any{
		{"gomod", "github.com/aws/", "github.com/aws/aws-sdk-go-v2", "v1.30.0", "denied",
			"2026-01-02T00:00:00.000Z", "2026-01-02T00:00:00.000Z", "10.0.0.2", 3, "https://proxy.golang.org/x"},
		{"gomod", "github.com/aws/", "github.com/aws/aws-sdk-go-v2", "v1.30.0", "would_deny",
			"2026-01-01T00:00:00.000Z", "2026-01-03T00:00:00.000Z", "10.0.0.9", 4, "https://proxy.golang.org/x"},
		{"npm", "lodash", "lodash", "4.17.21", "would_deny",
			"2026-01-04T00:00:00.000Z", "2026-01-04T00:00:00.000Z", "10.0.0.7", 9, "https://registry.npmjs.org/lodash"},
	} {
		if _, err := raw.Exec(seed, row...); err != nil {
			t.Fatalf("seed row at 009: %v", err)
		}
	}

	if err := m.Migrate(10); err != nil {
		t.Fatalf("migrate to 010: %v", err)
	}

	var stillThere int
	if err := raw.QueryRow(
		`SELECT COUNT(*) FROM upstream_discovery WHERE decision = 'would_deny'`,
	).Scan(&stillThere); err != nil {
		t.Fatalf("count would_deny: %v", err)
	}
	if stillThere != 0 {
		t.Errorf("would_deny rows after 010 = %d, want 0", stillThere)
	}

	var count int64
	var firstSeen, lastSeen, lastClient string
	if err := raw.QueryRow(
		`SELECT request_count, first_seen, last_seen, last_client FROM upstream_discovery
		 WHERE registry_type = 'gomod' AND decision = 'denied'`,
	).Scan(&count, &firstSeen, &lastSeen, &lastClient); err != nil {
		t.Fatalf("merged row missing: %v", err)
	}
	if count != 7 {
		t.Errorf("request_count = %d, want 7 — the collision must add, not overwrite", count)
	}
	if firstSeen != "2026-01-01T00:00:00.000Z" || lastSeen != "2026-01-03T00:00:00.000Z" {
		t.Errorf("window = %s..%s, want 2026-01-01..2026-01-03", firstSeen, lastSeen)
	}
	if lastClient != "10.0.0.9" {
		t.Errorf("last_client = %q, want 10.0.0.9 — the later of the two rows", lastClient)
	}

	// The uncontested case: relabeled in place, count untouched.
	if err := raw.QueryRow(
		`SELECT request_count FROM upstream_discovery WHERE pkg_name = 'lodash' AND decision = 'denied'`,
	).Scan(&count); err != nil {
		t.Fatalf("relabeled npm row missing: %v", err)
	}
	if count != 9 {
		t.Errorf("request_count = %d, want 9", count)
	}

	// Rolling back widens the constraint and keeps every row. The labels do
	// not come back, which is what the down migration says it cannot do.
	if err := m.Migrate(9); err != nil {
		t.Fatalf("migrate down to 009: %v", err)
	}
	var kept int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM upstream_discovery`).Scan(&kept); err != nil {
		t.Fatalf("count after down: %v", err)
	}
	if kept != 2 {
		t.Errorf("rows after down = %d, want 2", kept)
	}
}

// migrator builds a migrate instance over the embedded migrations, so a test
// can step the schema one version at a time rather than only running Open's
// all-the-way-up.
func migrator(t *testing.T, raw *sql.DB) *migrate.Migrate {
	t.Helper()
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("iofs source: %v", err)
	}
	driver, err := sqlite.WithInstance(raw, &sqlite.Config{})
	if err != nil {
		t.Fatalf("sqlite driver: %v", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "sqlite", driver)
	if err != nil {
		t.Fatalf("migrate instance: %v", err)
	}
	return m
}
