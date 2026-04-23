package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
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
	maxV, err := maxMigrationVersion()
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
