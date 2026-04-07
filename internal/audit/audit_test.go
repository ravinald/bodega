package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOpenCreatesDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := os.Stat(path); err != nil {
		t.Errorf("db file not created: %v", err)
	}
}

func TestRecordAndQuery(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	err := db.Record(ctx, Event{
		EventType:  EventFetch,
		PkgType:    "gomod",
		PkgName:    "github.com/aws/aws-sdk-go-v2",
		PkgVersion: "v1.30.0",
		ClientIP:   "10.0.0.5",
		UserAgent:  "Go-http-client/2.0",
		Status:     "cache_hit",
		DurationMs: 15,
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	events, err := db.Query(ctx, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}

	ev := events[0]
	if ev.EventType != EventFetch {
		t.Errorf("event_type = %q, want %q", ev.EventType, EventFetch)
	}
	if ev.PkgName != "github.com/aws/aws-sdk-go-v2" {
		t.Errorf("pkg_name = %q, want github.com/aws/aws-sdk-go-v2", ev.PkgName)
	}
	if ev.ClientIP != "10.0.0.5" {
		t.Errorf("client_ip = %q, want 10.0.0.5", ev.ClientIP)
	}
	if ev.Status != "cache_hit" {
		t.Errorf("status = %q, want cache_hit", ev.Status)
	}
	if ev.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestQueryByEventType(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "gomod", PkgName: "foo"})
	_ = db.Record(ctx, Event{EventType: EventBuild, PkgType: "gomod", PkgName: "foo"})
	_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "helm", PkgName: "bar"})

	events, err := db.Query(ctx, Filter{EventType: EventFetch})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("got %d events, want 2 fetches", len(events))
	}
}

func TestQueryByPkgType(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "gomod", PkgName: "foo"})
	_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "helm", PkgName: "bar"})

	events, err := db.Query(ctx, Filter{PkgType: "helm"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("got %d events, want 1", len(events))
	}
	if events[0].PkgName != "bar" {
		t.Errorf("pkg_name = %q, want bar", events[0].PkgName)
	}
}

func TestQueryByClientIP(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "npm", PkgName: "lodash", ClientIP: "10.0.0.1"})
	_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "npm", PkgName: "react", ClientIP: "10.0.0.2"})

	events, err := db.Query(ctx, Filter{ClientIP: "10.0.0.1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("got %d events, want 1", len(events))
	}
}

func TestQuerySince(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "gomod", PkgName: "old"})

	// Events inserted just now should be after a timestamp from an hour ago.
	since := time.Now().Add(-1 * time.Hour)
	events, err := db.Query(ctx, Filter{Since: since})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("got %d events, want 1", len(events))
	}

	// Query with future Since should return nothing.
	events, err = db.Query(ctx, Filter{Since: time.Now().Add(1 * time.Hour)})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("got %d events, want 0", len(events))
	}
}

func TestQueryLimit(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "gomod", PkgName: "pkg"})
	}

	events, err := db.Query(ctx, Filter{Limit: 3})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("got %d events, want 3", len(events))
	}
}

func TestQueryOrderDescending(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "gomod", PkgName: "first"})
	_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "gomod", PkgName: "second"})

	events, err := db.Query(ctx, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("got %d events, want >= 2", len(events))
	}
	// Most recent first.
	if events[0].PkgName != "second" {
		t.Errorf("first result = %q, want second (most recent)", events[0].PkgName)
	}
}

func TestCount(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "gomod", PkgName: "a"})
	_ = db.Record(ctx, Event{EventType: EventBuild, PkgType: "gomod", PkgName: "a"})
	_ = db.Record(ctx, Event{EventType: EventFetch, PkgType: "helm", PkgName: "b"})

	count, err := db.Count(ctx, Filter{})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 3 {
		t.Errorf("total count = %d, want 3", count)
	}

	count, err = db.Count(ctx, Filter{EventType: EventFetch})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 2 {
		t.Errorf("fetch count = %d, want 2", count)
	}
}

// ---- Checksum tests --------------------------------------------------------

func TestStoreAndGetChecksum(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	err := db.StoreChecksum(ctx, "gomod/github.com/aws/sdk/@v/v1.0.0.zip",
		"gomod", "github.com/aws/sdk", "v1.0.0", "sha256",
		"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "computed")
	if err != nil {
		t.Fatalf("StoreChecksum: %v", err)
	}

	cs, err := db.GetChecksum(ctx, "gomod/github.com/aws/sdk/@v/v1.0.0.zip")
	if err != nil {
		t.Fatalf("GetChecksum: %v", err)
	}
	if cs == nil {
		t.Fatal("expected checksum, got nil")
	}
	if cs.Algorithm != "sha256" {
		t.Errorf("algorithm = %q, want sha256", cs.Algorithm)
	}
	if cs.Source != "computed" {
		t.Errorf("source = %q, want computed", cs.Source)
	}
	if cs.PkgName != "github.com/aws/sdk" {
		t.Errorf("pkg_name = %q, want github.com/aws/sdk", cs.PkgName)
	}
}

func TestGetChecksumNotFound(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	cs, err := db.GetChecksum(ctx, "nonexistent/key")
	if err != nil {
		t.Fatalf("GetChecksum: %v", err)
	}
	if cs != nil {
		t.Errorf("expected nil for nonexistent key, got %+v", cs)
	}
}

func TestStoreChecksumUpsert(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	key := "charts/nginx-1.0.0.tgz"
	_ = db.StoreChecksum(ctx, key, "helm", "nginx", "1.0.0", "sha256", "aaa", "computed")
	_ = db.StoreChecksum(ctx, key, "helm", "nginx", "1.0.0", "sha256", "bbb", "upstream")

	cs, _ := db.GetChecksum(ctx, key)
	if cs.Value != "bbb" {
		t.Errorf("value = %q, want bbb (upsert)", cs.Value)
	}
	if cs.Source != "upstream" {
		t.Errorf("source = %q, want upstream (upsert)", cs.Source)
	}
}

func TestListChecksums(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	_ = db.StoreChecksum(ctx, "gomod/foo/@v/v1.zip", "gomod", "foo", "v1", "sha256", "aaa", "computed")
	_ = db.StoreChecksum(ctx, "gomod/bar/@v/v2.zip", "gomod", "bar", "v2", "sha256", "bbb", "computed")
	_ = db.StoreChecksum(ctx, "npm/lodash/lodash-4.tgz", "npm", "lodash", "4.17.21", "sha256", "ccc", "computed")

	all, err := db.ListChecksums(ctx, "", "")
	if err != nil {
		t.Fatalf("ListChecksums: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("got %d checksums, want 3", len(all))
	}

	gomod, _ := db.ListChecksums(ctx, "gomod", "")
	if len(gomod) != 2 {
		t.Errorf("gomod checksums = %d, want 2", len(gomod))
	}

	specific, _ := db.ListChecksums(ctx, "gomod", "foo")
	if len(specific) != 1 {
		t.Errorf("gomod/foo checksums = %d, want 1", len(specific))
	}
}

func TestClearChecksum(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	key := "npm/lodash/lodash-4.tgz"
	_ = db.StoreChecksum(ctx, key, "npm", "lodash", "4.17.21", "sha256", "aaa", "computed")

	if err := db.ClearChecksum(ctx, key); err != nil {
		t.Fatalf("ClearChecksum: %v", err)
	}

	cs, _ := db.GetChecksum(ctx, key)
	if cs != nil {
		t.Error("checksum should be cleared")
	}
}

func TestClearChecksumNotFound(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	err := db.ClearChecksum(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestClearChecksumsByPackage(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	_ = db.StoreChecksum(ctx, "npm/lodash/lodash-4.17.tgz", "npm", "lodash", "4.17.21", "sha256", "aaa", "computed")
	_ = db.StoreChecksum(ctx, "npm/lodash/lodash-4.18.tgz", "npm", "lodash", "4.18.0", "sha256", "bbb", "computed")
	_ = db.StoreChecksum(ctx, "npm/react/react-18.tgz", "npm", "react", "18.0.0", "sha256", "ccc", "computed")

	if err := db.ClearChecksumsByPackage(ctx, "npm", "lodash"); err != nil {
		t.Fatalf("ClearChecksumsByPackage: %v", err)
	}

	lodash, _ := db.ListChecksums(ctx, "npm", "lodash")
	if len(lodash) != 0 {
		t.Errorf("lodash checksums = %d, want 0", len(lodash))
	}

	react, _ := db.ListChecksums(ctx, "npm", "react")
	if len(react) != 1 {
		t.Errorf("react checksums = %d, want 1 (should not be affected)", len(react))
	}
}

func TestMultipleEventTypes(t *testing.T) {
	db := tempDB(t)
	ctx := context.Background()

	for _, et := range []EventType{EventFetch, EventBuild, EventCreate, EventDelete, EventCache} {
		err := db.Record(ctx, Event{EventType: et, PkgType: "gomod", PkgName: "test"})
		if err != nil {
			t.Fatalf("Record %s: %v", et, err)
		}
	}

	events, err := db.Query(ctx, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 5 {
		t.Errorf("got %d events, want 5", len(events))
	}
}
