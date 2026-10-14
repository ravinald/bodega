package audit

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func openQueueDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func refuse(t *testing.T, db *DB, f QueueRefusal, at time.Time) {
	t.Helper()
	if err := db.RecordRefusal(t.Context(), f, at); err != nil {
		t.Fatalf("RecordRefusal: %v", err)
	}
}

// One row per (type, package, version, check): repeats count, every asker is
// kept, the profiles that refused accumulate, and the newest refusal's detail
// and incident are the ones shown.
func TestRecordRefusalAggregatesOneRowPerTuple(t *testing.T) {
	db := openQueueDB(t)
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	base := QueueRefusal{PkgType: "pypi", PkgName: "django", PkgVersion: "5.0.0", Check: "profile"}

	a := base
	a.Profile, a.Identity, a.ClientIP, a.Detail, a.Incident = "web", "web01", "10.0.0.1", "first", "inc1"
	refuse(t, db, a, t0)
	b := base
	b.Profile, b.Identity, b.ClientIP, b.Detail, b.Incident = "batch", "batch01", "10.0.0.2", "second", "inc2"
	refuse(t, db, b, t0.Add(time.Second))
	refuse(t, db, a, t0.Add(2*time.Second))
	other := base
	other.PkgVersion = "5.0.1"
	refuse(t, db, other, t0.Add(500*time.Millisecond))

	rows, err := db.ListQueue(t.Context(), QueueFilter{State: QueueOpen})
	if err != nil {
		t.Fatalf("ListQueue: %v", err)
	}
	if len(rows) != 2 || rows[0].PkgVersion != "5.0.0" {
		t.Fatalf("rows = %+v, want 5.0.0 first, then 5.0.1", rows)
	}
	q := rows[0]
	if q.RequestCount != 3 || q.Detail != "first" || q.Incident != "inc1" {
		t.Errorf("row = %+v, want 3 requests and the newest detail", q)
	}
	if !q.FirstSeen.Equal(t0) || !q.LastSeen.Equal(t0.Add(2*time.Second)) {
		t.Errorf("seen %s .. %s", q.FirstSeen, q.LastSeen)
	}
	if !slices.Equal(q.Profiles, []string{"web", "batch"}) {
		t.Errorf("profiles = %v", q.Profiles)
	}
	if len(q.Requesters) != 2 || q.Requesters[0].Identity != "web01" || q.Requesters[0].RequestCount != 2 ||
		q.Requesters[1].ClientIP != "10.0.0.2" {
		t.Errorf("requesters = %+v", q.Requesters)
	}
}

// A resolved row stays out of the open listing until the same refusal comes
// back after the resolution, when it reopens with its last resolution kept.
func TestResolvedRowReopensOnARefusalAfterIt(t *testing.T) {
	db := openQueueDB(t)
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	f := QueueRefusal{PkgType: "npm", PkgName: "leftpad", PkgVersion: "1.2.0", Check: "age"}
	for _, state := range []string{QueueApproved, QueueDismissed} {
		t.Run(state, func(t *testing.T) {
			refuse(t, db, f, t0)
			rows, _ := db.ListQueue(t.Context(), QueueFilter{State: QueueOpen})
			if len(rows) != 1 {
				t.Fatalf("open rows = %+v", rows)
			}
			if _, err := db.ResolveQueueRow(t.Context(), rows[0].ID, state, "alice", "override abc", "why", t0.Add(time.Minute)); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if _, err := db.ResolveQueueRow(t.Context(), rows[0].ID, state, "bob", "", "again", t0.Add(2*time.Minute)); !errors.Is(err, ErrQueueRowClosed) {
				t.Errorf("resolving a closed row: %v, want ErrQueueRowClosed", err)
			}
			if open, _ := db.ListQueue(t.Context(), QueueFilter{State: QueueOpen}); len(open) != 0 {
				t.Fatalf("a resolved row is still open: %+v", open)
			}
			t0 = t0.Add(time.Hour)
			refuse(t, db, f, t0)
			got, err := db.GetQueueRow(t.Context(), rows[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != QueueOpen || got.ResolvedBy != "alice" || got.Resolution != "override abc" {
				t.Errorf("after a later refusal: %+v, want open with the last resolution kept", got)
			}
		})
	}
	if _, err := db.GetQueueRow(t.Context(), 999); !errors.Is(err, ErrQueueRowNotFound) {
		t.Errorf("unknown id: %v", err)
	}
}

// Timestamps inside one second still order: RFC3339Nano would write .1 and
// .12, which compare backwards as text.
func TestQueueOrdersWithinOneSecond(t *testing.T) {
	db := openQueueDB(t)
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 100_000_000, time.UTC)
	refuse(t, db, QueueRefusal{PkgType: "npm", PkgName: "a", PkgVersion: "1", Check: "age"}, t0)
	refuse(t, db, QueueRefusal{PkgType: "npm", PkgName: "b", PkgVersion: "1", Check: "age"}, t0.Add(20*time.Millisecond))
	rows, err := db.ListQueue(t.Context(), QueueFilter{PkgType: "npm", Check: "age"})
	if err != nil || len(rows) != 2 || rows[0].PkgName != "b" {
		t.Fatalf("rows = %+v (%v), want b first", rows, err)
	}
}
