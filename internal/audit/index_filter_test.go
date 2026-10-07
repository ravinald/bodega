package audit

import (
	"context"
	"path/filepath"
	"testing"
)

func TestIndexFilterDefaultsOffAndRoundTrips(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	if on, err := db.IndexFilterEnabled(ctx, "npm"); err != nil || on {
		t.Fatalf("fresh store: on = %v, err = %v; want off with no row", on, err)
	}
	for _, want := range []bool{true, false, true} {
		if err := db.SetIndexFilter(ctx, IndexFilter{Ecosystem: "npm", Enabled: want}); err != nil {
			t.Fatal(err)
		}
		if on, err := db.IndexFilterEnabled(ctx, "npm"); err != nil || on != want {
			t.Fatalf("after set %v: on = %v, err = %v", want, on, err)
		}
	}
	rows, err := db.ListIndexFilters(ctx)
	if err != nil || len(rows) != 1 || rows[0].Ecosystem != "npm" || !rows[0].Enabled || rows[0].UpdatedAt.IsZero() {
		t.Fatalf("list = %+v, %v; want one dated npm row, on", rows, err)
	}
}
