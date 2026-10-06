package policy

import (
	"context"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
)

type fakeIndexFilterStore struct {
	on  bool
	age *audit.AgePolicy
	osv *audit.OSVPolicy
}

func (f fakeIndexFilterStore) IndexFilterEnabled(context.Context, string) (bool, error) {
	return f.on, nil
}

func (f fakeIndexFilterStore) GetAgePolicy(context.Context, string) (audit.AgePolicy, error) {
	if f.age == nil {
		return audit.AgePolicy{}, audit.ErrAgePolicyNotFound
	}
	return *f.age, nil
}

func (f fakeIndexFilterStore) GetOSVPolicy(context.Context, string) (audit.OSVPolicy, error) {
	if f.osv == nil {
		return audit.OSVPolicy{}, audit.ErrOSVPolicyNotFound
	}
	return *f.osv, nil
}

func TestIndexFilterGate(t *testing.T) {
	ctx := context.Background()
	week := &audit.AgePolicy{MinAgeSeconds: 7 * 24 * 3600, Action: ActionBlock}
	db := dbWithNpm(t, t.TempDir(), npmAdvisory("GHSA-x", "minimist", "1.0.0", "1.2.6"))
	ck := NewOSVChecker(nil)
	ck.LocalDB = db
	ck.AllowAPIFallback = true

	t.Run("off withholds nothing", func(t *testing.T) {
		g, err := NewIndexFilter(fakeIndexFilterStore{age: week}, ck).Gate(ctx, "npm")
		if err != nil || g != nil {
			t.Errorf("gate = %+v, %v; want nil with the filter off", g, err)
		}
	})
	t.Run("a warn gate withholds nothing", func(t *testing.T) {
		warn := &audit.AgePolicy{MinAgeSeconds: 7 * 24 * 3600, Action: ActionWarn}
		g, err := NewIndexFilter(fakeIndexFilterStore{on: true, age: warn, osv: &audit.OSVPolicy{Action: ActionWarn}}, ck).Gate(ctx, "npm")
		if err != nil || g != nil {
			t.Errorf("gate = %+v, %v; want nil when neither gate blocks", g, err)
		}
	})

	f := NewIndexFilter(fakeIndexFilterStore{on: true, age: week, osv: &audit.OSVPolicy{Action: ActionBlock}}, ck)
	now := time.Now()
	f.Now = func() time.Time { return now }
	g, err := f.Gate(ctx, "npm")
	if err != nil || g == nil {
		t.Fatalf("gate = %v, %v; want one with both gates blocking", g, err)
	}
	if g.osv.AllowAPIFallback {
		t.Error("the filter's OSV copy must not query the live API once per listed version")
	}
	for _, tc := range []struct {
		version   string
		published time.Time
		want      string
	}{
		{"1.2.8", now.Add(-24 * time.Hour), WithheldAge},
		{"1.2.8", now.Add(-30 * 24 * time.Hour), ""},
		{"1.2.5", now.Add(-30 * 24 * time.Hour), WithheldOSV},
		// Undated: the age gate cannot decide and keeps it; OSV still can.
		{"1.2.8", time.Time{}, ""},
		{"1.2.5", time.Time{}, WithheldOSV},
	} {
		if got := g.Withhold(ctx, "minimist", tc.version, tc.published); got != tc.want {
			t.Errorf("Withhold(%s, %v) = %q, want %q", tc.version, tc.published, got, tc.want)
		}
	}
}
