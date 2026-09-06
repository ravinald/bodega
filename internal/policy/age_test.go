package policy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

type fakeAgeStore struct {
	policies map[string]audit.AgePolicy
}

func (f *fakeAgeStore) GetAgePolicy(_ context.Context, ecosystem string) (audit.AgePolicy, error) {
	p, ok := f.policies[ecosystem]
	if !ok {
		return audit.AgePolicy{}, audit.ErrAgePolicyNotFound
	}
	return p, nil
}

// stubNpm replies to /{pkg} with a packument carrying one version's time.
func stubNpm(t *testing.T, pkg, version string, publishedAt time.Time) *httptest.Server {
	t.Helper()
	body := fmt.Sprintf(`{"time":{"%s":%q}}`, version, publishedAt.UTC().Format(time.RFC3339Nano))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+pkg {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		fmt.Fprint(w, body)
	}))
}

func TestAgePolicy_NoPolicy(t *testing.T) {
	ck := NewAgeChecker(&fakeAgeStore{})
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "lodash", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "4.17.21"})
	if r.Action != ActionPass {
		t.Errorf("no policy should short-circuit pass, got %+v", r)
	}
}

func TestAgePolicy_BlocksTooNew(t *testing.T) {
	published := time.Now().Add(-12 * time.Hour)
	srv := stubNpm(t, "left-pad", "0.0.1", published)
	defer srv.Close()

	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: ActionBlock},
	}}
	ck := NewAgeChecker(store)
	ck.NpmRegistry = srv.URL

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "left-pad", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "0.0.1"})
	if r.Action != ActionBlock {
		t.Errorf("expected block for 12h-old vs 7d policy, got %+v", r)
	}
	if r.Details["min_age_seconds"] == nil {
		t.Error("block result missing structured details")
	}
}

func TestAgePolicy_PassesWhenOldEnough(t *testing.T) {
	published := time.Now().Add(-30 * 24 * time.Hour)
	srv := stubNpm(t, "pkg", "1.0.0", published)
	defer srv.Close()

	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: ActionBlock},
	}}
	ck := NewAgeChecker(store)
	ck.NpmRegistry = srv.URL

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "pkg", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "1.0.0"})
	if r.Action != ActionPass {
		t.Errorf("30d old vs 7d policy should pass, got %+v", r)
	}
}

func TestAgePolicy_WarnDoesNotBlock(t *testing.T) {
	published := time.Now().Add(-1 * time.Hour)
	srv := stubNpm(t, "fresh", "1.0.0", published)
	defer srv.Close()

	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, MinAgeSeconds: int64((24 * time.Hour).Seconds()), Action: ActionWarn},
	}}
	ck := NewAgeChecker(store)
	ck.NpmRegistry = srv.URL

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "fresh", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "1.0.0"})
	if r.Action != ActionWarn {
		t.Errorf("1h old + warn policy should warn, got %+v", r)
	}
}

// Ecosystems without an upstream-time endpoint short-circuit to pass even
// when a policy row exists for them.
func TestAgePolicy_UnsupportedEcosystem(t *testing.T) {
	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeApt: {Ecosystem: manifest.TypeApt, MinAgeSeconds: 86400, Action: ActionBlock},
	}}
	ck := NewAgeChecker(store)
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "bash", Type: manifest.TypeApt},
		&manifest.VersionEntry{Version: "5.2.21"})
	// Unsupported ecosystem => publishedAt errors => warn (not block).
	// The operator sees "upstream timestamp unavailable" in the audit.
	if r.Action == ActionBlock {
		t.Errorf("unsupported ecosystem should not block; got %+v", r)
	}
}

func TestRunChecks_CombinesResults(t *testing.T) {
	passChecker := stubChecker{name: "pass-one", action: ActionPass}
	warnChecker := stubChecker{name: "warn-one", action: ActionWarn, reason: "stale"}
	blockChecker := stubChecker{name: "block-one", action: ActionBlock, reason: "cve"}

	combined := RunChecks(context.Background(), nil, nil, passChecker, warnChecker, blockChecker)
	if !combined.Blocked() {
		t.Error("expected Blocked true")
	}
	if len(combined.Blocks) != 1 || len(combined.Warns) != 1 {
		t.Errorf("buckets wrong: blocks=%d warns=%d", len(combined.Blocks), len(combined.Warns))
	}
	reasons := combined.Reasons()
	if !contains(reasons, "cve") || !contains(reasons, "stale") {
		t.Errorf("Reasons() dropped context: %q", reasons)
	}
}

type stubChecker struct{ name, action, reason string }

func (s stubChecker) Check(_ context.Context, _ *manifest.PackageManifest, _ *manifest.VersionEntry) Result {
	return Result{Check: s.name, Action: s.action, Reason: s.reason}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestAgePolicy_CargoDatedFromCratesIO(t *testing.T) {
	published := time.Now().Add(-3 * time.Hour)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprintf(w, `{"version":{"num":"0.1.44","created_at":%q}}`,
			published.UTC().Format(time.RFC3339Nano))
	}))
	defer srv.Close()

	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeCargo: {Ecosystem: manifest.TypeCargo, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: ActionBlock},
	}}
	ck := NewAgeChecker(store)
	ck.CratesBase = srv.URL

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "time", Type: manifest.TypeCargo},
		&manifest.VersionEntry{Version: "0.1.44"})
	if r.Action != ActionBlock {
		t.Fatalf("3h-old crate under a 7d policy blocks; got %+v", r)
	}
	if gotPath != "/api/v1/crates/time/0.1.44" {
		t.Errorf("crates.io version endpoint, got %q", gotPath)
	}
}

func TestAgeEcosystems_MatchesDispatch(t *testing.T) {
	want := []string{manifest.TypeCargo, manifest.TypeGomod, manifest.TypeNpm, manifest.TypePypi}
	got := AgeEcosystems()
	if len(got) != len(want) {
		t.Fatalf("AgeEcosystems() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AgeEcosystems() = %v, want %v", got, want)
		}
	}
	// An ecosystem `policy age set` refuses must also be one publishedAt
	// cannot date, or the refusal and the gate disagree.
	_, err := (&AgeChecker{}).publishedAt(context.Background(), manifest.TypeApt, "bash", "5.2")
	if err == nil || !strings.Contains(err.Error(), "no upstream timestamp source") {
		t.Errorf("apt has no timestamp source; got err=%v", err)
	}
}
