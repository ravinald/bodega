package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

// The two fakes below are complete source types. Each is one type and one
// Register line, which is the whole cost of adding a source.
func init() {
	Register("fake-push", newFakePush)
	Register("fake-pull", newFakePull)
}

// fakePush authenticates a host by the X-Host header, and vouches for an
// identity when X-Vouch is set, standing in for a source with its own
// enrollment.
type fakePush struct{}

func newFakePush(string, *Settings) (Source, error) { return fakePush{}, nil }

func (fakePush) Type() string { return "fake-push" }
func (fakePush) Mode() Mode   { return ModePush }
func (fakePush) Capabilities() []Capability {
	return []Capability{CapInventory, CapAttempts}
}
func (fakePush) Routes() []Route {
	return []Route{{Method: http.MethodPost, Path: "report", MaxBody: 1024}}
}
func (fakePush) Authenticate(r *http.Request, _ Credentials) (Principal, error) {
	host := r.Header.Get("X-Host")
	if host == "" {
		return Principal{}, &AuthError{Status: http.StatusUnauthorized, Reason: audit.DenialTokenMissing, Message: "no host"}
	}
	return Principal{ExternalID: host, Identity: r.Header.Get("X-Vouch")}, nil
}
func (fakePush) Normalize(doc []byte, ext string) (Batch, error) {
	var in struct {
		Components []Component `json:"components"`
		Attempts   []Attempt   `json:"attempts"`
	}
	if err := json.Unmarshal(doc, &in); err != nil {
		return Batch{}, err
	}
	b := Batch{Attempts: in.Attempts}
	if in.Components != nil {
		b.Reports = []Report{{ExternalID: ext, Components: in.Components}}
	}
	return b, nil
}

// fakePull polls whatever poll returns. It takes one required key, tenant,
// to stand in for a type with its own validation.
type fakePull struct {
	mu   sync.Mutex
	poll func() ([]Document, error)
}

func newFakePull(_ string, s *Settings) (Source, error) {
	tenant, err := s.String("tenant", "")
	if err != nil {
		return nil, err
	}
	if tenant == "" {
		return nil, s.Errorf("tenant", "required")
	}
	return &fakePull{}, nil
}

func (*fakePull) Type() string               { return "fake-pull" }
func (*fakePull) Mode() Mode                 { return ModePull }
func (*fakePull) Capabilities() []Capability { return []Capability{CapInventory} }
func (p *fakePull) Poll(context.Context) ([]Document, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.poll == nil {
		return nil, nil
	}
	return p.poll()
}
func (*fakePull) Normalize(doc []byte, ext string) (Batch, error) {
	return fakePush{}.Normalize(doc, ext)
}

func openDB(t *testing.T) *audit.DB {
	t.Helper()
	db, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func configure(t *testing.T, raw map[string]config.InventorySource) []*Instance {
	t.Helper()
	inst, err := Configure(raw)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return inst
}

func TestRegisteredFakesConfigureAsPushAndPull(t *testing.T) {
	for _, want := range []string{"fake-push", "fake-pull"} {
		if !slices.Contains(Types(), want) {
			t.Errorf("Types() = %v, missing %s", Types(), want)
		}
	}
	insts := configure(t, map[string]config.InventorySource{
		"edge":   {"type": "fake-push", "enabled": true},
		"tenant": {"type": "fake-pull", "enabled": true, "tenant": "acme"},
	})
	byName := map[string]*Instance{}
	for _, i := range insts {
		byName[i.Name] = i
	}
	if byName["edge"].Source.Mode() != ModePush || byName["edge"].Interval != DefaultPushInterval {
		t.Errorf("edge = %+v, want push at the 24h expected-report default", byName["edge"])
	}
	if byName["tenant"].Source.Mode() != ModePull || byName["tenant"].Interval != DefaultPullInterval {
		t.Errorf("tenant = %+v, want pull at the 1h default", byName["tenant"])
	}
	if !HasCapability(byName["edge"].Source, CapAttempts) || HasCapability(byName["tenant"].Source, CapAttempts) {
		t.Error("capabilities not reported as declared")
	}
}

func TestConfigureErrorsNameInstanceAndKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  config.InventorySource
		want string
	}{
		{"unknown type", config.InventorySource{"type": "nope"}, "inventory_sources.x.type"},
		{"missing type", config.InventorySource{"enabled": true}, "inventory_sources.x.type"},
		{"unknown key", config.InventorySource{"type": "fake-push", "colour": "red"}, "inventory_sources.x.colour"},
		{"push interval not a duration", config.InventorySource{"type": "fake-push", "interval": "daily"}, "inventory_sources.x.interval"},
		{"type validation", config.InventorySource{"type": "fake-pull"}, "inventory_sources.x.tenant"},
		{"interval too short", config.InventorySource{"type": "fake-pull", "tenant": "a", "interval": "4m"}, "inventory_sources.x.interval"},
		{"interval not a duration", config.InventorySource{"type": "fake-pull", "tenant": "a", "interval": "hourly"}, "inventory_sources.x.interval"},
		{"enabled not a bool", config.InventorySource{"type": "fake-push", "enabled": "yes"}, "inventory_sources.x.enabled"},
		{"retention not a duration", config.InventorySource{"type": "fake-push", "retention": "90 days"}, "inventory_sources.x.retention"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Configure(map[string]config.InventorySource{"x": tc.raw})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one naming %s", err, tc.want)
			}
		})
	}
	if _, err := Configure(map[string]config.InventorySource{"Bad/Name": {"type": "fake-push"}}); err == nil {
		t.Error("an instance name that cannot sit in a URL path segment was accepted")
	}
	if insts, err := Configure(map[string]config.InventorySource{
		"x": {"type": "fake-pull", "tenant": "a", "interval": "5m"},
	}); err != nil || insts[0].Interval != MinPullInterval {
		t.Errorf("interval at the 5m floor: %v, %v", insts, err)
	}
}

// Configure is what config.Load runs on inventory_sources.
func TestConfigLoadValidatorIsInstalled(t *testing.T) {
	if config.ValidateInventorySources == nil {
		t.Fatal("importing internal/inventory did not install the config validator")
	}
	err := config.ValidateInventorySources(map[string]config.InventorySource{"x": {"type": "nope"}})
	if err == nil || !strings.Contains(err.Error(), "inventory_sources.x.type") {
		t.Errorf("validator err = %v", err)
	}
}

func push(t *testing.T, f *Frame, instance, host, vouch, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, RoutePrefix+instance+"/report", strings.NewReader(body))
	if host != "" {
		req.Header.Set("X-Host", host)
	}
	if vouch != "" {
		req.Header.Set("X-Vouch", vouch)
	}
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, req)
	return rec
}

const oneComponent = `{"components":[{"ecosystem":"pypi","name":"requests","version":"2.32.3"}]}`

func TestUnmappedHostIsStoredUnboundThenBound(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	f := NewFrame(configure(t, map[string]config.InventorySource{"edge": {"type": "fake-push", "enabled": true}}), db, nil, nil)

	if rec := push(t, f, "edge", "node-9", "", oneComponent); rec.Code != http.StatusAccepted {
		t.Fatalf("push: %d %s", rec.Code, rec.Body)
	}
	unbound, _ := db.ListUnboundInventoryHosts(ctx)
	if len(unbound) != 1 || unbound[0].ExternalID != "node-9" {
		t.Fatalf("unbound = %+v, want node-9", unbound)
	}
	if _, err := db.BindInventoryHost(ctx, "edge", "node-9", "db-02"); err != nil {
		t.Fatal(err)
	}
	if rec := push(t, f, "edge", "node-9", "", oneComponent); rec.Code != http.StatusAccepted {
		t.Fatalf("push: %d %s", rec.Code, rec.Body)
	}
	reports, _ := db.InventoryReports(ctx, "edge")
	if len(reports) != 2 || reports[0].Identity != "" || reports[1].Identity != "db-02" {
		t.Errorf("reports = %+v, want the first unbound and the second db-02", reports)
	}
}

// Identity comes from the mapping alone. A normalizer that writes one is
// ignored, and a source that vouches writes the mapping rather than the row.
func TestIdentityComesOnlyFromTheMapping(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	insts := configure(t, map[string]config.InventorySource{"edge": {"type": "fake-push", "enabled": true}})
	f := NewFrame(insts, db, nil, nil)

	forged := Batch{Reports: []Report{{ExternalID: "node-1", Identity: "root-of-all", Components: []Component{{Ecosystem: "npm", Name: "x"}}}}}
	if _, err := f.Ingest(ctx, insts[0], Principal{ExternalID: "node-1"}, forged); err != nil {
		t.Fatal(err)
	}
	if rec := push(t, f, "edge", "node-2", "web-07", oneComponent); rec.Code != http.StatusAccepted {
		t.Fatalf("push: %d %s", rec.Code, rec.Body)
	}
	reports, _ := db.InventoryReports(ctx, "edge")
	if len(reports) != 2 || reports[0].Identity != "" || reports[1].Identity != "web-07" {
		t.Errorf("reports = %+v, want node-1 unbound and node-2 as web-07", reports)
	}
	if id, _ := db.InventoryHostIdentity(ctx, "edge", "node-2"); id != "web-07" {
		t.Errorf("vouched mapping = %q, want web-07", id)
	}
}

func TestOneHostManySourcesKeepsEveryReport(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	f := NewFrame(configure(t, map[string]config.InventorySource{
		"a": {"type": "fake-push", "enabled": true},
		"b": {"type": "fake-push", "enabled": true},
	}), db, nil, nil)
	for _, inst := range []string{"a", "b"} {
		if rec := push(t, f, inst, "h", "web-01", oneComponent); rec.Code != http.StatusAccepted {
			t.Fatalf("push %s: %d", inst, rec.Code)
		}
	}
	all, _ := db.InventoryReports(ctx, "")
	if len(all) != 2 || all[0].Source == all[1].Source || all[0].Identity != "web-01" || all[1].Identity != "web-01" {
		t.Errorf("reports = %+v, want one per instance for web-01", all)
	}
}

func TestBatchOutsideDeclaredCapabilitiesIsRefused(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	insts := configure(t, map[string]config.InventorySource{"t": {"type": "fake-pull", "tenant": "a", "enabled": true}})
	f := NewFrame(insts, db, nil, nil)
	_, err := f.Ingest(ctx, insts[0], Principal{ExternalID: "h"}, Batch{Attempts: []Attempt{{Destination: "pypi.org"}}})
	var ce *ContractError
	if !errors.As(err, &ce) {
		t.Errorf("attempts from a source without the attempts capability: err = %v, want *ContractError", err)
	}
	_, err = f.Ingest(ctx, insts[0], Principal{ExternalID: "h"}, Batch{Reports: []Report{{Components: []Component{{Ecosystem: "maven", Name: "x"}}}}})
	if !errors.As(err, &ce) {
		t.Errorf("component in an unknown ecosystem: err = %v, want *ContractError", err)
	}
	if all, _ := db.InventoryReports(ctx, ""); len(all) != 0 {
		t.Errorf("a refused batch stored %d reports", len(all))
	}
}

func TestPushAttemptsAndRefusals(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	f := NewFrame(configure(t, map[string]config.InventorySource{"edge": {"type": "fake-push", "enabled": true}}), db, nil, nil)
	var refused []string
	f.OnRefusal = func(_ *http.Request, reason string, _ map[string]string) { refused = append(refused, reason) }

	if rec := push(t, f, "edge", "", "", oneComponent); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: %d, want 401", rec.Code)
	}
	if len(refused) != 1 || refused[0] != audit.DenialTokenMissing {
		t.Errorf("refusals = %v", refused)
	}
	if rec := push(t, f, "edge", "h", "", strings.Repeat("x", 2000)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("over MaxBody: %d, want 413", rec.Code)
	}
	if rec := push(t, f, "edge", "h", "", `{"attempts":[{"destination":"registry.npmjs.org","ecosystem":"npm"}]}`); rec.Code != http.StatusAccepted {
		t.Errorf("attempt push: %d %s", rec.Code, rec.Body)
	}
	attempts, _ := db.InventoryAttempts(ctx, "edge")
	if len(attempts) != 1 || attempts[0].ExternalID != "h" || attempts[0].Destination != "registry.npmjs.org" {
		t.Errorf("attempts = %+v", attempts)
	}
}

func TestPushRouteMatchesOnlyEnabledRegisteredRoutes(t *testing.T) {
	f := NewFrame(configure(t, map[string]config.InventorySource{
		"on":   {"type": "fake-push", "enabled": true},
		"off":  {"type": "fake-push"},
		"poll": {"type": "fake-pull", "tenant": "a", "enabled": true},
	}), nil, nil, nil)
	for path, want := range map[string]bool{
		RoutePrefix + "on/report":    true,
		RoutePrefix + "off/report":   false,
		RoutePrefix + "poll/report":  false,
		RoutePrefix + "on/report/x":  false,
		RoutePrefix + "on/":          false,
		RoutePrefix + "nope/report":  false,
		"/api/v1/packages/on/report": false,
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if _, _, got := f.PushRoute(req); got != want {
			t.Errorf("PushRoute(POST %s) = %v, want %v", path, got, want)
		}
	}
	req := httptest.NewRequest(http.MethodGet, RoutePrefix+"on/report", nil)
	if _, _, ok := f.PushRoute(req); ok {
		t.Error("PushRoute matched a GET on a POST route")
	}
}

// syncBuffer lets the poll goroutine log while the test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A failed poll is logged with the instance and the upstream's error, and
// the next attempt waits a full interval. The success after it is recorded
// for the staleness check.
func TestPullFailureIsLoggedAndRetriedAtTheNextInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := openDB(t)
	insts := configure(t, map[string]config.InventorySource{"tenant-a": {"type": "fake-pull", "tenant": "a", "enabled": true}})
	const interval = 40 * time.Millisecond
	insts[0].Interval = interval
	src := insts[0].Source.(*fakePull)

	var mu sync.Mutex
	var calls []time.Time
	done := make(chan struct{})
	src.poll = func() ([]Document, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, time.Now())
		switch len(calls) {
		case 1:
			return nil, errors.New("upstream said 503 Service Unavailable")
		case 2:
			close(done)
			return []Document{{ExternalID: "host-1", Body: []byte(oneComponent)}}, nil
		}
		return nil, nil
	}

	var logs syncBuffer
	f := NewFrame(insts, db, nil, slog.New(slog.NewTextHandler(&logs, nil)))
	var jitterArg time.Duration
	f.jitter = func(d time.Duration) time.Duration { jitterArg = d; return 0 }
	go f.Run(ctx)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("second poll never ran")
	}

	if jitterArg != interval {
		t.Errorf("start jitter drawn over %s, want the instance interval %s", jitterArg, interval)
	}
	mu.Lock()
	gap := calls[1].Sub(calls[0])
	mu.Unlock()
	if gap < interval {
		t.Errorf("retry came %s after the failure, want at least the %s interval", gap, interval)
	}
	out := logs.String()
	if !strings.Contains(out, "instance=tenant-a") || !strings.Contains(out, "upstream said 503") {
		t.Errorf("failure log %q does not name the instance and the upstream error", out)
	}

	// Run records the success after the poll returns, so wait for it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := db.InventorySourceStats(context.Background(), "tenant-a")
		if err == nil && !st.LastSuccess.IsZero() && st.LastError == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("last success never recorded: %+v %v", st, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if reports, _ := db.InventoryReports(context.Background(), "tenant-a"); len(reports) != 1 {
		t.Errorf("reports = %d, want the second poll's one", len(reports))
	}
}

func TestDefaultJitterStaysInsideTheInterval(t *testing.T) {
	f := NewFrame(nil, nil, nil, nil)
	for range 1000 {
		if j := f.jitter(time.Hour); j < 0 || j >= time.Hour {
			t.Fatalf("jitter %s outside [0, 1h)", j)
		}
	}
}

func TestRetentionIsOffByDefault(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	insts := configure(t, map[string]config.InventorySource{
		"keep": {"type": "fake-push", "enabled": true},
		"trim": {"type": "fake-push", "enabled": true, "retention": "24h"},
	})
	if insts[0].Retention != 0 {
		t.Fatalf("retention with no key = %s, want off", insts[0].Retention)
	}
	f := NewFrame(insts, db, nil, nil)
	old := time.Now().Add(-48 * time.Hour)
	for _, inst := range insts {
		f.now = func() time.Time { return old }
		if _, err := f.Ingest(ctx, inst, Principal{ExternalID: "h"}, Batch{Reports: []Report{{}}}); err != nil {
			t.Fatal(err)
		}
	}
	f.now = time.Now
	f.Prune(ctx)
	keep, _ := db.InventoryReports(ctx, "keep")
	trim, _ := db.InventoryReports(ctx, "trim")
	if len(keep) != 1 || len(trim) != 0 {
		t.Errorf("after prune: keep=%d trim=%d, want 1 and 0", len(keep), len(trim))
	}
}

// config.Load is where a bad inventory_sources entry stops the process.
func TestConfigLoadStopsOnABadInstance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv(config.EnvConfigFile, path)
	t.Setenv(config.EnvBucket, "")
	t.Setenv(config.EnvRegion, "")
	t.Setenv(config.EnvBuildRoot, "")
	t.Setenv(config.EnvListenAddr, "")
	for body, want := range map[string]string{
		`{"inventory_sources":{"edge":{"type":"fake-push","enabled":true,"colour":"red"}}}`: "inventory_sources.edge.colour",
		`{"inventory_sources":{"edge":{"type":"no-such-type"}}}`:                            "inventory_sources.edge.type",
		`{"inventory_sources":{"tenant-b":{"type":"fake-pull","interval":"1h"}}}`:           "inventory_sources.tenant-b.tenant",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := config.Load(dir, "", "", "", false, false)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Load(%s) = %v, want an error naming %s", body, err, want)
		}
	}
}
