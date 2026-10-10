package osquery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
)

const testPepper = "test-pepper"

type refusal struct {
	reason  string
	details map[string]string
}

type harness struct {
	t        *testing.T
	db       *audit.DB
	frame    *inventory.Frame
	src      *Source
	instance string

	mu      sync.Mutex
	refused []refusal
	dirs    map[string]config.OsqueryDirs
}

type stubCreds struct {
	tok inventory.Token
	err error
}

func (s stubCreds) Token(*http.Request) (inventory.Token, error) { return s.tok, s.err }

func newHarness(t *testing.T, raw config.InventorySource, creds inventory.Credentials) *harness {
	t.Helper()
	db, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	insts, err := inventory.Configure(map[string]config.InventorySource{"osq": raw})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	h := &harness{t: t, db: db, instance: "osq", src: insts[0].Source.(*Source), dirs: map[string]config.OsqueryDirs{}}
	h.src.SetScanDirs(func(identity string) config.OsqueryDirs {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.dirs[identity]
	})
	h.frame = inventory.NewFrame(insts, db, creds, nil)
	h.frame.HashSecret = func(s string) (string, error) { return audit.HashToken(s, testPepper), nil }
	h.frame.OnRefusal = func(_ *http.Request, reason string, details map[string]string) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.refused = append(h.refused, refusal{reason, details})
	}
	return h
}

func serverHarness(t *testing.T) *harness {
	return newHarness(t, config.InventorySource{"type": TypeName, "enabled": true, "mode": ModeServer, "interval": "30m", "max_body_bytes": float64(4096)}, nil)
}

func (h *harness) post(route, body string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPost, inventory.RoutePrefix+h.instance+"/"+route, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.frame.ServeHTTP(rec, req)
	return rec
}

func (h *harness) secret(id, identity string, expires *time.Time) string {
	h.t.Helper()
	secret := "bodega_es_" + id
	if err := h.db.InsertOsquerySecret(context.Background(), audit.OsquerySecret{
		ID: id, Source: h.instance, Label: id, Identity: identity, ExpiresAt: expires,
	}, audit.HashToken(secret, testPepper)); err != nil {
		h.t.Fatal(err)
	}
	return secret
}

func (h *harness) lastRefusal() refusal {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.refused) == 0 {
		h.t.Fatal("no refusal recorded")
	}
	return h.refused[len(h.refused)-1]
}

func (h *harness) refusals() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.refused)
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response %d %q is not JSON: %v", rec.Code, rec.Body.String(), err)
	}
	return out
}

func (h *harness) enroll(secret string) string {
	h.t.Helper()
	rec := h.post(RouteEnroll, `{"enroll_secret":"`+secret+`","host_identifier":"web-01.example","host_details":{"os_version":{"name":"Ubuntu"}}}`)
	out := decode(h.t, rec)
	key, _ := out["node_key"].(string)
	if rec.Code != http.StatusOK || out["node_invalid"] != false || len(key) != 64 {
		h.t.Fatalf("enroll = %d %v, want a 64-hex node_key", rec.Code, out)
	}
	return key
}

func TestSettings(t *testing.T) {
	for want, raw := range map[string]config.InventorySource{
		"inventory_sources.osq.mode":           {"type": TypeName},
		"inventory_sources.osq.interval":       {"type": TypeName, "mode": ModeServer, "interval": "30s"},
		"inventory_sources.osq.max_body_bytes": {"type": TypeName, "mode": ModeShipper, "max_body_bytes": float64(0)},
		"inventory_sources.osq.colour":         {"type": TypeName, "mode": ModeServer, "colour": "red"},
	} {
		if _, err := inventory.Configure(map[string]config.InventorySource{"osq": raw}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want one naming %s", err, want)
		}
	}
	if _, err := inventory.Configure(map[string]config.InventorySource{"osq": {"type": TypeName, "mode": "A"}}); err == nil {
		t.Error("a mode other than server or shipper was accepted")
	}
	insts, err := inventory.Configure(map[string]config.InventorySource{
		"a": {"type": TypeName, "mode": ModeServer},
		"b": {"type": TypeName, "mode": ModeShipper},
	})
	if err != nil {
		t.Fatal(err)
	}
	paths := func(src inventory.Source) []string {
		var out []string
		for _, r := range src.(inventory.PushSource).Routes() {
			out = append(out, r.Path)
		}
		return out
	}
	if got := paths(insts[0].Source); !reflect.DeepEqual(got, []string{RouteEnroll, RouteConfig, RouteLog}) {
		t.Errorf("server routes = %v", got)
	}
	if got := paths(insts[1].Source); !reflect.DeepEqual(got, []string{RouteResults}) {
		t.Errorf("shipper routes = %v", got)
	}
	if insts[0].Source.(*Source).Interval() != DefaultInterval {
		t.Errorf("interval default = %s", insts[0].Source.(*Source).Interval())
	}
}

// Requirement 2: a valid secret yields a fresh key and the host mapping;
// everything else yields one indistinguishable node_invalid answer, with the
// failed check in the refusal.
func TestEnroll(t *testing.T) {
	h := serverHarness(t)
	ctx := context.Background()
	secret := h.secret("s1", "web-01", nil)

	key := h.enroll(secret)
	id, err := h.db.InventoryHostIdentity(ctx, h.instance, KeyDigest(key))
	if err != nil || id != "web-01" {
		t.Errorf("mapping for the key's sha256 = %q, %v; want web-01", id, err)
	}
	if again := h.enroll(secret); again == key {
		t.Error("a second enrollment returned the same node_key")
	}

	past := time.Now().Add(-time.Hour)
	expired := h.secret("s2", "web-02", &past)
	other := newHarness(t, config.InventorySource{"type": TypeName, "enabled": true, "mode": ModeServer}, nil)
	otherSecret := other.secret("s3", "web-03", nil)

	var bodies []string
	for _, tc := range []struct {
		name, body, reason, check string
	}{
		{"unknown secret", `{"enroll_secret":"bodega_es_nope","host_identifier":"x"}`, audit.DenialTokenInvalid, "unknown or revoked secret"},
		{"expired secret", `{"enroll_secret":"` + expired + `"}`, audit.DenialTokenExpired, "secret expired"},
		{"another instance's secret", `{"enroll_secret":"` + otherSecret + `"}`, audit.DenialTokenInvalid, "unknown or revoked secret"},
		{"no secret", `{"host_identifier":"x"}`, audit.DenialTokenMissing, "no secret presented"},
		{"malformed", `{"enroll_secret":`, audit.DenialTokenMissing, "malformed request"},
	} {
		rec := h.post(RouteEnroll, tc.body)
		if rec.Code != http.StatusOK || decode(t, rec)["node_invalid"] != true {
			t.Errorf("%s: %d %s, want 200 node_invalid", tc.name, rec.Code, rec.Body.String())
		}
		bodies = append(bodies, rec.Body.String())
		r := h.lastRefusal()
		if r.reason != tc.reason || r.details["check"] != tc.check || r.details["instance"] != h.instance {
			t.Errorf("%s: refusal = %+v, want reason %s check %q", tc.name, r, tc.reason, tc.check)
		}
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Errorf("responses differ between failed checks: %q vs %q", b, bodies[0])
		}
	}

	h.frame.HashSecret = nil
	if rec := h.post(RouteEnroll, `{"enroll_secret":"`+secret+`"}`); decode(t, rec)["node_invalid"] != true {
		t.Errorf("enroll with no pepper loaded = %s", rec.Body.String())
	}
}

// Requirement 1's revoke, as the protocol sees it: the secret stops
// enrolling and every key it handed out stops working.
func TestRevokedSecret(t *testing.T) {
	h := serverHarness(t)
	ctx := context.Background()
	secret := h.secret("s1", "web-01", nil)
	keep := h.secret("s2", "web-02", nil)
	k1, k2 := h.enroll(secret), h.enroll(secret)
	survivor := h.enroll(keep)

	sec, nodes, err := h.db.RevokeOsquerySecret(ctx, "s1")
	if err != nil || nodes != 2 || sec.Identity != "web-01" {
		t.Fatalf("revoke = %+v, %d, %v; want web-01 with 2 nodes", sec, nodes, err)
	}
	if _, _, err := h.db.RevokeOsquerySecret(ctx, "s1"); err != audit.ErrNoOsquerySecret {
		t.Errorf("second revoke err = %v", err)
	}
	if rec := h.post(RouteEnroll, `{"enroll_secret":"`+secret+`"}`); decode(t, rec)["node_invalid"] != true {
		t.Errorf("enroll with a revoked secret = %s", rec.Body.String())
	}
	for _, k := range []string{k1, k2} {
		for _, route := range []string{RouteConfig, RouteLog} {
			rec := h.post(route, `{"node_key":"`+k+`","log_type":"status","data":[]}`)
			if decode(t, rec)["node_invalid"] != true {
				t.Errorf("%s with a revoked node_key = %s", route, rec.Body.String())
			}
		}
	}
	if rec := h.post(RouteConfig, `{"node_key":"`+survivor+`"}`); decode(t, rec)["schedule"] == nil {
		t.Errorf("a key from another secret stopped working: %s", rec.Body.String())
	}
	rows, err := h.db.ListOsquerySecrets(ctx)
	if err != nil || len(rows) != 1 || rows[0].ID != "s2" || rows[0].Nodes != 1 {
		t.Errorf("secrets after revoke = %+v, %v", rows, err)
	}
}

// Requirement 3.
func TestConfigSchedule(t *testing.T) {
	h := serverHarness(t)
	key := h.enroll(h.secret("s1", "web-01", nil))

	forged := strings.Repeat("ab", 32)
	before := h.refusals()
	rec := h.post(RouteConfig, `{"node_key":"`+forged+`"}`)
	if decode(t, rec)["node_invalid"] != true || h.refusals() != before+1 || h.lastRefusal().details["credential"] != "node_key" {
		t.Errorf("forged node_key: %s, refusal %+v", rec.Body.String(), h.lastRefusal())
	}

	var atc map[string]AutoTable
	schedule := func() map[string]Query {
		t.Helper()
		rec := h.post(RouteConfig, `{"node_key":"`+key+`"}`)
		var out struct {
			Schedule    map[string]Query     `json:"schedule"`
			ATC         map[string]AutoTable `json:"auto_table_construction"`
			NodeInvalid *bool                `json:"node_invalid"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("config = %d %s", rec.Code, rec.Body.String())
		}
		atc = out.ATC
		return out.Schedule
	}
	first := schedule()
	lin, fbsd := first[QueryLinux], first[QueryFreeBSD]
	if lin.Interval != 1800 || !lin.Snapshot || lin.Platform != "linux" || fbsd.Platform != "freebsd" {
		t.Errorf("schedule = %+v", first)
	}
	for _, table := range []string{"deb_packages", "rpm_packages"} {
		if !strings.Contains(lin.Query, table) {
			t.Errorf("linux query lacks %s: %s", table, lin.Query)
		}
	}
	// The filter rides on the schedule a host fetches every config_refresh,
	// so a host enrolled before it existed gets it on its next fetch with the
	// key it already holds: no re-enrollment.
	if !strings.Contains(lin.Query, "FROM deb_packages WHERE status = 'install ok installed'") {
		t.Errorf("linux query reads removed packages too: %s", lin.Query)
	}
	// osquery's FreeBSD build registers no pkg_packages table (#100): the
	// query reads the table the config mounts over pkg's own database.
	pkg := atc[TableFreeBSDPkg]
	if pkg.Path != "/var/db/pkg/local.sqlite" || pkg.Platform != "freebsd" || !strings.Contains(pkg.Query, "FROM packages") ||
		!reflect.DeepEqual(pkg.Columns, []string{"name", "version"}) {
		t.Errorf("config's auto_table_construction = %+v, want %s over pkg's local.sqlite on freebsd", atc, TableFreeBSDPkg)
	}
	if !strings.Contains(fbsd.Query, "FROM "+TableFreeBSDPkg) || strings.Contains(fbsd.Query, "FROM pkg_packages") {
		t.Errorf("freebsd query does not read %s: %s", TableFreeBSDPkg, fbsd.Query)
	}
	if strings.Contains(lin.Query, "python_packages") || strings.Contains(lin.Query, "npm_packages") {
		t.Errorf("with no declared trees the schedule still scans language packages: %s", lin.Query)
	}
	if again := schedule(); !reflect.DeepEqual(first, again) {
		t.Error("the schedule changed with no change to the plan")
	}

	h.mu.Lock()
	h.dirs["web-01"] = config.OsqueryDirs{Python: []string{"/opt/b", "/opt/a", "/opt/a"}, NPM: []string{"/srv/app"}}
	h.mu.Unlock()
	changed := schedule()
	q := changed[QueryLinux].Query
	if !strings.Contains(q, "FROM python_packages WHERE directory IN ('/opt/a', '/opt/b')") ||
		!strings.Contains(q, "FROM npm_packages WHERE directory IN ('/srv/app')") ||
		!strings.Contains(changed[QueryFreeBSD].Query, "python_packages") {
		t.Errorf("declared trees not scheduled as sorted, deduplicated IN lists: %s", q)
	}
	if reflect.DeepEqual(first, changed) {
		t.Error("the schedule did not change when the plan did")
	}
}

func TestScheduleQuotesDirectories(t *testing.T) {
	s := Schedule(config.OsqueryDirs{Python: []string{"/opt/it's"}}, time.Hour)
	if !strings.Contains(s[QueryLinux].Query, "('/opt/it''s')") {
		t.Errorf("a quote reached the query undoubled: %s", s[QueryLinux].Query)
	}
}

const snapshotEvent = `{"name":"pack_bodega_bodega_packages_linux","hostIdentifier":"claimed-elsewhere","unixTime":1791500000,"action":"snapshot","snapshot":[
 {"ecosystem":"apt","name":"curl","version":"8.5.0-2ubuntu10","path":""},
 {"ecosystem":"rpm","name":"bash","version":"5.2-1","path":""},
 {"ecosystem":"pypi","name":"requests","version":"2.32.3","path":"/opt/a/requests-2.32.3.dist-info/"},
 {"ecosystem":"npm","name":"lodash","version":"4.17.21","path":"/srv/app/node_modules/lodash"},
 {"ecosystem":"freebsd","name":"nginx","version":"1.26.2","path":""},
 {"ecosystem":"apt","name":"","version":"1"}
]}`

// Requirement 4.
func TestLogResults(t *testing.T) {
	h := serverHarness(t)
	ctx := context.Background()
	key := h.enroll(h.secret("s1", "web-01", nil))

	other := `{"name":"someone_elses_query","hostIdentifier":"x","action":"snapshot","snapshot":[{"name":"x"}]}`
	diff := `{"name":"bodega_packages_linux","hostIdentifier":"x","action":"added","columns":{"name":"x"}}`
	rec := h.post(RouteLog, `{"node_key":"`+key+`","log_type":"result","data":[`+snapshotEvent+`,`+other+`,`+diff+`]}`)
	if rec.Code != http.StatusOK || decode(t, rec)["node_invalid"] != nil {
		t.Fatalf("log result = %d %s", rec.Code, rec.Body.String())
	}
	reps, err := h.db.InventoryReports(ctx, h.instance)
	if err != nil || len(reps) != 1 {
		t.Fatalf("reports = %+v, %v; want one per snapshot run", reps, err)
	}
	r := reps[0]
	if r.ExternalID != KeyDigest(key) || r.Identity != "web-01" || !r.ObservedAt.Equal(time.Unix(1791500000, 0)) {
		t.Errorf("report header = %+v; want the key's sha256, its identity and the event's unixTime", r)
	}
	got := map[string]audit.InventoryComponent{}
	for _, c := range r.Components {
		got[c.Name] = c
	}
	want := map[string]string{"curl": "apt", "bash": inventory.EcosystemOther, "requests": "pypi", "lodash": "npm", "nginx": "freebsd"}
	if len(got) != len(want) {
		t.Errorf("components = %+v", r.Components)
	}
	for name, eco := range want {
		if got[name].Ecosystem != eco {
			t.Errorf("%s ecosystem = %q, want %q", name, got[name].Ecosystem, eco)
		}
	}
	if got["bash"].PURL != "pkg:rpm/bash@5.2-1" || got["requests"].Path != "/opt/a/requests-2.32.3.dist-info/" {
		t.Errorf("rpm purl or python path lost: %+v %+v", got["bash"], got["requests"])
	}

	rec = h.post(RouteLog, `{"node_key":"`+key+`","log_type":"status","data":[{"severity":"0","message":"osqueryd started"}]}`)
	if rec.Code != http.StatusOK {
		t.Errorf("log status = %d %s", rec.Code, rec.Body.String())
	}
	if reps, _ := h.db.InventoryReports(ctx, h.instance); len(reps) != 1 {
		t.Errorf("a status line was stored: %d reports", len(reps))
	}

	if rec := h.post(RouteLog, `{"node_key":"`+key+`","log_type":"bogus","data":[]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown log_type = %d", rec.Code)
	}
	before := h.refusals()
	rec = h.post(RouteLog, `{"node_key":"`+strings.Repeat("0", 64)+`","log_type":"result","data":[`+snapshotEvent+`]}`)
	if decode(t, rec)["node_invalid"] != true || h.refusals() != before+1 || h.lastRefusal().reason != audit.DenialTokenInvalid {
		t.Errorf("unknown key on log = %s, refusals %d", rec.Body.String(), h.refusals()-before)
	}
	if reps, _ := h.db.InventoryReports(ctx, h.instance); len(reps) != 1 {
		t.Errorf("a forged key's results were stored: %d reports", len(reps))
	}
}

func TestOversizeBodies(t *testing.T) {
	h := serverHarness(t)
	big := `{"node_key":"x","log_type":"result","data":["` + strings.Repeat("a", 8192) + `"]}`
	if rec := h.post(RouteLog, big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("log over max_body_bytes = %d", rec.Code)
	}
	huge := `{"enroll_secret":"` + strings.Repeat("a", 70<<10) + `"}`
	if rec := h.post(RouteEnroll, huge); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("enroll over the control cap = %d", rec.Code)
	}
	// No Content-Length: the cap holds on a streamed body too.
	req := httptest.NewRequest(http.MethodPost, inventory.RoutePrefix+"osq/"+RouteConfig, strings.NewReader(huge))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.frame.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("streamed config over the cap = %d", rec.Code)
	}

	b := newHarness(t, config.InventorySource{"type": TypeName, "enabled": true, "mode": ModeShipper, "max_body_bytes": float64(1024)},
		stubCreds{tok: inventory.Token{ID: "t", Scope: audit.ScopeInventory}})
	if rec := b.post(RouteResults, strings.Repeat(snapshotEvent+"\n", 4)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("results over max_body_bytes = %d", rec.Code)
	}
}

// Requirement 5: same normalizer, the line names its host, and the host
// table decides the identity.
func TestShippedResults(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, config.InventorySource{"type": TypeName, "enabled": true, "mode": ModeShipper},
		stubCreds{tok: inventory.Token{ID: "t", Scope: audit.ScopeInventory}})
	if err := func() error { _, err := h.db.BindInventoryHost(ctx, h.instance, "db-01", "database-01"); return err }(); err != nil {
		t.Fatal(err)
	}
	mapped := strings.Replace(snapshotEvent, "claimed-elsewhere", "db-01", 1)
	unmapped := strings.Replace(snapshotEvent, "claimed-elsewhere", "new-host", 1)
	noise := `{"name":"fleet_uptime","hostIdentifier":"db-01","action":"snapshot","snapshot":[{"uptime":"1"}]}`
	rec := h.post(RouteResults, mapped+"\n"+noise+"\n"+unmapped+"\n")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("results = %d %s", rec.Code, rec.Body.String())
	}
	if out := decode(t, rec); out["reports"] != float64(2) || out["unbound"] != float64(1) {
		t.Errorf("ingest result = %v, want 2 reports with 1 unbound", out)
	}
	reps, err := h.db.InventoryReports(ctx, h.instance)
	if err != nil || len(reps) != 2 {
		t.Fatalf("reports = %+v, %v", reps, err)
	}
	byHost := map[string]audit.InventoryReport{}
	for _, r := range reps {
		byHost[r.ExternalID] = r
	}
	if byHost["db-01"].Identity != "database-01" || byHost["new-host"].Identity != "" {
		t.Errorf("identities = %q / %q; want the mapping's and unbound", byHost["db-01"].Identity, byHost["new-host"].Identity)
	}

	// The mode A code path produces the same components for the same event.
	viaA, err := normalize([]event{mustEvent(t, snapshotEvent)}, "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(viaA.Reports[0].Components) != len(byHost["db-01"].Components) {
		t.Errorf("server and shipper paths disagree: %d vs %d components", len(viaA.Reports[0].Components), len(byHost["db-01"].Components))
	}

	nameless := strings.Replace(snapshotEvent, `"hostIdentifier":"claimed-elsewhere",`, "", 1)
	if rec := h.post(RouteResults, nameless+"\n"); rec.Code != http.StatusBadRequest {
		t.Errorf("a bodega line with no hostIdentifier = %d", rec.Code)
	}
	if rec := h.post(RouteResults, "{not json\n"); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed NDJSON = %d", rec.Code)
	}

	full := newHarness(t, config.InventorySource{"type": TypeName, "enabled": true, "mode": ModeShipper},
		stubCreds{tok: inventory.Token{ID: "t", Scope: audit.ScopeFull}})
	if rec := full.post(RouteResults, mapped+"\n"); rec.Code != http.StatusForbidden || full.lastRefusal().reason != audit.DenialTokenScope {
		t.Errorf("full-scope token on results = %d", rec.Code)
	}
	bad := newHarness(t, config.InventorySource{"type": TypeName, "enabled": true, "mode": ModeShipper},
		stubCreds{err: &inventory.AuthError{Status: http.StatusUnauthorized, Reason: audit.DenialTokenInvalid, Message: "token not recognized"}})
	if rec := bad.post(RouteResults, mapped+"\n"); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown token on results = %d", rec.Code)
	}
	if rec := h.post(RouteEnroll, `{}`); rec.Code != http.StatusNotFound {
		t.Errorf("a shipper instance answered enroll: %d", rec.Code)
	}
}

func mustEvent(t *testing.T, s string) event {
	t.Helper()
	var ev event
	if err := json.Unmarshal([]byte(s), &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}
