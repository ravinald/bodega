package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/inventory/cyclonedx"
	"github.com/ravinald/bodega/internal/manifest"
)

// The second sources are fakes on purpose: nothing here may depend on one
// vendor. "fake-agent" is a push source that sees only apt, standing in for a
// collector with declared coverage; "fake-vendor" is a pull source that sees
// everything.
func init() {
	inventory.Register("fake-agent", func(string, *inventory.Settings) (inventory.Source, error) { return fakeAgent{}, nil })
	inventory.Register("fake-vendor", func(string, *inventory.Settings) (inventory.Source, error) { return &fakeVendor{}, nil })
}

type fakeAgent struct{}

func (fakeAgent) Type() string         { return "fake-agent" }
func (fakeAgent) Mode() inventory.Mode { return inventory.ModePush }
func (fakeAgent) Capabilities() []inventory.Capability {
	return []inventory.Capability{inventory.CapInventory}
}
func (fakeAgent) Routes() []inventory.Route {
	return []inventory.Route{{Method: http.MethodPost, Path: "report"}}
}
func (fakeAgent) Authenticate(*http.Request, inventory.Credentials) (inventory.Principal, error) {
	return inventory.Principal{}, nil
}
func (fakeAgent) Normalize(doc []byte, ext string) (inventory.Batch, error) {
	return normalizeJSON(doc, ext)
}
func (fakeAgent) Covers(_, ecosystem string) bool { return ecosystem == manifest.TypeApt }

type fakeVendor struct {
	mu   sync.Mutex
	docs []inventory.Document
}

func (*fakeVendor) Type() string         { return "fake-vendor" }
func (*fakeVendor) Mode() inventory.Mode { return inventory.ModePull }
func (*fakeVendor) Capabilities() []inventory.Capability {
	return []inventory.Capability{inventory.CapInventory}
}
func (v *fakeVendor) Poll(context.Context) ([]inventory.Document, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.docs, nil
}
func (*fakeVendor) Normalize(doc []byte, ext string) (inventory.Batch, error) {
	return normalizeJSON(doc, ext)
}

func normalizeJSON(doc []byte, ext string) (inventory.Batch, error) {
	var cs []inventory.Component
	if err := json.Unmarshal(doc, &cs); err != nil {
		return inventory.Batch{}, err
	}
	return inventory.Batch{Reports: []inventory.Report{{ExternalID: ext, Components: cs}}}, nil
}

const (
	digA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type harness struct {
	t     *testing.T
	ctx   context.Context
	db    *audit.DB
	store *manifest.Store
	insts map[string]*inventory.Instance
	frame *inventory.Frame
	rc    *Reconciler
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	insts, err := inventory.Configure(map[string]config.InventorySource{
		"cdx":    {"type": cyclonedx.TypeName, "enabled": true, "interval": "1h"},
		"agent":  {"type": "fake-agent", "enabled": true, "interval": "1h"},
		"vendor": {"type": "fake-vendor", "enabled": true, "interval": "1h"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, ctx: context.Background(), db: db, store: manifest.NewLocalStore(t.TempDir()), insts: map[string]*inventory.Instance{}}
	for _, i := range insts {
		h.insts[i.Name] = i
	}
	h.rc = &Reconciler{DB: db, Catalog: h.store, Instances: insts}
	h.frame = inventory.NewFrame(insts, db, nil, nil)
	h.frame.OnReport = h.rc.Ingested
	return h
}

// bom posts a CycloneDX document for identity through the cyclonedx source's
// own normalizer and the frame, the path a host's push takes.
func (h *harness) bom(identity string, comps ...string) audit.InventoryReport {
	h.t.Helper()
	doc := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[%s]}`, strings.Join(comps, ","))
	b, err := h.insts["cdx"].Source.Normalize([]byte(doc), identity)
	if err != nil {
		h.t.Fatalf("normalize: %v", err)
	}
	if _, err := h.frame.Ingest(h.ctx, h.insts["cdx"], inventory.Principal{ExternalID: identity, Identity: identity}, b); err != nil {
		h.t.Fatalf("ingest: %v", err)
	}
	return h.latest(identity, "cdx")
}

func purl(purl, name, version, sha256 string) string {
	hashes := ""
	if sha256 != "" {
		hashes = fmt.Sprintf(`,"hashes":[{"alg":"SHA-256","content":%q}]`, sha256)
	}
	return fmt.Sprintf(`{"name":%q,"version":%q,"purl":%q%s}`, name, version, purl, hashes)
}

// agent posts a report through the fake push source for the host mapped as
// external id ext.
func (h *harness) agent(ext string, comps ...inventory.Component) {
	h.t.Helper()
	b, _ := json.Marshal(comps)
	batch, err := h.insts["agent"].Source.Normalize(b, ext)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.frame.Ingest(h.ctx, h.insts["agent"], inventory.Principal{ExternalID: ext}, batch); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) bind(source, ext, identity string) {
	h.t.Helper()
	if _, err := h.db.BindInventoryHost(h.ctx, source, ext, identity); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) served(identity, typ, name, version, key, digest string) {
	h.t.Helper()
	if err := h.db.Record(h.ctx, audit.Event{EventType: audit.EventServeFetch, PkgType: typ, PkgName: name,
		PkgVersion: version, Identity: identity, ObjectKey: key, Digest: digest, Status: "success"}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) catalog(typ, name string, ves ...manifest.VersionEntry) {
	h.t.Helper()
	if err := h.store.SavePackage(h.ctx, &manifest.PackageManifest{Name: name, Type: typ, Versions: ves}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) latest(identity, source string) audit.InventoryReport {
	h.t.Helper()
	reps, err := h.db.LatestInventoryReports(h.ctx, identity)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, r := range reps {
		if r.Source == source {
			return r
		}
	}
	h.t.Fatalf("no %s report for %s", source, identity)
	return audit.InventoryReport{}
}

func (h *harness) classesOf(rep audit.InventoryReport) map[string]audit.ClassifiedComponent {
	h.t.Helper()
	cls, err := h.db.InventoryClassifications(h.ctx, []int64{rep.ID})
	if err != nil {
		h.t.Fatal(err)
	}
	c, ok := cls[rep.ID]
	if !ok {
		h.t.Fatalf("report %d was not classified on ingest", rep.ID)
	}
	out := map[string]audit.ClassifiedComponent{}
	for _, cc := range c.Components {
		out[cc.Name+"@"+cc.Version] = cc
	}
	return out
}

func wantClass(t *testing.T, got map[string]audit.ClassifiedComponent, comp, class, reasonPart string) {
	t.Helper()
	cc, ok := got[comp]
	if !ok {
		t.Errorf("%s: not in the classification", comp)
		return
	}
	if cc.Class != class || !strings.Contains(cc.Reason, reasonPart) {
		t.Errorf("%s = %s (%s), want %s with a reason naming %q", comp, cc.Class, cc.Reason, class, reasonPart)
	}
}

func (h *harness) events(status string) []audit.StoredEvent {
	h.t.Helper()
	evs, err := h.db.Query(h.ctx, audit.Filter{EventType: audit.EventInventory, Limit: 100})
	if err != nil {
		h.t.Fatal(err)
	}
	var out []audit.StoredEvent
	for _, e := range evs {
		if e.Status == status {
			out = append(out, e)
		}
	}
	return out
}

// Each class, from fixture reports and audit rows alone.
func TestEveryClassFromFixtures(t *testing.T) {
	h := newHarness(t)
	h.served("web-01", "npm", "left-pad", "1.3.0", "npm/left-pad/left-pad-1.3.0.tgz", digA)
	h.served("build-07", "npm", "is-odd", "3.0.1", "npm/is-odd/is-odd-3.0.1.tgz", "")
	h.catalog(manifest.TypeNpm, "is-even", manifest.VersionEntry{Version: "1.0.0", Mode: manifest.ModeProxy})
	h.catalog(manifest.TypeNpm, "quarantined", manifest.VersionEntry{Version: "2.0.0", Hidden: true})
	if err := h.db.RecordAdmission(h.ctx, audit.Admission{PkgType: "npm", PkgName: "evil", PkgVersion: "6.6.6",
		Decision: audit.AdmissionPolicyBlocked, Checks: []audit.AdmissionCheck{{Check: audit.CheckOSV, Action: "block", Status: audit.CheckBlock}}}); err != nil {
		t.Fatal(err)
	}

	rep := h.bom("web-01",
		purl("pkg:npm/left-pad@1.3.0", "left-pad", "1.3.0", digA),
		purl("pkg:npm/is-odd@3.0.1", "is-odd", "3.0.1", ""),
		purl("pkg:npm/is-even@1.0.0", "is-even", "1.0.0", ""),
		purl("pkg:npm/quarantined@2.0.0", "quarantined", "2.0.0", ""),
		purl("pkg:npm/evil@6.6.6", "evil", "6.6.6", ""),
		purl("pkg:npm/sideload@0.1.0", "sideload", "0.1.0", ""),
		purl("pkg:generic/firmware@9", "firmware", "9", ""),
	)
	got := h.classesOf(rep)
	wantClass(t, got, "left-pad@1.3.0", ClassServed, "served left-pad@1.3.0 to web-01")
	wantClass(t, got, "is-odd@3.0.1", ClassUnattributed, "never to web-01")
	wantClass(t, got, "is-even@1.0.0", ClassUnattributed, "cataloged")
	wantClass(t, got, "quarantined@2.0.0", ClassRefused, "hidden")
	wantClass(t, got, "evil@6.6.6", ClassRefused, "policy_blocked")
	wantClass(t, got, "sideload@0.1.0", ClassUnknown, "no catalog entry and no serve_fetch row")
	wantClass(t, got, "firmware@9", ClassUnknown, `no "other" packages`)

	// Requirement 7: one event naming the identity, the report and the counts.
	evs := h.events(audit.InventoryBypass)
	if len(evs) != 1 {
		t.Fatalf("bypass events = %d, want 1", len(evs))
	}
	var details struct {
		ReportID int64          `json:"report_id"`
		Counts   map[string]int `json:"counts"`
	}
	if err := json.Unmarshal([]byte(evs[0].Details), &details); err != nil {
		t.Fatal(err)
	}
	if evs[0].Identity != "web-01" || details.ReportID != rep.ID || details.Counts[ClassRefused] != 2 || details.Counts[ClassUnknown] != 2 {
		t.Errorf("bypass event = identity %q details %s, want web-01, report %d, 2 refused and 2 unknown", evs[0].Identity, evs[0].Details, rep.ID)
	}
}

// Same name, different bytes is what a bypass looks like.
func TestDigestMismatchIsUnknown(t *testing.T) {
	h := newHarness(t)
	h.served("web-01", "npm", "left-pad", "1.3.0", "npm/left-pad/left-pad-1.3.0.tgz", digA)
	rep := h.bom("web-01", purl("pkg:npm/left-pad@1.3.0", "left-pad", "1.3.0", digB))
	wantClass(t, h.classesOf(rep), "left-pad@1.3.0", ClassUnknown, "digest mismatch")
}

// Names compare the way bodega's types canonicalize them: pypi per PEP 503,
// apt by the pool filename with the epoch dpkg reports and the pool omits, and
// npm not at all, since its names are case-sensitive.
func TestNamesCanonicalizeAcrossEcosystems(t *testing.T) {
	h := newHarness(t)
	h.served("web-01", "pypi", "django", "4.2.0", "pypi/wheels/django-4.2.0-py3-none-any.whl", "")
	h.served("web-01", "pypi", "zope-interface", "6.0", "pypi/wheels/zope_interface-6.0-cp311-none-any.whl", "")
	h.served("web-01", "apt", "pool/main/u/util-linux/util-linux_2.38.1-5_amd64.deb", "",
		"packages/apt/pool/main/u/util-linux/util-linux_2.38.1-5_amd64.deb", "")
	h.served("web-01", "freebsd", "FreeBSD", "FreeBSD:14:amd64", "freebsd/FreeBSD:14:amd64/FreeBSD/All/py311-requests-2.31.0~1a2b3c.pkg", "")
	h.served("web-01", "npm", "react", "18.2.0", "npm/react/react-18.2.0.tgz", "")

	rep := h.bom("web-01",
		purl("pkg:pypi/Django@4.2.0", "Django", "4.2.0", ""),
		purl("pkg:pypi/zope.interface@6.0", "zope.interface", "6.0", ""),
		purl("pkg:deb/debian/util-linux@1:2.38.1-5", "util-linux", "1:2.38.1-5", ""),
		purl("pkg:freebsd/py311-requests@2.31.0", "py311-requests", "2.31.0", ""),
		purl("pkg:npm/React@18.2.0", "React", "18.2.0", ""),
	)
	got := h.classesOf(rep)
	wantClass(t, got, "Django@4.2.0", ClassServed, "")
	wantClass(t, got, "zope.interface@6.0", ClassServed, "")
	wantClass(t, got, "util-linux@1:2.38.1-5", ClassServed, "")
	wantClass(t, got, "py311-requests@2.31.0", ClassServed, "")
	wantClass(t, got, "React@18.2.0", ClassUnknown, "")
}

// A baseline hides unknown, never refused, and applies to reports that arrive
// after it: the report it was taken from keeps the classes it got.
func TestBaselineHidesUnknownNotRefused(t *testing.T) {
	h := newHarness(t)
	if err := h.db.RecordAdmission(h.ctx, audit.Admission{PkgType: "apt", PkgName: "telnetd", PkgVersion: "0.17-44",
		Decision: audit.AdmissionPolicyBlocked}); err != nil {
		t.Fatal(err)
	}
	image := []string{
		purl("pkg:deb/debian/bash@5.2.15-2", "bash", "5.2.15-2", ""),
		purl("pkg:deb/debian/telnetd@0.17-44", "telnetd", "0.17-44", ""),
	}
	first := h.bom("web-01", image...)
	b, err := h.rc.AcceptReport(h.ctx, "web-01", 0, "ops", "golden image")
	if err != nil {
		t.Fatal(err)
	}
	if b.Actor != "ops" || b.Comment != "golden image" || len(b.ReportIDs) != 1 || b.ReportIDs[0] != first.ID {
		t.Errorf("baseline = %+v, want actor, comment and the accepted report recorded", b)
	}

	second := h.bom("web-01", append(image, purl("pkg:deb/debian/netcat@1.10-47", "netcat", "1.10-47", ""))...)
	got := h.classesOf(second)
	wantClass(t, got, "bash@5.2.15-2", ClassBaseline, "accepted baseline")
	wantClass(t, got, "telnetd@0.17-44", ClassRefused, "policy_blocked")
	wantClass(t, got, "netcat@1.10-47", ClassUnknown, "")

	wantClass(t, h.classesOf(first), "bash@5.2.15-2", ClassUnknown, "")

	bs, err := h.rc.BaselinesFor(h.ctx, "web-01")
	if err != nil || bs.Own == nil || len(bs.Own.Components) != 2 || bs.Own.CreatedAt.IsZero() {
		t.Errorf("BaselinesFor = %+v, %v; want the accepted baseline with its two components and time", bs, err)
	}
}

// A profile's entries are a baseline for every identity bound to it: a
// pinned entry for its version, an unpinned one for any.
func TestProfileBaseline(t *testing.T) {
	h := newHarness(t)
	if err := h.db.CreateProfileWith(h.ctx, audit.Profile{Name: "web-tier"}, nil, []audit.ProfileEntry{
		{Profile: "web-tier", Type: "pypi", Name: "Flask", Constraint: manifest.ConstraintExact, Version: "3.0.0"},
		{Profile: "web-tier", Type: "pypi", Name: "gunicorn"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.BindProfile(h.ctx, audit.ProfileBinding{Identity: "web-01", Profile: "web-tier"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.rc.AcceptProfile(h.ctx, "web-tier", "ops", ""); err != nil {
		t.Fatal(err)
	}
	got := h.classesOf(h.bom("web-01",
		purl("pkg:pypi/flask@3.0.0", "flask", "3.0.0", ""),
		purl("pkg:pypi/flask@3.1.0", "flask", "3.1.0", ""),
		purl("pkg:pypi/gunicorn@21.2.0", "gunicorn", "21.2.0", ""),
	))
	wantClass(t, got, "flask@3.0.0", ClassBaseline, "")
	wantClass(t, got, "flask@3.1.0", ClassUnknown, "")
	wantClass(t, got, "gunicorn@21.2.0", ClassBaseline, "every version")

	other := h.classesOf(h.bom("db-01", purl("pkg:pypi/gunicorn@21.2.0", "gunicorn", "21.2.0", "")))
	wantClass(t, other, "gunicorn@21.2.0", ClassUnknown, "")
}

// The current set is the union of each source's latest report, each
// component naming the instances that reported it.
func TestUnionAcrossTwoSources(t *testing.T) {
	h := newHarness(t)
	h.bind("agent", "node-7", "web-01")
	h.bom("web-01", purl("pkg:deb/debian/bash@5.2.15-2", "bash", "5.2.15-2", ""))
	h.bom("web-01",
		purl("pkg:deb/debian/bash@5.2.15-2", "bash", "5.2.15-2", ""),
		purl("pkg:deb/debian/curl@7.88.1-10", "curl", "7.88.1-10", ""),
	)
	h.agent("node-7",
		inventory.Component{Ecosystem: "apt", Name: "bash", Version: "5.2.15-2"},
		inventory.Component{Ecosystem: "apt", Name: "curl", Version: "7.88.1-10"},
		inventory.Component{Ecosystem: "pypi", Name: "requests", Version: "2.31.0", Path: "/opt/venv/lib"},
	)
	rep, err := h.rc.Host(h.ctx, "web-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Components) != 3 {
		t.Fatalf("components = %+v, want bash, curl and requests once each", rep.Components)
	}
	for _, c := range rep.Components {
		want := "cdx,agent"
		if c.Name == "requests" {
			want = "agent"
			if len(c.Paths) != 1 || c.Paths[0] != "/opt/venv/lib" {
				t.Errorf("requests paths = %v, want the path the agent reported", c.Paths)
			}
		}
		if got := strings.Join(c.Sources, ","); got != want && !(want == "cdx,agent" && got == "agent,cdx") {
			t.Errorf("%s sources = %s, want %s", c.Name, got, want)
		}
	}
	if len(rep.Sources) != 2 || !rep.Alert {
		t.Errorf("sources = %+v alert = %v, want both instances and an alert for the unknown components", rep.Sources, rep.Alert)
	}
}

// One source reports, another enabled source covering the ecosystem does not:
// a finding naming both, with its own audit event. A source that cannot see
// the ecosystem never disagrees about it.
func TestSourceDisagreement(t *testing.T) {
	h := newHarness(t)
	h.bind("agent", "node-7", "web-01")
	h.agent("node-7",
		inventory.Component{Ecosystem: "apt", Name: "bash", Version: "5.2.15-2"},
	)
	h.bom("web-01",
		purl("pkg:deb/debian/bash@5.2.15-2", "bash", "5.2.15-2", ""),
		purl("pkg:deb/debian/nmap@7.93", "nmap", "7.93", ""),
		purl("pkg:pypi/requests@2.31.0", "requests", "2.31.0", ""),
	)
	rep, err := h.rc.Host(h.ctx, "web-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Disagreements) != 1 {
		t.Fatalf("disagreements = %+v, want nmap alone: the agent cannot see pip, so requests is not one", rep.Disagreements)
	}
	d := rep.Disagreements[0]
	if d.Name != "nmap" || d.ReportedBy != "cdx" || d.AbsentFrom != "agent" || d.ReportedIn == 0 || d.AbsentIn == 0 {
		t.Errorf("finding = %+v, want nmap reported by cdx and absent from agent, with both report ids", d)
	}
	if !rep.Alert {
		t.Error("a disagreement must alert")
	}
	if evs := h.events(audit.InventoryDisagreement); len(evs) != 1 || evs[0].Identity != "web-01" {
		t.Errorf("disagreement events = %+v, want one for web-01", evs)
	}

	// The agent's next report carries nmap: the disagreement is gone, and the
	// newest report says so.
	h.agent("node-7",
		inventory.Component{Ecosystem: "apt", Name: "bash", Version: "5.2.15-2"},
		inventory.Component{Ecosystem: "apt", Name: "nmap", Version: "7.93"},
	)
	if rep, err = h.rc.Host(h.ctx, "web-01"); err != nil || len(rep.Disagreements) != 0 {
		t.Errorf("after the agent caught up: disagreements = %+v, %v; want none", rep.Disagreements, err)
	}
}

// The reverse direction: the newly arrived report omits what an older one
// from another source holds, and the arriving source covers it.
func TestDisagreementBothWays(t *testing.T) {
	h := newHarness(t)
	h.bind("agent", "node-7", "web-01")
	h.bom("web-01", purl("pkg:deb/debian/bash@5.2.15-2", "bash", "5.2.15-2", ""), purl("pkg:deb/debian/nmap@7.93", "nmap", "7.93", ""))
	h.agent("node-7", inventory.Component{Ecosystem: "apt", Name: "bash", Version: "5.2.15-2"})
	rep, err := h.rc.Host(h.ctx, "web-01")
	if err != nil || len(rep.Disagreements) != 1 || rep.Disagreements[0].ReportedBy != "cdx" || rep.Disagreements[0].AbsentFrom != "agent" {
		t.Errorf("disagreements = %+v, %v; want nmap reported by cdx, absent from the agent's newer report", rep.Disagreements, err)
	}
}

// Staleness is per instance: a push host silent past twice its interval, a
// pull host no successful poll has returned recently, and a mapped host that
// never reported at all.
func TestStalenessPerInstance(t *testing.T) {
	h := newHarness(t)
	vendor := h.insts["vendor"].Source.(*fakeVendor) //nolint:forcetypeassert // configured above
	h.bind("vendor", "v-42", "web-01")
	vendor.docs = []inventory.Document{{ExternalID: "v-42", Body: []byte(`[{"ecosystem":"apt","name":"bash","version":"5.2.15-2"}]`)}}
	if err := h.frame.PollOnce(h.ctx, h.insts["vendor"]); err != nil {
		t.Fatal(err)
	}
	h.bom("web-01", purl("pkg:deb/debian/bash@5.2.15-2", "bash", "5.2.15-2", ""))
	h.bind("agent", "node-7", "web-01")

	state := func(at time.Time) map[string]SourceState {
		t.Helper()
		h.rc.Now = func() time.Time { return at }
		rep, err := h.rc.Host(h.ctx, "web-01")
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]SourceState{}
		for _, s := range rep.Sources {
			out[s.Instance] = s
		}
		return out
	}
	fresh := state(time.Now().Add(90 * time.Minute))
	if fresh["cdx"].Stale || fresh["vendor"].Stale {
		t.Errorf("at 1.5 intervals: cdx %+v, vendor %+v; want neither stale", fresh["cdx"], fresh["vendor"])
	}
	if !fresh["agent"].Stale || !strings.Contains(fresh["agent"].Reason, "never reported") {
		t.Errorf("agent = %+v, want stale: mapped and never reported", fresh["agent"])
	}
	if fresh["vendor"].LastPoll == nil {
		t.Error("a pull instance's state carries its last successful poll")
	}

	late := state(time.Now().Add(150 * time.Minute))
	if !late["cdx"].Stale || !late["vendor"].Stale {
		t.Errorf("at 2.5 intervals: cdx %+v, vendor %+v; want both stale", late["cdx"], late["vendor"])
	}

	h.bind("vendor", "v-43", "db-01")
	if s := hostsByID(t, h)["db-01"]; len(s.Sources) != 1 || !s.Sources[0].Stale || !strings.Contains(s.Sources[0].Reason, "no successful poll") {
		t.Errorf("db-01 = %+v, want its pull instance stale with no poll ever returning it", s)
	}
}

func hostsByID(t *testing.T, h *harness) map[string]HostSummary {
	t.Helper()
	hosts, err := h.rc.Hosts(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]HostSummary{}
	for _, s := range hosts {
		out[s.Identity] = s
	}
	return out
}

// A report classified on arrival keeps its classes when the catalog changes
// afterwards: report reads the record, it does not recompute it.
func TestRecordedClassesDoNotMove(t *testing.T) {
	h := newHarness(t)
	h.bom("web-01", purl("pkg:npm/sideload@0.1.0", "sideload", "0.1.0", ""))
	h.served("web-01", "npm", "sideload", "0.1.0", "npm/sideload/sideload-0.1.0.tgz", "")
	rep, err := h.rc.Host(h.ctx, "web-01")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Components[0].Class != ClassUnknown {
		t.Errorf("class = %s, want the unknown recorded on arrival", rep.Components[0].Class)
	}
	if _, err := h.rc.Host(h.ctx, "nobody"); err == nil {
		t.Error("an identity nothing maps must be an error, not an empty report")
	}
}

func TestServedIdentityParsesKeys(t *testing.T) {
	for _, tc := range []struct {
		so                 audit.ServedObject
		eco, name, version string
	}{
		{audit.ServedObject{PkgType: "apt", PkgName: "pool/main/c/curl/curl_7.88.1-10_amd64.deb", ObjectKey: "packages/apt/pool/main/c/curl/curl_7.88.1-10_amd64.deb"}, "apt", "curl", "7.88.1-10"},
		{audit.ServedObject{PkgType: "apt", PkgName: "pool/main/s/sudo/sudo_1%3a1.9_amd64.deb", ObjectKey: "apt-cache/x"}, "apt", "sudo", "1:1.9"},
		{audit.ServedObject{PkgType: "freebsd", PkgName: "FreeBSD", PkgVersion: "FreeBSD:14:amd64", ObjectKey: "freebsd/FreeBSD:14:amd64/FreeBSD/All/curl-8.5.0.pkg"}, "freebsd", "curl", "8.5.0"},
		{audit.ServedObject{PkgType: "npm", PkgName: "@scope/pkg", PkgVersion: "1.0.0", ObjectKey: "npm/@scope--pkg/pkg-1.0.0.tgz"}, "npm", "@scope/pkg", "1.0.0"},
	} {
		eco, name, version := ServedIdentity(tc.so)
		if eco != tc.eco || name != tc.name || version != tc.version {
			t.Errorf("ServedIdentity(%+v) = %s %s %s, want %s %s %s", tc.so, eco, name, version, tc.eco, tc.name, tc.version)
		}
	}
}
