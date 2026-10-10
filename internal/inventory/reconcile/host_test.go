package reconcile

import (
	"net/http"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
)

// pipOnly is a third push source that sees only pypi, so a host can carry
// three collectors whose pairs disagree independently.
type pipOnly struct{ fakeAgent }

func (pipOnly) Type() string                    { return "pip-only" }
func (pipOnly) Covers(_, ecosystem string) bool { return ecosystem == manifest.TypePypi }
func (pipOnly) Routes() []inventory.Route {
	return []inventory.Route{{Method: http.MethodPost, Path: "r"}}
}

func init() {
	inventory.Register("pip-only", func(string, *inventory.Settings) (inventory.Source, error) { return pipOnly{}, nil })
}

// threeSources returns a harness whose web-01 is reported by cdx, agent (apt
// only) and pip (pypi only), with bash, nmap and requests all served to it, so
// a disagreement is the only thing that can alert.
func threeSources(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	insts, err := inventory.Configure(map[string]config.InventorySource{
		"cdx":   {"type": "cyclonedx", "enabled": true, "interval": "1h"},
		"agent": {"type": "fake-agent", "enabled": true, "interval": "1h"},
		"pip":   {"type": "pip-only", "enabled": true, "interval": "1h"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.insts = map[string]*inventory.Instance{}
	for _, i := range insts {
		h.insts[i.Name] = i
	}
	h.rc.Instances = insts
	h.frame = inventory.NewFrame(insts, h.db, nil, nil)
	h.frame.OnReport = h.rc.Ingested
	h.served("web-01", "apt", "pool/main/b/bash/bash_5.2.15-2_amd64.deb", "", "packages/apt/pool/main/b/bash/bash_5.2.15-2_amd64.deb", "")
	h.served("web-01", "apt", "pool/main/n/nmap/nmap_7.93_amd64.deb", "", "packages/apt/pool/main/n/nmap/nmap_7.93_amd64.deb", "")
	h.served("web-01", "pypi", "requests", "2.31.0", "pypi/x/requests-2.31.0.whl", "")
	h.bind("agent", "node-7", "web-01")
	h.bind("pip", "p-1", "web-01")
	return h
}

func (h *harness) pip(doc string) {
	h.t.Helper()
	b, err := h.insts["pip"].Source.Normalize([]byte(doc), "p-1")
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.frame.Ingest(h.ctx, h.insts["pip"], inventory.Principal{ExternalID: "p-1"}, b); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) cdxAll() {
	h.t.Helper()
	h.bom("web-01", purl("pkg:deb/debian/bash@5.2.15-2", "bash", "5.2.15-2", ""),
		purl("pkg:deb/debian/nmap@7.93", "nmap", "7.93", ""), purl("pkg:pypi/requests@2.31.0", "requests", "2.31.0", ""))
}

// A report from a third source records only its own pairs, so it must not
// erase a finding between the other two that still stands.
func TestThirdSourceKeepsOtherPairsDisagreement(t *testing.T) {
	h := threeSources(t)
	h.agent("node-7", inventory.Component{Ecosystem: "apt", Name: "bash", Version: "5.2.15-2"})
	h.cdxAll()
	h.pip(`[{"ecosystem":"pypi","name":"requests","version":"2.31.0"}]`)
	rep, err := h.rc.Host(h.ctx, "web-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Disagreements) != 1 || !rep.Alert {
		t.Fatalf("disagreements=%+v alert=%v; want nmap reported by cdx, absent from agent, still alerting", rep.Disagreements, rep.Alert)
	}
	if d := rep.Disagreements[0]; d.Name != "nmap" || d.ReportedBy != "cdx" || d.AbsentFrom != "agent" {
		t.Errorf("finding = %+v, want nmap reported by cdx and absent from agent", d)
	}

	// The agent catches up: its report retires the cdx/agent pair, and a
	// later pip report must not bring the old finding back.
	h.agent("node-7", inventory.Component{Ecosystem: "apt", Name: "bash", Version: "5.2.15-2"},
		inventory.Component{Ecosystem: "apt", Name: "nmap", Version: "7.93"})
	h.pip(`[{"ecosystem":"pypi","name":"requests","version":"2.31.0"}]`)
	if rep, err = h.rc.Host(h.ctx, "web-01"); err != nil || len(rep.Disagreements) != 0 || rep.Alert {
		t.Errorf("after the agent caught up: disagreements=%+v alert=%v err=%v; want none", rep.Disagreements, rep.Alert, err)
	}
}

// Findings from two pairs recorded by different reports both stand, each
// once.
func TestDisagreementsUnionAcrossReports(t *testing.T) {
	h := threeSources(t)
	h.agent("node-7", inventory.Component{Ecosystem: "apt", Name: "bash", Version: "5.2.15-2"})
	h.cdxAll()
	h.pip(`[]`)
	rep, err := h.rc.Host(h.ctx, "web-01")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, d := range rep.Disagreements {
		got[d.Name+":"+d.ReportedBy+">"+d.AbsentFrom]++
	}
	want := map[string]int{"nmap:cdx>agent": 1, "requests:cdx>pip": 1}
	if len(got) != len(want) || got["nmap:cdx>agent"] != 1 || got["requests:cdx>pip"] != 1 {
		t.Errorf("disagreements = %v, want %v", got, want)
	}
}

// A report nothing classified has not been shown to be anything but unknown,
// so it alerts rather than reading clean.
func TestUnclassifiedAlerts(t *testing.T) {
	h := newHarness(t)
	h.served("web-01", "apt", "pool/main/b/bash/bash_5.2.15-2_amd64.deb", "", "packages/apt/pool/main/b/bash/bash_5.2.15-2_amd64.deb", "")
	h.frame.OnReport = nil
	h.bind("agent", "node-7", "web-01")
	h.agent("node-7", inventory.Component{Ecosystem: "apt", Name: "bash", Version: "5.2.15-2"})
	rep, err := h.rc.Host(h.ctx, "web-01")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[ClassUnclassified] != 1 || !rep.Alert {
		t.Errorf("counts=%v alert=%v; want one unclassified component, alerting", rep.Counts, rep.Alert)
	}
	hosts, err := h.rc.Hosts(h.ctx)
	if err != nil || len(hosts) != 1 || !hosts[0].Alert {
		t.Errorf("hosts = %+v, %v; want web-01 alerting", hosts, err)
	}
	if evs := h.events(audit.InventoryBypass); len(evs) != 0 {
		t.Errorf("bypass events = %+v; an unrecorded classification writes none", evs)
	}
}
