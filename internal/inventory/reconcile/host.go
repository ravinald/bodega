package reconcile

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/inventory"
)

// SourceState is one source instance's standing on one host.
type SourceState struct {
	Instance   string     `json:"instance"`
	Type       string     `json:"type,omitempty"`
	Mode       string     `json:"mode,omitempty"`
	Enabled    bool       `json:"enabled"`
	Interval   string     `json:"interval,omitempty"`
	ReportID   int64      `json:"report_id,omitempty"`
	LastReport *time.Time `json:"last_report"`
	LastPoll   *time.Time `json:"last_poll,omitempty"`
	Stale      bool       `json:"stale"`
	Reason     string     `json:"reason,omitempty"`
}

// Component is one installed component in a host's current set: the union of
// the latest report from each source instance mapped to the host.
type Component struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Version   string   `json:"version,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	Sources   []string `json:"sources"`
	Class     string   `json:"class"`
	Reason    string   `json:"reason"`
}

// HostReport is a host's current installed set, classified. Alert is set when
// a component is refused, unknown or unclassified, or two sources disagree,
// which is when `bodega inventory report` exits 1. An unclassified component
// has not been shown to be anything but unknown, so it alerts too.
type HostReport struct {
	Identity      string                     `json:"identity"`
	GeneratedAt   time.Time                  `json:"generated_at"`
	Alert         bool                       `json:"alert"`
	Counts        map[string]int             `json:"counts"`
	Sources       []SourceState              `json:"sources"`
	Components    []Component                `json:"components"`
	Disagreements []audit.SourceDisagreement `json:"disagreements"`
}

// ErrUnknownIdentity is returned for an identity no host mapping names.
var ErrUnknownIdentity = errors.New("no inventory source maps this identity")

// Host assembles identity's current state from the recorded classifications
// of the latest report from each mapped source instance. It recomputes
// nothing: a report's classes are the ones recorded when it arrived.
func (r *Reconciler) Host(ctx context.Context, identity string) (*HostReport, error) {
	hosts, err := r.DB.ListInventoryHosts(ctx)
	if err != nil {
		return nil, err
	}
	mapped := map[string]bool{}
	for _, h := range hosts {
		if h.Identity == identity {
			mapped[h.Source] = true
		}
	}
	if len(mapped) == 0 {
		return nil, fmt.Errorf("%w: %q; `bodega inventory hosts` lists the identities that are", ErrUnknownIdentity, identity)
	}
	return r.host(ctx, identity, mapped)
}

func (r *Reconciler) host(ctx context.Context, identity string, mapped map[string]bool) (*HostReport, error) {
	now := r.now()
	latest, err := r.DB.LatestInventoryReports(ctx, identity)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, len(latest))
	for i, rep := range latest {
		ids[i] = rep.ID
	}
	classes, err := r.DB.InventoryClassifications(ctx, ids)
	if err != nil {
		return nil, err
	}

	out := &HostReport{Identity: identity, GeneratedAt: now, Counts: map[string]int{}}
	bySource := map[string]audit.InventoryReport{}
	for _, rep := range latest {
		bySource[rep.Source] = rep
	}
	for _, src := range sortedKeys(mapped) {
		st, err := r.sourceState(ctx, src, bySource[src], now)
		if err != nil {
			return nil, err
		}
		if st.Stale {
			out.Counts[ClassStale]++
		}
		out.Sources = append(out.Sources, st)
	}

	out.Components = union(latest, classes)
	for _, c := range out.Components {
		out.Counts[c.Class]++
	}
	out.Disagreements = currentDisagreements(latest, classes)
	out.Alert = out.Counts[ClassRefused]+out.Counts[ClassUnknown]+out.Counts[ClassUnclassified] > 0 || len(out.Disagreements) > 0
	return out, nil
}

// sourceState applies the staleness rule: no report within twice the
// instance's interval. For a pull source a report exists only where a poll
// succeeded and returned the host, so its last report is its last successful
// poll covering the host.
func (r *Reconciler) sourceState(ctx context.Context, src string, rep audit.InventoryReport, now time.Time) (SourceState, error) {
	st := SourceState{Instance: src, ReportID: rep.ID}
	if !rep.ReceivedAt.IsZero() {
		t := rep.ReceivedAt
		st.LastReport = &t
	}
	inst := r.instance(src)
	if inst == nil {
		st.Stale, st.Reason = true, "instance is mapped to this host but not configured in inventory_sources"
		return st, nil
	}
	st.Type, st.Mode, st.Enabled = inst.Source.Type(), string(inst.Source.Mode()), inst.Enabled
	st.Interval = inst.Interval.String()
	if inst.Source.Mode() == inventory.ModePull {
		stats, err := r.DB.InventorySourceStats(ctx, src)
		if err != nil {
			return st, err
		}
		if !stats.LastSuccess.IsZero() {
			t := stats.LastSuccess
			st.LastPoll = &t
		}
	}
	window := 2 * inst.Interval
	switch {
	case st.LastReport == nil && inst.Source.Mode() == inventory.ModePull:
		st.Stale, st.Reason = true, "no successful poll has returned this host"
	case st.LastReport == nil:
		st.Stale, st.Reason = true, "this host has never reported through this instance"
	case now.Sub(*st.LastReport) > window:
		st.Stale = true
		st.Reason = fmt.Sprintf("last report %s ago, beyond twice the %s interval", now.Sub(*st.LastReport).Round(time.Minute), inst.Interval)
	}
	return st, nil
}

// union merges the latest reports into one component list. A component two
// sources report is one entry naming both, with the worse recorded class.
func union(latest []audit.InventoryReport, classes map[int64]audit.InventoryClassification) []Component {
	merged := map[string]*Component{}
	var order []string
	for _, rep := range latest {
		cls, classified := classes[rep.ID]
		recorded := map[string]audit.ClassifiedComponent{}
		for _, cc := range cls.Components {
			k := Key(cc.Ecosystem, cc.Name, cc.Version)
			if prev, ok := recorded[k]; !ok || rank(cc.Class) < rank(prev.Class) {
				recorded[k] = cc
			}
		}
		for _, c := range rep.Components {
			k := Key(c.Ecosystem, c.Name, c.Version)
			class, reason := ClassUnclassified, fmt.Sprintf("report %d from %s has no recorded classification", rep.ID, rep.Source)
			if cc, ok := recorded[k]; ok && classified {
				class, reason = cc.Class, cc.Reason
			}
			m := merged[k]
			if m == nil {
				m = &Component{Ecosystem: c.Ecosystem, Name: c.Name, Version: c.Version, Class: class, Reason: reason}
				merged[k] = m
				order = append(order, k)
			} else if betterRecord(class, m.Class) {
				m.Class, m.Reason = class, reason
			}
			if c.Path != "" && !contains(m.Paths, c.Path) {
				m.Paths = append(m.Paths, c.Path)
			}
			if !contains(m.Sources, rep.Source) {
				m.Sources = append(m.Sources, rep.Source)
			}
		}
	}
	out := make([]Component, 0, len(order))
	for _, k := range order {
		out = append(out, *merged[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := rank(out[i].Class), rank(out[j].Class); ri != rj {
			return ri < rj
		}
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// betterRecord reports whether class should replace current on a merged
// component: a recorded class always beats unclassified, and between two
// recorded classes the worse one wins.
func betterRecord(class, current string) bool {
	switch {
	case class == ClassUnclassified:
		return false
	case current == ClassUnclassified:
		return true
	}
	return rank(class) < rank(current)
}

// currentDisagreements returns the findings that still stand between the
// latest reports. Each ingest records only the pairs that include its own
// source, so a host's findings are spread over every latest report; a finding
// stands while both reports it names are still their sources' latest, and is
// retired once either source reports again, because that report recorded the
// pair afresh. Two reports ingested together can both compare against each
// other, so findings are de-duplicated.
func currentDisagreements(latest []audit.InventoryReport, classes map[int64]audit.InventoryClassification) []audit.SourceDisagreement {
	latestID := map[string]int64{}
	for _, rep := range latest {
		latestID[rep.Source] = rep.ID
	}
	out := []audit.SourceDisagreement{}
	seen := map[string]bool{}
	for _, rep := range latest {
		for _, d := range classes[rep.ID].Disagreements {
			if latestID[d.ReportedBy] != d.ReportedIn || latestID[d.AbsentFrom] != d.AbsentIn {
				continue
			}
			k := Key(d.Ecosystem, d.Name, d.Version) + "\x00" + d.ReportedBy + "\x00" + d.AbsentFrom
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.ReportedBy != b.ReportedBy {
			return a.ReportedBy < b.ReportedBy
		}
		if a.AbsentFrom != b.AbsentFrom {
			return a.AbsentFrom < b.AbsentFrom
		}
		return Key(a.Ecosystem, a.Name, a.Version) < Key(b.Ecosystem, b.Name, b.Version)
	})
	return out
}

// HostSummary is one identity's line in `bodega inventory hosts`.
type HostSummary struct {
	Identity string         `json:"identity"`
	Alert    bool           `json:"alert"`
	Counts   map[string]int `json:"counts"`
	Sources  []SourceState  `json:"sources"`
}

// Hosts summarizes every identity the host mapping knows, including mapped
// hosts that never reported, sorted by identity.
func (r *Reconciler) Hosts(ctx context.Context) ([]HostSummary, error) {
	hosts, err := r.DB.ListInventoryHosts(ctx)
	if err != nil {
		return nil, err
	}
	byIdentity := map[string]map[string]bool{}
	for _, h := range hosts {
		if byIdentity[h.Identity] == nil {
			byIdentity[h.Identity] = map[string]bool{}
		}
		byIdentity[h.Identity][h.Source] = true
	}
	out := make([]HostSummary, 0, len(byIdentity))
	for _, id := range sortedKeys(boolKeys(byIdentity)) {
		rep, err := r.host(ctx, id, byIdentity[id])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		out = append(out, HostSummary{Identity: id, Alert: rep.Alert, Counts: rep.Counts, Sources: rep.Sources})
	}
	return out, nil
}

func boolKeys[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
