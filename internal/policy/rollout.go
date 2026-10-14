package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/ravinald/bodega/internal/audit"
)

// RolloutGates are the gates `policy enforce` switches, in the order an
// admission row lists them: every gate whose action an operator configures
// per ecosystem.
//
// The OSV malware action is not among them. Report mode exists so turning
// gates on breaks no build that already works, and a build that pulls a
// package OSV records as published to do harm is not one to keep working
// while somebody reads a report. The allow-list is not either: it has no
// action to switch, and `policy mode set <ecosystem> open` is how it stops
// deciding admission.
var RolloutGates = []string{audit.CheckAge, audit.CheckOSV, audit.CheckUpstreamProvenance, audit.CheckNameSimilarity}

// Rollout states, as `policy enforce` takes them.
const (
	RolloutReport  = "report"
	RolloutEnforce = "enforce"
)

// gateActions reads the action each rollout gate has a row for. A gate with
// no row is absent from the map: its default applies, and there is nothing
// stored to switch or restore.
func gateActions(ctx context.Context, db *audit.DB, eco string) (map[string]string, error) {
	out := map[string]string{}
	if p, err := db.GetAgePolicy(ctx, eco); err == nil {
		out[audit.CheckAge] = p.Action
	} else if !errors.Is(err, audit.ErrAgePolicyNotFound) {
		return nil, fmt.Errorf("read age policy: %w", err)
	}
	if p, err := db.GetOSVPolicy(ctx, eco); err == nil {
		out[audit.CheckOSV] = p.Action
	} else if !errors.Is(err, audit.ErrOSVPolicyNotFound) {
		return nil, fmt.Errorf("read osv policy: %w", err)
	}
	if p, err := db.GetProvenancePolicy(ctx, eco); err == nil {
		out[audit.CheckUpstreamProvenance] = p.Action
	} else if !errors.Is(err, audit.ErrProvenancePolicyNotFound) {
		return nil, fmt.Errorf("read upstream provenance policy: %w", err)
	}
	if p, err := db.GetSimilarityPolicy(ctx, eco); err == nil {
		out[audit.CheckNameSimilarity] = p.Action
	} else if !errors.Is(err, audit.ErrSimilarityPolicyNotFound) {
		return nil, fmt.Errorf("read name similarity policy: %w", err)
	}
	return out, nil
}

// SwitchRollout puts eco's gates in report mode (every gate with a row set
// to warn, the previous actions saved) or back to enforce (each saved action
// written back), and records one audit event naming actor and each gate's
// before and after. It returns the switches it made.
//
// report refuses an ecosystem already in report mode, because saving the
// warns it set would lose the actions enforce has to restore. enforce
// refuses one that is not in report mode, since there is nothing saved to
// restore. A gate whose action someone changed during report mode is still
// restored to what it was before the switch, and its before says what it
// was changed to.
func SwitchRollout(ctx context.Context, db *audit.DB, eco, state, actor string) ([]audit.GateSwitch, error) {
	prev, err := db.GetRollout(ctx, eco)
	inReport := err == nil
	if err != nil && !errors.Is(err, audit.ErrRolloutNotFound) {
		return nil, fmt.Errorf("read rollout state: %w", err)
	}
	current, err := gateActions(ctx, db, eco)
	if err != nil {
		return nil, err
	}

	var switches []audit.GateSwitch
	actions := map[string]string{}
	switch state {
	case RolloutReport:
		if inReport {
			return nil, fmt.Errorf("%s is already in report mode (since %s, by %s); run 'bodega policy enforce %s enforce' first",
				eco, prev.UpdatedAt.UTC().Format(time.RFC3339), prev.Actor, eco)
		}
		for _, gate := range RolloutGates {
			before, ok := current[gate]
			if !ok {
				continue
			}
			switches = append(switches, audit.GateSwitch{Gate: gate, Before: before, After: ActionWarn})
			actions[gate] = ActionWarn
		}
	case RolloutEnforce:
		if !inReport {
			return nil, fmt.Errorf("%s is not in report mode, so there are no saved actions to restore", eco)
		}
		for _, saved := range prev.Saved {
			before, ok := current[saved.Gate]
			if !ok {
				before = "removed"
			}
			switches = append(switches, audit.GateSwitch{Gate: saved.Gate, Before: before, After: saved.Before})
			actions[saved.Gate] = saved.Before
		}
	default:
		return nil, fmt.Errorf("state must be %s or %s, got %q", RolloutReport, RolloutEnforce, state)
	}

	if err := db.SetRollout(ctx, audit.Rollout{Ecosystem: eco, Saved: switches, Actor: actor}, actions, state == RolloutReport); err != nil {
		return nil, fmt.Errorf("switch %s to %s: %w", eco, state, err)
	}
	details, _ := json.Marshal(map[string]any{"rollout": state, "gates": nonNil(switches)})
	if err := db.Record(ctx, audit.Event{EventType: audit.EventPolicy, PkgType: eco, Actor: actor,
		Status: state, Details: string(details)}); err != nil {
		return switches, fmt.Errorf("switched %s to %s, but the audit event was not written: %w", eco, state, err)
	}
	return switches, nil
}

func nonNil(s []audit.GateSwitch) []audit.GateSwitch {
	if s == nil {
		return []audit.GateSwitch{}
	}
	return s
}

// ReportEntry is one (ecosystem, check, package) group of a policy report.
type ReportEntry struct {
	Ecosystem string `json:"ecosystem"`
	Check     string `json:"check"`
	Package   string `json:"package"`
	// Status is the worst status the check recorded in the group: block,
	// warn, or baseline for a baseline debt entry.
	Status string `json:"status"`
	// OnEnforce is the action the check takes once the ecosystem is
	// enforced: the action saved by report mode, or the one in force now.
	OnEnforce string   `json:"on_enforce,omitempty"`
	Requests  int      `json:"requests"`
	Versions  []string `json:"versions"`
	// Hosts are the identities whose requests the group's rows recorded.
	// Unidentified counts rows that carried none: a CLI import, or a request
	// no identity binding resolved.
	Hosts        []string `json:"hosts"`
	Unidentified int      `json:"unidentified"`
	// Detail is the most recent row's detail for the check.
	Detail string `json:"detail"`
}

// Report is what the gates flagged since a moment, and the baseline debt.
type Report struct {
	Since        time.Time     `json:"since"`
	Flagged      []ReportEntry `json:"flagged"`
	BaselineDebt []ReportEntry `json:"baseline_debt"`
	// Truncated is set when the window held more rows than were read, so the
	// counts are a floor.
	Truncated bool `json:"truncated"`
}

// BuildReport groups flagged, admission rows newest first, by ecosystem,
// check and package, keeping every check whose status is warn or block. debt
// is the newest row of each version still marked baseline; a check on it
// whose status is baseline is a finding the mark is admitting past.
// onEnforce maps ecosystem then check to the action enforce would leave.
func BuildReport(since time.Time, flagged, debt []audit.Admission, onEnforce map[string]map[string]string) Report {
	return Report{
		Since: since,
		Flagged: group(flagged, onEnforce, func(c audit.AdmissionCheck) bool {
			return c.Status == audit.CheckWarn || c.Status == audit.CheckBlock
		}),
		BaselineDebt: group(debt, onEnforce, func(c audit.AdmissionCheck) bool { return c.Status == audit.CheckBaseline }),
	}
}

func group(rows []audit.Admission, onEnforce map[string]map[string]string, keep func(audit.AdmissionCheck) bool) []ReportEntry {
	byKey := map[string]*ReportEntry{}
	for _, row := range rows {
		for _, c := range row.Checks {
			if !keep(c) {
				continue
			}
			k := row.PkgType + "\x00" + c.Check + "\x00" + row.PkgName
			e := byKey[k]
			if e == nil {
				e = &ReportEntry{Ecosystem: row.PkgType, Check: c.Check, Package: row.PkgName, Status: c.Status,
					OnEnforce: onEnforce[row.PkgType][c.Check], Detail: c.Detail, Versions: []string{}, Hosts: []string{}}
				byKey[k] = e
			}
			e.Requests++
			if c.Status == audit.CheckBlock {
				e.Status = c.Status
			}
			if row.PkgVersion != "" && !slices.Contains(e.Versions, row.PkgVersion) {
				e.Versions = append(e.Versions, row.PkgVersion)
			}
			switch {
			case row.Identity == "":
				e.Unidentified++
			case !slices.Contains(e.Hosts, row.Identity):
				e.Hosts = append(e.Hosts, row.Identity)
			}
		}
	}
	out := make([]ReportEntry, 0, len(byKey))
	for _, k := range slices.Sorted(maps.Keys(byKey)) {
		e := byKey[k]
		slices.Sort(e.Hosts)
		slices.Sort(e.Versions)
		out = append(out, *e)
	}
	return out
}

// EnforceActions maps each ecosystem in report mode, then each gate, to the
// action enforce would restore, and every other ecosystem's gates to the
// action in force now. A gate with no row is absent.
func EnforceActions(ctx context.Context, db *audit.DB, ecosystems []string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for _, eco := range ecosystems {
		current, err := gateActions(ctx, db, eco)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", eco, err)
		}
		r, err := db.GetRollout(ctx, eco)
		switch {
		case err == nil:
			for _, s := range r.Saved {
				current[s.Gate] = s.Before
			}
		case !errors.Is(err, audit.ErrRolloutNotFound):
			return nil, fmt.Errorf("%s: read rollout state: %w", eco, err)
		}
		out[eco] = current
	}
	return out, nil
}
