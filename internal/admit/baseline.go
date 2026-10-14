package admit

import (
	"context"
	"fmt"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// MarkBaseline marks every version of pm as baseline at now, which is what
// `bodega pkg import --baseline` does before admitting it.
func MarkBaseline(pm *manifest.PackageManifest, now time.Time) {
	at := now.UTC().Format(time.RFC3339)
	for i := range pm.Versions {
		pm.Versions[i].Baseline = true
		pm.Versions[i].BaselineAt = at
	}
}

// CarryBaseline makes pm's baseline marks the ones existing already holds:
// a version existing marks keeps its mark and time, and every other loses
// any mark it arrived with. It returns the versions whose mark was dropped.
//
// Every write path but `pkg import --baseline` runs it before admission. The
// mark admits a version past a failing gate, so a manifest that could carry
// one in from a host's push, an API call or an editor buffer would be a way
// around every gate. existing may be nil.
func CarryBaseline(pm, existing *manifest.PackageManifest) []string {
	held := map[string]manifest.VersionEntry{}
	if existing != nil {
		for _, ve := range existing.Versions {
			if ve.Baseline {
				held[admissionVersion(ve)] = ve
			}
		}
	}
	var dropped []string
	for i := range pm.Versions {
		ve := &pm.Versions[i]
		if prev, ok := held[admissionVersion(*ve)]; ok {
			ve.Baseline, ve.BaselineAt = true, prev.BaselineAt
			continue
		}
		if ve.Baseline || ve.BaselineAt != "" {
			dropped = append(dropped, admissionVersion(*ve))
		}
		ve.Baseline, ve.BaselineAt = false, ""
	}
	return dropped
}

// BaselineCheck turns c, a failed check on ve, into a baseline one when ve
// carries the baseline mark: admitted, with the failure kept in the detail.
// It reports false for a check that did not fail or a version not marked.
func BaselineCheck(ve manifest.VersionEntry, c audit.AdmissionCheck) (audit.AdmissionCheck, bool) {
	if c.Status != audit.CheckBlock || !ve.Baseline {
		return c, false
	}
	c.Status = audit.CheckBaseline
	c.Detail = fmt.Sprintf("%s; admitted as baseline (marked %s)", c.Detail, ve.BaselineAt)
	return c, true
}

// admitPast turns c, a failed check on version i, into one that admits: an
// active override first, because it is a decision two people made about this
// failure, then the baseline mark.
func (ev *evaluation) admitPast(pm *manifest.PackageManifest, i int, c audit.AdmissionCheck) (audit.AdmissionCheck, bool) {
	if oc, ok := ev.overrideCheck(pm, i, c); ok {
		return oc, true
	}
	if i < len(pm.Versions) {
		return BaselineCheck(pm.Versions[i], c)
	}
	return c, false
}

// BaselineCleared is one version whose baseline mark was removed, with the
// checks it fails now that the gates apply to it.
type BaselineCleared struct {
	Type       string                 `json:"type"`
	Name       string                 `json:"name"`
	Version    string                 `json:"version"`
	BaselineAt string                 `json:"baseline_at"`
	Failing    []audit.AdmissionCheck `json:"failing"`
}

// ClearBaseline removes the baseline mark from every version of typ marked
// at least olderThan before now (every marked version when olderThan is
// zero), saves each package it changed, and evaluates each cleared version
// against the gates as they stand.
//
// The evaluation writes nothing: no admission row, no audit event, no
// provenance pin. It answers "how many of these now fail", and the next
// fetch or re-vet of each version is the decision that acts on it. A mark
// whose time does not parse is cleared whatever olderThan says, since
// clearing is the direction that applies the gates.
func ClearBaseline(ctx context.Context, store *manifest.Store, checker *policy.Checker, adb *audit.DB, cfg *config.Config,
	typ string, olderThan time.Duration, now time.Time) ([]BaselineCleared, error) {
	cutoff := now.Add(-olderThan)
	var out []BaselineCleared
	for _, name := range store.ListPackages(typ) {
		pm, err := store.GetPackage(ctx, typ, name)
		if err != nil {
			return out, fmt.Errorf("load %s/%s: %w", typ, name, err)
		}
		var cleared []manifest.VersionEntry
		for i := range pm.Versions {
			ve := &pm.Versions[i]
			if !ve.Baseline {
				continue
			}
			if at, err := time.Parse(time.RFC3339, ve.BaselineAt); olderThan > 0 && err == nil && at.After(cutoff) {
				continue
			}
			cleared = append(cleared, *ve)
			ve.Baseline, ve.BaselineAt = false, ""
		}
		if len(cleared) == 0 {
			continue
		}
		if err := store.SavePackage(ctx, pm); err != nil {
			return out, fmt.Errorf("save %s/%s: %w", typ, name, err)
		}
		for _, ve := range cleared {
			at := ve.BaselineAt
			ve.Baseline, ve.BaselineAt = false, ""
			out = append(out, BaselineCleared{Type: typ, Name: pm.Name, Version: admissionVersion(ve), BaselineAt: at,
				Failing: failingChecks(ctx, checker, adb, cfg, pm, ve, now)})
		}
	}
	if len(out) > 0 {
		if err := store.SaveIndex(ctx); err != nil {
			return out, fmt.Errorf("save index: %w", err)
		}
	}
	return out, nil
}

// failingChecks evaluates ve as an admission would, overrides included, and
// returns the checks that refuse it, without recording anything.
func failingChecks(ctx context.Context, checker *policy.Checker, adb *audit.DB, cfg *config.Config,
	pkg *manifest.PackageManifest, ve manifest.VersionEntry, now time.Time) []audit.AdmissionCheck {
	pm := &manifest.PackageManifest{Type: pkg.Type, Name: pkg.Name, Versions: []manifest.VersionEntry{ve}}
	ev := newEvaluation(ctx, adb, pm, now)
	if checker != nil {
		if candidate := policy.CandidateFor(pm.Type, pm.Name, ve.URL); candidate != "" {
			listed, _ := checker.Listed(ctx, pm.Type)
			c := AllowListCheck(listed, candidate, checker.Check(ctx, pm.Type, candidate))
			if oc, ok := ev.admitPast(pm, 0, c); ok {
				c = oc
			}
			ev.set(0, c)
		}
	}
	if adb != nil {
		ev.runVersion(ctx, pm, 0, VersionCheckers(cfg, adb))
	}
	var failing []audit.AdmissionCheck
	for _, c := range ev.checks[0] {
		if c.Status == audit.CheckBlock {
			failing = append(failing, c)
		}
	}
	return failing
}
