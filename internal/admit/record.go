package admit

import (
	"context"
	"errors"
	"sort"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// evaluation accumulates the per-check verdicts of one admission, one list
// per version, and turns them into the rows it writes. The policy digest and
// the configured actions are read once, before any check runs, so every row
// of one decision cites the policy that decision started under.
type evaluation struct {
	checks    [][]audit.AdmissionCheck
	digest    string
	digestErr error
	actions   map[string]string
}

func newEvaluation(ctx context.Context, adb *audit.DB, pm *manifest.PackageManifest) *evaluation {
	ev := &evaluation{
		checks:  make([][]audit.AdmissionCheck, max(len(pm.Versions), 1)),
		actions: map[string]string{audit.CheckAge: audit.ActionNone, audit.CheckOSV: audit.ActionNone},
	}
	if adb == nil {
		return ev
	}
	ev.digest, ev.digestErr = policy.Digest(ctx, adb)
	if p, err := adb.GetAgePolicy(ctx, pm.Type); err == nil {
		ev.actions[audit.CheckAge] = p.Action
	} else if !errors.Is(err, audit.ErrAgePolicyNotFound) {
		ev.actions[audit.CheckAge] = "unknown"
	}
	if p, err := adb.GetOSVPolicy(ctx, pm.Type); err == nil {
		ev.actions[audit.CheckOSV] = p.Action
	} else if !errors.Is(err, audit.ErrOSVPolicyNotFound) {
		ev.actions[audit.CheckOSV] = "unknown"
	}
	return ev
}

// set records c for version i, replacing an earlier verdict of the same
// check. i of -1 means every version.
func (ev *evaluation) set(i int, c audit.AdmissionCheck) {
	for _, j := range ev.indexes(i) {
		ev.checks[j] = upsertCheck(ev.checks[j], c, false)
	}
}

// add records c for version i beside whatever is there.
func (ev *evaluation) add(i int, c audit.AdmissionCheck) {
	for _, j := range ev.indexes(i) {
		ev.checks[j] = append(ev.checks[j], c)
	}
}

// notRunChecks marks the named checks not evaluated on version i (every
// version for -1), leaving any that already have a verdict alone.
func (ev *evaluation) notRunChecks(i int, detail string, names ...string) {
	for _, j := range ev.indexes(i) {
		for _, name := range names {
			ev.checks[j] = upsertCheck(ev.checks[j], ev.notRunCheck(name, detail), true)
		}
	}
}

// notRun marks every check without a verdict not evaluated, on every version.
func (ev *evaluation) notRun(detail string) {
	ev.notRunChecks(-1, detail, audit.CheckAllowList, audit.CheckAge, audit.CheckOSV)
}

// notRunAfter is the bookkeeping for a refusal at version i: the checks that
// would have followed on i, and every check on the versions after it, never
// ran.
func (ev *evaluation) notRunAfter(i int, detail string) {
	ev.notRunChecks(i, detail, audit.CheckAge, audit.CheckOSV)
	for j := i + 1; j < len(ev.checks); j++ {
		ev.notRunChecks(j, detail, audit.CheckAllowList, audit.CheckAge, audit.CheckOSV)
	}
}

func (ev *evaluation) notRunCheck(name, detail string) audit.AdmissionCheck {
	action := ev.actions[name]
	if name == audit.CheckAllowList || action == "" {
		action = audit.ActionNone
	}
	return audit.AdmissionCheck{Check: name, Action: action, Status: audit.CheckNotEvaluated, Detail: detail}
}

// runVersion runs every checker on version i, records each verdict and
// returns the raw results for the caller's own warn and block handling.
func (ev *evaluation) runVersion(ctx context.Context, pm *manifest.PackageManifest, i int, checkers []policy.VersionChecker) []policy.Result {
	results := make([]policy.Result, 0, len(checkers))
	for _, c := range checkers {
		r := c.Check(ctx, pm, &pm.Versions[i])
		results = append(results, r)
		status := audit.CheckPass
		switch r.Action {
		case policy.ActionWarn:
			status = audit.CheckWarn
		case policy.ActionBlock:
			status = audit.CheckBlock
		}
		action := ev.actions[r.Check]
		if action == "" {
			action = audit.ActionNone
		}
		ev.set(i, audit.AdmissionCheck{Check: r.Check, Action: action, Status: status, Detail: r.Reason})
	}
	return results
}

// row renders version i as an admission row. Every row names the allow-list,
// age and OSV checks, so a consumer never has to read a missing entry as a
// pass.
func (ev *evaluation) row(pm *manifest.PackageManifest, i int, decision string, who Who) audit.Admission {
	checks := append([]audit.AdmissionCheck(nil), ev.checks[i]...)
	fill := "not run"
	if len(pm.Versions) == 0 {
		fill = "not run: the manifest names no version"
	}
	for _, name := range []string{audit.CheckAllowList, audit.CheckAge, audit.CheckOSV} {
		checks = upsertCheck(checks, ev.notRunCheck(name, fill), true)
	}
	sort.SliceStable(checks, func(a, b int) bool { return checkRank(checks[a].Check) < checkRank(checks[b].Check) })
	version := ""
	if i < len(pm.Versions) {
		version = admissionVersion(pm.Versions[i])
	}
	return audit.Admission{
		PkgType:      pm.Type,
		PkgName:      pm.Name,
		PkgVersion:   version,
		Decision:     decision,
		Checks:       checks,
		PolicyDigest: ev.digest,
		Actor:        who.Actor,
		Identity:     who.Identity,
	}
}

// record writes one row per version and returns res carrying them. The
// decision is the manifest's: a version whose own checks passed is still
// policy_blocked when a sibling was refused, because nothing of the manifest
// was written.
//
// A row that cannot be written is a warning rather than a refusal. The
// decision itself was made, and refusing an import because the audit sink is
// unreachable would make every sink outage an outage of the manifest store.
func (ev *evaluation) record(ctx context.Context, adb *audit.DB, pm *manifest.PackageManifest, res Result, who Who) Result {
	if adb == nil {
		return res
	}
	if ev.digestErr != nil {
		res.Warnings = append(res.Warnings, "admission recorded with no policy digest: "+ev.digestErr.Error())
	}
	for i := range ev.checks {
		row := ev.row(pm, i, res.Decision.String(), who)
		if err := adb.RecordAdmission(ctx, row); err != nil {
			res.Warnings = append(res.Warnings, "admission decision not recorded for "+pm.Type+"/"+pm.Name+"@"+row.PkgVersion+": "+err.Error())
			continue
		}
		res.Admissions = append(res.Admissions, row)
	}
	return res
}

func (ev *evaluation) indexes(i int) []int {
	if i >= 0 {
		return []int{i}
	}
	out := make([]int, len(ev.checks))
	for j := range out {
		out[j] = j
	}
	return out
}

// upsertCheck replaces the entry for c.Check, or appends c. keep leaves an
// existing entry alone, for marking checks not run without overwriting one
// that did run.
func upsertCheck(checks []audit.AdmissionCheck, c audit.AdmissionCheck, keep bool) []audit.AdmissionCheck {
	for k := range checks {
		if checks[k].Check == c.Check {
			if !keep {
				checks[k] = c
			}
			return checks
		}
	}
	return append(checks, c)
}

func checkRank(name string) int {
	switch name {
	case audit.CheckAllowList:
		return 0
	case audit.CheckOverride:
		return 1
	case audit.CheckAge:
		return 2
	case audit.CheckOSV:
		return 3
	}
	return 4
}

// admissionVersion is the version an admission row is keyed by, and it is
// the label the digest pins use: the version, or for a git entry pinned by
// ref, the ref.
func admissionVersion(ve manifest.VersionEntry) string {
	if ve.Version != "" {
		return ve.Version
	}
	return ve.Ref
}
