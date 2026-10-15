package admit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/provenance"
)

// versionChecks are the checks VersionCheckers run, in row order, for the
// bookkeeping that marks them not run.
var versionChecks = []string{audit.CheckAge, audit.CheckOSV, audit.CheckUpstreamProvenance, audit.CheckNameSimilarity}

// allChecks is every check an admission row names.
var allChecks = append([]string{audit.CheckAllowList}, versionChecks...)

// evaluation accumulates the per-check verdicts of one admission, one list
// per version, and turns them into the rows it writes. The policy digest, the
// configured actions and the overrides in effect are read once, before any
// check runs, so every row of one decision cites the policy that decision
// started under.
type evaluation struct {
	checks [][]audit.AdmissionCheck
	// versionChecks are the per-version checks this admission runs: the
	// built-in ones and each enabled integration instance. Every row names
	// all of them.
	versionChecks []string
	digest        string
	digestErr     error
	actions       map[string]string
	// overrides are the active overrides for the package, keyed by version
	// and check; see loadOverrides.
	overrides   map[string]audit.Override
	overrideErr error
}

func newEvaluation(ctx context.Context, adb *audit.DB, pm *manifest.PackageManifest, now time.Time) *evaluation {
	ev := &evaluation{
		checks:        make([][]audit.AdmissionCheck, max(len(pm.Versions), 1)),
		versionChecks: slices.Clone(versionChecks),
		actions: map[string]string{audit.CheckAge: audit.ActionNone, audit.CheckOSV: audit.ActionNone,
			audit.CheckUpstreamProvenance: policy.ActionWarn, audit.CheckNameSimilarity: policy.ActionWarn},
	}
	if adb == nil {
		return ev
	}
	if a, err := provenance.Action(ctx, adb, pm.Type); err == nil {
		ev.actions[audit.CheckUpstreamProvenance] = a
	} else {
		ev.actions[audit.CheckUpstreamProvenance] = "unknown"
	}
	if a, err := policy.SimilarityAction(ctx, adb, pm.Type); err == nil {
		ev.actions[audit.CheckNameSimilarity] = a
	} else {
		ev.actions[audit.CheckNameSimilarity] = "unknown"
	}
	ev.digest, ev.digestErr = policy.Digest(ctx, adb)
	ev.loadOverrides(ctx, adb, pm, now)
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

// actionChecker is a per-version check whose name and action are not among
// the built-in ones: an integration instance, whose name the config file
// chooses and whose action is its integration_policy row.
type actionChecker interface {
	CheckName() string
	ActionFor(ctx context.Context, ecosystem string) string
}

// include adds every checker among checkers that names itself to the checks
// this admission's rows name, with the action each would take on pm's type.
func (ev *evaluation) include(ctx context.Context, pm *manifest.PackageManifest, checkers []policy.VersionChecker) {
	for _, c := range checkers {
		ac, ok := c.(actionChecker)
		if !ok || slices.Contains(ev.versionChecks, ac.CheckName()) {
			continue
		}
		ev.versionChecks = append(ev.versionChecks, ac.CheckName())
		ev.actions[ac.CheckName()] = ac.ActionFor(ctx, pm.Type)
	}
}

// allChecks is every check this admission's rows name.
func (ev *evaluation) allChecks() []string {
	return append([]string{audit.CheckAllowList}, ev.versionChecks...)
}

// set records c for version i, replacing an earlier verdict of the same
// check. i of -1 means every version.
func (ev *evaluation) set(i int, c audit.AdmissionCheck) {
	for _, j := range ev.indexes(i) {
		ev.checks[j] = upsertCheck(ev.checks[j], c, false)
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
	ev.notRunChecks(-1, detail, ev.allChecks()...)
}

// notRunAfter is the bookkeeping for a refusal at version i: the checks that
// would have followed on i, and every check on the versions after it, never
// ran.
func (ev *evaluation) notRunAfter(i int, detail string) {
	ev.notRunChecks(i, detail, ev.versionChecks...)
	for j := i + 1; j < len(ev.checks); j++ {
		ev.notRunChecks(j, detail, ev.allChecks()...)
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
		results = append(results, ev.setResult(pm, i, c.Check(ctx, pm, &pm.Versions[i])))
	}
	return results
}

// setResult records r as version i's verdict for its check, and returns the
// verdict the caller decides on: r, or a pass when an active override
// admitted past r's block.
func (ev *evaluation) setResult(pm *manifest.PackageManifest, i int, r policy.Result) policy.Result {
	status := audit.CheckPass
	switch r.Action {
	case policy.ActionWarn:
		status = audit.CheckWarn
	case policy.ActionBlock:
		status = audit.CheckBlock
	case policy.ActionNotEvaluated:
		status = audit.CheckNotEvaluated
	}
	action := ev.actions[r.Check]
	if action == "" {
		action = audit.ActionNone
	}
	c := audit.AdmissionCheck{Check: r.Check, Action: action, Status: status, Detail: r.Reason, Provenance: r.Provenance}
	if status == audit.CheckBlock {
		if why := notOverridable(r); why == "" {
			if oc, ok := ev.admitPast(pm, i, c); ok {
				ev.set(i, oc)
				return policy.Result{Check: r.Check, Action: policy.ActionPass, Provenance: r.Provenance}
			}
		} else {
			c.Unwaivable = why
			if o, ok := ev.overrideFor(pm, i, r.Check); ok {
				c.Detail += fmt.Sprintf("; override %s does not apply: %s", o.ID, why)
			}
			if i < len(pm.Versions) && pm.Versions[i].Baseline {
				c.Detail += "; the baseline mark does not apply: " + why
			}
		}
	}
	ev.set(i, c)
	return r
}

// committer is a checker that holds a write back until the admission it
// judged is decided: the upstream provenance check's trust-on-first-use pin.
type committer interface {
	Commit(ctx context.Context) map[*manifest.VersionEntry]policy.Result
}

// commit runs every committer among checkers once an admission of pm is
// decided admitted, records any verdict that changed, and returns the changed
// verdicts per version index.
func (ev *evaluation) commit(ctx context.Context, pm *manifest.PackageManifest, checkers []policy.VersionChecker) [][]policy.Result {
	var out [][]policy.Result
	for _, c := range checkers {
		cm, ok := c.(committer)
		if !ok {
			continue
		}
		for ve, r := range cm.Commit(ctx) {
			for i := range pm.Versions {
				if &pm.Versions[i] != ve {
					continue
				}
				if out == nil {
					out = make([][]policy.Result, len(pm.Versions))
				}
				out[i] = append(out[i], ev.setResult(pm, i, r))
			}
		}
	}
	return out
}

// row renders version i as an admission row. Every row names the allow-list,
// age, OSV, upstream provenance and name similarity checks, so a consumer never has to read a
// missing entry as a pass.
func (ev *evaluation) row(pm *manifest.PackageManifest, i int, decision string, who Who) audit.Admission {
	checks := append([]audit.AdmissionCheck(nil), ev.checks[i]...)
	fill := "not run"
	if len(pm.Versions) == 0 {
		fill = "not run: the manifest names no version"
	}
	for _, name := range ev.allChecks() {
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
	if ev.overrideErr != nil {
		res.Warnings = append(res.Warnings, "overrides not read, so none applied: "+ev.overrideErr.Error())
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
	case audit.CheckUpstreamProvenance:
		return 4
	case audit.CheckNameSimilarity:
		return 5
	}
	return 6
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
