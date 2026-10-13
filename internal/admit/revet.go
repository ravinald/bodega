package admit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/storage"
)

// RevetActor is the actor a re-vet's rows and hides are recorded under. It
// names the mechanism rather than whoever triggered it, so every version
// bodega refused on its own after admitting it is one filter away; the
// trigger is in the row's identity.
const RevetActor = "revet"

// What a re-vet did about a version it refused.
const (
	RevetNone     = "none"     // the version passed
	RevetReported = "reported" // audit event and WARN, still served
	RevetHidden   = "hidden"
	// RevetFrozen is a refused version left served because it is frozen.
	// Freezing is an operator's statement that the version must not change,
	// and a re-vet overruling it would take a pinned fleet offline with
	// nobody in the loop.
	RevetFrozen        = "frozen"
	RevetAlreadyHidden = "already_hidden"
)

// RevetFilter selects the versions a re-vet walks. An empty field matches
// everything. OlderThan keeps only versions whose newest decision is older
// than that, a version with no decision on record included.
type RevetFilter struct {
	Type, Name, Version string
	OlderThan           time.Duration
}

// RevetTarget is one cataloged version. Version is the label admission rows
// key it by: the version, or a git entry's ref.
type RevetTarget struct {
	Type, Name, Version string
}

// RevetOutcome is one version's re-vet.
type RevetOutcome struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Previous string `json:"previous_decision,omitempty"`
	Decision string `json:"decision,omitempty"`
	Action   string `json:"action,omitempty"`
	// Failing are the checks that refused, in row order.
	Failing []audit.AdmissionCheck `json:"failing,omitempty"`
	// Envelopes are the attestation keys this re-vet signed.
	Envelopes []string `json:"envelopes,omitempty"`
	// Notes are what qualified the outcome: a row not written, an envelope
	// not signed, a hide not saved.
	Notes []string `json:"notes,omitempty"`
	Error string   `json:"error,omitempty"`
}

// Blocked reports whether the re-vet refused the version.
func (o RevetOutcome) Blocked() bool { return o.Decision == audit.AdmissionPolicyBlocked }

// RevetSummary counts one sweep.
type RevetSummary struct {
	Walked, Admitted, Blocked, Hidden, Frozen, Errors int
}

// Add folds one outcome in.
func (s *RevetSummary) Add(o RevetOutcome) {
	s.Walked++
	switch {
	case o.Error != "":
		s.Errors++
	case o.Blocked():
		s.Blocked++
	default:
		s.Admitted++
	}
	switch o.Action {
	case RevetHidden:
		s.Hidden++
	case RevetFrozen:
		s.Frozen++
	}
}

// Revetter re-runs admission over versions already in the catalog: the
// allow-list, OSV and upstream provenance, everything but the publish-age
// gate, whose verdict only improves as a version gets older. Each version
// gets a new admission row beside the old one, so the table reads as the
// history of what bodega concluded about it and when.
type Revetter struct {
	Cfg   *config.Config
	DB    *audit.DB
	Store *manifest.Store
	// Allow is the upstream allow-list; nil records it as not run.
	Allow *policy.Checker
	// OnBlock is revet_on_block: config.RevetReport or config.RevetHide.
	OnBlock string
	// Checkers replaces RevetCheckers, for a test that drives a verdict.
	Checkers func() []policy.VersionChecker

	// Write is held around the read-modify-write of a hide, so it cannot
	// interleave with another writer of the same manifest. Nil holds nothing.
	Write sync.Locker
	// Saved runs after a hide reaches the store: the server's index rebuild.
	Saved func(ctx context.Context, typ string)

	// Emitter and Stores sign the envelope a refusal leaves behind. Either
	// nil signs nothing, and the outcome says so.
	Emitter *attest.Emitter
	Stores  storage.Resolver

	Logger *slog.Logger
	Now    func() time.Time

	// serial is what keeps two re-vets of anything from running at once, a
	// sweep and a webhook call included: each version is decided under it.
	serial sync.Mutex
}

// RevetCheckers are the per-version checks a re-vet runs: VersionCheckers
// without the age gate.
func RevetCheckers(cfg *config.Config, adb *audit.DB) []policy.VersionChecker {
	return []policy.VersionChecker{OSVChecker(cfg, adb), ProvenanceChecker(cfg, adb)}
}

// ErrNoRevetTargets is Targets finding nothing the filter names.
var ErrNoRevetTargets = errors.New("no cataloged version matches")

// Targets lists the cataloged versions f selects, in catalog order.
func (r *Revetter) Targets(ctx context.Context, f RevetFilter) ([]RevetTarget, error) {
	if r.DB == nil {
		return nil, errors.New("no audit store is open; a re-vet writes admission rows and has nowhere to write them")
	}
	if f.Type != "" && !manifest.IsKnownType(f.Type) {
		return nil, fmt.Errorf("unknown type %q (want one of %s)", f.Type, strings.Join(manifest.AllTypes, ", "))
	}
	if f.OlderThan > 0 && !r.DB.EventsQueryable() {
		return nil, fmt.Errorf("--older-than reads the admissions table, and audit_sink %s keeps none this process can query", r.DB.SinkName())
	}
	types := manifest.AllTypes
	if f.Type != "" {
		types = []string{f.Type}
	}
	// The index keys packages by SafeName, which collapses "/" to "--", so
	// an operator's spelling of a scoped npm name or a module path is
	// compared in that form.
	want := ""
	if f.Name != "" {
		want = manifest.SafeName(f.Name)
	}
	cutoff := r.now().Add(-f.OlderThan)
	var out []RevetTarget
	for _, t := range types {
		for _, name := range r.Store.ListPackages(t) {
			if want != "" && name != want {
				continue
			}
			pm, err := r.Store.GetPackage(ctx, t, name)
			if err != nil {
				return nil, err
			}
			if pm == nil {
				continue
			}
			for _, ve := range pm.Versions {
				v := admissionVersion(ve)
				if f.Version != "" && v != f.Version {
					continue
				}
				if f.OlderThan > 0 {
					prev, err := r.previous(ctx, t, pm.Name, v)
					if err != nil {
						return nil, err
					}
					if len(prev) > 0 && prev[0].DecidedAt.After(cutoff) {
						continue
					}
				}
				out = append(out, RevetTarget{Type: t, Name: pm.Name, Version: v})
			}
		}
	}
	if len(out) == 0 && (f.Name != "" || f.Version != "") {
		return nil, ErrNoRevetTargets
	}
	return out, nil
}

// Sweep re-vets every target, pause apart, and returns each outcome. It
// stops early when ctx ends, with the outcomes it reached.
func (r *Revetter) Sweep(ctx context.Context, targets []RevetTarget, trigger string, pause time.Duration, each func(RevetOutcome)) RevetSummary {
	var sum RevetSummary
	for i, tg := range targets {
		if i > 0 && pause > 0 {
			select {
			case <-ctx.Done():
				return sum
			case <-time.After(pause):
			}
		}
		if ctx.Err() != nil {
			return sum
		}
		o := r.One(ctx, tg, trigger)
		sum.Add(o)
		if each != nil {
			each(o)
		}
	}
	return sum
}

// One re-vets a single cataloged version. trigger names what asked for it
// ("schedule", "webhook", or the operator's name) and is recorded as the
// row's identity.
func (r *Revetter) One(ctx context.Context, tg RevetTarget, trigger string) RevetOutcome {
	r.serial.Lock()
	defer r.serial.Unlock()

	out := RevetOutcome{Type: tg.Type, Name: tg.Name, Version: tg.Version}
	if r.DB == nil {
		out.Error = "no audit store is open"
		return out
	}
	pm, ve, err := r.lookup(ctx, tg)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	prev, err := r.previous(ctx, tg.Type, tg.Name, tg.Version)
	if err != nil {
		// A write-only sink has no history to read, and the re-vet is
		// still worth recording: its rows carry no object key and no
		// carried age verdict, and the note says why.
		out.Notes = append(out.Notes, "no earlier decision read: "+err.Error())
	}
	if len(prev) > 0 {
		out.Previous = prev[0].Decision
	}

	// A copy of the one version, so a check cannot write into the entry the
	// store serves from.
	cp := *pm
	cp.Versions = []manifest.VersionEntry{ve}
	ev := newEvaluation(ctx, r.DB, &cp)
	allow := r.allowList(ctx, &cp)
	ev.set(0, allow)
	ev.set(0, carriedAge(prev, ev.actions[audit.CheckAge]))

	blocked := allow.Status == audit.CheckBlock
	if blocked {
		ev.notRunChecks(0, "not run: the allow-list refused this version", audit.CheckOSV, audit.CheckUpstreamProvenance)
	} else {
		checkers := r.checkers()
		results := ev.runVersion(ctx, &cp, 0, checkers)
		combined := policy.Combine(results)
		if !combined.Blocked() {
			if changed := ev.commit(ctx, &cp, checkers); changed != nil {
				combined = policy.Combine(replaceResults(results, changed[0]))
			}
		}
		blocked = combined.Blocked()
	}

	out.Decision = audit.AdmissionAdmitted
	if blocked {
		out.Decision = audit.AdmissionPolicyBlocked
	}
	rows := r.record(ctx, &out, ev, &cp, prev, trigger)
	for _, c := range rows[0].Checks {
		if c.Status == audit.CheckBlock {
			out.Failing = append(out.Failing, c)
		}
	}

	out.Action = RevetNone
	if blocked {
		out.Action = r.onBlock(ctx, &out, ve, trigger)
	}
	// A refusal is signed every time, so the newest envelope always carries
	// the newest refusal. A pass is signed only when it overturns one:
	// re-signing every clean re-vet would add an envelope per version per
	// interval and say nothing the admission's envelope did not.
	if blocked || out.Previous == audit.AdmissionPolicyBlocked {
		r.sign(ctx, &out, ve, rows)
	}
	return out
}

// lookup returns the manifest and the version tg names.
func (r *Revetter) lookup(ctx context.Context, tg RevetTarget) (*manifest.PackageManifest, manifest.VersionEntry, error) {
	pm, err := r.Store.GetPackage(ctx, tg.Type, tg.Name)
	if err != nil {
		return nil, manifest.VersionEntry{}, err
	}
	if pm != nil {
		for _, ve := range pm.Versions {
			if admissionVersion(ve) == tg.Version {
				return pm, ve, nil
			}
		}
	}
	return nil, manifest.VersionEntry{}, fmt.Errorf("%s/%s@%s is no longer in the catalog", tg.Type, tg.Name, tg.Version)
}

// previous is the newest decision on record for the version: every row
// sharing the newest decided_at, which is one per object key a pypi release
// was pinned under.
func (r *Revetter) previous(ctx context.Context, typ, name, version string) ([]audit.Admission, error) {
	if !r.DB.EventsQueryable() {
		return nil, fmt.Errorf("audit_sink %s keeps no admissions table this process can query", r.DB.SinkName())
	}
	rows, err := r.DB.Admissions(ctx, audit.AdmissionFilter{PkgType: typ, PkgName: name, PkgVersion: version, Limit: 200})
	if err != nil {
		return nil, err
	}
	var out []audit.Admission
	for _, row := range rows {
		// An empty filter field matches everything.
		if row.PkgVersion != version {
			continue
		}
		if len(out) > 0 && !row.DecidedAt.Equal(out[0].DecidedAt) {
			break
		}
		out = append(out, row)
	}
	return out, nil
}

func (r *Revetter) allowList(ctx context.Context, pm *manifest.PackageManifest) audit.AdmissionCheck {
	if r.Allow == nil {
		return audit.AdmissionCheck{Check: audit.CheckAllowList, Action: audit.ActionNone, Status: audit.CheckNotEvaluated,
			Detail: "not run: no allow-list loaded"}
	}
	hasRules, _ := r.Allow.HasRules(ctx, pm.Type)
	candidate := policy.CandidateFor(pm.Type, pm.Name, pm.Versions[0].URL)
	if candidate == "" {
		return AllowListCheck(hasRules, "", nil)
	}
	return AllowListCheck(hasRules, candidate, r.Allow.Check(ctx, pm.Type, candidate))
}

// carriedAge is the age entry of a re-vet row. The gate is not re-run,
// because a version that was old enough at admission is older now, so the
// verdict the last decision recorded is carried with its date. A block or a
// verdict nobody evaluated is not carried: the first cannot have admitted the
// version, and the second is not a verdict.
func carriedAge(prev []audit.Admission, action string) audit.AdmissionCheck {
	if action == "" {
		action = audit.ActionNone
	}
	if len(prev) > 0 {
		for _, c := range prev[0].Checks {
			if c.Check == audit.CheckAge && (c.Status == audit.CheckPass || c.Status == audit.CheckWarn) {
				c.Detail = fmt.Sprintf("not re-run, carried from the decision of %s: %s",
					prev[0].DecidedAt.UTC().Format(time.RFC3339), c.Detail)
				return c
			}
		}
	}
	return audit.AdmissionCheck{Check: audit.CheckAge, Action: action, Status: audit.CheckNotEvaluated,
		Detail: "not re-run: a version only gets older, and no earlier decision on record evaluated it"}
}

// record writes the re-vet's rows: one per object key the previous decision
// was pinned under, so the envelope for each key has a row to cite, or one
// with no key when nothing was pinned. Every row shares one decided_at,
// which is what makes them copies of one decision.
func (r *Revetter) record(ctx context.Context, out *RevetOutcome, ev *evaluation, pm *manifest.PackageManifest, prev []audit.Admission, trigger string) []audit.Admission {
	var keys []string
	for _, p := range prev {
		if p.ObjectKey != "" && !slices.Contains(keys, p.ObjectKey) {
			keys = append(keys, p.ObjectKey)
		}
	}
	if len(keys) == 0 {
		keys = []string{""}
	}
	if ev.digestErr != nil {
		out.Notes = append(out.Notes, "recorded with no policy digest: "+ev.digestErr.Error())
	}
	now := r.now().UTC()
	rows := make([]audit.Admission, 0, len(keys))
	for _, k := range keys {
		row := ev.row(pm, 0, out.Decision, Who{Actor: RevetActor, Identity: trigger})
		row.ObjectKey = k
		row.DecidedAt = now
		if err := r.DB.RecordAdmission(ctx, row); err != nil {
			out.Notes = append(out.Notes, "admission row not written: "+err.Error())
		}
		rows = append(rows, row)
	}
	return rows
}

// onBlock applies revet_on_block to a refused version and records what it
// did.
func (r *Revetter) onBlock(ctx context.Context, out *RevetOutcome, ve manifest.VersionEntry, trigger string) string {
	action := RevetReported
	switch {
	case ve.Frozen:
		action = RevetFrozen
	case ve.Hidden:
		action = RevetAlreadyHidden
	case r.OnBlock == config.RevetHide:
		if err := r.hide(ctx, out); err != nil {
			out.Notes = append(out.Notes, "not hidden: "+err.Error())
		} else {
			action = RevetHidden
		}
	}
	details, _ := json.Marshal(map[string]any{
		"decision": out.Decision, "previous_decision": out.Previous, "action": action,
		"failing": out.Failing, "trigger": trigger,
	})
	if err := r.DB.Record(ctx, audit.Event{
		EventType: audit.EventRevet, PkgType: out.Type, PkgName: out.Name, PkgVersion: out.Version,
		Actor: RevetActor, Status: "policy_violation", Details: string(details),
	}); err != nil {
		out.Notes = append(out.Notes, "audit event not written: "+err.Error())
	}
	r.logger().Warn("re-vet refused a cataloged version",
		"type", out.Type, "package", out.Name, "version", out.Version, "action", action,
		"previous", out.Previous, "failing", failingSummary(out.Failing))
	return action
}

// hide sets the version hidden and saves the manifest, as `bodega pkg hide`
// does, and writes the hide event under RevetActor with the failing checks.
// The manifest is re-read under Write, because the copy the checks ran on
// may be minutes old by the time a slow registry answered.
func (r *Revetter) hide(ctx context.Context, out *RevetOutcome) error {
	if r.Write != nil {
		r.Write.Lock()
		defer r.Write.Unlock()
	}
	pm, err := r.Store.GetPackage(ctx, out.Type, out.Name)
	if err != nil {
		return err
	}
	if pm == nil {
		return errors.New("the package is no longer in the catalog")
	}
	found := false
	for i := range pm.Versions {
		ve := &pm.Versions[i]
		if admissionVersion(*ve) != out.Version {
			continue
		}
		if ve.Frozen {
			return errors.New("the version was frozen while the re-vet ran")
		}
		ve.Hidden = true
		found = true
	}
	if !found {
		return errors.New("the version is no longer in the catalog")
	}
	if err := r.Store.SavePackage(ctx, pm); err != nil {
		return err
	}
	if r.Saved != nil {
		r.Saved(ctx, out.Type)
	}
	details, _ := json.Marshal(map[string]any{"hidden": true, "failing": out.Failing})
	if err := r.DB.Record(ctx, audit.Event{
		EventType: audit.EventHide, PkgType: out.Type, PkgName: out.Name, PkgVersion: out.Version,
		Actor: RevetActor, Status: "success", Details: string(details),
	}); err != nil {
		out.Notes = append(out.Notes, "hidden, but the hide event was not written: "+err.Error())
	}
	return nil
}

// sign writes the envelope for each row that names an object.
func (r *Revetter) sign(ctx context.Context, out *RevetOutcome, ve manifest.VersionEntry, rows []audit.Admission) {
	if r.Emitter == nil || r.Stores == nil {
		return
	}
	store, err := r.Stores.ByName(ve.Storage)
	if err != nil {
		out.Notes = append(out.Notes, "no envelope signed: "+err.Error())
		return
	}
	for _, row := range rows {
		if row.ObjectKey == "" {
			out.Notes = append(out.Notes, "no envelope signed: no object of this version is pinned")
			continue
		}
		sum, err := r.DB.GetChecksum(ctx, row.ObjectKey)
		if err != nil || sum == nil || !strings.EqualFold(sum.Algorithm, "sha256") {
			out.Notes = append(out.Notes, "no envelope signed for "+row.ObjectKey+": no sha256 pinned for it")
			continue
		}
		p := attest.Pin{Type: row.PkgType, Name: row.PkgName, Version: row.PkgVersion, ObjectKey: row.ObjectKey,
			SHA256: sum.Value, RequiredBy: ve.RequiredBy}
		emit := r.Emitter.Emit
		if row.Decision == audit.AdmissionPolicyBlocked {
			emit = r.Emitter.Revoke
		}
		key, err := emit(ctx, store, p)
		switch {
		case err != nil:
			out.Notes = append(out.Notes, "no envelope signed for "+row.ObjectKey+": "+err.Error())
		case key != "":
			out.Envelopes = append(out.Envelopes, key)
		}
	}
}

func (r *Revetter) checkers() []policy.VersionChecker {
	if r.Checkers != nil {
		return r.Checkers()
	}
	return RevetCheckers(r.Cfg, r.DB)
}

func (r *Revetter) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Revetter) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func failingSummary(checks []audit.AdmissionCheck) string {
	parts := make([]string, 0, len(checks))
	for _, c := range checks {
		parts = append(parts, c.Check+": "+c.Detail)
	}
	return strings.Join(parts, "; ")
}
