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
	"github.com/ravinald/bodega/internal/integration"
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

// RevetTarget is one admitted version, cataloged or served only from the
// proxy cache. Version is the label admission rows key it by: the version, or
// a git entry's ref.
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

// Revetter re-runs admission over versions already admitted, whether into the
// catalog or into the proxy cache: the
// allow-list, OSV, upstream provenance and each enabled integration instance
// whose revet field is on. The publish-age gate is re-run only
// when the last decision recorded it failing, since a verdict that passed
// only improves as a version gets older; see carriedAge. Each version
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
	// Age replaces the age checker a re-vet runs when carriedAge says to.
	Age func() policy.VersionChecker

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

// RevetCheckers are the per-version checks a re-vet runs: OSV, upstream
// provenance and each enabled integration instance in name order, the last
// built by integration.Checks so a re-vet and an admission in one process
// share an instance, its answer cache and its quota.
func RevetCheckers(cfg *config.Config, adb *audit.DB) []policy.VersionChecker {
	var store integration.Store
	if adb != nil {
		store = adb
	}
	out := []policy.VersionChecker{OSVChecker(cfg, adb), ProvenanceChecker(cfg, adb)}
	if cfg != nil {
		for _, c := range integration.Checks(cfg.Integrations, cfg.LogDir, store) {
			out = append(out, c.ForRevet())
		}
	}
	return out
}

// ErrNoRevetTargets is Targets finding nothing the filter names.
var ErrNoRevetTargets = errors.New("no admitted version matches")

// noCatalogEntry qualifies a refusal of a version served only from the proxy
// cache: hiding is a manifest flag, and such a version has no manifest.
const noCatalogEntry = "not hidden: no catalog entry exists to hide; the version is served from the proxy cache"

// Targets lists the versions f selects: the cataloged ones in catalog order,
// then, sorted, every version the admissions table holds an admitted or
// pinned decision for that has no catalog entry, which is what a proxy fill
// leaves behind.
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
	old := func(t, name, v string) (bool, error) {
		if f.OlderThan <= 0 {
			return true, nil
		}
		prev, err := r.previous(ctx, t, name, v)
		if err != nil {
			return false, err
		}
		return len(prev) == 0 || !prev[0].DecidedAt.After(cutoff), nil
	}
	// cataloged holds every version the walk saw, filtered out or not, so
	// the admissions pass below cannot add back one the filter dropped.
	cataloged := map[RevetTarget]bool{}
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
				cataloged[RevetTarget{Type: t, Name: name, Version: v}] = true
				if f.Version != "" && v != f.Version {
					continue
				}
				if ok, err := old(t, pm.Name, v); err != nil {
					return nil, err
				} else if !ok {
					continue
				}
				out = append(out, RevetTarget{Type: t, Name: pm.Name, Version: v})
			}
		}
	}
	admitted, err := r.DB.AdmittedVersions(ctx, audit.AdmissionFilter{PkgType: f.Type, PkgVersion: f.Version})
	if err != nil {
		// A jsonl or syslog sink keeps no table to enumerate, so only the
		// catalog can be walked; the WARN keeps that from passing unseen.
		r.logger().Warn("re-vet walked the catalog only: versions served from the proxy cache cannot be listed",
			"error", err)
		admitted = nil
	}
	for _, a := range admitted {
		safe := manifest.SafeName(a.PkgName)
		if (want != "" && safe != want) || cataloged[RevetTarget{Type: a.PkgType, Name: safe, Version: a.PkgVersion}] {
			continue
		}
		if ok, err := old(a.PkgType, a.PkgName, a.PkgVersion); err != nil {
			return nil, err
		} else if !ok {
			continue
		}
		out = append(out, RevetTarget{Type: a.PkgType, Name: a.PkgName, Version: a.PkgVersion})
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

// One re-vets a single admitted version. trigger names what asked for it
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
	pm, ve, cataloged, err := r.lookup(ctx, tg)
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
	ev := newEvaluation(ctx, r.DB, &cp, r.now())
	checkers := r.checkers()
	ev.include(ctx, &cp, checkers)
	allow := r.allowList(ctx, &out, &cp, cataloged, prev)
	if c, ok := ev.admitPast(&cp, 0, allow); ok {
		allow = c
	}
	ev.set(0, allow)
	age, rerun := carriedAge(prev, ev.actions[audit.CheckAge])
	var ageResults []policy.Result
	if rerun {
		ageResults = ev.runVersion(ctx, &cp, 0, []policy.VersionChecker{r.ageChecker()})
	} else {
		ev.set(0, age)
	}

	blocked := allow.Status == audit.CheckBlock
	if blocked {
		ev.notRunChecks(0, "not run: the allow-list refused this version", ev.versionChecks...)
	} else {
		results := append(ageResults, ev.runVersion(ctx, &cp, 0, checkers)...)
		for _, res := range results {
			if msg, ok := res.Details[integration.RevetErrorKey].(string); ok {
				out.Notes = append(out.Notes, res.Check+" could not be asked: "+msg)
			}
		}
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
		out.Action = r.onBlock(ctx, &out, ve, cataloged, trigger)
	}
	// A refusal is signed every time, so the newest envelope always carries
	// the newest refusal. A pass is signed only when it overturns one:
	// re-signing every clean re-vet would add an envelope per version per
	// interval and say nothing the admission's envelope did not.
	if blocked || out.Previous == audit.AdmissionPolicyBlocked {
		r.sign(ctx, &out, ve, cataloged, rows)
	}
	return out
}

// lookup returns the manifest and the version tg names, and whether the
// catalog holds it. A version the catalog lacks is re-vetted when the
// admissions table holds an admitted or pinned decision for it, against a
// manifest built from type and name alone, as the proxy fill's gate built it.
func (r *Revetter) lookup(ctx context.Context, tg RevetTarget) (*manifest.PackageManifest, manifest.VersionEntry, bool, error) {
	pm, err := r.Store.GetPackage(ctx, tg.Type, tg.Name)
	if err != nil {
		return nil, manifest.VersionEntry{}, false, err
	}
	if pm != nil {
		for _, ve := range pm.Versions {
			if admissionVersion(ve) == tg.Version {
				return pm, ve, true, nil
			}
		}
	}
	admitted, err := r.DB.AdmittedVersions(ctx, audit.AdmissionFilter{PkgType: tg.Type, PkgName: tg.Name, PkgVersion: tg.Version})
	if err != nil {
		return nil, manifest.VersionEntry{}, false, fmt.Errorf("%s/%s@%s is not in the catalog, and the admissions table could not be read: %w", tg.Type, tg.Name, tg.Version, err)
	}
	if len(admitted) == 0 {
		return nil, manifest.VersionEntry{}, false, fmt.Errorf("%s/%s@%s is neither in the catalog nor admitted to the proxy cache", tg.Type, tg.Name, tg.Version)
	}
	ve := manifest.VersionEntry{Version: tg.Version, Mode: manifest.ModeProxy}
	return &manifest.PackageManifest{Type: tg.Type, Name: tg.Name, Versions: []manifest.VersionEntry{ve}}, ve, false, nil
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

// allowList rules on what admission ruled on: the name for a type the list
// keys by name, the upstream URL for every other. A URL-keyed version whose
// entry names no URL, which is every version a helm, binary or apt proxy
// fill admitted, is ruled on by the upstream each of its pinned objects was
// cached from, and refused if any of them is outside the list. Without that
// the re-vet of such a version re-runs nothing, and a narrowed allow-list
// never reaches what the cache already serves.
func (r *Revetter) allowList(ctx context.Context, out *RevetOutcome, pm *manifest.PackageManifest, cataloged bool, prev []audit.Admission) audit.AdmissionCheck {
	if r.Allow == nil {
		return audit.AdmissionCheck{Check: audit.CheckAllowList, Action: audit.ActionNone, Status: audit.CheckNotEvaluated,
			Detail: "not run: no allow-list loaded"}
	}
	listed, _ := r.Allow.Listed(ctx, pm.Type)
	ve := pm.Versions[0]
	candidates := []string{policy.CandidateFor(pm.Type, pm.Name, ve.URL)}
	if candidates[0] == "" && !policy.KeysByName(pm.Type) {
		var unknown []string
		candidates, unknown = r.cacheOrigins(ctx, ve, cataloged, prev)
		for _, why := range unknown {
			out.Notes = append(out.Notes, "allow-list not re-run: the upstream of the cached object is unknown: "+why)
		}
	}
	if len(candidates) == 0 || candidates[0] == "" {
		return AllowListCheck(listed, "", nil)
	}
	var check audit.AdmissionCheck
	for i, c := range candidates {
		got := AllowListCheck(listed, c, r.Allow.Check(ctx, pm.Type, c))
		if i == 0 || got.Status == audit.CheckBlock {
			check = got
		}
		if got.Status == audit.CheckBlock {
			break
		}
	}
	return check
}

// cacheOrigins returns the distinct upstreams recorded for the objects the
// previous decision was pinned under, and for each object whose upstream
// cannot be established, why not. An origin is read only against the
// identity of the object at the key now, so bytes written over since by a
// path that fetched nothing are not credited with the fill's upstream.
func (r *Revetter) cacheOrigins(ctx context.Context, ve manifest.VersionEntry, cataloged bool, prev []audit.Admission) (origins, unknown []string) {
	var keys []string
	for _, p := range prev {
		if p.ObjectKey != "" && !slices.Contains(keys, p.ObjectKey) {
			keys = append(keys, p.ObjectKey)
		}
	}
	if len(keys) == 0 {
		return nil, []string{"no cached object of this version is on record"}
	}
	if r.Stores == nil {
		return nil, []string{"no object store is open to identify the cached object"}
	}
	for _, k := range keys {
		u, err := r.cacheOrigin(ctx, ve, cataloged, prev[0].PkgType, k)
		switch {
		case err != nil:
			unknown = append(unknown, k+": "+err.Error())
		case u == "":
			unknown = append(unknown, k+": no upstream is recorded for the object now at that key")
		case !slices.Contains(origins, u):
			origins = append(origins, u)
		}
	}
	return origins, unknown
}

func (r *Revetter) cacheOrigin(ctx context.Context, ve manifest.VersionEntry, cataloged bool, typ, key string) (string, error) {
	store, err := r.objectStore(ve, cataloged, typ, key)
	if err != nil {
		return "", err
	}
	res, err := store.GetStream(ctx, key)
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", errors.New("the object is no longer in the store")
	}
	_ = res.Body.Close()
	return r.DB.CacheOrigin(ctx, key, StreamIdentity(store, res))
}

// objectStore is the backend an object of the version lives in: the one the
// manifest records for a cataloged version, and for a proxy-cache entry the
// one its key's type resolves to, which is where the fill cached it.
func (r *Revetter) objectStore(ve manifest.VersionEntry, cataloged bool, typ, key string) (storage.ObjectStore, error) {
	if cataloged {
		return r.Stores.ByName(ve.Storage)
	}
	if t, _, _ := manifest.ParseKey(key); t != "" {
		typ = t
	}
	return r.Stores.ForType(typ), nil
}

// StreamIdentity is what the store said about the object an open handle is
// on, in the form the audit store compares. A fill records its origin under
// this identity and a re-vet reads it back under this identity, so the two
// cannot drift apart. The zero value is what a caller with no metadata in
// hand produces, and it matches no recorded origin.
func StreamIdentity(store storage.ObjectStore, res *storage.StreamResult) audit.ObjectIdentity {
	if store == nil || res == nil {
		return audit.ObjectIdentity{}
	}
	obj := audit.ObjectIdentity{
		Backend: store.Label(),
		Size:    res.ContentLength,
		ETag:    res.ETag,
	}
	if !res.LastModified.IsZero() {
		obj.Modified = res.LastModified.UTC().Format(time.RFC3339Nano)
	}
	return obj
}

// carriedAge is the age entry of a re-vet row, or true when the gate has to
// be re-run instead. A pass or a warn is carried with its date, because a
// version that was old enough at the last decision is older now. A block, an
// override or a baseline mark is re-run: the version may have aged past the
// minimum since, and an override or a mark may no longer apply, so carrying
// either would cite an exception nobody holds. A verdict nobody evaluated is
// not a verdict, and is neither carried nor re-run.
func carriedAge(prev []audit.Admission, action string) (audit.AdmissionCheck, bool) {
	if action == "" {
		action = audit.ActionNone
	}
	if len(prev) > 0 {
		for _, c := range prev[0].Checks {
			if c.Check != audit.CheckAge {
				continue
			}
			switch c.Status {
			case audit.CheckPass, audit.CheckWarn:
				c.Detail = fmt.Sprintf("not re-run, carried from the decision of %s: %s",
					prev[0].DecidedAt.UTC().Format(time.RFC3339), c.Detail)
				return c, false
			case audit.CheckBlock, audit.CheckOverridden, audit.CheckBaseline:
				return audit.AdmissionCheck{}, true
			}
		}
	}
	return audit.AdmissionCheck{Check: audit.CheckAge, Action: action, Status: audit.CheckNotEvaluated,
		Detail: "not re-run: a version only gets older, and no earlier decision on record evaluated it"}, false
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
	if ev.overrideErr != nil {
		out.Notes = append(out.Notes, "overrides not read, so none applied: "+ev.overrideErr.Error())
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
func (r *Revetter) onBlock(ctx context.Context, out *RevetOutcome, ve manifest.VersionEntry, cataloged bool, trigger string) string {
	action := RevetReported
	switch {
	case !cataloged:
		out.Notes = append(out.Notes, noCatalogEntry)
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
	r.logger().Warn("re-vet refused an admitted version", "cataloged", cataloged,
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

// sign writes the envelope for each row that names an object, beside the
// object: in the backend the manifest records for a cataloged version, and
// for a proxy-cache entry in the one its key's type resolves to, which is
// where the fill cached it and signed its first envelope.
func (r *Revetter) sign(ctx context.Context, out *RevetOutcome, ve manifest.VersionEntry, cataloged bool, rows []audit.Admission) {
	if r.Emitter == nil || r.Stores == nil {
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
		into, err := r.objectStore(ve, cataloged, row.PkgType, row.ObjectKey)
		if err != nil {
			out.Notes = append(out.Notes, "no envelope signed: "+err.Error())
			return
		}
		p := attest.Pin{Type: row.PkgType, Name: row.PkgName, Version: row.PkgVersion, ObjectKey: row.ObjectKey,
			SHA256: sum.Value, RequiredBy: ve.RequiredBy}
		emit := r.Emitter.Emit
		if row.Decision == audit.AdmissionPolicyBlocked {
			emit = r.Emitter.Revoke
		}
		key, err := emit(ctx, into, p)
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

// ageChecker judges age at the re-vet's clock, so a test moving Now moves
// how old the version is along with which overrides are active.
func (r *Revetter) ageChecker() policy.VersionChecker {
	if r.Age != nil {
		return r.Age()
	}
	c := policy.NewAgeChecker(r.DB)
	c.Now = r.now
	return c
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
