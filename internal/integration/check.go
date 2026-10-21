package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// Store is what an instance's check reads its action from and records its
// failures in. *audit.DB satisfies it.
type Store interface {
	GetIntegrationPolicy(ctx context.Context, instance, ecosystem string) (audit.IntegrationPolicy, error)
	RecordIntegrationError(ctx context.Context, instance, message string) error
}

// Action is the instance's action for an ecosystem: its integration_policy
// row, or the descriptor's default when there is none. A store that cannot
// answer reads as block, so a broken policy table never admits on an
// integration that would have refused.
func Action(ctx context.Context, store Store, inst *Instance, ecosystem string) string {
	if store == nil {
		return inst.Descriptor.DefaultAction
	}
	p, err := store.GetIntegrationPolicy(ctx, inst.Name, ecosystem)
	switch {
	case err == nil:
		return p.Action
	case errors.Is(err, audit.ErrIntegrationPolicyNotFound):
		return inst.Descriptor.DefaultAction
	}
	return policy.ActionBlock
}

// VersionCheck runs one enabled instance as an admission check.
type VersionCheck struct {
	inst  *Instance
	impl  Checker
	store Store
	cache *answerCache
	// buildErr is why the instance could not be built. Every check then
	// records it as an error under the action rather than skipping.
	buildErr error
	now      func() time.Time
	// held is the error a Prefetch got for each purl. It lives on this copy
	// only, so it lasts one admission and never reaches the answer cache.
	held map[string]error
	// revet asks as a re-vet does: an instance with revet off is not asked,
	// and an error rules nothing, since the version was already admitted on
	// evidence and an outage adds none.
	revet bool
}

// ForRevet is this check as a re-vet runs it. It shares the instance's
// answer cache and whatever quota state its type holds.
func (c VersionCheck) ForRevet() *VersionCheck {
	c.revet = true
	return &c
}

// RevetErrorKey is the Details key a re-vet result carries the lookup error
// under, so the re-vet can say which instance could not be asked.
const RevetErrorKey = "revet_error"

// Instance is the configured instance this check runs.
func (c *VersionCheck) Instance() *Instance { return c.inst }

// CheckName is the check name the admission row carries.
func (c *VersionCheck) CheckName() string { return c.inst.CheckName() }

// ActionFor is the action the admission row records for ecosystem.
func (c *VersionCheck) ActionFor(ctx context.Context, ecosystem string) string {
	return Action(ctx, c.store, c.inst, ecosystem)
}

// Check asks the instance about one version.
func (c *VersionCheck) Check(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) policy.Result {
	r := policy.Result{Check: c.CheckName(), Action: policy.ActionPass}
	d := c.inst.Descriptor
	if c.revet && c.buildErr == nil && !c.inst.Bool(KeyRevet) {
		r.Action = policy.ActionNotEvaluated
		r.Reason = "not re-run: revet is off for this instance"
		return r
	}
	if !d.Covers(pm.Type) {
		r.Action = policy.ActionNotEvaluated
		r.Reason = fmt.Sprintf("%s covers %s, not %s", d.DisplayName, strings.Join(d.Ecosystems, ", "), pm.Type)
		return r
	}
	version := strings.TrimSpace(ve.Version)
	if version == "" || version == "*" {
		r.Action = policy.ActionNotEvaluated
		r.Reason = "no concrete version to ask about"
		return r
	}
	q := Query{Ecosystem: pm.Type, Name: pm.Name, Version: version}
	action := c.ActionFor(ctx, pm.Type)
	type answered struct {
		a   Answer
		err error
	}
	got := policy.SharedLookup(ctx, c.CheckName()+"\x00"+q.PURL(), func() answered {
		a, err := c.lookup(ctx, q)
		return answered{a, err}
	})
	a, err := got.a, got.err
	switch {
	case err != nil:
		if c.store != nil {
			_ = c.store.RecordIntegrationError(ctx, c.inst.Name, err.Error())
		}
		r.Details = map[string]any{"instance": c.inst.Name, "outcome": "error", "purl": q.PURL()}
		if c.revet {
			r.Action = policy.ActionNotEvaluated
			r.Reason = "not re-run: " + err.Error()
			r.Details[RevetErrorKey] = err.Error()
			return r
		}
		r.Action = action
		r.Reason = "error: " + err.Error()
	case a.Flagged:
		r.Action = action
		r.Reason = a.Reason
		r.Details = map[string]any{"instance": c.inst.Name, "outcome": "flagged", "purl": q.PURL()}
		if d.EffectiveFlag(a) == FlagMalware {
			r.Details["malware"] = []string{c.CheckName()}
		}
	default:
		r.Reason = "not flagged by " + d.DisplayName
		if a.Reason != "" {
			r.Reason += ": " + a.Reason
		}
	}
	return r
}

// Probe asks the instance about its descriptor's well-known package,
// bypassing the cache, for `bodega integration test`.
func (c *VersionCheck) Probe(ctx context.Context) (Query, Answer, time.Duration, error) {
	q := c.inst.Descriptor.Probe
	if c.buildErr != nil {
		return q, Answer{}, 0, c.buildErr
	}
	start := time.Now()
	if err := c.prepare(ctx, q.Ecosystem); err != nil {
		return q, Answer{}, time.Since(start), err
	}
	ctx, cancel := context.WithTimeout(ctx, c.inst.Duration(KeyTimeout))
	defer cancel()
	a, err := c.impl.Lookup(ctx, q)
	return q, a, time.Since(start), err
}

func (c *VersionCheck) prepare(ctx context.Context, ecosystem string) error {
	if p, ok := c.impl.(Preparer); ok {
		return p.Prepare(ctx, ecosystem)
	}
	return nil
}

func (c *VersionCheck) lookup(ctx context.Context, q Query) (Answer, error) {
	if c.buildErr != nil {
		return Answer{}, c.buildErr
	}
	key := q.PURL()
	if a, ok := c.cache.get(key, c.now()); ok {
		return a, nil
	}
	if err, ok := c.held[key]; ok {
		return Answer{}, err
	}
	if err := c.prepare(ctx, q.Ecosystem); err != nil {
		return Answer{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.inst.Duration(KeyTimeout))
	defer cancel()
	a, err := c.impl.Lookup(ctx, q)
	if err != nil {
		return Answer{}, withDeadline(ctx, err)
	}
	// Only answers are cached. An error is retried on the next admission,
	// so an outage ends when the vendor is back rather than when a TTL does.
	c.cache.put(key, a, c.now().Add(c.inst.Duration(KeyCacheTTL)))
	return a, nil
}

// withDeadline names the context's end in a lookup error that does not
// already say it, so a timeout reads as one.
func withDeadline(ctx context.Context, err error) error {
	if ctx.Err() != nil && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", ctx.Err(), err)
	}
	return err
}

// Prefetch asks a BatchChecker about every version of pm that Check would
// send it, in as few requests as its batch limit allows, so the per-version
// Check that follows reads the answers from the cache. A vendor that meters
// requests then charges one request per admission rather than one per
// version. Any other type, or an instance that did not build, sends nothing
// here and is asked by Check as before.
func (c *VersionCheck) Prefetch(ctx context.Context, pm *manifest.PackageManifest) {
	bc, ok := c.impl.(BatchChecker)
	if !ok || c.buildErr != nil || !c.inst.Descriptor.Covers(pm.Type) {
		return
	}
	now := c.now()
	seen := map[string]bool{}
	var qs []Query
	for _, ve := range pm.Versions {
		version := strings.TrimSpace(ve.Version)
		if version == "" || version == "*" {
			continue
		}
		q := Query{Ecosystem: pm.Type, Name: pm.Name, Version: version}
		key := q.PURL()
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, ok := c.cache.get(key, now); !ok {
			qs = append(qs, q)
		}
	}
	if len(qs) == 0 {
		return
	}
	c.held = map[string]error{}
	if err := c.prepare(ctx, pm.Type); err != nil {
		for _, q := range qs {
			c.held[q.PURL()] = err
		}
		return
	}
	limit := max(bc.BatchLimit(), 1)
	for chunk := range slices.Chunk(qs, limit) {
		c.prefetchChunk(ctx, bc, chunk)
	}
}

func (c *VersionCheck) prefetchChunk(ctx context.Context, bc BatchChecker, qs []Query) {
	ctx, cancel := context.WithTimeout(ctx, c.inst.Duration(KeyTimeout))
	defer cancel()
	got := bc.LookupBatch(ctx, qs)
	expires := c.now().Add(c.inst.Duration(KeyCacheTTL))
	for _, q := range qs {
		key := q.PURL()
		r, ok := got[key]
		switch {
		case !ok:
			c.held[key] = fmt.Errorf("%s returned no answer for %s", c.inst.Descriptor.DisplayName, key)
		case r.Err != nil:
			c.held[key] = withDeadline(ctx, r.Err)
		default:
			c.cache.put(key, r.Answer, expires)
		}
	}
}

type cachedAnswer struct {
	answer  Answer
	expires time.Time
}

// answerCacheMax bounds one instance's cache. Past it the cache is emptied
// rather than evicted entry by entry: an install admitting this many distinct
// versions inside one TTL loses only the reuse, not correctness.
const answerCacheMax = 100_000

type answerCache struct {
	mu      sync.Mutex
	entries map[string]cachedAnswer
}

func (c *answerCache) get(key string, now time.Time) (Answer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !now.Before(e.expires) {
		return Answer{}, false
	}
	return e.answer, true
}

func (c *answerCache) put(key string, a Answer, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) >= answerCacheMax {
		c.entries = map[string]cachedAnswer{}
	}
	c.entries[key] = cachedAnswer{answer: a, expires: expires}
}

// live is one built instance, kept across admissions so its cache and any
// state its type holds (a downloaded list) outlive a single call.
type live struct {
	fingerprint string
	check       *VersionCheck
}

var (
	liveMu sync.Mutex
	lives  = map[string]*live{}
)

// Checks returns a check for every enabled instance in raw, sorted by name.
// An instance is built once and reused for as long as its entry is
// unchanged, so its cache survives from one admission to the next. An entry
// that no longer validates becomes a check that records the validation error
// under its action on every version, rather than one that silently stops
// running.
//
// logDir is the config's log_dir. Each instance keeps its files in its
// StateDir under it.
func Checks(raw map[string]config.Integration, logDir string, store Store) []*VersionCheck {
	names := make([]string, 0, len(raw))
	for n := range raw {
		names = append(names, n)
	}
	sort.Strings(names)
	liveMu.Lock()
	defer liveMu.Unlock()
	var out []*VersionCheck
	for _, n := range names {
		enabled, _ := raw[n]["enabled"].(bool)
		if !enabled {
			continue
		}
		fp, _ := json.Marshal([]any{logDir, raw[n]})
		if l, ok := lives[n]; ok && l.fingerprint == string(fp) {
			c := *l.check
			c.store = store
			out = append(out, &c)
			continue
		}
		c := build(n, raw[n], logDir)
		lives[n] = &live{fingerprint: string(fp), check: c}
		cp := *c
		cp.store = store
		out = append(out, &cp)
	}
	return out
}

// Build constructs one instance's check whether or not it is enabled, for
// `bodega integration test`. Its cache is its own.
func Build(name string, raw config.Integration, logDir string, store Store) *VersionCheck {
	c := build(name, raw, logDir)
	c.store = store
	return c
}

// Clock is what an instance built after it is set reads the time from: its
// answer cache's expiry and whatever its type times itself, such as a list's
// refresh. A test outside this package replaces it to move both at once.
var Clock = time.Now

func build(name string, raw config.Integration, logDir string) *VersionCheck {
	inst, err := ValidateInstance(name, raw)
	if err != nil {
		t, _ := raw["type"].(string)
		d, ok := Lookup(t)
		if !ok {
			d = &Descriptor{Type: t, DisplayName: name, DefaultAction: policy.ActionBlock}
		}
		return &VersionCheck{inst: &Instance{Name: name, Descriptor: d, StateDir: StateDir(logDir, name), values: map[string]any{}}, buildErr: err,
			cache: &answerCache{}, now: Clock}
	}
	inst.StateDir = StateDir(logDir, name)
	impl, err := inst.Descriptor.New(inst)
	return &VersionCheck{inst: inst, impl: impl, buildErr: err, cache: &answerCache{}, now: Clock}
}

// RunTest makes one real query for the instance's probe package and writes
// the answer, the latency and any quota the vendor reported. It is
// `bodega integration test` and the TUI's Test action. A failed query is
// recorded as the instance's last error and returned. logDir is the config's
// log_dir, as Checks takes it.
func RunTest(ctx context.Context, out io.Writer, name string, entry config.Integration, logDir string, store Store) error {
	c := Build(name, entry, logDir, store)
	q, a, latency, err := c.Probe(ctx)
	fmt.Fprintf(out, "query:   %s\nlatency: %s\n", q.PURL(), latency.Round(time.Millisecond))
	if err != nil {
		if store != nil {
			_ = store.RecordIntegrationError(ctx, name, err.Error())
		}
		fmt.Fprintf(out, "answer:  error: %v\n", err)
		return fmt.Errorf("%s: %w", name, err)
	}
	verdict := "not flagged"
	if a.Flagged {
		verdict = "flagged"
	}
	fmt.Fprintf(out, "answer:  %s", verdict)
	if a.Reason != "" {
		fmt.Fprintf(out, " (%s)", a.Reason)
	}
	quota := a.Quota
	if quota == "" {
		quota = "none reported"
	}
	fmt.Fprintf(out, "\nquota:   %s\n", quota)
	return nil
}
