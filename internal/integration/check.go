package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
}

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
		r.Action = action
		r.Reason = "error: " + err.Error()
		r.Details = map[string]any{"instance": c.inst.Name, "outcome": "error", "purl": q.PURL()}
	case a.Flagged:
		r.Action = action
		r.Reason = a.Reason
		r.Details = map[string]any{"instance": c.inst.Name, "outcome": "flagged", "purl": q.PURL()}
	default:
		r.Reason = "not flagged by " + d.DisplayName
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
	ctx, cancel := context.WithTimeout(ctx, c.inst.Duration(KeyTimeout))
	defer cancel()
	a, err := c.impl.Lookup(ctx, q)
	return q, a, time.Since(start), err
}

func (c *VersionCheck) lookup(ctx context.Context, q Query) (Answer, error) {
	if c.buildErr != nil {
		return Answer{}, c.buildErr
	}
	key := q.PURL()
	if a, ok := c.cache.get(key, c.now()); ok {
		return a, nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.inst.Duration(KeyTimeout))
	defer cancel()
	a, err := c.impl.Lookup(ctx, q)
	if err != nil {
		if ctx.Err() != nil && !errors.Is(err, context.DeadlineExceeded) {
			err = fmt.Errorf("%w: %v", ctx.Err(), err)
		}
		return Answer{}, err
	}
	// Only answers are cached. An error is retried on the next admission,
	// so an outage ends when the vendor is back rather than when a TTL does.
	c.cache.put(key, a, c.now().Add(c.inst.Duration(KeyCacheTTL)))
	return a, nil
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
func Checks(raw map[string]config.Integration, store Store) []*VersionCheck {
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
		fp, _ := json.Marshal(raw[n])
		if l, ok := lives[n]; ok && l.fingerprint == string(fp) {
			c := *l.check
			c.store = store
			out = append(out, &c)
			continue
		}
		c := build(n, raw[n])
		lives[n] = &live{fingerprint: string(fp), check: c}
		cp := *c
		cp.store = store
		out = append(out, &cp)
	}
	return out
}

// Build constructs one instance's check whether or not it is enabled, for
// `bodega integration test`. Its cache is its own.
func Build(name string, raw config.Integration, store Store) *VersionCheck {
	c := build(name, raw)
	c.store = store
	return c
}

func build(name string, raw config.Integration) *VersionCheck {
	inst, err := ValidateInstance(name, raw)
	if err != nil {
		t, _ := raw["type"].(string)
		d, ok := Lookup(t)
		if !ok {
			d = &Descriptor{Type: t, DisplayName: name, DefaultAction: policy.ActionBlock}
		}
		return &VersionCheck{inst: &Instance{Name: name, Descriptor: d, values: map[string]any{}}, buildErr: err,
			cache: &answerCache{}, now: time.Now}
	}
	impl, err := inst.Descriptor.New(inst)
	return &VersionCheck{inst: inst, impl: impl, buildErr: err, cache: &answerCache{}, now: time.Now}
}

// RunTest makes one real query for the instance's probe package and writes
// the answer, the latency and any quota the vendor reported. It is
// `bodega integration test` and the TUI's Test action. A failed query is
// recorded as the instance's last error and returned.
func RunTest(ctx context.Context, out io.Writer, name string, entry config.Integration, store Store) error {
	c := Build(name, entry, store)
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
