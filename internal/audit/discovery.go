package audit

import (
	"context"
	"time"
)

// Decision values recorded on a DiscoveryRow. The first three come from the
// policy check inside proxyOrCache; the last two come from handlers that
// decide before it, where no upstream fetch was ever attempted.
//
// The set is constrained by a CHECK on upstream_discovery — a value added here
// needs a migration widening that constraint or every write of it fails.
//
// "would_deny" was a sixth value, written only under the retired
// discover_mode=learn. Migration 010 rewrote those rows to denied and narrowed
// the CHECK; a database rolled back below 010 can still hold the string, so a
// reader must not assume the set here is exhaustive of what it will scan.
const (
	DecisionAllowed     = "allowed"
	DecisionDenied      = "denied"
	DecisionNoPolicy    = "no_policy"
	DecisionNoManifest  = "no_manifest"  // request named a package with no manifest entry
	DecisionNoNamespace = "no_namespace" // request named a namespace no upstream is configured for
)

// Decisions returns the decision set in a stable order, for the error text a
// sink prints when it refuses a value outside it.
func Decisions() []string {
	return []string{DecisionAllowed, DecisionDenied, DecisionNoPolicy, DecisionNoManifest, DecisionNoNamespace}
}

// ValidDecision reports whether d is in the set the upstream_discovery CHECK
// allows. The queryable sinks get this from the constraint; the write-only
// ones have nothing to enforce it, so they call this before encoding.
func ValidDecision(d string) bool {
	for _, v := range Decisions() {
		if v == d {
			return true
		}
	}
	return false
}

// DiscoveryRow is one request observation, whether the cache answered it or an
// upstream fetch did. Rows are deduplicated at insert time on
// (registry_type, pattern_hint, pkg_name, pkg_version, decision) — repeat
// requests bump request_count and update last_seen / last_client, so those two
// columns describe the fleet rather than the cache.
//
// Host and UpstreamURL are preserved on an upsert that leaves them empty: a
// cache hit records without resolving an upstream it will not fetch, and
// blanking a column the miss filled in would trade one true value for none.
type DiscoveryRow struct {
	RegistryType string
	Host         string
	PatternHint  string // suggested promotion pattern (policy.SuggestPattern)
	PkgName      string
	PkgVersion   string
	Decision     string // one of the Decision* constants above
	UpstreamURL  string // full upstream URL bodega fetched (or would have); empty on rows recorded before migration 007
	FirstSeen    time.Time
	LastSeen     time.Time
	LastClient   string
	RequestCount int64
}

// DiscoveryFilter restricts which rows ListDiscovery / CountDiscovery return.
type DiscoveryFilter struct {
	RegistryType string    // empty = all
	PatternHint  string    // empty = all; exact match
	Decision     string    // empty = all
	Since        time.Time // zero = no lower bound on last_seen
	Limit        int       // 0 = default (1000)
}

// RecordDiscovery upserts an observation into the configured sink. A
// write-only sink cannot deduplicate, so it emits one record per call and the
// rollup happens wherever the stream lands; see the DiscoveryRow comment for
// what the queryable sinks collapse.
func (a *DB) RecordDiscovery(ctx context.Context, r DiscoveryRow) error {
	return a.sink.RecordDiscovery(ctx, r)
}

// ListDiscovery returns observations matching the filter, newest last_seen
// first. Default limit is 1000 when filter.Limit <= 0. Refuses when the
// configured sink keeps no table.
func (a *DB) ListDiscovery(ctx context.Context, f DiscoveryFilter) ([]DiscoveryRow, error) {
	r, err := a.reader("discovery rows")
	if err != nil {
		return nil, err
	}
	return r.ListDiscovery(ctx, f)
}

// DiscoveryAggregate is one (registry_type, pattern_hint) bucket, summed over
// every (pkg_name, pkg_version, decision) row that matched it. Used by
// `bodega discover list` — the bucket key is what `promote` will use.
type DiscoveryAggregate struct {
	RegistryType   string
	PatternHint    string
	Host           string
	RequestCount   int64
	FirstSeen      time.Time
	LastSeen       time.Time
	Decisions      string // comma-joined distinct decisions, e.g. "allowed,denied"
	SampleUpstream string // an example upstream URL from the bucket; empty if all rows pre-date migration 007
}

// AggregateDiscovery rolls observations into one row per (type, pattern_hint).
// Optional registryType filter ("" = all). Refuses when the configured sink
// keeps no table.
func (a *DB) AggregateDiscovery(ctx context.Context, registryType string) ([]DiscoveryAggregate, error) {
	r, err := a.reader("discovery rows")
	if err != nil {
		return nil, err
	}
	return r.AggregateDiscovery(ctx, registryType)
}

// ClearDiscovery deletes rows for registryType. Empty = wipe table. Returns
// rows deleted. Refuses when the configured sink keeps no table: there is
// nothing local to clear, and reporting 0 deleted would read as an empty table.
func (a *DB) ClearDiscovery(ctx context.Context, registryType string) (int64, error) {
	r, err := a.reader("discovery rows")
	if err != nil {
		return 0, err
	}
	return r.ClearDiscovery(ctx, registryType)
}

// DiscoveryCount returns the row count for the given type ("" = all). Used by
// CLI guards ("no observations yet — is discover_mode set?"). Refuses when the
// configured sink keeps no table.
func (a *DB) DiscoveryCount(ctx context.Context, registryType string) (int64, error) {
	r, err := a.reader("discovery rows")
	if err != nil {
		return 0, err
	}
	return r.DiscoveryCount(ctx, registryType)
}
