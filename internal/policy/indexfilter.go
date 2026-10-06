package policy

import (
	"context"
	"errors"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// Reasons a proxied index withholds a version. They are the check names the
// age and OSV gates report under, so a header, an audit row and a refusal all
// name the gate the same way.
const (
	WithheldAge = "age"
	WithheldOSV = "osv"
)

// IndexFilterStore is the subset of audit.DB the index filter reads: its own
// switch and the two gates whose block it applies.
type IndexFilterStore interface {
	IndexFilterEnabled(ctx context.Context, ecosystem string) (bool, error)
	AgeStore
	OSVStore
}

// IndexFilterEcosystems returns the registry types whose proxied index the
// filter can rewrite, sorted. cargo has an age gate and a sparse index too,
// and is not here because nothing in its index dates a release.
func IndexFilterEcosystems() []string {
	return []string{manifest.TypeGomod, manifest.TypeNpm, manifest.TypePypi}
}

// IndexFilter decides which versions a proxied index omits so a client's
// resolver settles on the newest version the gates would admit, rather than
// on the newest upstream and a refusal it cannot route around.
//
// It applies only a gate whose action is block. A warn admits the version,
// so hiding it would refuse at the index what the artifact route serves.
type IndexFilter struct {
	store IndexFilterStore
	osv   *OSVChecker
	Now   func() time.Time
}

// NewIndexFilter returns a filter reading its switch and both policies from
// store. osv answers the advisory half; nil leaves OSV out of the filter.
func NewIndexFilter(store IndexFilterStore, osv *OSVChecker) *IndexFilter {
	return &IndexFilter{store: store, osv: osv, Now: time.Now}
}

// Gate returns the rules in force for one ecosystem, or nil when the filter
// is off for it or neither gate blocks. Read per request: an operator turning
// the filter on expects the next index to change, not the next restart.
func (f *IndexFilter) Gate(ctx context.Context, ecosystem string) (*IndexGate, error) {
	if f == nil {
		return nil, nil
	}
	on, err := f.store.IndexFilterEnabled(ctx, ecosystem)
	if err != nil || !on {
		return nil, err
	}
	g := &IndexGate{Ecosystem: ecosystem, now: f.Now()}

	age, err := f.store.GetAgePolicy(ctx, ecosystem)
	switch {
	case errors.Is(err, audit.ErrAgePolicyNotFound):
	case err != nil:
		return nil, err
	case age.Action == ActionBlock && age.MinAgeSeconds > 0:
		g.MinAge = time.Duration(age.MinAgeSeconds) * time.Second
	}

	osv, err := f.store.GetOSVPolicy(ctx, ecosystem)
	switch {
	case errors.Is(err, audit.ErrOSVPolicyNotFound):
	case err != nil:
		return nil, err
	case osv.Action == ActionBlock && f.osv != nil:
		// A copy answering from the row already read, so a packument of two
		// thousand versions is one policy query rather than two thousand. The
		// live API is off for the same reason: one index read would be a
		// query per version against a host the admission path only reaches
		// when the operator asked it to. A version the local database cannot
		// answer comes back as a warn, and a warn keeps it.
		ck := *f.osv
		ck.store = fixedOSVPolicy(osv)
		ck.AllowAPIFallback = false
		g.osv = &ck
	}

	if g.MinAge == 0 && g.osv == nil {
		return nil, nil
	}
	return g, nil
}

// IndexGate is the filter in force for one ecosystem on one request.
type IndexGate struct {
	Ecosystem string
	// MinAge is the blocking age window, zero when the age gate does not
	// block.
	MinAge time.Duration
	osv    *OSVChecker
	now    time.Time
}

// Dates reports whether the gate needs a publish time to decide.
func (g *IndexGate) Dates() bool { return g.MinAge > 0 }

// Young reports whether a version published at t is still inside the age
// window.
func (g *IndexGate) Young(t time.Time) bool {
	return g.MinAge > 0 && g.now.Sub(t) < g.MinAge
}

// Withhold names the gate that refuses one version, or "" to keep it.
// published is zero when no publish time could be read, and the age gate
// keeps such a version: an index that dropped what it failed to date would
// hide a release on the strength of an upstream hiccup.
func (g *IndexGate) Withhold(ctx context.Context, name, version string, published time.Time) string {
	if !published.IsZero() && g.Young(published) {
		return WithheldAge
	}
	if g.osv != nil {
		r := g.osv.Check(ctx, &manifest.PackageManifest{Type: g.Ecosystem, Name: name},
			&manifest.VersionEntry{Version: version})
		if r.Action == ActionBlock {
			return WithheldOSV
		}
	}
	return ""
}

type fixedOSVPolicy audit.OSVPolicy

func (p fixedOSVPolicy) GetOSVPolicy(context.Context, string) (audit.OSVPolicy, error) {
	return audit.OSVPolicy(p), nil
}
