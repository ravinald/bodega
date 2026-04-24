package policy

import (
	"context"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// Action is the outcome of a version-level check.
const (
	ActionPass   = "pass"
	ActionWarn   = "warn"
	ActionBlock  = "block"
	ActionIgnore = "ignore"
)

// Result is a single check's verdict on a single VersionEntry.
type Result struct {
	Check   string         // check name, e.g. "age" / "osv"
	Action  string         // pass | warn | block
	Reason  string         // human-readable; empty on pass
	Details map[string]any // structured payload for audit
}

// VersionChecker runs a policy check against a specific version. Unlike the
// upstream allow-list Checker (which takes a URL/name candidate), these
// checks need the full VersionEntry to reason about publish time, vulns,
// etc.
type VersionChecker interface {
	Check(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry) Result
}

// RunChecks runs all checkers and collects results. A block from any checker
// fails the admission, but the combined reason carries context from every
// non-pass result — "a block with context about what else was wrong is more
// useful than a premature return."
func RunChecks(ctx context.Context, pm *manifest.PackageManifest, ve *manifest.VersionEntry, checkers ...VersionChecker) Combined {
	var out Combined
	for _, c := range checkers {
		r := c.Check(ctx, pm, ve)
		switch r.Action {
		case "", ActionPass, ActionIgnore:
			continue
		case ActionWarn:
			out.Warns = append(out.Warns, r)
		case ActionBlock:
			out.Blocks = append(out.Blocks, r)
		}
	}
	return out
}

// Combined aggregates results across checkers. Blocked() is the only
// fail-closed signal; Warns feed the audit log without breaking admission.
type Combined struct {
	Warns  []Result
	Blocks []Result
}

func (c Combined) Blocked() bool { return len(c.Blocks) > 0 }

// Reasons joins warn + block reasons for error messages or audit text.
func (c Combined) Reasons() string {
	parts := make([]string, 0, len(c.Warns)+len(c.Blocks))
	for _, r := range c.Blocks {
		parts = append(parts, r.Check+": "+r.Reason)
	}
	for _, r := range c.Warns {
		parts = append(parts, r.Check+": "+r.Reason+" (warn)")
	}
	return strings.Join(parts, "; ")
}

// AuditDetails renders a compact map for the audit Details JSON field.
func (c Combined) AuditDetails() map[string]any {
	if len(c.Warns) == 0 && len(c.Blocks) == 0 {
		return nil
	}
	m := make(map[string]any, 2)
	if len(c.Blocks) > 0 {
		m["block"] = resultsAsList(c.Blocks)
	}
	if len(c.Warns) > 0 {
		m["warn"] = resultsAsList(c.Warns)
	}
	return m
}

func resultsAsList(rs []Result) []map[string]any {
	out := make([]map[string]any, 0, len(rs))
	for _, r := range rs {
		entry := map[string]any{"check": r.Check, "reason": r.Reason}
		if r.Details != nil {
			for k, v := range r.Details {
				entry[k] = v
			}
		}
		out = append(out, entry)
	}
	return out
}
