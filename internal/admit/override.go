package admit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/integration"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// OverrideRequest is a request to admit one version past one check's
// failure, as `bodega override request` and POST /api/v1/overrides carry it.
// Expires is a duration from now, "7d" or "72h".
type OverrideRequest struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Check   string `json:"check"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
}

// ErrInvalidOverride wraps every refusal of a request's own content, so the
// API can answer it 400 and anything else 500.
var ErrInvalidOverride = errors.New("invalid override request")

// RequestOverride validates req and records it as pending, requested by
// identity at now. The quorum is the one configured now, recorded with the
// request.
func RequestOverride(ctx context.Context, adb *audit.DB, cfg *config.Config, req OverrideRequest, identity string, now time.Time) (audit.Override, error) {
	if adb == nil {
		return audit.Override{}, errors.New("no audit store is open; overrides are recorded there")
	}
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidOverride, fmt.Sprintf(format, args...))
	}
	req.Reason = strings.TrimSpace(req.Reason)
	switch {
	case identity == "":
		return audit.Override{}, invalid("no identity to record as the requester")
	case !manifest.IsKnownType(req.Type):
		return audit.Override{}, invalid("unknown type %q (want one of %s)", req.Type, strings.Join(manifest.AllTypes, ", "))
	case req.Name == "":
		return audit.Override{}, invalid("name is required")
	case req.Version == "":
		return audit.Override{}, invalid("version is required: an override names one version")
	case !slices.Contains(allChecks, req.Check) && !isIntegrationCheck(req.Check):
		return audit.Override{}, invalid("unknown check %q (want one of %s, or %s<instance>)", req.Check, strings.Join(allChecks, ", "), integration.CheckPrefix)
	case req.Reason == "":
		return audit.Override{}, invalid("a reason is required; it is what the approvers read")
	case req.Expires == "":
		return audit.Override{}, invalid("an expiry is required, at most %s", formatTTL(cfg.ResolveOverrideMaxTTL()))
	}
	if err := manifest.ValidatePackageName(req.Name); err != nil {
		return audit.Override{}, invalid("%v", err)
	}
	ttl, err := config.ParseTTL(req.Expires)
	if err != nil {
		return audit.Override{}, invalid("expires: %v", err)
	}
	if limit := cfg.ResolveOverrideMaxTTL(); ttl > limit {
		return audit.Override{}, invalid("expires %s is beyond override_max_ttl (%s)", req.Expires, formatTTL(limit))
	}

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return audit.Override{}, err
	}
	o := audit.Override{
		ID: hex.EncodeToString(b[:]), PkgType: req.Type, PkgName: req.Name, PkgVersion: req.Version,
		Check: req.Check, Reason: req.Reason, RequestedBy: identity,
		RequestedAt: now.UTC(), ExpiresAt: now.Add(ttl).UTC(),
		Quorum: cfg.ResolveOverrideQuorum(), State: audit.OverridePending, Votes: []audit.OverrideVote{},
	}
	if err := adb.InsertOverride(ctx, o); err != nil {
		return audit.Override{}, fmt.Errorf("record override: %w", err)
	}
	recordOverrideEvent(ctx, adb, o, identity, "requested", map[string]any{"reason": o.Reason})
	o.Status = o.StatusAt(now)
	return o, nil
}

// VoteOverride records identity's approval or rejection of override id. It
// is the one place both surfaces decide one, so the rules in
// audit.DB.VoteOverride hold whichever way the vote arrived.
func VoteOverride(ctx context.Context, adb *audit.DB, id, identity string, approve bool, comment string, now time.Time) (audit.Override, error) {
	if adb == nil {
		return audit.Override{}, errors.New("no audit store is open; overrides are recorded there")
	}
	if identity == "" {
		return audit.Override{}, fmt.Errorf("%w: no identity to record the vote under", ErrInvalidOverride)
	}
	vote, status := audit.VoteApprove, "approve"
	if !approve {
		vote, status = audit.VoteReject, "reject"
	}
	o, err := adb.VoteOverride(ctx, id, identity, vote, strings.TrimSpace(comment), now)
	if err != nil {
		return o, err
	}
	recordOverrideEvent(ctx, adb, o, identity, status, map[string]any{"comment": strings.TrimSpace(comment)})
	o.Status = o.StatusAt(now)
	return o, nil
}

// ListOverrides returns every override with its Status as of now, keeping
// only those whose status is want when want is set.
func ListOverrides(ctx context.Context, adb *audit.DB, want string, now time.Time) ([]audit.Override, error) {
	if adb == nil {
		return nil, errors.New("no audit store is open; overrides are recorded there")
	}
	all, err := adb.ListOverrides(ctx, audit.OverrideFilter{})
	if err != nil {
		return nil, err
	}
	out := []audit.Override{}
	for _, o := range all {
		o.Status = o.StatusAt(now)
		if want == "" || o.Status == want {
			out = append(out, o)
		}
	}
	return out, nil
}

func recordOverrideEvent(ctx context.Context, adb *audit.DB, o audit.Override, actor, status string, extra map[string]any) {
	details := map[string]any{"id": o.ID, "check": o.Check, "state": o.State,
		"approvers": o.Approvers(), "quorum": o.Quorum, "expires_at": o.ExpiresAt.Format(time.RFC3339)}
	for k, v := range extra {
		details[k] = v
	}
	blob, _ := json.Marshal(details)
	_ = adb.Record(ctx, audit.Event{EventType: audit.EventOverride, PkgType: o.PkgType, PkgName: o.PkgName,
		PkgVersion: o.PkgVersion, Actor: actor, Status: status, Details: string(blob)})
}

// isIntegrationCheck reports whether check names an integration instance in
// the form its admission rows carry. The instance need not be configured
// now: an override outlives a config edit the way the row it answers does.
func isIntegrationCheck(check string) bool {
	name, ok := strings.CutPrefix(check, integration.CheckPrefix)
	return ok && integration.ValidInstanceName(name)
}

// OverrideChecks are the check names an override may name: every check an
// admission row carries.
func OverrideChecks() []string { return slices.Clone(allChecks) }

func formatTTL(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.String()
}

// loadOverrides reads the overrides that apply to pm at now, keyed by
// version and check. An error leaves none loaded: an override that cannot be
// read does not apply.
func (ev *evaluation) loadOverrides(ctx context.Context, adb *audit.DB, pm *manifest.PackageManifest, now time.Time) {
	all, err := adb.ListOverrides(ctx, audit.OverrideFilter{PkgType: pm.Type, State: audit.OverrideApproved})
	if err != nil {
		ev.overrideErr = err
		return
	}
	want := overrideNameKey(pm.Type, pm.Name)
	for _, o := range all {
		if !o.Active(now) || overrideNameKey(o.PkgType, o.PkgName) != want {
			continue
		}
		k := o.PkgVersion + "\x00" + o.Check
		if _, seen := ev.overrides[k]; !seen {
			if ev.overrides == nil {
				ev.overrides = map[string]audit.Override{}
			}
			ev.overrides[k] = o
		}
	}
}

// overrideNameKey is the form an override's package name is matched in: the
// one the catalog keys by, and for pypi the PEP 503 name, so "Foo_Bar" and
// "foo-bar" are the same request.
func overrideNameKey(typ, name string) string {
	if typ == manifest.TypePypi {
		return manifest.CanonicalPypiName(name)
	}
	return manifest.SafeName(name)
}

func (ev *evaluation) overrideFor(pm *manifest.PackageManifest, i int, check string) (audit.Override, bool) {
	if i >= len(pm.Versions) {
		return audit.Override{}, false
	}
	o, ok := ev.overrides[admissionVersion(pm.Versions[i])+"\x00"+check]
	return o, ok
}

// overrideCheck turns c, a failed check on version i, into an overridden one
// when an active override names it. It reports false for a check that did not
// fail, or that no override names.
func (ev *evaluation) overrideCheck(pm *manifest.PackageManifest, i int, c audit.AdmissionCheck) (audit.AdmissionCheck, bool) {
	if c.Status != audit.CheckBlock {
		return c, false
	}
	o, ok := ev.overrideFor(pm, i, c.Check)
	if !ok {
		return c, false
	}
	c.Status = audit.CheckOverridden
	c.Override = o.ID
	c.Detail = fmt.Sprintf("%s; overridden by %s (approved by %s; expires %s)",
		c.Detail, o.ID, strings.Join(o.Approvers(), ", "), o.ExpiresAt.UTC().Format(time.RFC3339))
	return c, true
}

// notOverridable says why a failed result admits no override, or "" when it
// does. These are the verdicts that a version is hostile rather than that it
// misses a policy: a MAL- record says it was published to do harm, and
// provenance that fails to verify says someone signed something other than
// what was served. Two people agreeing does not change either fact.
func notOverridable(r policy.Result) string {
	switch {
	case r.Check == audit.CheckOSV && r.Details["malware"] != nil:
		return "known malware is never overridden"
	case r.Check == audit.CheckUpstreamProvenance && r.Provenance != nil && r.Provenance.Outcome == audit.ProvenanceInvalid:
		return "invalid upstream provenance is never overridden"
	}
	return ""
}
