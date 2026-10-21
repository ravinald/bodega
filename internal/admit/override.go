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
// requester at now. The quorum is the one configured now, and whether the
// requester counts toward it is whether they hold approve now; both are
// recorded with the request.
func RequestOverride(ctx context.Context, adb *audit.DB, cfg *config.Config, req OverrideRequest, requester audit.OverrideCaller, now time.Time) (audit.Override, error) {
	identity := requester.Identity
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
	if check, why := recordedUnwaivable(ctx, adb, req); check == req.Check {
		return audit.Override{}, invalid("%s/%s@%s was refused by %s, and %s; an override cannot admit it",
			req.Type, req.Name, req.Version, req.Check, why)
	} else if check != "" {
		return audit.Override{}, invalid("%s/%s@%s was also refused by %s, and %s; an override of %s cannot admit it",
			req.Type, req.Name, req.Version, check, why, req.Check)
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
		Quorum: cfg.ResolveOverrideQuorum(), RequesterCounts: requester.HoldsApprove(),
		State: audit.OverridePending, Votes: []audit.OverrideVote{},
	}
	if err := adb.InsertOverride(ctx, o); err != nil {
		return audit.Override{}, fmt.Errorf("record override: %w", err)
	}
	recordOverrideEvent(ctx, adb, o, identity, "requested", map[string]any{"reason": o.Reason,
		"requester_counts": o.RequesterCounts, "approvals_needed": o.Remaining()})
	return withStatus(o, now), nil
}

// VoteOverride records voter's approval or rejection of override id. It is
// the one place both surfaces decide one, so the rules in
// audit.DB.VoteOverride hold whichever way the vote arrived.
func VoteOverride(ctx context.Context, adb *audit.DB, id string, voter audit.OverrideCaller, approve bool, comment string, now time.Time) (audit.Override, error) {
	if adb == nil {
		return audit.Override{}, errors.New("no audit store is open; overrides are recorded there")
	}
	identity := voter.Identity
	if identity == "" {
		return audit.Override{}, fmt.Errorf("%w: no identity to record the vote under", ErrInvalidOverride)
	}
	vote, status := audit.VoteApprove, "approve"
	if !approve {
		vote, status = audit.VoteReject, "reject"
	}
	o, err := adb.VoteOverride(ctx, id, voter, vote, strings.TrimSpace(comment), now)
	if err != nil {
		return o, err
	}
	extra := map[string]any{"comment": strings.TrimSpace(comment), "scope": voter.Scope}
	if v, ok := VoteBy(o, identity); ok && !v.Counted {
		extra["not_counted"] = v.NotCounted
	}
	recordOverrideEvent(ctx, adb, o, identity, status, extra)
	return withStatus(o, now), nil
}

// VoteBy returns identity's vote on o.
func VoteBy(o audit.Override, identity string) (audit.OverrideVote, bool) {
	for _, v := range o.Votes {
		if v.Identity == identity {
			return v, true
		}
	}
	return audit.OverrideVote{}, false
}

// withStatus fills the fields an override carries as read at now and never
// stores. Only a pending request still open to votes needs approvals.
func withStatus(o audit.Override, now time.Time) audit.Override {
	o.Status = o.StatusAt(now)
	o.ApprovalsNeeded = 0
	if o.Status == audit.OverrideStatusPending {
		o.ApprovalsNeeded = o.Remaining()
	}
	return o
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
		o = withStatus(o, now)
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

// recordedUnwaivable names a check the newest admission row for req's
// version records as admitting no override, with why, or "" when the row
// records none or no row can be read. req's own check comes first. Any one
// such check makes every override of the version moot, because an override
// skips only the check it names and the unwaivable one still refuses.
// Admission refuses such an override whatever is recorded here; this only
// stops a request nobody could ever see applied.
func recordedUnwaivable(ctx context.Context, adb *audit.DB, req OverrideRequest) (check, why string) {
	rows, err := adb.Admissions(ctx, audit.AdmissionFilter{PkgType: req.Type, PkgName: req.Name, PkgVersion: req.Version, Limit: 1})
	if err != nil || len(rows) == 0 {
		return "", ""
	}
	for _, c := range rows[0].Checks {
		if c.Unwaivable != "" && (check == "" || c.Check == req.Check) {
			check, why = c.Check, c.Unwaivable
		}
	}
	return check, why
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

// Overrides are the active approved overrides on one package at one moment,
// keyed by version and check. The first one listed for a version and check
// is the one that applies.
type Overrides map[string]audit.Override

// LoadOverrides reads the overrides on typ/name that apply at now. A read
// error returns none alongside it: an override that cannot be read does not
// apply, and the caller says so where its operator looks.
func LoadOverrides(ctx context.Context, adb *audit.DB, typ, name string, now time.Time) (Overrides, error) {
	if adb == nil {
		return nil, nil
	}
	all, err := adb.ListOverrides(ctx, audit.OverrideFilter{PkgType: typ, State: audit.OverrideApproved})
	if err != nil {
		return nil, err
	}
	want := overrideNameKey(typ, name)
	var out Overrides
	for _, o := range all {
		if !o.Active(now) || overrideNameKey(o.PkgType, o.PkgName) != want {
			continue
		}
		k := o.PkgVersion + "\x00" + o.Check
		if _, seen := out[k]; !seen {
			if out == nil {
				out = Overrides{}
			}
			out[k] = o
		}
	}
	return out, nil
}

// For returns the override naming check on version. An empty version matches
// an override on any version of the package, which is what a request for a
// package's index, naming no version, needs.
func (ovs Overrides) For(version, check string) (audit.Override, bool) {
	if version != "" {
		o, ok := ovs[version+"\x00"+check]
		return o, ok
	}
	for _, o := range ovs {
		if o.Check == check {
			return o, true
		}
	}
	return audit.Override{}, false
}

// ActiveOverride returns the active approved override naming check on
// typ/name at version at now; see LoadOverrides and Overrides.For.
func ActiveOverride(ctx context.Context, adb *audit.DB, typ, name, version, check string, now time.Time) (audit.Override, bool, error) {
	ovs, err := LoadOverrides(ctx, adb, typ, name, now)
	if err != nil {
		return audit.Override{}, false, err
	}
	o, ok := ovs.For(version, check)
	return o, ok, nil
}

// OverriddenCheck renders c, a failed check, as the entry an override admits
// it under: status overridden, the override's id, and a detail naming the
// failure, the approvers and the expiry. Every path that admits past a
// failure through an override writes it this way.
func OverriddenCheck(c audit.AdmissionCheck, o audit.Override) audit.AdmissionCheck {
	c.Status = audit.CheckOverridden
	c.Override = o.ID
	c.Detail = fmt.Sprintf("%s; overridden by %s (approved by %s; expires %s)",
		c.Detail, o.ID, strings.Join(o.Approvers(), ", "), o.ExpiresAt.UTC().Format(time.RFC3339))
	return c
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
	return OverriddenCheck(c, o), true
}

// reportedBlock is the block a refusal names when a version fails several
// checks: the first unwaivable one, else the first in check order. Naming an
// overridable check while an unwaivable one stands would send the client to an
// override that can never admit the version.
func reportedBlock(blocks []policy.Result) policy.Result {
	for _, b := range blocks {
		if notOverridable(b) != "" {
			return b
		}
	}
	return blocks[0]
}

// notOverridable says why a failed result admits no override, or "" when it
// does. These are the verdicts that a version is hostile rather than that it
// misses a policy: a MAL- record or a malware-list hit says it was published
// to do harm, and provenance that fails to verify says someone signed
// something other than what was served. Two people agreeing does not change
// either fact.
func notOverridable(r policy.Result) string {
	switch {
	case r.Details["malware"] != nil && (r.Check == audit.CheckOSV || isIntegrationCheck(r.Check)):
		return "known malware is never overridden"
	case r.Check == audit.CheckUpstreamProvenance && r.Provenance != nil && r.Provenance.Outcome == audit.ProvenanceInvalid:
		return "invalid upstream provenance is never overridden"
	}
	return ""
}
