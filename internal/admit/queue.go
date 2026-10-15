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
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// The checks a queue row names. allow-list, age, osv and profile are the
// words a refusal's X-Bodega-Refusal header carries; malware is split out of
// osv because it is the one osv result an approval can never admit, and the
// two admission checks a refusal header has no word of its own for keep
// their admission names.
const (
	QueueAllowList  = "allow-list"
	QueueAge        = "age"
	QueueOSV        = "osv"
	QueueMalware    = "malware"
	QueueProfile    = "profile"
	QueueProvenance = audit.CheckUpstreamProvenance
	QueueSimilarity = audit.CheckNameSimilarity
)

// QueueChecks is every check a queue row can name.
func QueueChecks() []string {
	return []string{QueueAllowList, QueueAge, QueueOSV, QueueMalware, QueueProfile, QueueProvenance, QueueSimilarity}
}

// QueueCheckFor is the queue check for a blocking admission result.
func QueueCheckFor(r policy.Result) string {
	switch {
	case r.Check == audit.CheckOSV && r.Details["malware"] != nil:
		return QueueMalware
	case r.Check == audit.CheckAllowList:
		return QueueAllowList
	}
	return r.Check
}

// Unwaivable says why a blocking result may never be approved from the
// queue, or "" when it may. It is the override rule: whatever two people
// cannot override, one person approving a queue row cannot either.
func Unwaivable(r policy.Result) string { return notOverridable(r) }

// ErrQueueUnwaivable refuses an approval of a row whose check no approval
// can waive.
var ErrQueueUnwaivable = errors.New("cannot be waived")

// ErrInvalidQueue wraps every refusal of a resolution's own content.
var ErrInvalidQueue = errors.New("invalid queue resolution")

// QueueApproval is what an approval carries besides the row: the operator's
// reason, and for a row approved into an override, how long it applies.
// Expires empty means override_max_ttl.
type QueueApproval struct {
	Reason  string `json:"reason"`
	Expires string `json:"expires,omitempty"`
}

// QueueResolution is what approving a row did. Exactly one of Rule,
// Override and Profiles is set.
type QueueResolution struct {
	Row      audit.QueueRow    `json:"row"`
	Rule     *audit.PolicyInfo `json:"rule,omitempty"`
	Override *audit.Override   `json:"override,omitempty"`
	Profiles []string          `json:"profiles,omitempty"`
	// Warning is something the approval did that the operator should read,
	// such as an exact rule for a name within two edits of a popular one.
	Warning string `json:"warning,omitempty"`
}

// ApproveQueued resolves open row id by the action its check calls for: an
// allow-list rule for allow-list, an exact pin in every profile that refused
// it for profile, and an override request through the two-person flow for
// every other check. A row whose refusal no override could waive is refused
// and the row left open.
func ApproveQueued(ctx context.Context, adb *audit.DB, cfg *config.Config, id int64, actor string, a QueueApproval, now time.Time) (QueueResolution, error) {
	if adb == nil {
		return QueueResolution{}, errors.New("no audit store is open; the queue is recorded there")
	}
	a.Reason = strings.TrimSpace(a.Reason)
	if actor == "" {
		return QueueResolution{}, fmt.Errorf("%w: no identity to record the approval under", ErrInvalidQueue)
	}
	if a.Reason == "" {
		return QueueResolution{}, fmt.Errorf("%w: a reason is required; it is what the audit trail keeps", ErrInvalidQueue)
	}
	row, err := adb.GetQueueRow(ctx, id)
	if err != nil {
		return QueueResolution{}, err
	}
	if row.State != audit.QueueOpen {
		return QueueResolution{Row: row}, fmt.Errorf("%w: it was %s by %s", audit.ErrQueueRowClosed, row.State, row.ResolvedBy)
	}
	switch {
	case row.Check == QueueMalware && row.Unwaivable == "":
		row.Unwaivable = "known malware is never overridden"
		fallthrough
	case row.Unwaivable != "":
		return QueueResolution{Row: row}, fmt.Errorf("queue row %d was refused by %s, which %w: %s; dismiss it instead",
			id, row.Check, ErrQueueUnwaivable, row.Unwaivable)
	}

	var out QueueResolution
	var resolution string
	switch row.Check {
	case QueueAllowList:
		out.Rule, out.Warning, err = approveAllowList(ctx, adb, row, actor, a.Reason)
		if err == nil {
			resolution = "allow-list rule " + out.Rule.ID
		}
	case QueueProfile:
		out.Profiles, err = approveProfile(ctx, adb, row, actor, a.Reason, now)
		if err == nil {
			resolution = "pinned in profile " + strings.Join(out.Profiles, ", ")
		}
	default:
		var o audit.Override
		o, err = approveOverride(ctx, adb, cfg, row, actor, a, now)
		if err == nil {
			out.Override = &o
			resolution = "override " + o.ID
		}
	}
	if err != nil {
		return QueueResolution{Row: row}, err
	}
	if out.Row, err = adb.ResolveQueueRow(ctx, id, audit.QueueApproved, actor, resolution, a.Reason, now); err != nil {
		return out, err
	}
	recordQueueEvent(ctx, adb, out.Row, actor)
	return out, nil
}

// DismissQueued closes open row id without admitting anything.
func DismissQueued(ctx context.Context, adb *audit.DB, id int64, actor, reason string, now time.Time) (audit.QueueRow, error) {
	if adb == nil {
		return audit.QueueRow{}, errors.New("no audit store is open; the queue is recorded there")
	}
	reason = strings.TrimSpace(reason)
	if actor == "" {
		return audit.QueueRow{}, fmt.Errorf("%w: no identity to record the dismissal under", ErrInvalidQueue)
	}
	if reason == "" {
		return audit.QueueRow{}, fmt.Errorf("%w: a reason is required; it is what the audit trail keeps", ErrInvalidQueue)
	}
	row, err := adb.ResolveQueueRow(ctx, id, audit.QueueDismissed, actor, "", reason, now)
	if err != nil {
		return row, err
	}
	recordQueueEvent(ctx, adb, row, actor)
	return row, nil
}

func approveAllowList(ctx context.Context, adb *audit.DB, row audit.QueueRow, actor, reason string) (*audit.PolicyInfo, string, error) {
	if err := policy.ValidateType(row.PkgType); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrInvalidQueue, err)
	}
	pattern := row.Pattern
	if pattern == "" {
		pattern = row.PkgName
	}
	kind := policy.RuleKindForType(row.PkgType)
	// A rule someone already added by hand resolves the row: inserting it
	// again would only trip the table's uniqueness on type, kind and pattern.
	rules, err := adb.ListPolicies(ctx)
	if err != nil {
		return nil, "", err
	}
	for _, p := range rules {
		if p.RegistryType == row.PkgType && p.RuleKind == kind && p.Pattern == pattern {
			return &p, "", nil
		}
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, "", err
	}
	rule := audit.PolicyInfo{
		ID: hex.EncodeToString(b[:]), RegistryType: row.PkgType, RuleKind: kind,
		Pattern: pattern, Comment: fmt.Sprintf("queue #%d: %s", row.ID, reason), CreatedBy: actor,
	}
	details := fmt.Sprintf("id=%s kind=%s queue=%d", rule.ID, rule.RuleKind, row.ID)
	warning := ""
	if popular, distance, near, err := policy.NearPopularName(ctx, adb, row.PkgType, pattern); err == nil && near {
		warning = fmt.Sprintf("%s is %d edit(s) from the popular %s package %s, and an exact rule exempts it from the name similarity check",
			pattern, distance, row.PkgType, popular)
		details += fmt.Sprintf(" near_popular=%s distance=%d", popular, distance)
	}
	if err := adb.InsertPolicy(ctx, rule); err != nil {
		return nil, "", fmt.Errorf("insert allow-list rule %s %q: %w", row.PkgType, pattern, err)
	}
	_ = adb.Record(ctx, audit.Event{EventType: audit.EventCreate, PkgType: "policy",
		PkgName: row.PkgType + ":" + pattern, Actor: actor, Status: "success", Details: details})
	return &rule, warning, nil
}

// approveProfile pins the refused version in every profile the row records.
// It is a single-actor exception, because the two-person flow decides
// admission checks and a profile is not one: it is the same write
// `bodega profile pin` makes, with the reason and the actor on the entry.
// A row with no version names a package refused at the membership level,
// which is admitted by listing it with no constraint.
func approveProfile(ctx context.Context, adb *audit.DB, row audit.QueueRow, actor, reason string, now time.Time) ([]string, error) {
	if len(row.Profiles) == 0 {
		return nil, fmt.Errorf("%w: queue row %d names no profile to admit it into", ErrInvalidQueue, row.ID)
	}
	if !manifest.IsKnownType(row.PkgType) {
		return nil, fmt.Errorf("%w: unknown type %q", ErrInvalidQueue, row.PkgType)
	}
	var done []string
	for _, name := range row.Profiles {
		d, err := adb.GetProfile(ctx, name)
		if err != nil {
			return done, fmt.Errorf("profile %s: %w", name, err)
		}
		e := audit.ProfileEntry{Profile: name, Type: row.PkgType, Name: row.PkgName}
		key := manifest.CanonicalName(row.PkgType, row.PkgName)
		if i := slices.IndexFunc(d.Entries, func(x audit.ProfileEntry) bool {
			return x.Type == row.PkgType && manifest.CanonicalName(x.Type, x.Name) == key
		}); i >= 0 {
			e = d.Entries[i]
		}
		e.Reason, e.Actor = fmt.Sprintf("queue #%d: %s", row.ID, reason), actor
		if row.PkgVersion != "" {
			e.Constraint, e.Version = manifest.ConstraintExact, row.PkgVersion
			e.PinnedAt, e.PinnedBy = now.UTC(), actor
		}
		created, err := adb.PutProfileEntry(ctx, e)
		if err != nil {
			return done, fmt.Errorf("profile %s: %w", name, err)
		}
		ev := audit.EventEdit
		if created {
			ev = audit.EventCreate
		}
		_ = adb.Record(ctx, audit.Event{EventType: ev, PkgType: "profile", PkgName: name,
			PkgVersion: row.PkgType + "/" + e.Name, Actor: actor, Status: "success",
			Details: fmt.Sprintf("constraint=%s version=%s reason=%s", e.Constraint, e.Version, e.Reason)})
		done = append(done, name)
	}
	return done, nil
}

// approveOverride requests an override for the row's version and check, or
// hands back the one already pending or active for it, so a row that
// reopened while its override waited for a second approver does not file a
// second request.
func approveOverride(ctx context.Context, adb *audit.DB, cfg *config.Config, row audit.QueueRow, actor string, a QueueApproval, now time.Time) (audit.Override, error) {
	if !slices.Contains(allChecks, row.Check) && !isIntegrationCheck(row.Check) {
		return audit.Override{}, fmt.Errorf("%w: no approval is defined for check %q; `bodega queue dismiss %d` closes the row",
			ErrInvalidQueue, row.Check, row.ID)
	}
	existing, err := ListOverrides(ctx, adb, "", now)
	if err != nil {
		return audit.Override{}, err
	}
	key := overrideNameKey(row.PkgType, row.PkgName)
	for _, o := range existing {
		if o.PkgType == row.PkgType && overrideNameKey(o.PkgType, o.PkgName) == key && o.PkgVersion == row.PkgVersion &&
			o.Check == row.Check && (o.Status == audit.OverrideStatusPending || o.Status == audit.OverrideStatusActive) {
			return o, nil
		}
	}
	expires := a.Expires
	if expires == "" {
		expires = formatTTL(cfg.ResolveOverrideMaxTTL())
	}
	return RequestOverride(ctx, adb, cfg, OverrideRequest{
		Type: row.PkgType, Name: row.PkgName, Version: row.PkgVersion, Check: row.Check,
		Reason: fmt.Sprintf("queue #%d: %s", row.ID, a.Reason), Expires: expires,
	}, actor, now)
}

func recordQueueEvent(ctx context.Context, adb *audit.DB, row audit.QueueRow, actor string) {
	blob, _ := json.Marshal(map[string]any{"id": row.ID, "check": row.Check, "resolution": row.Resolution,
		"reason": row.ResolutionReason, "request_count": row.RequestCount})
	_ = adb.Record(ctx, audit.Event{EventType: audit.EventQueue, PkgType: row.PkgType, PkgName: row.PkgName,
		PkgVersion: row.PkgVersion, Actor: actor, Status: row.State, Details: string(blob)})
}
