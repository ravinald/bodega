package pins

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// ReviewDateLayout is the one spelling a review date is written and read in.
// A pin is compared against it to decide whether it is overdue, so a value
// nothing can parse is a review that never comes due.
const ReviewDateLayout = "2006-01-02"

// OSV states a pinned version can be in. Unchecked and Clean are separated on
// purpose: a version nobody ever queried and a version with no findings carry
// the same empty advisory list, and reporting the first as the second is how a
// pin acquires a clean bill of health nobody issued.
const (
	OSVUnchecked = "unchecked" // no run has ever answered for this version
	OSVClean     = "clean"     // answered, no findings
	OSVFlagged   = "flagged"   // answered, findings recorded
	OSVUnknown   = "n/a"       // OSV holds no records for this registry type
)

// OSVState is one pinned version's recorded OSV answer, as E6 stamped it and
// B34 scored it.
type OSVState struct {
	State    string                          `json:"state"`
	Vulns    []string                        `json:"vulns,omitempty"`
	Severity map[string][]policy.OSVSeverity `json:"severity,omitempty"`
	Checked  *time.Time                      `json:"checked_at,omitempty"`
}

// Pin is one recorded decision to stop receiving updates for one package, and
// everything bodega knows about the version it holds.
//
// The report is the whole of what this reports: no suppression state, no
// ticket, no SLA clock. The reason and the review date are the only
// suppression concept bodega has, and that boundary is deliberate — a pin
// accepts the known vulnerabilities in that version for the life of the pin,
// and what to do about them belongs to the tool that tracks remediation.
type Pin struct {
	Profile     string     `json:"profile"`
	Type        string     `json:"type"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Reason      string     `json:"reason"`
	Actor       string     `json:"actor,omitempty"`
	PinnedAt    *time.Time `json:"pinned_at,omitempty"`
	ReviewAfter string     `json:"review_after,omitempty"`
	// OverdueDays is how far past the review date the pin is, in whole days.
	// Zero when the review date is in the future, absent or unparsable, and
	// Stale is what separates those from a pin that came due today.
	OverdueDays int  `json:"overdue_days"`
	Stale       bool `json:"stale"`
	// Cataloged reports whether the catalog still holds the pinned version.
	// A pin on a version nothing serves has no stamp to read, so its OSV state
	// is unchecked for a reason that has nothing to do with OSV.
	Cataloged bool     `json:"cataloged"`
	OSV       OSVState `json:"osv"`
}

// Collect reads every pin in one profile, or in all of them when profile is
// empty, and answers for each of them from the catalog.
//
// now is passed rather than read, because "how far past the review date" is
// the whole output of the --stale gate and a test that cannot fix the clock
// cannot assert it.
func Collect(ctx context.Context, adb *audit.DB, store *manifest.Store, profile string, now time.Time) ([]Pin, error) {
	names := []string{profile}
	if profile == "" {
		all, err := adb.ListProfiles(ctx)
		if err != nil {
			return nil, fmt.Errorf("list profiles: %w", err)
		}
		names = names[:0]
		for _, p := range all {
			names = append(names, p.Name)
		}
	}

	var out []Pin
	for _, name := range names {
		d, err := adb.GetProfile(ctx, name)
		if err != nil {
			return nil, err
		}
		for _, e := range d.Entries {
			if !e.Pinned() {
				continue
			}
			p, err := pinFor(ctx, store, e, now)
			if err != nil {
				return nil, err
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// Stale narrows a report to the pins past their review date.
func Stale(all []Pin) []Pin {
	var out []Pin
	for _, p := range all {
		if p.Stale {
			out = append(out, p)
		}
	}
	return out
}

func pinFor(ctx context.Context, store *manifest.Store, e audit.ProfileEntry, now time.Time) (Pin, error) {
	p := Pin{
		Profile: e.Profile, Type: e.Type, Name: e.Name, Version: e.Version,
		Reason: e.Reason, Actor: e.Actor, ReviewAfter: e.ReviewAfter,
		OSV: OSVState{State: OSVUnchecked},
	}
	if at := e.PinDecidedAt(); !at.IsZero() {
		p.PinnedAt = &at
	}
	if due, ok := ParseReviewDate(e.ReviewAfter); ok && !now.Before(due) {
		p.Stale = true
		p.OverdueDays = int(math.Floor(now.Sub(due).Hours() / 24))
	}
	if !policy.OSVCovers(e.Type) {
		p.OSV.State = OSVUnknown
	}
	if store == nil {
		return p, nil
	}

	pm, err := store.GetPackage(ctx, e.Type, e.Name)
	if err != nil {
		// The two repairs are opposite ones, the same split `profile check`
		// makes: a catalog that cannot be read is a broken catalog, and
		// reporting its pins as uncataloged would send an operator to delete
		// entries that are fine.
		return Pin{}, fmt.Errorf("load %s/%s: %w", e.Type, e.Name, err)
	}
	if pm == nil {
		return p, nil
	}
	for _, ve := range pm.Versions {
		if ve.Version != e.Version {
			continue
		}
		p.Cataloged = true
		if p.OSV.State == OSVUnknown {
			break
		}
		p.OSV = osvStateOf(ve)
		break
	}
	return p, nil
}

// osvStateOf renders one version's stamp. A range entry's date is dropped for
// the reason `show pkg` drops it: the gate refuses to date a constraint no
// point lookup settles, so a date on one was written against the base version
// and claims an answer for releases nobody queried.
func osvStateOf(ve manifest.VersionEntry) OSVState {
	st := policy.OSVStampOf(ve)
	if !policy.OSVDatable(ve) {
		st.Checked = time.Time{}
	}
	out := OSVState{Vulns: st.Vulns, Severity: st.Severity}
	switch {
	case st.Checked.IsZero():
		// Unchecked even when ids are recorded: the ids came from a run whose
		// date did not survive, so what is known is the finding and not that
		// the finding is current. Reporting it as flagged-and-dated would put
		// a day on an answer nobody has.
		out.State = OSVUnchecked
	case st.Flagged():
		out.State = OSVFlagged
	default:
		out.State = OSVClean
	}
	if !st.Checked.IsZero() {
		checked := st.Checked
		out.Checked = &checked
	}
	return out
}

// ParseReviewDate reads a stored review date, reporting whether it is one.
func ParseReviewDate(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(ReviewDateLayout, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// ValidateReviewDate refuses a review date nothing can compare against.
//
// Stored unvalidated, "next quarter" is a pin that never comes due: --stale is
// a CI gate, and a date it cannot parse is silently not overdue forever, which
// is the exact failure the review date exists to prevent.
func ValidateReviewDate(s string) error {
	if s == "" {
		return nil
	}
	if _, ok := ParseReviewDate(s); !ok {
		return fmt.Errorf("--review-after %q is not a date: write it as YYYY-MM-DD, for example %s.\n"+
			"  A date nothing can parse is a pin that is never overdue, so 'bodega profile pins --stale' would pass on it forever",
			s, time.Now().UTC().AddDate(0, 6, 0).Format(ReviewDateLayout))
	}
	return nil
}
