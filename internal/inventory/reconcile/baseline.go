package reconcile

import (
	"context"
	"fmt"

	"github.com/ravinald/bodega/internal/audit"
)

// AcceptReport records a report as identity's baseline: reportID when it is
// set, otherwise the host's current set (the latest report from each mapped
// source). Reports that arrive afterwards classify the components it holds as
// baseline, unless bodega refused them; reports already classified keep the
// classes they were given.
func (r *Reconciler) AcceptReport(ctx context.Context, identity string, reportID int64, actor, comment string) (audit.InventoryBaseline, error) {
	var reps []audit.InventoryReport
	var err error
	if reportID != 0 {
		if reps, err = r.DB.InventoryReportsByID(ctx, []int64{reportID}); err != nil {
			return audit.InventoryBaseline{}, err
		}
		if len(reps) == 0 {
			return audit.InventoryBaseline{}, fmt.Errorf("no inventory report has id %d", reportID)
		}
		if reps[0].Identity != identity {
			return audit.InventoryBaseline{}, fmt.Errorf("report %d belongs to %q, not %q; `bodega inventory report %s --json` lists this host's report ids",
				reportID, reps[0].Identity, identity, identity)
		}
	} else {
		if reps, err = r.DB.LatestInventoryReports(ctx, identity); err != nil {
			return audit.InventoryBaseline{}, err
		}
		if len(reps) == 0 {
			return audit.InventoryBaseline{}, fmt.Errorf("%q has no stored report to accept; `bodega inventory hosts` shows when each host last reported", identity)
		}
	}
	b := audit.InventoryBaseline{Identity: identity, Actor: actor, Comment: comment}
	seen := map[string]bool{}
	for _, rep := range reps {
		b.ReportIDs = append(b.ReportIDs, rep.ID)
		for _, c := range rep.Components {
			bc := audit.BaselineComponent{
				Ecosystem: c.Ecosystem, Name: canonical(c.Ecosystem, c.Name), Version: c.Version,
				DigestAlgorithm: c.DigestAlgorithm, DigestValue: c.DigestValue,
			}
			k := Key(bc.Ecosystem, bc.Name, bc.Version) + "\x00" + bc.DigestAlgorithm + "\x00" + bc.DigestValue
			if !seen[k] {
				seen[k] = true
				b.Components = append(b.Components, bc)
			}
		}
	}
	return r.DB.AcceptInventoryBaseline(ctx, b)
}

// AcceptProfile records a profile's entries as the baseline of every identity
// bound to it, now and later. A pinned entry covers its one version and an
// unpinned one every version of the name. The entries are copied: a later
// edit to the profile takes effect when it is accepted again.
func (r *Reconciler) AcceptProfile(ctx context.Context, profile, actor, comment string) (audit.InventoryBaseline, error) {
	d, err := r.DB.GetProfile(ctx, profile)
	if err != nil {
		return audit.InventoryBaseline{}, err
	}
	if len(d.Entries) == 0 {
		return audit.InventoryBaseline{}, fmt.Errorf("profile %q lists no entries, so it has nothing to accept; `bodega profile show %s` shows what it holds", profile, profile)
	}
	b := audit.InventoryBaseline{Profile: profile, Actor: actor, Comment: comment}
	for _, e := range d.Entries {
		bc := audit.BaselineComponent{Ecosystem: e.Type, Name: canonical(e.Type, e.Name)}
		if e.Pinned() {
			bc.Version = e.Version
		}
		b.Components = append(b.Components, bc)
	}
	return r.DB.AcceptInventoryBaseline(ctx, b)
}

// Baselines is what is accepted for one identity: its own baseline and the
// one its bound profile carries. Either may be nil.
type Baselines struct {
	Identity  string                   `json:"identity"`
	Profile   string                   `json:"profile,omitempty"`
	Own       *audit.InventoryBaseline `json:"own"`
	ByProfile *audit.InventoryBaseline `json:"by_profile"`
}

// BaselinesFor returns the baselines in force for identity.
func (r *Reconciler) BaselinesFor(ctx context.Context, identity string) (Baselines, error) {
	out := Baselines{Identity: identity}
	var err error
	if out.Own, err = r.DB.CurrentInventoryBaseline(ctx, identity, ""); err != nil {
		return out, err
	}
	if out.Profile, err = r.DB.ProfileBindingFor(ctx, identity); err != nil {
		return out, err
	}
	if out.Profile != "" {
		if out.ByProfile, err = r.DB.CurrentInventoryBaseline(ctx, "", out.Profile); err != nil {
			return out, err
		}
	}
	return out, nil
}
