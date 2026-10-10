// Package reconcile compares what each host has installed, as inventory
// sources report it, with what bodega served that host and what it refused,
// and says which installed component falls in which class.
//
// It reads the common model alone (audit.InventoryReport and its
// components), never a source's own format, so a new source type needs no
// change here. Classification runs once per report as it arrives and is
// recorded: a component's class in an old report is what bodega knew when the
// report came in, and the read side assembles a host's current state from
// those records rather than recomputing them.
package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
)

// Classes, worst first. Stale is a host-level class: it describes a source
// instance that stopped reporting, not a component.
const (
	ClassRefused      = "refused"
	ClassUnknown      = "unknown"
	ClassUnattributed = "unattributed"
	ClassServed       = "served"
	ClassBaseline     = "baseline"
	ClassStale        = "stale"

	// ClassUnclassified marks a component of a report that has no recorded
	// classification: it arrived before reconciliation existed, or while the
	// audit sink could not answer the served-set query.
	ClassUnclassified = "unclassified"
)

// Classes lists every class a report can show, in display order.
var Classes = []string{ClassRefused, ClassUnknown, ClassUnattributed, ClassUnclassified, ClassServed, ClassBaseline, ClassStale}

func rank(class string) int {
	for i, c := range Classes {
		if c == class {
			return i
		}
	}
	return len(Classes)
}

// Catalog is the part of the manifest store reconciliation reads. ListPackages
// answers from the in-memory index, so a name the catalog lacks costs no
// backend read.
type Catalog interface {
	ListPackages(typ string) []string
	GetPackage(ctx context.Context, typ, name string) (*manifest.PackageManifest, error)
}

// Reconciler classifies reports and assembles host state. DB is required;
// Catalog may be nil (nothing is cataloged), and Instances names the
// configured sources, which coverage, staleness and disagreement read.
type Reconciler struct {
	DB        *audit.DB
	Catalog   Catalog
	Instances []*inventory.Instance
	Logger    *slog.Logger
	Now       func() time.Time
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Reconciler) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (r *Reconciler) instance(name string) *inventory.Instance {
	for _, inst := range r.Instances {
		if inst.Name == name {
			return inst
		}
	}
	return nil
}

// Ingested classifies a report the frame has just stored, records the result
// with any source-disagreement findings, and writes the audit events
// reconciliation owes. It is the frame's OnReport hook: an unbound report has
// no identity to reconcile against and is left alone, and a failure is logged
// rather than returned, because the report is already stored.
func (r *Reconciler) Ingested(ctx context.Context, _ *inventory.Instance, rep audit.InventoryReport) {
	if rep.Identity == "" {
		return
	}
	if _, err := r.Record(ctx, rep); err != nil {
		r.logger().Error("inventory report not reconciled; it stays stored and reads unclassified",
			"instance", rep.Source, "identity", rep.Identity, "report", rep.ID, "error", err)
	}
}

// Record classifies rep, computes the disagreements it produces against the
// host's other sources, stores both, and writes the audit events.
func (r *Reconciler) Record(ctx context.Context, rep audit.InventoryReport) (audit.InventoryClassification, error) {
	c, err := r.Classify(ctx, rep)
	if err != nil {
		return c, err
	}
	if c.Disagreements, err = r.disagreements(ctx, rep); err != nil {
		return c, err
	}
	if err := r.DB.RecordInventoryClassification(ctx, c); err != nil {
		return c, err
	}
	r.audit(ctx, rep, c)
	return c, nil
}

func (r *Reconciler) audit(ctx context.Context, rep audit.InventoryReport, c audit.InventoryClassification) {
	counts := Count(c.Components)
	if counts[ClassRefused]+counts[ClassUnknown] > 0 {
		details, _ := json.Marshal(map[string]any{
			"report_id": rep.ID, "source": rep.Source, "counts": counts,
		})
		r.recordEvent(ctx, rep, audit.InventoryBypass, string(details))
	}
	if len(c.Disagreements) > 0 {
		with := map[string]bool{}
		for _, d := range c.Disagreements {
			with[d.ReportedBy], with[d.AbsentFrom] = true, true
		}
		details, _ := json.Marshal(map[string]any{
			"report_id": rep.ID, "source": rep.Source, "findings": len(c.Disagreements), "instances": sortedKeys(with),
		})
		r.recordEvent(ctx, rep, audit.InventoryDisagreement, string(details))
	}
}

func (r *Reconciler) recordEvent(ctx context.Context, rep audit.InventoryReport, status, details string) {
	err := r.DB.Record(ctx, audit.Event{
		EventType: audit.EventInventory, PkgType: "inventory", PkgName: rep.Source,
		Identity: rep.Identity, Status: status, Details: details,
	})
	if err != nil {
		r.logger().Error("could not record an inventory audit event", "identity", rep.Identity, "report", rep.ID, "status", status, "error", err)
	}
}

// Count tallies components by class.
func Count(cs []audit.ClassifiedComponent) map[string]int {
	out := map[string]int{}
	for _, c := range cs {
		out[c.Class]++
	}
	return out
}

// Classify gives every component of rep its class against what bodega has
// served, refused, cataloged and accepted as of now. It writes nothing.
func (r *Reconciler) Classify(ctx context.Context, rep audit.InventoryReport) (audit.InventoryClassification, error) {
	out := audit.InventoryClassification{
		ReportID: rep.ID, Source: rep.Source, Identity: rep.Identity, ClassifiedAt: r.now(),
	}
	if rep.Identity == "" {
		return out, errors.New("an unbound report has no identity to reconcile against")
	}
	ev, err := r.evidence(ctx, rep.Identity)
	if err != nil {
		return out, err
	}
	out.Components = make([]audit.ClassifiedComponent, 0, len(rep.Components))
	for _, c := range rep.Components {
		class, reason, err := r.classify(ctx, ev, rep.Identity, c)
		if err != nil {
			return out, err
		}
		out.Components = append(out.Components, audit.ClassifiedComponent{
			Ecosystem: c.Ecosystem, Name: c.Name, Version: c.Version, Path: c.Path,
			Class: class, Reason: reason,
		})
	}
	return out, nil
}

// evidence is what one classification run reads once and consults per
// component.
type evidence struct {
	mine     map[string][]string // key -> digests served to this identity
	anyone   map[string][]string // key -> digests served to anyone
	baseline map[string][]audit.BaselineComponent
	catalog  map[string]map[string]bool // type -> safe names in the index
	pkgs     map[string]*manifest.PackageManifest
	refusal  map[string]string // key -> reason, "" when not refused
}

func (r *Reconciler) evidence(ctx context.Context, identity string) (*evidence, error) {
	ev := &evidence{
		baseline: map[string][]audit.BaselineComponent{},
		catalog:  map[string]map[string]bool{},
		pkgs:     map[string]*manifest.PackageManifest{},
		refusal:  map[string]string{},
	}
	var err error
	if ev.mine, err = r.servedSet(ctx, identity); err != nil {
		return nil, err
	}
	if ev.anyone, err = r.servedSet(ctx, ""); err != nil {
		return nil, err
	}
	own, err := r.DB.CurrentInventoryBaseline(ctx, identity, "")
	if err != nil {
		return nil, err
	}
	profile, err := r.DB.ProfileBindingFor(ctx, identity)
	if err != nil {
		return nil, err
	}
	var byProfile *audit.InventoryBaseline
	if profile != "" {
		if byProfile, err = r.DB.CurrentInventoryBaseline(ctx, "", profile); err != nil {
			return nil, err
		}
	}
	for _, b := range []*audit.InventoryBaseline{own, byProfile} {
		if b == nil {
			continue
		}
		for _, bc := range b.Components {
			k := nameKey(bc.Ecosystem, bc.Name)
			ev.baseline[k] = append(ev.baseline[k], bc)
		}
	}
	return ev, nil
}

func (r *Reconciler) servedSet(ctx context.Context, identity string) (map[string][]string, error) {
	objs, err := r.DB.ServedObjects(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("read what bodega served: %w", err)
	}
	out := map[string][]string{}
	for _, so := range objs {
		eco, name, version := ServedIdentity(so)
		if name == "" {
			continue
		}
		k := Key(eco, name, version)
		out[k] = append(out[k], strings.ToLower(so.Digest))
	}
	return out, nil
}

// ServedIdentity is the package a serve_fetch row handed over. Most rows name
// it directly; an apt row names the pool path and no version, and a FreeBSD
// row names the repository and the ABI, so for those two the object key's
// filename is what says which package the bytes were.
func ServedIdentity(so audit.ServedObject) (eco, name, version string) {
	eco, name, version = so.PkgType, so.PkgName, so.PkgVersion
	switch eco {
	case manifest.TypeApt:
		for _, p := range []string{so.ObjectKey, so.PkgName} {
			if n, v := manifest.AptDebIdentity(path.Base(p)); n != "" {
				return eco, n, v
			}
		}
		return eco, "", ""
	case manifest.TypeFreeBSD:
		if n, v := freeBSDPkgIdentity(path.Base(so.ObjectKey)); n != "" {
			return eco, n, v
		}
		return eco, "", ""
	}
	return eco, name, version
}

// freeBSDPkgIdentity splits a pkg repository filename, "<name>-<version>.pkg"
// with an optional "~<hash>" before the extension. A port's version holds no
// "-", so the last one separates the two.
func freeBSDPkgIdentity(file string) (name, version string) {
	base, ok := strings.CutSuffix(file, ".pkg")
	if !ok {
		return "", ""
	}
	if i := strings.LastIndex(base, "~"); i > 0 {
		base = base[:i]
	}
	i := strings.LastIndex(base, "-")
	if i <= 0 || i == len(base)-1 {
		return "", ""
	}
	return base[:i], base[i+1:]
}

// Key is the form two records of one package compare equal under: the
// ecosystem, the name as bodega's own types canonicalize it, and the version
// with an apt epoch dropped, since a pool filename carries none and dpkg
// reports one.
func Key(eco, name, version string) string {
	return nameKey(eco, name) + "\x00" + normVersion(eco, version)
}

func nameKey(eco, name string) string {
	return eco + "\x00" + canonical(eco, name)
}

func canonical(eco, name string) string {
	if manifest.IsKnownType(eco) {
		return manifest.CanonicalName(eco, name)
	}
	return name
}

func normVersion(eco, v string) string {
	if eco != manifest.TypeApt {
		return v
	}
	if i := strings.IndexByte(v, ':'); i > 0 && strings.Trim(v[:i], "0123456789") == "" {
		return v[i+1:]
	}
	return v
}

func (r *Reconciler) classify(ctx context.Context, ev *evidence, identity string, c audit.InventoryComponent) (class, reason string, err error) {
	known := manifest.IsKnownType(c.Ecosystem)
	k := Key(c.Ecosystem, c.Name, c.Version)
	label := c.Name + "@" + c.Version

	var pm *manifest.PackageManifest
	if known {
		if refused, err := r.refusal(ctx, ev, c); err != nil {
			return "", "", err
		} else if refused != "" {
			return ClassRefused, refused, nil
		}
		if pm, err = r.cataloged(ctx, ev, c.Ecosystem, canonical(c.Ecosystem, c.Name)); err != nil {
			return "", "", err
		}
		if ve := versionEntry(pm, c.Ecosystem, c.Version); ve != nil && ve.Hidden {
			return ClassRefused, fmt.Sprintf("%s is hidden in the catalog", label), nil
		}
	}
	if bc, ok := baselineCovers(ev.baseline[nameKey(c.Ecosystem, c.Name)], c); ok {
		if bc.Version == "" {
			return ClassBaseline, fmt.Sprintf("an accepted baseline covers every version of %s", c.Name), nil
		}
		return ClassBaseline, fmt.Sprintf("an accepted baseline covers %s", label), nil
	}
	if !known {
		return ClassUnknown, fmt.Sprintf("bodega serves no %q packages, and no baseline covers this one", c.Ecosystem), nil
	}
	digest := sha256Of(c)
	if digest != "" {
		if served := nonEmpty(ev.anyone[k]); len(served) > 0 && !contains(served, digest) {
			return ClassUnknown, fmt.Sprintf("digest mismatch: the host has sha256 %s, bodega served %s for %s", short(digest), short(served[0]), label), nil
		}
	}
	if mine, ok := ev.mine[k]; ok && (digest == "" || contains(mine, "") || contains(mine, digest)) {
		return ClassServed, fmt.Sprintf("bodega served %s to %s", label, identity), nil
	}
	if _, ok := ev.anyone[k]; ok {
		return ClassUnattributed, fmt.Sprintf("bodega served %s, never to %s", label, identity), nil
	}
	if versionEntry(pm, c.Ecosystem, c.Version) != nil {
		return ClassUnattributed, fmt.Sprintf("%s is cataloged, and bodega never served it to %s", label, identity), nil
	}
	return ClassUnknown, fmt.Sprintf("no catalog entry and no serve_fetch row for %s", label), nil
}

// refusal answers with the reason bodega refused this name@version at
// admission, or "". The newest decision is the one in force: a version
// blocked and later admitted under a changed policy is not refused now.
func (r *Reconciler) refusal(ctx context.Context, ev *evidence, c audit.InventoryComponent) (string, error) {
	k := Key(c.Ecosystem, c.Name, c.Version)
	if reason, ok := ev.refusal[k]; ok {
		return reason, nil
	}
	rows, err := r.DB.Admissions(ctx, audit.AdmissionFilter{
		PkgType: c.Ecosystem, PkgName: canonical(c.Ecosystem, c.Name), PkgVersion: c.Version, Limit: 1,
	})
	if err != nil {
		return "", fmt.Errorf("read admission decisions: %w", err)
	}
	reason := ""
	if len(rows) > 0 && rows[0].Decision != audit.AdmissionAdmitted {
		reason = fmt.Sprintf("bodega refused %s@%s at admission (%s, %s)", c.Name, c.Version,
			rows[0].Decision, rows[0].DecidedAt.UTC().Format(time.DateOnly))
	}
	ev.refusal[k] = reason
	return reason, nil
}

func (r *Reconciler) cataloged(ctx context.Context, ev *evidence, typ, name string) (*manifest.PackageManifest, error) {
	if r.Catalog == nil {
		return nil, nil
	}
	names, ok := ev.catalog[typ]
	if !ok {
		names = map[string]bool{}
		for _, n := range r.Catalog.ListPackages(typ) {
			names[n] = true
		}
		ev.catalog[typ] = names
	}
	if !names[manifest.SafeName(name)] {
		return nil, nil
	}
	k := typ + "\x00" + name
	if pm, ok := ev.pkgs[k]; ok {
		return pm, nil
	}
	pm, err := r.Catalog.GetPackage(ctx, typ, name)
	if err != nil {
		return nil, fmt.Errorf("read catalog entry %s/%s: %w", typ, name, err)
	}
	ev.pkgs[k] = pm
	return pm, nil
}

// versionEntry returns the catalog entry naming exactly this version. A range
// or an open entry does not count: bodega recorded nothing for a version it
// never served under one, so a host holding such a version got it elsewhere.
func versionEntry(pm *manifest.PackageManifest, eco, version string) *manifest.VersionEntry {
	if pm == nil || version == "" {
		return nil
	}
	want := normVersion(eco, version)
	for i := range pm.Versions {
		ve := &pm.Versions[i]
		if (ve.Version != "" && normVersion(eco, ve.Version) == want) || (ve.Ref != "" && ve.Ref == version) {
			return ve
		}
	}
	return nil
}

func baselineCovers(bcs []audit.BaselineComponent, c audit.InventoryComponent) (audit.BaselineComponent, bool) {
	want := normVersion(c.Ecosystem, c.Version)
	for _, bc := range bcs {
		if bc.Version != "" && normVersion(c.Ecosystem, bc.Version) != want {
			continue
		}
		if bc.DigestValue != "" && c.DigestValue != "" && strings.EqualFold(bc.DigestAlgorithm, c.DigestAlgorithm) &&
			!strings.EqualFold(bc.DigestValue, c.DigestValue) {
			continue
		}
		return bc, true
	}
	return audit.BaselineComponent{}, false
}

// sha256Of is the component's digest when it is the sha256 bodega records for
// what it served, and "" otherwise: another algorithm cannot be compared.
func sha256Of(c audit.InventoryComponent) string {
	if strings.EqualFold(strings.ReplaceAll(c.DigestAlgorithm, "-", ""), "sha256") {
		return strings.ToLower(c.DigestValue)
	}
	return ""
}

// disagreements compares rep with the latest report of every other enabled
// source instance mapped to the same host, both ways. A component one reports
// and the other omits is a finding unless the omitting source does not cover
// that ecosystem on this host.
func (r *Reconciler) disagreements(ctx context.Context, rep audit.InventoryReport) ([]audit.SourceDisagreement, error) {
	self := r.instance(rep.Source)
	if self == nil {
		return nil, nil
	}
	latest, err := r.DB.LatestInventoryReports(ctx, rep.Identity)
	if err != nil {
		return nil, err
	}
	var out []audit.SourceDisagreement
	seen := map[string]bool{}
	add := func(c audit.InventoryComponent, by audit.InventoryReport, absent audit.InventoryReport) {
		k := Key(c.Ecosystem, c.Name, c.Version) + "\x00" + by.Source + "\x00" + absent.Source
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, audit.SourceDisagreement{
			Ecosystem: c.Ecosystem, Name: c.Name, Version: c.Version,
			ReportedBy: by.Source, ReportedIn: by.ID, AbsentFrom: absent.Source, AbsentIn: absent.ID,
		})
	}
	mine := componentKeys(rep.Components)
	for _, other := range latest {
		if other.Source == rep.Source {
			continue
		}
		inst := r.instance(other.Source)
		if inst == nil || !inst.Enabled || !inventory.HasCapability(inst.Source, inventory.CapInventory) {
			continue
		}
		theirs := componentKeys(other.Components)
		for _, c := range rep.Components {
			if !theirs[Key(c.Ecosystem, c.Name, c.Version)] && inventory.Covers(inst.Source, rep.Identity, c.Ecosystem) {
				add(c, rep, other)
			}
		}
		if !self.Enabled {
			continue
		}
		for _, c := range other.Components {
			if !mine[Key(c.Ecosystem, c.Name, c.Version)] && inventory.Covers(self.Source, rep.Identity, c.Ecosystem) {
				add(c, other, rep)
			}
		}
	}
	return out, nil
}

func componentKeys(cs []audit.InventoryComponent) map[string]bool {
	out := make(map[string]bool, len(cs))
	for _, c := range cs {
		out[Key(c.Ecosystem, c.Name, c.Version)] = true
	}
	return out
}

func nonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
