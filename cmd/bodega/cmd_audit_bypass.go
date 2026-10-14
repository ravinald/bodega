package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/hostpkg"
	"github.com/ravinald/bodega/internal/inventory/reconcile"
	"github.com/ravinald/bodega/internal/manifest"
)

// Bypass classes. Only the first two are evidence that a host went around
// bodega; predates_audit says the store cannot answer either way.
const (
	bypassNeverServed     = "never_served"
	bypassServedElsewhere = "served_elsewhere"
	bypassPredatesAudit   = "predates_audit"
)

var bypassClasses = []string{bypassNeverServed, bypassServedElsewhere, bypassPredatesAudit}

// Reasons a serve of the version exists and still cannot be pinned on or
// cleared from the host.
const (
	unattributedNoIdentity     = "no_identity"
	unattributedBindingChanged = "binding_changed"
	unattributedHostUnbound    = "host_unbound"
)

// installedMetadataKey is where a JSON inventory records an install time. pkg
// convert writes none, so it comes from whatever built the file.
const installedMetadataKey = "installed_at"

// installedPkg is one (type, name, version) a host reports, with its install
// time when the inventory carries one.
type installedPkg struct {
	Type        string
	Name        string
	Version     string
	InstalledAt time.Time
}

type bypassFinding struct {
	Type        string     `json:"type"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Class       string     `json:"class"`
	Reason      string     `json:"reason"`
	InstalledAt *time.Time `json:"installed_at,omitempty"`
}

// bypassReport is one host's comparison. Unattributable and NoInstallTime are
// counts and never findings: they are what the report cannot say, and stating
// them is what keeps a clean result from reading as proof.
type bypassReport struct {
	Host           string          `json:"host"`
	Inventory      string          `json:"inventory"`
	AnyHost        bool            `json:"any_host"`
	AuditSince     *time.Time      `json:"audit_since"`
	Unbound        bool            `json:"unbound"`
	Installed      int             `json:"installed"`
	ExcludedImage  int             `json:"excluded_image"`
	Served         int             `json:"served"`
	Counts         map[string]int  `json:"counts"`
	Unattributable map[string]int  `json:"unattributable"`
	NoInstallTime  int             `json:"no_install_time"`
	Skipped        []string        `json:"skipped,omitempty"`
	Findings       []bypassFinding `json:"findings"`
	Error          string          `json:"error,omitempty"`
}

func (r *bypassReport) alerts() bool {
	return r.Counts[bypassNeverServed]+r.Counts[bypassServedElsewhere] > 0
}

func (r *bypassReport) unattributableTotal() int {
	n := 0
	for _, c := range r.Unattributable {
		n += c
	}
	return n
}

func newAuditBypassCmd(gf *globalFlags) *cobra.Command {
	var (
		inventoryPath string
		inventoryDir  string
		excludeImage  string
		typ           string
		all           bool
		anyHost       bool
		asJSON        bool
	)
	cmd := &cobra.Command{
		Use:   "bypass <host> --inventory <file> | --all --inventory-dir <dir>",
		Short: "List installed packages bodega never served to the host that has them",
		Long: `bypass compares what a host has installed with the serve_fetch rows bodega
wrote for that host's identity, and lists every installed (type, name,
version) bodega has no record of handing to it:

  never_served      bodega never served that version to anyone
  served_elsewhere  bodega served it, but never to this host
  predates_audit    installed before the audit store's oldest event, so the
                    store cannot say where it came from

The inventory is anything 'bodega pkg convert' reads, or the JSON it writes.
Raw manager output needs --type to pick the parser; on converted JSON, --type
keeps one ecosystem. An install time comes from a sixth dpkg-query column,
${db-fsys:Last-Modified}, or a version's metadata "installed_at" (RFC 3339 or
Unix seconds) in JSON. Without one, predates_audit cannot be told apart.

--exclude-image drops every (type, name, version) the base image's inventory
lists: a package the host was imaged with was never fetched by it.

A serve that cannot be pinned on the host or cleared from it is counted, not
reported as bypass: a request no identity binding resolved, a serve before the
host's binding existed or from an address its binding now covers under
another name, and every serve at all when no binding names the host.

--all reads every <host>.json in --inventory-dir and prints one line per host.

Exits 0 when no host has a never_served or served_elsewhere finding, 2 when
any does, and 1 when bodega could not answer, so a scheduled job can alert on
it. Under --all, a host that cannot be read is named on stderr and does not
hide another host's findings: 2 wins over 1.

Examples:
  dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\t${db-fsys:Last-Modified}\n' > web-01.txt
  bodega audit bypass web-01 --inventory web-01.txt --type apt --exclude-image ubuntu-24.04.txt
  bodega audit bypass web-01 --inventory web-01.json --json
  bodega audit bypass web-01 --inventory web-01.json --any-host
  bodega audit bypass --all --inventory-dir /var/lib/inventories --type npm`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := bypassRequest{
				Type: typ, AnyHost: anyHost, ExcludeImage: excludeImage,
				Stderr: cmd.ErrOrStderr(),
			}
			switch {
			case all && len(args) > 0:
				return errors.New("--all reads every host in --inventory-dir; drop the host argument or drop --all")
			case all:
				if inventoryDir == "" {
					return errors.New("--all needs --inventory-dir <dir> holding one <host>.json per host")
				}
				if inventoryPath != "" {
					return errors.New("--inventory names one host's file; --all reads --inventory-dir instead")
				}
				req.Dir = inventoryDir
			case len(args) == 1:
				if inventoryPath == "" {
					return fmt.Errorf("--inventory <file> is required: the installed list for %s", args[0])
				}
				if inventoryDir != "" {
					return errors.New("--inventory-dir is read only under --all")
				}
				req.Host, req.Inventory = args[0], inventoryPath
			default:
				return errors.New("name a host and its --inventory, or pass --all --inventory-dir <dir>")
			}

			db, err := openQueryableAuditDB(gf, "the serve_fetch rows `audit bypass` compares against")
			if err != nil {
				return err
			}
			defer db.Close()

			code, err := runAuditBypass(backgroundCtx(), os.Stdout, db, req, asJSON)
			if err != nil {
				return err
			}
			if code != 0 {
				_ = db.Close()
				os.Exit(code) //nolint:revive // the alerting exit code a scheduled job reads
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&inventoryPath, "inventory", "", "The host's installed list: pkg convert input or output")
	cmd.Flags().StringVar(&inventoryDir, "inventory-dir", "", "With --all: directory of <host>.json inventories")
	cmd.Flags().StringVar(&excludeImage, "exclude-image", "", "Inventory of the base OS image; its packages are not findings")
	cmd.Flags().StringVar(&typ, "type", "", "Parser for raw manager output, or the one ecosystem to keep from JSON ("+strings.Join(hostpkg.Types(), ", ")+")")
	cmd.Flags().BoolVar(&all, "all", false, "Compare every <host>.json in --inventory-dir")
	cmd.Flags().BoolVar(&anyHost, "any-host", false, "Count a serve to any identity as served")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit the reports as JSON")
	return cmd
}

type bypassRequest struct {
	Host         string
	Inventory    string
	Dir          string
	Type         string
	AnyHost      bool
	ExcludeImage string
	Stderr       io.Writer
}

// runAuditBypass answers req and returns the exit code: 0 clean, 2 when any
// host has a bypass finding. An error is the case where bodega could not
// answer at all, which the caller turns into 1.
func runAuditBypass(ctx context.Context, w io.Writer, db *audit.DB, req bypassRequest, asJSON bool) (int, error) {
	if req.Stderr == nil {
		req.Stderr = io.Discard
	}
	if req.Type != "" {
		if req.Type == manifest.TypeFreeBSD {
			return 1, freeBSDBypassError()
		}
		if _, err := hostpkg.For(req.Type); err != nil {
			return 1, err
		}
	}
	var image map[string]bool
	if req.ExcludeImage != "" {
		pkgs, _, err := readBypassInventory(req.ExcludeImage, req.Type, req.Stderr)
		if err != nil {
			return 1, fmt.Errorf("--exclude-image: %w", err)
		}
		image = make(map[string]bool, len(pkgs))
		for _, p := range pkgs {
			image[reconcile.Key(p.Type, p.Name, p.Version)] = true
		}
	}

	hist, err := db.ServeHistory(ctx)
	if err != nil {
		return 1, fmt.Errorf("read what bodega served: %w", err)
	}
	bindings, err := db.ListIdentityBindings(ctx)
	if err != nil {
		return 1, fmt.Errorf("read identity bindings: %w", err)
	}
	served := indexServeHistory(hist.Records)

	if req.Dir == "" {
		pkgs, skipped, err := readBypassInventory(req.Inventory, req.Type, req.Stderr)
		if err != nil {
			return 1, err
		}
		rep := classifyBypass(req.Host, pkgs, image, served, hist.Since, bindings, req.AnyHost)
		rep.Inventory, rep.Skipped = req.Inventory, skipped
		if asJSON {
			if err := writeJSON(w, rep); err != nil {
				return 1, err
			}
		} else {
			printBypassReport(w, rep)
		}
		if rep.alerts() {
			return 2, nil
		}
		return 0, nil
	}

	paths, err := filepath.Glob(filepath.Join(req.Dir, "*.json"))
	if err != nil {
		return 1, fmt.Errorf("list %s: %w", req.Dir, err)
	}
	if len(paths) == 0 {
		return 1, fmt.Errorf("%s holds no <host>.json inventories; nothing to compare", req.Dir)
	}
	sort.Strings(paths)
	var reps []bypassReport
	alert, failed := false, 0
	for _, p := range paths {
		host := strings.TrimSuffix(filepath.Base(p), ".json")
		pkgs, skipped, err := readBypassInventory(p, req.Type, req.Stderr)
		if err != nil {
			failed++
			fmt.Fprintf(req.Stderr, "audit bypass: %s: %v\n", host, err)
			reps = append(reps, bypassReport{Host: host, Inventory: p, Error: err.Error()})
			continue
		}
		rep := classifyBypass(host, pkgs, image, served, hist.Since, bindings, req.AnyHost)
		rep.Inventory, rep.Skipped = p, skipped
		alert = alert || rep.alerts()
		reps = append(reps, rep)
	}
	if asJSON {
		if err := writeJSON(w, reps); err != nil {
			return 1, err
		}
	} else {
		printBypassSummary(w, reps, hist.Since, req.AnyHost)
	}
	switch {
	case alert:
		return 2, nil
	case failed > 0:
		return 1, fmt.Errorf("%d of %d inventories could not be read; see the lines above", failed, len(paths))
	}
	return 0, nil
}

func freeBSDBypassError() error {
	return errors.New("a freebsd inventory ('pkg query %R\\t%q') names the repositories packages came from, not the packages, " +
		"so there is no installed version to look for in the serve record")
}

// readBypassInventory reads one host's installed list. JSON that pkg convert
// wrote (or pkg export) is recognized by every entry naming a type; anything
// else is raw manager output and goes through the parser --type names.
//
// The second return names what was left out and why, for the report to state.
func readBypassInventory(path, typ string, stderr io.Writer) ([]installedPkg, []string, error) {
	data, err := readInput(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil, fmt.Errorf("%s is empty: an empty inventory would report a clean host", path)
	}
	if pms, ok := convertedManifests(data); ok {
		return fromManifests(pms, typ)
	}
	if typ == "" {
		return nil, nil, fmt.Errorf("%s is not JSON that 'bodega pkg convert' wrote; name its manager with --type (%s)",
			path, strings.Join(hostpkg.Types(), ", "))
	}
	var out []installedPkg
	if typ == manifest.TypeApt {
		inv, err := hostpkg.ParseAptRows(bytes.NewReader(data))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		warnInventory(stderr, typ, inv.Warnings)
		for _, row := range inv.Rows {
			out = append(out, installedPkg{
				Type: typ, Name: manifest.CanonicalName(typ, row.Name), Version: row.Version, InstalledAt: row.InstalledAt,
			})
		}
		return out, nil, nil
	}
	parse, err := hostpkg.For(typ)
	if err != nil {
		return nil, nil, err
	}
	res, err := parse(bytes.NewReader(data))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	warnInventory(stderr, typ, res.Warnings)
	pkgs, skipped, err := fromManifests(res.Packages, typ)
	return pkgs, skipped, err
}

func warnInventory(w io.Writer, typ string, warnings []string) {
	for _, s := range warnings {
		fmt.Fprintf(w, "%s: %s\n", typ, s)
	}
}

// convertedManifests parses data as pkg convert's output: a JSON array of
// manifests, or one manifest. pip, npm and helm print JSON of their own, and
// none of it names a bodega type on every entry, which is what tells them
// apart.
func convertedManifests(data []byte) ([]manifest.PackageManifest, bool) {
	trimmed := bytes.TrimSpace(data)
	var pms []manifest.PackageManifest
	if trimmed[0] == '{' {
		var one manifest.PackageManifest
		if json.Unmarshal(trimmed, &one) != nil {
			return nil, false
		}
		pms = []manifest.PackageManifest{one}
	} else if json.Unmarshal(trimmed, &pms) != nil {
		return nil, false
	}
	if len(pms) == 0 {
		return nil, false
	}
	for _, pm := range pms {
		if pm.Name == "" || !manifest.IsKnownType(pm.Type) {
			return nil, false
		}
	}
	return pms, true
}

func fromManifests(pms []manifest.PackageManifest, typ string) ([]installedPkg, []string, error) {
	var out []installedPkg
	freebsd := 0
	for _, pm := range pms {
		if typ != "" && pm.Type != typ {
			continue
		}
		if pm.Type == manifest.TypeFreeBSD {
			freebsd++
			continue
		}
		name := manifest.CanonicalName(pm.Type, pm.Name)
		for _, ve := range pm.Versions {
			v := ve.Version
			if v == "" {
				v = ve.Ref
			}
			if v == "" {
				continue
			}
			at, err := parseInstalledAt(ve.Metadata[installedMetadataKey])
			if err != nil {
				return nil, nil, fmt.Errorf("%s/%s %s: %w", pm.Type, pm.Name, v, err)
			}
			out = append(out, installedPkg{Type: pm.Type, Name: name, Version: v, InstalledAt: at})
		}
	}
	var skipped []string
	if freebsd > 0 {
		skipped = append(skipped, fmt.Sprintf("%d freebsd entr%s skipped: each names a repository, not an installed package",
			freebsd, plural(freebsd, "y", "ies")))
	}
	return out, skipped, nil
}

func parseInstalledAt(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if secs, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(secs, 0).UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("metadata %q is %q, want RFC 3339 or Unix seconds", installedMetadataKey, s)
	}
	return t.UTC(), nil
}

func indexServeHistory(recs []audit.ServeRecord) map[string][]audit.ServeRecord {
	out := map[string][]audit.ServeRecord{}
	for _, rec := range recs {
		eco, name, version := reconcile.ServedIdentity(rec.ServedObject)
		if name == "" {
			continue
		}
		k := reconcile.Key(eco, name, version)
		out[k] = append(out[k], rec)
	}
	return out
}

// hostBinding is what the binding table says about one host today: when it
// was first bound, and the networks that resolve to it.
type hostBinding struct {
	bound bool
	since time.Time
	cidrs []netip.Prefix
}

func bindingFor(host string, bindings []audit.IdentityBinding) hostBinding {
	var hb hostBinding
	for _, b := range bindings {
		if b.Identity != host {
			continue
		}
		if !hb.bound || (!b.CreatedAt.IsZero() && b.CreatedAt.Before(hb.since)) {
			hb.since = b.CreatedAt
		}
		hb.bound = true
		if b.Kind == audit.BindCIDR {
			if p, err := netip.ParsePrefix(b.Key); err == nil {
				hb.cidrs = append(hb.cidrs, p)
			}
		}
	}
	return hb
}

func (hb hostBinding) covers(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range hb.cidrs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// classifyBypass compares one host's installed list with the serve record.
//
// A version served to the host is not a finding. Of the rest, one installed
// before the store's window is predates_audit, since the store's silence says
// nothing about it. Then attribution: a serve the record cannot pin on another
// host (no identity, a binding that moved, or a host bound to nothing) is
// counted unattributable rather than called a bypass. What remains is
// served_elsewhere when anyone got it, never_served when nobody did.
func classifyBypass(host string, pkgs []installedPkg, image map[string]bool, served map[string][]audit.ServeRecord,
	since time.Time, bindings []audit.IdentityBinding, anyHost bool,
) bypassReport {
	rep := bypassReport{
		Host: host, AnyHost: anyHost,
		Counts:         map[string]int{},
		Unattributable: map[string]int{},
		Findings:       []bypassFinding{},
	}
	if !since.IsZero() {
		s := since.UTC()
		rep.AuditSince = &s
	}
	hb := bindingFor(host, bindings)
	rep.Unbound = !anyHost && !hb.bound

	for _, p := range pkgs {
		k := reconcile.Key(p.Type, p.Name, p.Version)
		if image[k] {
			rep.ExcludedImage++
			continue
		}
		rep.Installed++
		if p.InstalledAt.IsZero() {
			rep.NoInstallTime++
		}
		recs := served[k]
		if servedTo(recs, host, anyHost) {
			rep.Served++
			continue
		}
		label := p.Name + "@" + p.Version
		finding := func(class, reason string) {
			f := bypassFinding{Type: p.Type, Name: p.Name, Version: p.Version, Class: class, Reason: reason}
			if !p.InstalledAt.IsZero() {
				at := p.InstalledAt
				f.InstalledAt = &at
			}
			rep.Counts[class]++
			rep.Findings = append(rep.Findings, f)
		}
		if !p.InstalledAt.IsZero() && (since.IsZero() || p.InstalledAt.Before(since)) {
			finding(bypassPredatesAudit, fmt.Sprintf("installed %s, before the audit store's oldest event", p.InstalledAt.Format(time.RFC3339)))
			continue
		}
		if len(recs) == 0 {
			finding(bypassNeverServed, fmt.Sprintf("no serve_fetch row names %s for any identity", label))
			continue
		}
		if why := unattributable(recs, hb); why != "" {
			rep.Unattributable[why]++
			continue
		}
		finding(bypassServedElsewhere, fmt.Sprintf("bodega served %s to %s, never to %s", label, strings.Join(identities(recs), ", "), host))
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Class != b.Class {
			return classRank(a.Class) < classRank(b.Class)
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return rep
}

func servedTo(recs []audit.ServeRecord, host string, anyHost bool) bool {
	if anyHost {
		return len(recs) > 0
	}
	for _, r := range recs {
		if r.Identity == host {
			return true
		}
	}
	return false
}

// unattributable names why the record cannot say whether any of these serves
// went to the host, or "" when every one of them provably went elsewhere.
func unattributable(recs []audit.ServeRecord, hb hostBinding) string {
	if !hb.bound {
		return unattributedHostUnbound
	}
	for _, r := range recs {
		if r.Identity == "" {
			return unattributedNoIdentity
		}
	}
	for _, r := range recs {
		if hb.covers(r.ClientIP) || (!hb.since.IsZero() && r.First.Before(hb.since)) {
			return unattributedBindingChanged
		}
	}
	return ""
}

func identities(recs []audit.ServeRecord) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range recs {
		if !seen[r.Identity] {
			seen[r.Identity] = true
			out = append(out, r.Identity)
		}
	}
	sort.Strings(out)
	return out
}

func classRank(c string) int {
	for i, x := range bypassClasses {
		if x == c {
			return i
		}
	}
	return len(bypassClasses)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printBypassReport(w io.Writer, rep bypassReport) {
	if len(rep.Findings) > 0 {
		fmt.Fprintf(w, "%-18s %-8s %-40s %-24s %s\n", "CLASS", "TYPE", "NAME", "VERSION", "REASON")
		fmt.Fprintln(w, "---")
		for _, f := range rep.Findings {
			fmt.Fprintf(w, "%-18s %-8s %-40s %-24s %s\n", f.Class, f.Type, truncate(f.Name, 40), truncate(f.Version, 24), f.Reason)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%s: %d installed, %d served to it, %s\n", rep.Host, rep.Installed, rep.Served, classCounts(rep))
	for _, l := range bypassLimits(rep) {
		fmt.Fprintf(w, "  %s\n", l)
	}
}

func classCounts(rep bypassReport) string {
	parts := make([]string, 0, len(bypassClasses)+2)
	for _, c := range bypassClasses {
		parts = append(parts, fmt.Sprintf("%d %s", rep.Counts[c], c))
	}
	parts = append(parts, fmt.Sprintf("%d unattributable", rep.unattributableTotal()))
	parts = append(parts, fmt.Sprintf("%d excluded as image", rep.ExcludedImage))
	return strings.Join(parts, ", ")
}

// bypassLimits is what a clean result does not prove, in the report itself:
// the reader of a scheduled job's output never sees this command's help.
func bypassLimits(rep bypassReport) []string {
	var out []string
	if rep.AuditSince == nil {
		out = append(out, "limit: the audit store holds no events, so nothing installed can be traced to bodega")
	} else {
		out = append(out, fmt.Sprintf("limit: the audit window starts %s; only serve_fetch rows naming a stored object count",
			rep.AuditSince.Format(time.RFC3339)))
	}
	if rep.NoInstallTime > 0 {
		out = append(out, fmt.Sprintf("limit: %d package(s) carry no install time, so one installed before the window reads as never_served or served_elsewhere rather than predates_audit",
			rep.NoInstallTime))
	}
	if rep.AnyHost {
		out = append(out, "limit: --any-host counts a serve to any identity as served; attribution is not checked")
	}
	if rep.Unbound {
		out = append(out, fmt.Sprintf("limit: no identity binding names %s, so its requests reached bodega without an identity; a version anyone was served is counted unattributable, and only never_served is evidence",
			rep.Host))
	}
	if n := rep.unattributableTotal(); n > 0 {
		var why []string
		for _, k := range []string{unattributedNoIdentity, unattributedBindingChanged, unattributedHostUnbound} {
			if c := rep.Unattributable[k]; c > 0 {
				why = append(why, fmt.Sprintf("%d %s", c, unattributedText(k)))
			}
		}
		out = append(out, fmt.Sprintf("limit: %d package(s) cannot be attributed and are not counted as bypass: %s", n, strings.Join(why, "; ")))
	}
	for _, s := range rep.Skipped {
		out = append(out, "limit: "+s)
	}
	return out
}

func unattributedText(k string) string {
	switch k {
	case unattributedNoIdentity:
		return "served to a request no identity binding resolved"
	case unattributedBindingChanged:
		return "served before this host's binding existed, or from an address its binding now covers under another identity"
	case unattributedHostUnbound:
		return "served to someone while no binding names this host"
	}
	return k
}

func printBypassSummary(w io.Writer, reps []bypassReport, since time.Time, anyHost bool) {
	for _, rep := range reps {
		if rep.Error != "" {
			fmt.Fprintf(w, "%s: error: %s\n", rep.Host, rep.Error)
			continue
		}
		fmt.Fprintf(w, "%s: %d installed, %d served to it, %s\n", rep.Host, rep.Installed, rep.Served, classCounts(rep))
	}
	if since.IsZero() {
		fmt.Fprintln(w, "limit: the audit store holds no events, so nothing installed can be traced to bodega")
	} else {
		fmt.Fprintf(w, "limit: the audit window starts %s; only serve_fetch rows naming a stored object count\n", since.UTC().Format(time.RFC3339))
	}
	fmt.Fprintln(w, "limit: unattributable packages (no identity on the request, or a binding that changed) are counted, not reported as bypass; run 'bodega audit bypass <host> --inventory <file>' for one host's reasons")
	if anyHost {
		fmt.Fprintln(w, "limit: --any-host counts a serve to any identity as served; attribution is not checked")
	}
}
