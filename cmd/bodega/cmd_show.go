package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func newShowCmd(gf *globalFlags) *cobra.Command {
	show := &cobra.Command{
		Use:   "show",
		Short: "Display repository and package information",
	}
	show.AddCommand(
		newShowRepoCmd(gf),
		newShowPkgCmd(gf),
	)
	return show
}

// ---------- show repo (client view, excludes hidden) ----------

func newShowRepoCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "repo [TYPE] [PACKAGE] [VERSION]",
		Short: "Show repository contents (client view, excludes hidden)",
		Long: `Display what clients can install from this repository.
Hidden packages and versions are excluded.

  bodega show repo                       # all types with counts
  bodega show repo git                   # packages in git
  bodega show repo git widget            # versions of widget
  bodega show repo git widget v4.5.7     # version details
  bodega show repo git json              # JSON output`,
		Args:                  cobra.ArbitraryArgs,
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore(gf)
			if err != nil {
				return err
			}
			ctx := context.Background()
			args, jsonOut := stripJSON(args)
			return runShow(ctx, store, args, false, jsonOut, nil)
		},
	}
}

// ---------- show pkg (admin view, shows everything) ----------

func newShowPkgCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "pkg [TYPE] [PACKAGE] [VERSION|all]",
		Aliases: []string{"package"},
		Short:   "Show package configuration (admin view, includes hidden/frozen)",
		Long: `Display full package configuration including hidden versions,
frozen flags, build environment, and raw JSON.

  bodega show pkg                        # all types with counts
  bodega show pkg pypi                   # all pypi packages
  bodega show pkg pypi django            # django versions
  bodega show pkg pypi django all        # verbose with build_env
  bodega show pkg pypi django 5.2.12     # specific version detail
  bodega show pkg pypi django json       # JSON output`,
		Args:                  cobra.ArbitraryArgs,
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore(gf)
			if err != nil {
				return err
			}
			ctx := context.Background()
			args, jsonOut := stripJSON(args)
			return runShow(ctx, store, args, true, jsonOut, loadMirrorHides(ctx, gf, args))
		},
	}
}

// stripJSON checks if the last positional arg is "json" and removes it.
func stripJSON(args []string) ([]string, bool) {
	if len(args) > 0 && args[len(args)-1] == "json" {
		return args[:len(args)-1], true
	}
	return args, false
}

// runShow dispatches based on arg depth. admin=true shows hidden/frozen/build_env.
// hides are the mirrored apt hides the listing names beside the manifests,
// and are nil on the client view, which shows nothing hidden.
func runShow(ctx context.Context, store *manifest.Store, args []string, admin, jsonOut bool, hides []audit.AptMirrorHide) error {
	switch len(args) {
	case 0:
		return showTypeSummary(ctx, store, admin, jsonOut)
	case 1:
		return showPackageList(ctx, store, args[0], admin, jsonOut, hides)
	case 2:
		return showVersionList(ctx, store, args[0], args[1], admin, jsonOut, hides)
	case 3:
		return showVersionDetail(ctx, store, args[0], args[1], args[2], admin, jsonOut)
	default:
		return fmt.Errorf("too many arguments")
	}
}

// ---------- depth 0: type summary ----------

func showTypeSummary(ctx context.Context, store *manifest.Store, admin, jsonOut bool) error {
	type typeStat struct {
		Type     string `json:"type"`
		Packages int    `json:"packages"`
		Versions int    `json:"versions"`
		Hidden   int    `json:"hidden,omitempty"`
	}
	var stats []typeStat

	for _, typ := range manifest.AllTypes {
		names := store.ListPackages(typ)
		versions := 0
		hidden := 0
		for _, name := range names {
			pm, err := store.GetPackage(ctx, typ, name)
			if err != nil || pm == nil {
				continue
			}
			for _, ve := range pm.Versions {
				if ve.Hidden {
					hidden++
					if !admin {
						continue
					}
				}
				versions++
			}
		}
		stats = append(stats, typeStat{Type: typ, Packages: len(names), Versions: versions, Hidden: hidden})
	}

	if jsonOut {
		return printJSON(stats)
	}

	if admin {
		fmt.Printf("%-10s %-10s %-10s %-10s\n", "TYPE", "PACKAGES", "VERSIONS", "HIDDEN")
	} else {
		fmt.Printf("%-10s %-10s %-10s\n", "TYPE", "PACKAGES", "VERSIONS")
	}
	for _, s := range stats {
		if admin {
			fmt.Printf("%-10s %-10d %-10d %-10d\n", s.Type, s.Packages, s.Versions, s.Hidden)
		} else {
			fmt.Printf("%-10s %-10d %-10d\n", s.Type, s.Packages, s.Versions)
		}
	}
	return nil
}

// ---------- depth 1: package list ----------

func showPackageList(ctx context.Context, store *manifest.Store, typ string, admin, jsonOut bool, hides []audit.AptMirrorHide) error {
	if !isValidType(typ) {
		return fmt.Errorf("unknown type %q — must be one of: %s", typ, strings.Join(manifest.AllTypes, ", "))
	}

	type pkgInfo struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
		Versions    int    `json:"versions"`
		Latest      string `json:"latest,omitempty"`
		Mode        string `json:"mode,omitempty"`
		Hidden      int    `json:"hidden,omitempty"`
		// MirrorHidden lists the versions of a mirrored apt package hidden
		// server-wide. A package served only from a mirror has no manifest,
		// so it appears in the list through this field alone.
		MirrorHidden []audit.AptMirrorHide `json:"mirror_hidden,omitempty"`
	}
	var pkgs []pkgInfo

	for _, name := range store.ListPackages(typ) {
		pm, err := store.GetPackage(ctx, typ, name)
		if err != nil || pm == nil {
			continue
		}
		visibleVersions := 0
		hiddenVersions := 0
		latest := ""
		mode := ""
		for _, ve := range pm.Versions {
			if ve.Hidden {
				hiddenVersions++
				if !admin {
					continue
				}
			}
			visibleVersions++
			v := ve.Version
			if v == "" {
				v = ve.Ref
			}
			latest = v
			if mode == "" {
				mode = ve.EffectiveMode()
			}
		}
		if visibleVersions == 0 && !admin {
			continue
		}
		pkgs = append(pkgs, pkgInfo{
			Name:        pm.Name,
			Description: pm.Description,
			Versions:    visibleVersions,
			Latest:      latest,
			Mode:        mode,
			Hidden:      hiddenVersions,
		})
	}

	byName := map[string][]audit.AptMirrorHide{}
	var hiddenNames []string
	for _, h := range hides {
		if byName[h.Name] == nil {
			hiddenNames = append(hiddenNames, h.Name)
		}
		byName[h.Name] = append(byName[h.Name], h)
	}
	for i := range pkgs {
		if hs := byName[pkgs[i].Name]; hs != nil {
			pkgs[i].MirrorHidden = hs
			pkgs[i].Hidden += len(hs)
			delete(byName, pkgs[i].Name)
		}
	}
	for _, name := range hiddenNames {
		if hs := byName[name]; hs != nil {
			pkgs = append(pkgs, pkgInfo{Name: name, Mode: "mirrored", Hidden: len(hs), MirrorHidden: hs})
		}
	}

	if jsonOut {
		return printJSON(pkgs)
	}

	defer printMirrorHides(hides)
	if admin {
		fmt.Printf("%-35s %-10s %-12s %-10s %-8s\n", "PACKAGE", "VERSIONS", "LATEST", "MODE", "HIDDEN")
	} else {
		fmt.Printf("%-35s %-10s %-12s %-10s\n", "PACKAGE", "VERSIONS", "LATEST", "MODE")
	}
	for _, p := range pkgs {
		if p.Mode == "mirrored" {
			continue
		}
		if admin {
			fmt.Printf("%-35s %-10d %-12s %-10s %-8d\n", p.Name, p.Versions, p.Latest, p.Mode, p.Hidden)
		} else {
			fmt.Printf("%-35s %-10d %-12s %-10s\n", p.Name, p.Versions, p.Latest, p.Mode)
		}
	}
	return nil
}

// ---------- depth 2: version list ----------

func showVersionList(ctx context.Context, store *manifest.Store, typ, name string, admin, jsonOut bool, hides []audit.AptMirrorHide) error {
	pm, err := store.GetPackage(ctx, typ, name)
	if (err != nil || pm == nil) && len(hides) > 0 {
		if jsonOut {
			return printJSON(mirroredPackageJSON{Name: name, Type: typ, MirrorHidden: hides})
		}
		fmt.Printf("Package: %s (mirrored; no manifest)\n", name)
		printMirrorHides(hides)
		return nil
	}
	if err != nil || pm == nil {
		return fmt.Errorf("%s/%s not found", typ, name)
	}

	if jsonOut {
		if admin {
			return printJSON(struct {
				*manifest.PackageManifest
				MirrorHidden []audit.AptMirrorHide `json:"mirror_hidden,omitempty"`
			}{pm, hides})
		}
		// Filter hidden for repo view.
		filtered := *pm
		filtered.Versions = nil
		for _, ve := range pm.Versions {
			if !ve.Hidden {
				filtered.Versions = append(filtered.Versions, ve)
			}
		}
		return printJSON(filtered)
	}

	fmt.Printf("Package: %s\n", pm.Name)
	if pm.Description != "" {
		fmt.Printf("Description: %s\n", pm.Description)
	}
	fmt.Println()

	// ORIGIN is on the admin table only. The repo table renders what a client
	// may see, and an origin is an internal hostname. Its --json sibling still
	// carries the key: that output is a manifest dump, and it already emits
	// _pool_path and every other internal metadata key for the same reason.
	if admin {
		fmt.Printf("%-12s %-15s %-10s %-8s %-8s %-10s %-11s %-10s %s\n",
			"VERSION", "PLATFORM", "STORED", "FROZEN", "HIDDEN", "CONSTRAINT", "OSV", "CHECKED", "ORIGIN")
	} else {
		fmt.Printf("%-12s %-15s %-10s\n", "VERSION", "PLATFORM", "CONSTRAINT")
	}
	// The row's cells and the flagged block below the table read the same
	// stamp, so one answer to "can OSV cover this type at all" has to drive
	// both: an imported manifest can carry vetting.osv.* keys for a type
	// bodega's own writers never stamp.
	osvCovered := policy.OSVCovers(typ)
	var flagged []string
	for _, ve := range pm.Versions {
		if ve.Hidden && !admin {
			continue
		}
		v := ve.Version
		if v == "" {
			v = ve.Ref
		}
		platform := ve.Platform
		if platform == "" {
			platform = "any"
		}
		constraint := ve.VersionConstraint
		if constraint == "" {
			constraint = "exact"
		}
		if admin {
			frozen := "no"
			if ve.Frozen {
				frozen = "yes"
			}
			hidden := "no"
			if ve.Hidden {
				hidden = "yes"
			}
			st := policy.OSVStampOf(ve)
			if !policy.OSVDatable(ve) {
				// The gate refuses to date a range entry, so a date on one
				// arrived by import or by an edit to the constraint after
				// the check. The ids are records against the base version
				// and stay; the date claims an answer for the in-range
				// releases nobody queried.
				st.Checked = time.Time{}
			}
			osvState, osvChecked := osvVersionState(osvCovered, st)
			fmt.Printf("%-12s %-15s %-10s %-8s %-8s %-10s %-11s %-10s %s\n",
				v, platform, effectiveStorage(ve.Storage), frozen, hidden, constraint, osvState, osvChecked, originCell(ve))
			if osvCovered && st.Flagged() {
				flagged = append(flagged, fmt.Sprintf("  %-12s %s  (checked %s)",
					v, strings.Join(st.Vulns, ", "), osvCheckedOn(st)))
			}
		} else {
			fmt.Printf("%-12s %-15s %-10s\n", v, platform, constraint)
		}
	}
	if len(flagged) > 0 {
		fmt.Printf("\nFlagged by OSV:\n%s\n", strings.Join(flagged, "\n"))
	}
	printMirrorHides(hides)
	return nil
}

// mirroredPackageJSON is pkg show's --json for an apt package bodega serves
// only from a mirror, which has hides and no manifest to print.
type mirroredPackageJSON struct {
	Name         string                `json:"name"`
	Type         string                `json:"type"`
	MirrorHidden []audit.AptMirrorHide `json:"mirror_hidden"`
}

// printMirrorHides renders the mirrored apt hides under a listing, saying who
// set each and when, since the record is the only place that is kept.
func printMirrorHides(hides []audit.AptMirrorHide) {
	if len(hides) == 0 {
		return
	}
	fmt.Printf("\nHidden mirrored versions (server-wide):\n")
	fmt.Printf("%-35s %-24s %-16s %-21s %s\n", "PACKAGE", "VERSION", "HIDDEN BY", "HIDDEN AT", "CODENAMES")
	for _, h := range hides {
		fmt.Printf("%-35s %-24s %-16s %-21s %s\n", h.Name, h.Version, h.HiddenBy,
			h.HiddenAt.UTC().Format(time.RFC3339), strings.Join(h.Codenames, " "))
	}
}

// loadMirrorHides reads the mirrored apt hides an admin listing of args names:
// every one for a type listing, one package's for a package listing, none for
// any other type or depth. An audit store that cannot be opened is a warning,
// not a failure, so the manifest half of the listing still prints.
func loadMirrorHides(ctx context.Context, gf *globalFlags, args []string) []audit.AptMirrorHide {
	if len(args) == 0 || len(args) > 2 || args[0] != manifest.TypeApt {
		return nil
	}
	adb, err := openAuditDBErr(gf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: mirrored apt hides not listed: %v\n", err)
		return nil
	}
	if adb == nil {
		return nil
	}
	defer adb.Close()
	name := ""
	if len(args) == 2 {
		name = args[1]
	}
	hides, err := adb.ListAptMirrorHides(ctx, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: mirrored apt hides not listed: %v\n", err)
		return nil
	}
	return hides
}

// newPkgListCmd is `bodega pkg list TYPE`: the admin listing of one type,
// hidden versions included, with the mirrored apt hides beside it.
func newPkgListCmd(gf *globalFlags) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list TYPE",
		Short: "List one type's packages, hidden versions and mirrored apt hides included",
		Example: `  bodega pkg list apt
  bodega pkg list apt --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore(gf)
			if err != nil {
				return err
			}
			ctx := context.Background()
			return showPackageList(ctx, store, args[0], true, jsonOut, loadMirrorHides(ctx, gf, args))
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON")
	return cmd
}

// newPkgShowCmd is `bodega pkg show TYPE NAME`: one package's versions in the
// admin view, with any mirrored apt hide on it.
func newPkgShowCmd(gf *globalFlags) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "show TYPE NAME",
		Short: "Show one package's versions, hidden ones and mirrored apt hides included",
		Example: `  bodega pkg show apt php8.5-fpm
  bodega pkg show apt php8.5-fpm --json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore(gf)
			if err != nil {
				return err
			}
			ctx := context.Background()
			return showVersionList(ctx, store, args[0], args[1], true, jsonOut, loadMirrorHides(ctx, gf, args))
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON")
	return cmd
}

// originCell renders the hosts a version was cataloged from. A dash rather
// than a blank keeps the column readable on a store predating the field, where
// every row is empty.
func originCell(ve manifest.VersionEntry) string {
	origins := admit.Origins(ve)
	if len(origins) == 0 {
		return "-"
	}
	return strings.Join(origins, ", ")
}

// osvVersionState renders a version's OSV and CHECKED cells. A registry type
// OSV holds no records for reads "n/a" rather than "unchecked": no command can
// ever change that cell, and "unchecked" would send the operator to
// `policy osv rescan`, which refuses to run on an ecosystem the gate does not
// cover.
func osvVersionState(covered bool, st policy.OSVStamp) (state, checked string) {
	if !covered {
		return "n/a", "-"
	}
	return st.State(), osvCheckedOn(st)
}

// osvCheckedOn renders the date the OSV gate last answered for a version.
// "never" rather than a blank column: a version carrying no check date was
// either imported before the date existed or never reached the gate, and both
// mean nobody can say what it is today.
func osvCheckedOn(st policy.OSVStamp) string {
	if st.Checked.IsZero() {
		return "never"
	}
	return st.Checked.UTC().Format("2006-01-02")
}

// ---------- depth 3: version detail or "all" ----------

func showVersionDetail(ctx context.Context, store *manifest.Store, typ, name, versionOrAll string, admin, jsonOut bool) error {
	pm, err := store.GetPackage(ctx, typ, name)
	if err != nil || pm == nil {
		return fmt.Errorf("%s/%s not found", typ, name)
	}

	if versionOrAll == "all" {
		// Show all versions verbosely.
		if jsonOut {
			return printJSON(pm)
		}
		fmt.Printf("Package: %s (%s)\n", pm.Name, pm.Type)
		if pm.Description != "" {
			fmt.Printf("Description: %s\n", pm.Description)
		}
		fmt.Printf("Versions: %d\n\n", len(pm.Versions))
		for i, ve := range pm.Versions {
			if ve.Hidden && !admin {
				continue
			}
			printVersionDetail(pm, ve, admin)
			if i < len(pm.Versions)-1 {
				fmt.Println("---")
			}
		}
		return nil
	}

	// Find specific version.
	for _, ve := range pm.Versions {
		v := ve.Version
		if v == "" {
			v = ve.Ref
		}
		if v == versionOrAll {
			if jsonOut {
				return printJSON(ve)
			}
			printVersionDetail(pm, ve, admin)
			return nil
		}
	}
	return fmt.Errorf("version %q not found in %s/%s", versionOrAll, typ, name)
}

func printVersionDetail(pm *manifest.PackageManifest, ve manifest.VersionEntry, admin bool) {
	v := ve.Version
	if v == "" {
		v = ve.Ref
	}
	fmt.Printf("Package:     %s\n", pm.Name)
	fmt.Printf("Type:        %s\n", pm.Type)
	fmt.Printf("Version:     %s\n", v)
	if ve.URL != "" {
		fmt.Printf("Source URL:  %s\n", ve.URL)
	}
	if ve.Ref != "" && ve.Ref != v {
		fmt.Printf("Ref:         %s\n", ve.Ref)
	}
	if ve.Platform != "" {
		fmt.Printf("Platform:    %s\n", ve.Platform)
	}
	if ve.Checksum != nil {
		fmt.Printf("Checksum:    %s:%s\n", ve.Checksum.Algorithm, ve.Checksum.Value)
		if ve.ChecksumVerified {
			fmt.Printf("Verified:    yes\n")
		} else {
			fmt.Printf("Verified:    no\n")
		}
	}
	constraint := ve.VersionConstraint
	if constraint == "" {
		constraint = "exact"
	}
	fmt.Printf("Constraint:  %s\n", constraint)
	if ve.Mode != "" {
		fmt.Printf("Mode:        %s\n", ve.Mode)
	}

	if admin {
		fmt.Printf("Frozen:      %v\n", ve.Frozen)
		fmt.Printf("Hidden:      %v\n", ve.Hidden)
	}

	if len(ve.RequiredBy) > 0 {
		fmt.Printf("Required by: %s\n", strings.Join(ve.RequiredBy, ", "))
	}
	if origins := admit.Origins(ve); admin && len(origins) > 0 {
		fmt.Printf("Origins:     %s\n", strings.Join(origins, ", "))
	}

	if admin && ve.BuildEnv != nil {
		fmt.Println("Build Environment:")
		if ve.BuildEnv.OSRelease != "" {
			fmt.Printf("  OS:        %s\n", ve.BuildEnv.OSRelease)
		}
		if ve.BuildEnv.Python != "" {
			fmt.Printf("  Python:    %s\n", ve.BuildEnv.Python)
		}
		if ve.BuildEnv.Go != "" {
			fmt.Printf("  Go:        %s\n", ve.BuildEnv.Go)
		}
		if ve.BuildEnv.Rust != "" {
			fmt.Printf("  Rust:      %s\n", ve.BuildEnv.Rust)
		}
		if ve.BuildEnv.Bodega != "" {
			fmt.Printf("  Bodega:    %s\n", ve.BuildEnv.Bodega)
		}
		if ve.BuildEnv.BuiltAt != "" {
			fmt.Printf("  Built at:  %s\n", ve.BuildEnv.BuiltAt)
		}
	}

	// Type-specific fields.
	if ve.SourceName != "" {
		fmt.Printf("Package Name: %s\n", ve.SourceName)
	}
	if ve.BuildCmd != "" {
		fmt.Printf("Build Cmd:   %s\n", ve.BuildCmd)
	}
	if ve.Filename != "" {
		fmt.Printf("Filename:    %s\n", ve.Filename)
	}
	if ve.AppVersion != "" {
		fmt.Printf("App Version: %s\n", ve.AppVersion)
	}
	// The header is printed from the filtered key set, not from the map: an
	// entry whose only metadata is its origin would otherwise print a
	// "Metadata:" heading with nothing under it.
	keys := make([]string, 0, len(ve.Metadata))
	for k := range ve.Metadata {
		// Description-Full is too long for the block; origin has its own line
		// above, which the repo view withholds on purpose. Printing it here
		// would put it back and repeat it for an admin.
		if k != "Description-Full" && k != admit.MetaOrigin {
			keys = append(keys, k)
		}
	}
	if len(keys) > 0 {
		fmt.Println("Metadata:")
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-16s %s\n", k+":", ve.Metadata[k])
		}
	}
	fmt.Println()
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// isValidType is defined in main.go
