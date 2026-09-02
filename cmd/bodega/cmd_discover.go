package main

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// newDiscoverCmd returns the `bodega discover ...` subcommand tree. Discover
// mode is configured server-side via `discover_mode` in config.json; this CLI
// reads from and curates the resulting observation log.
func newDiscoverCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "discover",
		Short: "Inspect upstream-fetch observations and promote them to allow-list rules",
		Long: `Auto-discover mode is configured server-side. Set "discover_mode" in
config.json to one of:

  ""         off; nothing is recorded
  "observe"  log every upstream fetch and every pre-fetch miss (safe to leave on)

The mode decides whether a row is written and nothing else: the allow-list,
catalog mode and every other check enforce the same either way. To bootstrap a
catalog, read the host's own inventory with 'bodega pkg convert' rather than
watching traffic; discovery answers what the catalog does not cover.

Use these subcommands to review what's been captured and turn observations
into policy rules.`,
	}
	parent.AddCommand(
		newDiscoverListCmd(gf),
		newDiscoverShowCmd(gf),
		newDiscoverPromoteCmd(gf),
		newDiscoverPromoteAllCmd(gf),
		newDiscoverClearCmd(gf),
		newDiscoverExportCmd(gf),
	)
	return parent
}

func newDiscoverListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list [type]",
		Short: "List distinct (type, pattern) buckets seen by the discovery hook",
		Long: `Aggregate observations into one row per (registry_type, suggested-pattern).
The PATTERN column is exactly what 'bodega discover promote' would write.

Examples:
  bodega discover list                 # all types
  bodega discover list gomod           # filter to one type`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var regType string
			if len(args) > 0 {
				regType = args[0]
				if err := policy.ValidateType(regType); err != nil {
					return err
				}
			}

			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			ctx := context.Background()
			rows, err := adb.AggregateDiscovery(ctx, regType)
			if err != nil {
				return fmt.Errorf("aggregate discovery: %w", err)
			}
			if len(rows) == 0 {
				fmt.Println("No discovery observations yet.")
				fmt.Println("(Set \"discover_mode\" to \"observe\" in config.json and restart bodega.)")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "TYPE\tPATTERN\tHOST\tCOUNT\tDECISIONS\tLAST SEEN")
			for _, a := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
					a.RegistryType, a.PatternHint, a.Host, a.RequestCount,
					a.Decisions, a.LastSeen.Format("2006-01-02 15:04"))
			}
			return w.Flush()
		},
	}
}

func newDiscoverShowCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "show <type> <pattern>",
		Short: "Show raw observation rows for one (type, pattern) bucket",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			regType := args[0]
			pattern := args[1]
			if err := policy.ValidateType(regType); err != nil {
				return err
			}

			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			ctx := context.Background()
			rows, err := adb.ListDiscovery(ctx, audit.DiscoveryFilter{
				RegistryType: regType,
				PatternHint:  pattern,
				Limit:        500,
			})
			if err != nil {
				return fmt.Errorf("list discovery: %w", err)
			}
			if len(rows) == 0 {
				fmt.Printf("No observations for %s %q.\n", regType, pattern)
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "PACKAGE\tVERSION\tDECISION\tCOUNT\tLAST CLIENT\tLAST SEEN\tUPSTREAM URL")
			for _, r := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
					r.PkgName, r.PkgVersion, r.Decision, r.RequestCount,
					r.LastClient, r.LastSeen.Format("2006-01-02 15:04"),
					r.UpstreamURL)
			}
			return w.Flush()
		},
	}
}

func newDiscoverPromoteCmd(gf *globalFlags) *cobra.Command {
	var as string
	cmd := &cobra.Command{
		Use:   "promote <type> <pattern> [comment]",
		Short: "Promote one discovered pattern to an allow-list rule or manifest entries",
		Long: `--as policy (the default) inserts an allow-list rule with the type's natural
rule kind and the captured pattern. Same write path as 'bodega policy add'.

--as manifest writes package manifest entries instead, one per no_manifest
observation in the bucket, in proxy mode with the upstream URL the handler
would have fetched. Same write path as 'bodega pkg create'. Existing entries
are never rewritten: a version already in the manifest is left alone.

Examples:
  bodega discover promote gomod github.com/aws/
  bodega discover promote npm @aws-sdk/* "AWS SDK packages"
  bodega discover promote gomod github.com/aws/ --as manifest`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			regType := args[0]
			pattern := args[1]
			comment := ""
			if len(args) > 2 {
				comment = strings.Join(args[2:], " ")
			}
			switch as {
			case promoteAsPolicy:
				return promoteOne(gf, regType, pattern, comment)
			case promoteAsManifest:
				return promoteManifest(gf, os.Stdout, regType, pattern)
			}
			return errUnknownPromoteTarget(as)
		},
	}
	addPromoteAsFlag(cmd, &as)
	return cmd
}

// Promotion targets for --as. policy is the default so an operator who learned
// this command before manifests existed keeps the behavior they know.
const (
	promoteAsPolicy   = "policy"
	promoteAsManifest = "manifest"
)

func addPromoteAsFlag(cmd *cobra.Command, as *string) {
	cmd.Flags().StringVar(as, "as", promoteAsPolicy,
		`what to write: "policy" (an allow-list rule) or "manifest" (package manifest entries)`)
}

func errUnknownPromoteTarget(as string) error {
	return fmt.Errorf("unknown --as target %q: use %q to write an allow-list rule or %q to write package manifest entries",
		as, promoteAsPolicy, promoteAsManifest)
}

func newDiscoverPromoteAllCmd(gf *globalFlags) *cobra.Command {
	var as string
	cmd := &cobra.Command{
		Use:   "promote-all <type>",
		Short: "Bulk-promote every captured pattern for a type",
		Long: `--as policy (the default) inserts an allow-list rule for every distinct
pattern observed for the given type. Already-existing rules are skipped
(duplicate-key on upstream_policies). Use this after an observe window to
widen the allow-list to what clients actually reached for.

--as manifest writes a package manifest entry for every no_manifest
observation of the type instead, and is idempotent: a second run adds
nothing.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			regType := args[0]
			if err := policy.ValidateType(regType); err != nil {
				return err
			}
			switch as {
			case promoteAsPolicy:
			case promoteAsManifest:
				return promoteManifest(gf, os.Stdout, regType, "")
			default:
				return errUnknownPromoteTarget(as)
			}

			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			ctx := context.Background()
			rows, err := adb.AggregateDiscovery(ctx, regType)
			if err != nil {
				return fmt.Errorf("aggregate discovery: %w", err)
			}
			if len(rows) == 0 {
				fmt.Printf("No observations for %s.\n", regType)
				return nil
			}

			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}

			added, skipped := 0, 0
			for _, a := range rows {
				err := insertPolicyRule(ctx, adb, regType, a.PatternHint, "promoted from discovery")
				switch {
				case err == nil:
					added++
					fmt.Printf("+ %s %s\n", regType, a.PatternHint)
				case strings.Contains(strings.ToLower(err.Error()), "unique"):
					skipped++
				default:
					return fmt.Errorf("insert %q: %w", a.PatternHint, err)
				}
			}
			fmt.Printf("\nPromoted %d, skipped %d (already present).\n", added, skipped)
			return nil
		},
	}
	addPromoteAsFlag(cmd, &as)
	return cmd
}

func newDiscoverClearCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "clear [type]",
		Short: "Delete discovery rows for a type, or all types when omitted",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}

			var regType string
			if len(args) > 0 {
				regType = args[0]
				if err := policy.ValidateType(regType); err != nil {
					return err
				}
			}

			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			n, err := adb.ClearDiscovery(context.Background(), regType)
			if err != nil {
				return fmt.Errorf("clear discovery: %w", err)
			}
			if regType == "" {
				fmt.Printf("Deleted %d discovery rows (all types).\n", n)
			} else {
				fmt.Printf("Deleted %d discovery rows for %s.\n", n, regType)
			}
			return nil
		},
	}
}

func newDiscoverExportCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "export <json|csv> [type]",
		Short: "Dump discovery rows to stdout in JSON or CSV",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			format := args[0]
			if format != "json" && format != "csv" {
				return fmt.Errorf("format must be \"json\" or \"csv\", got %q", format)
			}
			var regType string
			if len(args) > 1 {
				regType = args[1]
				if err := policy.ValidateType(regType); err != nil {
					return err
				}
			}

			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			rows, err := adb.ListDiscovery(context.Background(), audit.DiscoveryFilter{
				RegistryType: regType,
				Limit:        100000,
			})
			if err != nil {
				return fmt.Errorf("list discovery: %w", err)
			}

			if format == "json" {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			// CSV
			cw := csv.NewWriter(os.Stdout)
			defer cw.Flush()
			_ = cw.Write([]string{
				"registry_type", "host", "pattern_hint", "pkg_name", "pkg_version",
				"decision", "upstream_url", "first_seen", "last_seen", "last_client", "request_count",
			})
			for _, r := range rows {
				_ = cw.Write([]string{
					r.RegistryType, r.Host, r.PatternHint, r.PkgName, r.PkgVersion,
					r.Decision, r.UpstreamURL,
					r.FirstSeen.Format("2006-01-02T15:04:05Z07:00"),
					r.LastSeen.Format("2006-01-02T15:04:05Z07:00"),
					r.LastClient,
					fmt.Sprintf("%d", r.RequestCount),
				})
			}
			return nil
		},
	}
}

// promoteOne is the single-rule path shared by `discover promote` and
// (internally) by `discover promote-all`'s per-row loop. Keeping this in
// one place ensures both commands write rules identically to `policy add`.
func promoteOne(gf *globalFlags, regType, pattern, comment string) error {
	if err := policy.ValidateType(regType); err != nil {
		return err
	}

	cfg, err := loadConfig(gf)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := ensureMutable(cfg); err != nil {
		return err
	}

	adb := openAuditDB(gf)
	if adb == nil {
		return fmt.Errorf("could not open audit database")
	}
	defer adb.Close()

	ctx := context.Background()
	if err := insertPolicyRule(ctx, adb, regType, pattern, comment); err != nil {
		return err
	}
	fmt.Printf("Promoted %s %q\n", regType, pattern)
	return nil
}

func insertPolicyRule(ctx context.Context, adb *audit.DB, regType, pattern, comment string) error {
	kind := policy.RuleKindForType(regType)
	if kind == "" {
		return fmt.Errorf("no rule kind registered for type %q", regType)
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return fmt.Errorf("generate id: %w", err)
	}
	id := hex.EncodeToString(idBytes)
	return adb.InsertPolicy(ctx, audit.PolicyInfo{
		ID:           id,
		RegistryType: regType,
		RuleKind:     kind,
		Pattern:      pattern,
		Comment:      comment,
		CreatedBy:    "discover",
	})
}

// ---- Manifest promotion ----------------------------------------------------

// manifestEntry is one version entry a discovery row promotes to, paired with
// the package that will hold it.
type manifestEntry struct {
	PkgName string
	Entry   manifest.VersionEntry
}

// buildManifestEntries maps no_manifest observations onto the manifest entries
// they describe, touching no store. The mapping is split from the write so a
// caller that only renders the manifests it would produce reads the same
// function as the one that writes them — 'bodega discover generate-manifests'
// is that caller.
//
// Rows with no upstream_url are returned in noURL rather than dropped. A
// proxy-mode entry with no URL 404s exactly as the miss it came from did, so
// the operator has to know which packages need a URL supplied by hand.
func buildManifestEntries(rows []audit.DiscoveryRow) (entries []manifestEntry, noURL []string) {
	seenNoURL := map[string]bool{}
	for _, row := range rows {
		if row.PkgName == "" {
			continue
		}
		if row.UpstreamURL == "" {
			if !seenNoURL[row.PkgName] {
				seenNoURL[row.PkgName] = true
				noURL = append(noURL, row.PkgName)
			}
			continue
		}
		ve := manifest.VersionEntry{
			Version: row.PkgVersion,
			URL:     manifestURL(row),
			Mode:    manifest.ModeProxy,
		}
		if row.PkgVersion == "" {
			// A handler can observe a package without a version — git
			// smart-HTTP names a repository, not a ref. One open entry serves
			// whatever the client asks for, where dropping the row would leave
			// the type with no promote path at all.
			ve.VersionConstraint = manifest.ConstraintAny
		}
		entries = append(entries, manifestEntry{PkgName: row.PkgName, Entry: ve})
	}
	return entries, noURL
}

// manifestURL maps a discovery row's upstream URL onto the URL shape
// VersionEntry.URL means for that type.
//
// gomod and npm record the artifact URL the handler would have fetched, while
// the manifest field for both is the registry root the builder appends a
// module or package path to (internal/builder/gomod.go, internal/builder/npm.go).
// Promoting the artifact URL verbatim produces an entry whose next
// 'bodega build fetch' requests that path twice and 404s. Every other type
// records a URL that already means what the field means.
func manifestURL(row audit.DiscoveryRow) string {
	var artifact string
	switch row.RegistryType {
	case manifest.TypeGomod:
		artifact = "/" + row.PkgName + "/@v/"
	case manifest.TypeNpm:
		artifact = "/" + row.PkgName + "/-/"
	default:
		return row.UpstreamURL
	}
	if row.PkgName == "" {
		return row.UpstreamURL
	}
	if i := strings.Index(row.UpstreamURL, artifact); i > 0 {
		return row.UpstreamURL[:i]
	}
	return row.UpstreamURL
}

// applyManifestEntries writes entries that are not already in the store and
// reports how many it added versus found present. It never removes or edits an
// existing version: a version already in the manifest is left exactly as the
// operator (or a previous run) wrote it, which is what keeps a hosted entry
// from being downgraded to proxy by a promote.
func applyManifestEntries(ctx context.Context, store *manifest.Store, out io.Writer, typ string, entries []manifestEntry) (added, present int, err error) {
	for _, e := range entries {
		pm, err := store.GetPackage(ctx, typ, e.PkgName)
		if err != nil {
			return added, present, fmt.Errorf("read manifest %s/%s from %s: %w — %d entries were written before this one; fix the read and re-run, the run skips what it already wrote",
				typ, e.PkgName, store.Label(), err, added)
		}
		if versionPresent(pm, e.Entry) {
			present++
			continue
		}
		if err := store.AddVersion(ctx, typ, e.PkgName, e.Entry); err != nil {
			return added, present, fmt.Errorf("write manifest %s/%s to %s: %w — the manifest store must be writable by this user; 'bodega pkg create %s %s' writes to the same place and fails the same way",
				typ, e.PkgName, store.Label(), err, typ, e.PkgName)
		}
		added++
		fmt.Fprintf(out, "+ %s %s@%s\n", typ, e.PkgName, promotedVersionLabel(e.Entry))
	}
	return added, present, nil
}

// versionPresent reports whether pm already holds ve's version. An entry
// promoted from a row with no version is matched on its emptiness rather than
// on a version string, so a second promote of the same versionless package
// finds the entry the first one wrote.
func versionPresent(pm *manifest.PackageManifest, ve manifest.VersionEntry) bool {
	if pm == nil {
		return false
	}
	for _, existing := range pm.Versions {
		if ve.Version == "" {
			if existing.Version == "" && existing.Ref == "" {
				return true
			}
			continue
		}
		if existing.Version == ve.Version || existing.Ref == ve.Version {
			return true
		}
	}
	return false
}

// promotedVersionLabel names a promoted entry for the operator. A row with no
// version becomes an open entry, and "any" is what its constraint says;
// versionLabel's "?" would read as a parse failure instead.
func promotedVersionLabel(ve manifest.VersionEntry) string {
	if ve.Version == "" {
		return manifest.ConstraintAny
	}
	return versionLabel(ve)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// promoteManifest turns the no_manifest observations for a type (optionally
// narrowed to one pattern bucket) into package manifest entries. An empty
// pattern means every bucket, which is what `promote-all --as manifest` wants.
func promoteManifest(gf *globalFlags, out io.Writer, regType, pattern string) error {
	if err := policy.ValidateType(regType); err != nil {
		return err
	}

	cfg, err := loadConfig(gf)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := ensureMutable(cfg); err != nil {
		return err
	}

	adb := openAuditDB(gf)
	if adb == nil {
		return fmt.Errorf("could not open audit database")
	}
	defer adb.Close()

	ctx := context.Background()

	total, err := adb.DiscoveryCount(ctx, regType)
	if err != nil {
		return fmt.Errorf("count discovery rows for %s: %w", regType, err)
	}
	if total == 0 {
		return fmt.Errorf("no discovery observations for %s at all: set \"discover_mode\" to \"observe\" in %s, restart bodega, then re-drive the client traffic you want captured",
			regType, config.ConfigPath())
	}

	rows, err := adb.ListDiscovery(ctx, audit.DiscoveryFilter{
		RegistryType: regType,
		PatternHint:  pattern,
		Decision:     audit.DecisionNoManifest,
		Limit:        100000,
	})
	if err != nil {
		return fmt.Errorf("list discovery rows for %s: %w", regType, err)
	}
	if len(rows) == 0 {
		scope, next := regType, "bodega discover list "+regType
		if pattern != "" {
			scope = fmt.Sprintf("%s %q", regType, pattern)
			next = fmt.Sprintf("bodega discover show %s %s", regType, pattern)
		}
		return fmt.Errorf("no %s observations for %s, though %d row(s) are recorded for the type: only a request for a package with no manifest entry promotes to one, so run '%s' to see what the other rows say",
			audit.DecisionNoManifest, scope, total, next)
	}

	entries, noURL := buildManifestEntries(rows)
	for _, name := range noURL {
		fmt.Fprintf(os.Stderr, "skipped (%s, %s): the observation carries no upstream_url, so a proxy entry built from it would 404 — re-drive a request for it with discover_mode set, or supply the URL with 'bodega pkg create %s %s'\n",
			regType, name, regType, name)
	}
	if len(entries) == 0 {
		return fmt.Errorf("every %s observation for %s lacks an upstream_url (see above); nothing was written",
			audit.DecisionNoManifest, regType)
	}

	store, err := loadStore(gf)
	if err != nil {
		return fmt.Errorf("load manifests: %w", err)
	}
	added, present, err := applyManifestEntries(ctx, store, out, regType, entries)
	if err != nil {
		return err
	}
	if err := store.SaveIndex(ctx); err != nil {
		return fmt.Errorf("save manifest index to %s: %w — the %d entries above were written but will not be listed until the index saves; make the store writable and re-run",
			store.Label(), err, added)
	}

	fmt.Fprintf(out, "\nPromoted %d manifest %s, skipped %d already present, %d without an upstream URL.\n",
		added, plural(added, "entry", "entries"), present, len(noURL))
	return nil
}
