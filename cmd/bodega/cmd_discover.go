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
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
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
		newDiscoverGenerateManifestsCmd(gf),
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
// Rows with no upstream_url are returned in noURL rather than dropped, and
// versionless rows for a type that needs a version are returned in noVersion.
// Either one would produce an entry that 404s exactly as the miss it came from
// did, so the operator has to know which packages the promote passed over.
func buildManifestEntries(rows []audit.DiscoveryRow) (entries []manifestEntry, noURL, noVersion []string) {
	seenNoURL := map[string]bool{}
	seenNoVersion := map[string]bool{}
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
		if row.PkgVersion == "" && !versionlessNamesArtifact(row.RegistryType) {
			if !seenNoVersion[row.PkgName] {
				seenNoVersion[row.PkgName] = true
				noVersion = append(noVersion, row.PkgName)
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
	return entries, noURL, noVersion
}

// versionlessNamesArtifact reports whether a row with no pkg_version still
// names something a fetch can resolve.
//
// git and binary entries are fetched from VersionEntry.URL as recorded, so a
// repository or a download URL is complete without a version. Every other type
// composes the version into the fetch path (internal/builder gomod, npm, helm
// and cargo all append it), and an open entry there resolves to a URL that
// 404s. gomod produces these constantly: go resolves an unknown module through
// /@v/list and /@v/@latest, and neither request carries a version.
func versionlessNamesArtifact(regType string) bool {
	switch regType {
	case manifest.TypeGit, manifest.TypeBinary:
		return true
	}
	return false
}

// manifestURL maps a discovery row's upstream URL onto the URL shape
// VersionEntry.URL means for that type.
//
// gomod, npm and pypi record the URL the handler would have fetched, while the
// manifest field for all three is the registry root: gomod and npm append a
// module or package path to it (internal/builder/gomod.go,
// internal/builder/npm.go), and pypi resolves a wheel through /simple/ under
// it. Promoting the artifact URL verbatim produces an entry whose next
// 'bodega build fetch' requests that path twice and 404s. Every other type
// records a URL that already means what the field means.
func manifestURL(row audit.DiscoveryRow) string {
	var artifact string
	switch row.RegistryType {
	case manifest.TypeGomod:
		if row.PkgName == "" {
			return row.UpstreamURL
		}
		artifact = "/" + row.PkgName + "/@v/"
	case manifest.TypeNpm:
		if row.PkgName == "" {
			return row.UpstreamURL
		}
		artifact = "/" + row.PkgName + "/-/"
	case manifest.TypePypi:
		// The recorded URL is the simple index for one distribution; the
		// distribution name in it is normalized, so trimming at the fixed
		// segment is what works for a package whose name carries a "_" or ".".
		artifact = "/simple/"
	default:
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

	entries, noURL, noVersion := buildManifestEntries(rows)
	for _, name := range noURL {
		fmt.Fprintf(os.Stderr, "skipped (%s, %s): the observation carries no upstream_url, so a proxy entry built from it would 404 — re-drive a request for it with discover_mode set, or supply the URL with 'bodega pkg create %s %s'\n",
			regType, name, regType, name)
	}
	for _, name := range noVersion {
		fmt.Fprintf(os.Stderr, "skipped a versionless observation of (%s, %s): %s composes the version into the fetch URL, so an open entry would 404 — the versioned rows for this package are unaffected\n",
			regType, name, regType)
	}
	if len(entries) == 0 {
		return fmt.Errorf("no %s observation for %s produced an entry: %d lacked an upstream_url and %d named no version (see above); nothing was written",
			audit.DecisionNoManifest, regType, len(noURL), len(noVersion))
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

	fmt.Fprintf(out, "\nPromoted %d manifest %s, skipped %d already present, %d without an upstream URL, %d without a version.\n",
		added, plural(added, "entry", "entries"), present, len(noURL), len(noVersion))
	return nil
}

// ---- Bulk manifest generation ---------------------------------------------

// discoveryScanLimit bounds the rows one generate run reads, matching the
// ceiling `discover export` and `promote --as manifest` already use.
const discoveryScanLimit = 100000

// generateOpts carries the read-side filters of `discover generate-manifests`.
// A zero value generates from every row the discovery log holds.
type generateOpts struct {
	Since        time.Time
	MinRequests  int64
	SkipExisting bool
	Output       string
}

// generateSummary counts what never reached the payload. An operator importing
// the output is entitled to know the catalog it produces is partial, and why:
// silence here reads as "this is everything".
type generateSummary struct {
	Packages     int
	Versions     int
	StaleRows    int // dropped by --since
	QuietPkgs    int // dropped by --min-requests
	ExistingPkgs int // dropped by --skip-existing
	NoURLRows    int // rows carrying no upstream_url
	NoVersionRow int // versionless rows for a type that composes the version into the fetch
	UnnamedRows  int // rows carrying no pkg_name
	InvalidPkgs  int // packages the manifest validator refused
	NoNamespace  int // rows naming a namespace no upstream is configured for
	OtherRows    int // rows from decisions that are not catalog misses
}

func newDiscoverGenerateManifestsCmd(gf *globalFlags) *cobra.Command {
	var (
		since        string
		minRequests  int64
		skipExisting bool
		output       string
	)
	cmd := &cobra.Command{
		Use:   "generate-manifests [type]",
		Short: "Emit manifest entries for the observed packages the catalog has no entry for",
		Long: `generate-manifests turns the no_manifest rows in the discovery log into the
package manifests they describe and writes them to stdout as a JSON array —
the same shape 'bodega pkg convert' emits, so the same import reads it with
no editing in between.

Nothing is written to the manifest store and no discovery row is touched.
Review the output, edit it, then import it:

  bodega discover generate-manifests git > git-catalog.json
  $EDITOR git-catalog.json
  bodega pkg import git-catalog.json

Omitting the type generates for every type with rows. Rows come from
catalog-mode misses, so the types that produce them are the ones no
'bodega pkg convert' importer covers — git and binary — plus whatever an
importer missed elsewhere. Versions default to proxy mode; flip an entry to
hosted if you want 'bodega build fetch' to pre-fetch the artifact.

Skipped packages are named on stderr so stdout stays a clean payload.

Examples:
  bodega discover generate-manifests
  bodega discover generate-manifests git --since 30d
  bodega discover generate-manifests --min-requests 5 -o catalog.json
  bodega discover generate-manifests --skip-existing | bodega pkg import -`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var regType string
			if len(args) > 0 {
				regType = args[0]
			}
			opts := generateOpts{
				MinRequests:  minRequests,
				SkipExisting: skipExisting,
				Output:       output,
			}
			if since != "" {
				d, err := parseAgeDuration(since)
				if err != nil {
					return fmt.Errorf("--since: %w", err)
				}
				opts.Since = time.Now().Add(-d)
			}
			return generateManifests(gf, cmd.OutOrStdout(), cmd.ErrOrStderr(), regType, opts)
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "Only rows last seen within this window (e.g. 7d, 72h)")
	cmd.Flags().Int64Var(&minRequests, "min-requests", 0,
		"Only packages with at least this many recorded requests. The count is upstream fetches, not client requests, so a warm cache under-reports it")
	cmd.Flags().BoolVar(&skipExisting, "skip-existing", false, "Omit packages the manifest store already holds")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write the payload to this file instead of stdout")
	return cmd
}

// generateManifests reads the discovery log and emits the manifests its
// catalog misses describe. It opens the manifest store only for
// --skip-existing, and only to read: the review step between this command and
// 'pkg import' is the feature, not an obstacle to route around.
func generateManifests(gf *globalFlags, out, errOut io.Writer, regType string, opts generateOpts) error {
	if regType != "" {
		if err := policy.ValidateType(regType); err != nil {
			return err
		}
	}

	cfg, err := loadConfig(gf)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	adb := openAuditDB(gf)
	if adb == nil {
		return fmt.Errorf("could not open audit database")
	}
	defer adb.Close()

	ctx := context.Background()
	rows, err := adb.ListDiscovery(ctx, audit.DiscoveryFilter{
		RegistryType: regType,
		Limit:        discoveryScanLimit,
	})
	if err != nil {
		return fmt.Errorf("list discovery rows: %w", err)
	}

	var store *manifest.Store
	if opts.SkipExisting {
		store, err = loadStore(gf)
		if err != nil {
			return fmt.Errorf("load manifests: %w — --skip-existing reads the store to see what is already cataloged; drop the flag to generate without consulting it", err)
		}
	}

	pms, sum, err := buildGeneratedManifests(ctx, store, cfg, errOut, rows, opts)
	if err != nil {
		return err
	}

	blob, err := json.MarshalIndent(pms, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifests: %w", err)
	}
	blob = append(blob, '\n')

	if opts.Output == "" || opts.Output == "-" {
		if _, err := out.Write(blob); err != nil {
			return err
		}
	} else if err := os.WriteFile(opts.Output, blob, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", opts.Output, err)
	}

	writeGenerateSummary(errOut, sum, opts)
	return nil
}

// generateKey is the unit this command emits: one manifest per observed
// package of one type.
type generateKey struct {
	Type string
	Name string
}

// buildGeneratedManifests groups the discovery rows into manifests and applies
// every filter, counting what each one removed.
//
// The filters run here rather than in the SQL query so one read answers both
// what to emit and what was dropped. A filter that silently narrows the result
// set is how an operator ends up importing a partial catalog.
func buildGeneratedManifests(
	ctx context.Context,
	store *manifest.Store,
	cfg *config.Config,
	errOut io.Writer,
	rows []audit.DiscoveryRow,
	opts generateOpts,
) ([]manifest.PackageManifest, generateSummary, error) {
	var sum generateSummary
	groups := map[generateKey][]audit.DiscoveryRow{}
	requests := map[generateKey]int64{}
	var order []generateKey

	for _, row := range rows {
		switch row.Decision {
		case audit.DecisionNoManifest:
		case audit.DecisionNoNamespace:
			sum.NoNamespace++
			continue
		default:
			sum.OtherRows++
			continue
		}
		if !opts.Since.IsZero() && row.LastSeen.Before(opts.Since) {
			sum.StaleRows++
			continue
		}
		if row.PkgName == "" {
			sum.UnnamedRows++
			continue
		}
		if row.UpstreamURL == "" {
			sum.NoURLRows++
		}
		k := generateKey{Type: row.RegistryType, Name: row.PkgName}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], row)
		requests[k] += row.RequestCount
	}

	sort.Slice(order, func(i, j int) bool {
		if order[i].Type != order[j].Type {
			return order[i].Type < order[j].Type
		}
		return order[i].Name < order[j].Name
	})

	pms := []manifest.PackageManifest{}
	for _, k := range order {
		if opts.MinRequests > 0 && requests[k] < opts.MinRequests {
			sum.QuietPkgs++
			continue
		}
		if store != nil {
			existing, err := store.GetPackage(ctx, k.Type, k.Name)
			if err != nil {
				return nil, sum, fmt.Errorf("read manifest %s/%s from %s: %w — --skip-existing cannot tell what is already cataloged until this read works; fix it or drop the flag",
					k.Type, k.Name, store.Label(), err)
			}
			if existing != nil {
				sum.ExistingPkgs++
				continue
			}
		}

		entries, noURL, noVersion := buildManifestEntries(groups[k])
		for _, name := range noURL {
			fmt.Fprintf(errOut, "WARN skipped (%s, %s): the observation carries no upstream_url, so a proxy entry built from it would 404 — re-drive a request for it with discover_mode set, or write the entry with 'bodega pkg create %s %s'\n",
				k.Type, name, k.Type, name)
		}
		for _, name := range noVersion {
			sum.NoVersionRow++
			fmt.Fprintf(errOut, "WARN skipped a versionless observation of (%s, %s): %s composes the version into the fetch URL, so an open entry would 404 — the versioned rows for this package are unaffected\n",
				k.Type, name, k.Type)
		}
		if len(entries) == 0 {
			continue
		}

		pm := manifest.PackageManifest{
			ConfigVersion: manifest.CurrentConfigVersion,
			Name:          k.Name,
			Type:          k.Type,
			Versions:      generatedVersions(entries),
		}
		// The import applies this same check and aborts the whole file on the
		// first refusal, leaving the store half-written. Refusing the entry
		// here costs the operator one package instead.
		if err := validateManifest(&pm, cfg, errOut); err != nil {
			sum.InvalidPkgs++
			fmt.Fprintf(errOut, "WARN skipped (%s, %s): %v\n", k.Type, k.Name, err)
			continue
		}
		pms = append(pms, pm)
		sum.Packages++
		sum.Versions += len(pm.Versions)
	}

	return pms, sum, nil
}

// generatedVersions collapses a package's entries to one per version and
// orders them newest first.
//
// The order has to be total, not merely pleasant: an operator diffs a
// generation against last week's, and a sort that leaves two entries
// interchangeable makes every line downstream of them look changed.
func generatedVersions(entries []manifestEntry) []manifest.VersionEntry {
	seen := map[string]bool{}
	out := make([]manifest.VersionEntry, 0, len(entries))
	for _, e := range entries {
		if seen[e.Entry.Version] {
			continue
		}
		seen[e.Entry.Version] = true
		out = append(out, e.Entry)
	}
	sort.Slice(out, func(i, j int) bool { return versionEntryNewer(out[i], out[j]) })
	return out
}

// versionEntryNewer orders two generated entries, newest first. Semver order
// where both parse, string order otherwise — which keeps the comparison total
// for the tags and dates that reach a discovery row and never parse.
func versionEntryNewer(a, b manifest.VersionEntry) bool {
	av, aok := builder.ParseSemVer(a.Version)
	bv, bok := builder.ParseSemVer(b.Version)
	switch {
	case aok && bok:
		if !av.Equal(bv) {
			return bv.Less(av)
		}
	case aok != bok:
		return aok
	}
	return a.Version > b.Version
}

// writeGenerateSummary reports the run on stderr, one line per non-zero
// disposition, so stdout stays a payload a pipe can carry.
func writeGenerateSummary(w io.Writer, s generateSummary, opts generateOpts) {
	dest := "stdout"
	if opts.Output != "" && opts.Output != "-" {
		dest = opts.Output
	}
	fmt.Fprintf(w, "\nGenerated %d package %s (%d version %s) to %s. Nothing was written to the manifest store; review the payload, then 'bodega pkg import' it.\n",
		s.Packages, plural(s.Packages, "manifest", "manifests"),
		s.Versions, plural(s.Versions, "entry", "entries"), dest)

	for _, line := range []struct {
		n    int
		text string
	}{
		{s.StaleRows, fmt.Sprintf("%d row(s) dropped by --since", s.StaleRows)},
		{s.QuietPkgs, fmt.Sprintf("%d package(s) dropped by --min-requests", s.QuietPkgs)},
		{s.ExistingPkgs, fmt.Sprintf("%d package(s) dropped by --skip-existing (already in the store)", s.ExistingPkgs)},
		{s.NoURLRows, fmt.Sprintf("%d row(s) carry no upstream_url", s.NoURLRows)},
		{s.NoVersionRow, fmt.Sprintf("%d versionless row(s) skipped for a type that needs a version", s.NoVersionRow)},
		{s.UnnamedRows, fmt.Sprintf("%d row(s) carry no pkg_name", s.UnnamedRows)},
		{s.InvalidPkgs, fmt.Sprintf("%d package(s) failed manifest validation", s.InvalidPkgs)},
		{s.NoNamespace, fmt.Sprintf("%d %s row(s): a request named a namespace no upstream is configured for, which needs a git_upstreams or binary_upstreams entry rather than a manifest", s.NoNamespace, audit.DecisionNoNamespace)},
		{s.OtherRows, fmt.Sprintf("%d row(s) record a decision other than %s and are not catalog misses", s.OtherRows, audit.DecisionNoManifest)},
	} {
		if line.n > 0 {
			fmt.Fprintf(w, "  %s\n", line.text)
		}
	}
}
