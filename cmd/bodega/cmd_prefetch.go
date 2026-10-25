package main

import (
	"context"
	"crypto/sha1" //nolint:gosec // npm integrity may still name sha1, and comparing it is all this does
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/mod/sumdb/dirhash"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/lockfile"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// Prefetch outcomes beyond admission's own decisions.
const (
	prefetchMismatch    = "mismatch"
	prefetchUnsupported = "unsupported"
	prefetchError       = "error"
)

// Digest comparison outcomes.
const (
	digestMatch       = "match"
	digestMismatch    = "mismatch"
	digestNotCompared = "not_compared"
)

// exitBlocked is the exit status a CI job reads as "bodega answered, and the
// answer is no": a block or a digest mismatch. 1 stays cobra's "could not
// answer", which is what every other failure of the command returns.
const exitBlocked = 2

type prefetchResult struct {
	Type     string                 `json:"type"`
	Name     string                 `json:"name"`
	Version  string                 `json:"version"`
	Lockfile string                 `json:"lockfile"`
	Line     int                    `json:"line,omitempty"`
	Decision string                 `json:"decision"`
	Failing  []audit.AdmissionCheck `json:"failing_checks,omitempty"`
	Reason   string                 `json:"reason,omitempty"`
	Fetch    string                 `json:"fetch,omitempty"`
	Digest   *digestComparison      `json:"digest,omitempty"`

	entry lockfile.Entry
	pm    *manifest.PackageManifest
}

type digestComparison struct {
	Status         string `json:"status"`
	Lockfile       string `json:"lockfile,omitempty"`
	LockfileSource string `json:"lockfile_source,omitempty"`
	Bodega         string `json:"bodega,omitempty"`
	BodegaSource   string `json:"bodega_source,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

func newPrefetchCmd(gf *globalFlags) *cobra.Command {
	var (
		format string
		dryRun bool
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "prefetch <lockfile> [lockfile...]",
		Short: "Admit, fetch and pin every dependency a lockfile names",
		Long: `prefetch reads the lockfiles a project's package manager wrote and runs
each (type, name, version) through the same admission an import does. An
admitted version is written to the manifest store, merged into its package
when one exists, and fetched, which pins its digest exactly as
'bodega build fetch' does.

Formats, detected from the file name or named with --format:
  package-lock   package-lock.json or npm-shrinkwrap.json, lockfileVersion 2 or 3
  requirements   requirements*.txt, every line pinned with ==, hashes optional
  go.sum         every module zip line; /go.mod lines pin no download
  cargo.lock     every [[package]] from crates.io
  gemfile.lock   Gemfile.lock or gems.locked: every GEM spec from rubygems.org,
                 its platform kept on the version, checked against CHECKSUMS
                 when Bundler 2.5 or later wrote one
  gradle.lockfile  gradle.lockfile, buildscript-gradle.lockfile, or a
                 dependency-locks/*.lockfile: every <group>:<artifact>:<version>
  dependency-list  what 'mvn dependency:list -DoutputFile=<file>' writes,
                 recognized by its "The following files have been resolved:"
                 line whatever the file is named; classifiers kept

The digest the lockfile records is compared with the one bodega pinned. A
sha256 in the lockfile is compared with the pin itself; any other algorithm
(npm's sha512, Go's h1) is computed over the artifact in the build root, once
that artifact matches the pin. A comparison bodega cannot make is reported as
not_compared, never as a match.

New packages are recorded in proxy mode, as 'bodega pkg convert' records a
registry inventory, so a client's first request is served through the
proxy and checked against the pin this run took.

Exit status: 0 when every entry was admitted and no digest disagreed; 2 when
any entry was blocked, invalid or mismatched; 1 when bodega could not answer
for some entry (an unsupported source, a failed fetch) or could not run at
all. A definite no outranks an unanswered entry, so 2 wins over 1.

--dry-run evaluates the same checks and compares against pins already on
record, and writes nothing: no manifest, no admission row, no fetch.`,
		Example: `  bodega pkg prefetch package-lock.json
  bodega pkg prefetch --dry-run --json go.sum Cargo.lock
  bodega pkg prefetch --format requirements requirements/prod.txt`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRun {
				suppressReload(cmd)
			}
			code, err := runPrefetch(cmd.Context(), gf, args, format, dryRun, asJSON, os.Stdout)
			if err != nil || code != 0 {
				// An entry admitted beside one refused is already written, and
				// neither an error nor os.Exit reaches the post-run reload.
				signalReloadNow(cmd, gf)
			}
			if err != nil {
				return err
			}
			if code != 0 {
				os.Exit(code) //nolint:revive // the CI-gating exit status the help documents
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "", "Lockfile format for every file named: package-lock, requirements, go.sum, cargo.lock, gemfile.lock, gradle.lockfile, dependency-list")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Evaluate and compare without fetching or writing anything")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the results as a JSON array")
	return cmd
}

// runPrefetch does the work and returns the exit status a completed run
// earned: 0, or exitBlocked. An error is a run that could not answer, or an
// answer that is incomplete because some entry could not be decided.
func runPrefetch(ctx context.Context, gf *globalFlags, paths []string, format string, dryRun, asJSON bool, out io.Writer) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	type parsed struct {
		path    string
		entries []lockfile.Entry
	}
	var files []parsed
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", path, err)
		}
		f, err := prefetchFormat(path, format, data)
		if err != nil {
			return 0, err
		}
		entries, err := lockfile.Parse(f, data)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", path, err)
		}
		files = append(files, parsed{path, entries})
	}

	cfg, err := loadConfig(gf)
	if err != nil {
		return 0, fmt.Errorf("load config: %w", err)
	}
	if !dryRun {
		if err := ensureMutable(cfg); err != nil {
			return 0, err
		}
	}
	// Without the audit database the age, OSV, provenance and similarity checks
	// do not run at all, so "admitted" would describe an allow-list alone.
	adb, err := openAuditDBErr(gf)
	if err != nil {
		return 0, err
	}
	if adb == nil {
		return 0, errors.New("prefetch needs the audit database: without it only the allow-list runs, and an admitted answer would hide every other check; set audit_db or log_dir")
	}
	defer adb.Close()
	store, err := loadStore(gf)
	if err != nil {
		return 0, fmt.Errorf("load manifests: %w", err)
	}
	checker := policy.NewChecker(adb)
	if !dryRun {
		takeNameBaseline(ctx, adb, store)
	}

	bcfg := builder.NewConfig(cfg, checker)
	bcfg.AuditDB = adb
	// Fetch progress goes to stderr so stdout carries only the results, which
	// is what a CI step parsing --json reads.
	bcfg.Stdout = os.Stderr

	var results []*prefetchResult
	for _, f := range files {
		for _, e := range f.entries {
			r := &prefetchResult{Type: e.Type, Name: e.Name, Version: e.Version, Lockfile: f.path, Line: e.Line, entry: e}
			results = append(results, r)
			if e.Unsupported != "" {
				r.Decision, r.Reason = prefetchUnsupported, e.Unsupported
				continue
			}
			pm := prefetchManifest(cfg, e)
			r.pm = pm
			existing, err := carryStored(ctx, store, pm)
			if err != nil {
				r.Decision, r.Reason = prefetchError, err.Error()
				continue
			}
			if dryRun {
				v := admit.Evaluate(ctx, cfg, checker, adb, nil, pm, time.Now())
				r.Decision, r.Reason, r.Failing = v.Decision.String(), v.Reason, failingChecks(v.Checks)
				continue
			}
			admitPrefetched(ctx, cfg, checker, adb, store, pm, existing, r)
		}
	}

	if !dryRun {
		fetchPrefetched(bcfg, store, results)
	}
	for _, r := range results {
		if r.Decision != audit.AdmissionAdmitted {
			continue
		}
		r.Digest = compareDigest(ctx, adb, bcfg, r.pm, r.entry, r.Lockfile)
		if r.Digest.Status == digestMismatch {
			r.Decision = prefetchMismatch
			r.Reason = fmt.Sprintf("%s@%s: lockfile %s (%s) disagrees with bodega %s (%s)", r.Name, r.Version,
				r.Digest.Lockfile, r.Digest.LockfileSource, r.Digest.Bodega, r.Digest.BodegaSource)
		}
	}

	if err := printPrefetch(out, results, asJSON); err != nil {
		return 0, err
	}
	return prefetchExit(results)
}

func prefetchFormat(path, flag string, data []byte) (lockfile.Format, error) {
	if flag != "" {
		return lockfile.ParseFormat(flag)
	}
	f, err := lockfile.Detect(path)
	if err != nil {
		if sniffed, ok := lockfile.Sniff(data); ok {
			return sniffed, nil
		}
	}
	return f, err
}

// prefetchManifest is the single-version manifest an entry becomes. npm and
// gomod name the configured upstream so the fetch reads where the proxy would;
// cargo's and rubygems' fetches read cargo_dl_upstream and rubygems_upstream
// themselves, and pypi resolves through the index the store's pypi entries
// name.
func prefetchManifest(cfg *config.Config, e lockfile.Entry) *manifest.PackageManifest {
	ve := manifest.VersionEntry{Version: e.Version, Mode: manifest.ModeProxy, Classifiers: e.Classifiers}
	switch e.Type {
	case manifest.TypeNpm:
		ve.URL = strings.TrimRight(cfg.NpmUpstream, "/")
	case manifest.TypeGomod:
		ve.URL = strings.TrimRight(cfg.GomodUpstream, "/")
	}
	return &manifest.PackageManifest{Type: e.Type, Name: manifest.CanonicalName(e.Type, e.Name), Versions: []manifest.VersionEntry{ve}}
}

// carryStored gives pm what the stored package already settles for it, and
// returns that package (nil when there is none). A dry run and a real one
// both start here, so the two evaluate the same manifest. A store that cannot
// be read is an entry bodega cannot answer for: guessing "not stored" would
// drop a baseline mark the store holds, and the merge would then overwrite
// the package with this one version.
func carryStored(ctx context.Context, store *manifest.Store, pm *manifest.PackageManifest) (*manifest.PackageManifest, error) {
	existing, err := store.GetPackage(ctx, pm.Type, pm.Name)
	if err != nil {
		return nil, err
	}
	if existing != nil && len(existing.Versions) > 0 {
		// A package's mode is its first version's; a proxy entry appended to a
		// hosted package would change nothing but would read as a contradiction.
		pm.Versions[0].Mode = existing.Versions[0].Mode
	}
	// Only `pkg import --baseline` sets the mark; prefetch keeps the one the
	// store holds, as every other write path does.
	admit.CarryBaseline(pm, existing)
	return existing, nil
}

// admitPrefetched is `bodega pkg import --merge` for one entry: admission,
// publish time, then the write. A version the package already holds is
// admitted again, so the row cites today's policy, and written nowhere.
func admitPrefetched(ctx context.Context, cfg *config.Config, checker *policy.Checker, adb *audit.DB,
	store *manifest.Store, pm, existing *manifest.PackageManifest, r *prefetchResult) {
	res := admit.Admit(ctx, checker, adb, cfg, pm, audit.CurrentActor())
	for _, w := range res.Warnings {
		fmt.Fprintf(os.Stderr, "%s/%s: %s\n", pm.Type, pm.Name, w)
	}
	r.Decision = res.Decision.String()
	if len(res.Admissions) > 0 {
		r.Failing = failingChecks(res.Admissions[0].Checks)
	}
	if !res.OK() {
		r.Reason = res.Reason
		return
	}
	if existing != nil && slices.ContainsFunc(existing.Versions, func(ve manifest.VersionEntry) bool { return ve.Version == pm.Versions[0].Version }) {
		foldClassifiers(ctx, store, existing, pm.Versions[0], r)
		return
	}
	dated := admit.Result{}
	admit.RecordPublished(ctx, pm, existing, &dated)
	for _, w := range dated.Warnings {
		fmt.Fprintf(os.Stderr, "%s/%s: WARNING: %s\n", pm.Type, pm.Name, w)
	}
	toSave := pm
	if existing != nil {
		admit.MergeVersions(existing, pm)
		toSave = existing
	} else {
		pm.ConfigVersion = manifest.CurrentConfigVersion
	}
	if err := store.SavePackage(ctx, toSave); err != nil {
		r.Decision, r.Reason = prefetchError, fmt.Sprintf("save %s/%s: %v", pm.Type, pm.Name, err)
		return
	}
	if err := store.SaveIndex(ctx); err != nil {
		r.Decision, r.Reason = prefetchError, fmt.Sprintf("save index: %v", err)
		return
	}
	afterJSON, _ := json.MarshalIndent(pm, "", "  ")
	_ = adb.Record(ctx, audit.Event{EventType: audit.EventCreate, PkgType: pm.Type, PkgName: pm.Name,
		Actor: audit.CurrentActor(), Status: "success", Details: audit.FormatDiff(nil, afterJSON)})
}

// foldClassifiers adds the classifiers a lockfile names to the maven version
// the store already holds, so a dependency:list resolving a version's
// sources jar after its main jar was cataloged fetches the sources too. The
// merge alone skips a held version and would drop them.
func foldClassifiers(ctx context.Context, store *manifest.Store, existing *manifest.PackageManifest, ve manifest.VersionEntry, r *prefetchResult) {
	if existing.Type != manifest.TypeMaven || len(ve.Classifiers) == 0 {
		return
	}
	for i := range existing.Versions {
		held := &existing.Versions[i]
		if held.Version != ve.Version {
			continue
		}
		added := false
		for _, c := range ve.Classifiers {
			if !slices.Contains(held.Classifiers, c) {
				held.Classifiers = append(held.Classifiers, c)
				added = true
			}
		}
		if !added {
			return
		}
		if err := store.SavePackage(ctx, existing); err != nil {
			r.Decision, r.Reason = prefetchError, fmt.Sprintf("save %s/%s: %v", existing.Type, existing.Name, err)
		}
		return
	}
}

// fetchPrefetched runs the builder's own fetch for every admitted package, so
// the digest is pinned by the code that pins it for every other fetch. pypi
// resolves its closure across the whole type, so it runs once.
func fetchPrefetched(bcfg *builder.Config, store *manifest.Store, results []*prefetchResult) {
	fetchers := map[string]func(*builder.Config, *manifest.Store, string) *builder.Summary{
		manifest.TypeNpm:      builder.FetchNpm,
		manifest.TypeGomod:    builder.FetchGomod,
		manifest.TypeCargo:    builder.FetchCargo,
		manifest.TypeRubygems: builder.FetchRubygems,
		manifest.TypeMaven:    builder.FetchMaven,
	}
	failed := map[string]string{}
	done := map[string]bool{}
	for _, r := range results {
		if r.Decision != audit.AdmissionAdmitted {
			continue
		}
		key := r.Type + "/" + r.Name
		if r.Type == manifest.TypePypi {
			key = manifest.TypePypi
		}
		if done[key] {
			continue
		}
		done[key] = true
		var s *builder.Summary
		if r.Type == manifest.TypePypi {
			s = builder.FetchPypi(bcfg, store)
		} else {
			s = fetchers[r.Type](bcfg, store, manifest.SafeName(manifest.CanonicalName(r.Type, r.Name)))
		}
		for _, res := range s.Results {
			if res.Err != nil {
				failed[key] = res.Err.Error()
			}
		}
	}
	for _, r := range results {
		if r.Decision != audit.AdmissionAdmitted {
			continue
		}
		key := r.Type + "/" + r.Name
		if r.Type == manifest.TypePypi {
			key = manifest.TypePypi
		}
		if msg, ok := failed[key]; ok {
			r.Fetch, r.Decision, r.Reason = "failed", prefetchError, "fetch: "+msg
		} else {
			r.Fetch = "fetched"
		}
	}
}

// compareDigest holds the lockfile's digest against what bodega pinned for
// the same version.
func compareDigest(ctx context.Context, adb *audit.DB, bcfg *builder.Config, pm *manifest.PackageManifest, e lockfile.Entry, path string) *digestComparison {
	src := fmt.Sprintf("%s line %d", path, e.Line)
	if e.Line == 0 {
		src = path
	}
	if len(e.Digests) == 0 {
		return &digestComparison{Status: digestNotCompared, LockfileSource: src, Detail: "the lockfile records no digest for this version"}
	}
	if pm.Type == manifest.TypePypi {
		return comparePypi(ctx, adb, pm, e, src)
	}
	want := e.Digests[0]
	c := &digestComparison{Lockfile: want.String(), LockfileSource: src}
	ve := pm.Versions[0]
	keys, err := manifest.ArtifactKeys(pm, ve)
	if err != nil || len(keys) == 0 {
		c.Status, c.Detail = digestNotCompared, "no object key for this version"
		return c
	}
	key := keys[0]
	pin, err := adb.GetChecksum(ctx, key)
	if err != nil {
		c.Status, c.Detail = digestNotCompared, "read the pin: "+err.Error()
		return c
	}
	pinned := pin != nil && pin.Value != "" && strings.EqualFold(pin.Algorithm, "sha256")
	if want.Algorithm == "sha256" && pinned {
		c.Bodega, c.BodegaSource = "sha256:"+pin.Value, fmt.Sprintf("pin on %s (source %s)", key, pin.Source)
		c.Status = digestMatch
		if !strings.EqualFold(pin.Value, want.Value) {
			c.Status = digestMismatch
		}
		return c
	}
	file := bcfg.FetchedArtifact(pm.Type, manifest.SafeName(pm.Name), ve)
	if file == "" {
		c.Status, c.Detail = digestNotCompared, fmt.Sprintf("bodega holds no artifact for this version to compute %s over", want.Algorithm)
		return c
	}
	if pinned {
		sum, err := fileDigest(file, "sha256")
		if err != nil || !strings.EqualFold(sum, pin.Value) {
			c.Status, c.Detail = digestNotCompared, fmt.Sprintf("%s does not match the pin on %s, so it is not the pinned object", file, key)
			return c
		}
	}
	got, err := fileDigest(file, want.Algorithm)
	if err != nil {
		c.Status, c.Detail = digestNotCompared, err.Error()
		return c
	}
	c.Bodega = lockfile.Digest{Algorithm: want.Algorithm, Value: got}.String()
	c.BodegaSource = fmt.Sprintf("%s, the fetched artifact pinned on %s", file, key)
	c.Status = digestMatch
	if !strings.EqualFold(got, want.Value) {
		c.Status = digestMismatch
	}
	return c
}

// comparePypi checks every file bodega pinned for the version against the
// hashes the requirements line lists. pip installs a file only when its hash
// is listed, so one pinned file outside the list is one pip would refuse.
func comparePypi(ctx context.Context, adb *audit.DB, pm *manifest.PackageManifest, e lockfile.Entry, src string) *digestComparison {
	var listed []string
	for _, d := range e.Digests {
		if d.Algorithm == "sha256" {
			listed = append(listed, strings.ToLower(d.Value))
		}
	}
	c := &digestComparison{Lockfile: "sha256:" + strings.Join(listed, ",sha256:"), LockfileSource: src}
	if len(listed) == 0 {
		c.Lockfile, c.Status, c.Detail = "", digestNotCompared, "the lockfile lists no sha256 hash"
		return c
	}
	pins, err := adb.ListChecksums(ctx, manifest.TypePypi, pm.Name)
	if err != nil {
		c.Status, c.Detail = digestNotCompared, "read the pins: "+err.Error()
		return c
	}
	compared := 0
	for _, p := range pins {
		if p.PkgVersion != e.Version || p.Value == "" {
			continue
		}
		compared++
		if !slices.Contains(listed, strings.ToLower(p.Value)) {
			c.Status = digestMismatch
			c.Bodega, c.BodegaSource = "sha256:"+p.Value, fmt.Sprintf("pin on %s (source %s)", p.ObjectKey, p.Source)
			return c
		}
	}
	if compared == 0 {
		c.Status, c.Detail = digestNotCompared, "bodega has pinned no file for this version"
		return c
	}
	c.Status, c.Bodega, c.BodegaSource = digestMatch, fmt.Sprintf("%d pinned file(s)", compared), "pins under "+manifest.PypiWheelPrefix
	return c
}

// fileDigest computes algorithm over path in the encoding lockfile.Digest uses.
func fileDigest(path, algorithm string) (string, error) {
	if algorithm == "h1" {
		return dirhash.HashZip(path, dirhash.Hash1)
	}
	var h hash.Hash
	switch algorithm {
	case "sha1":
		h = sha1.New() //nolint:gosec // see the import
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	default:
		return "", fmt.Errorf("bodega cannot compute %s", algorithm)
	}
	f, err := os.Open(path) //nolint:gosec // a build-root path the builder derived
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// failingChecks keeps the checks that warned or blocked, and the ones a
// baseline mark or an override admitted past: a CI reader seeing a known
// vulnerable version go through needs to see why.
func failingChecks(checks []audit.AdmissionCheck) []audit.AdmissionCheck {
	var out []audit.AdmissionCheck
	for _, c := range checks {
		switch c.Status {
		case audit.CheckWarn, audit.CheckBlock, audit.CheckBaseline, audit.CheckOverridden:
			out = append(out, c)
		}
	}
	return out
}

func printPrefetch(out io.Writer, results []*prefetchResult, asJSON bool) error {
	if asJSON {
		if results == nil {
			results = []*prefetchResult{}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	for _, r := range results {
		var detail []string
		for _, c := range r.Failing {
			detail = append(detail, fmt.Sprintf("%s=%s: %s", c.Check, c.Status, c.Detail))
		}
		switch {
		case r.Decision == prefetchMismatch:
			detail = append(detail, r.Reason)
		case r.Digest != nil && r.Digest.Status == digestNotCompared:
			detail = append(detail, "digest not compared: "+r.Digest.Detail)
		case r.Reason != "" && len(r.Failing) == 0:
			detail = append(detail, r.Reason)
		}
		fmt.Fprintf(w, "%s\t%s@%s\t%s\t%s\n", r.Type, r.Name, r.Version, r.Decision, strings.Join(detail, "; "))
	}
	return w.Flush()
}

// prefetchExit turns the results into the documented exit status.
func prefetchExit(results []*prefetchResult) (int, error) {
	var unanswered int
	for _, r := range results {
		switch r.Decision {
		case audit.AdmissionPolicyBlocked, audit.AdmissionInvalid, prefetchMismatch:
			return exitBlocked, nil
		case prefetchUnsupported, prefetchError:
			unanswered++
		}
	}
	if unanswered > 0 {
		return 0, fmt.Errorf("%d entr%s could not be decided; each is named above", unanswered, plural(unanswered, "y", "ies"))
	}
	return 0, nil
}
