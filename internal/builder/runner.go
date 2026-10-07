// Package builder contains the orchestration logic for building bootstrap
// artifacts. Each sub-builder (apt, git, pypi, binary) calls out to system
// tools; the Go code manages directories, captures output, and reports results.
package builder

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/distinfo"
	"github.com/ravinald/bodega/internal/logging"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// Config holds the parameters shared by all builders.
type Config struct {
	BuildRoot   string
	ManifestDir string
	Bucket      string
	Region      string
	Verbose     bool
	// Per-type build root overrides. Empty means use BuildRoot.
	AptRoot     string
	GitRoot     string
	PypiRoot    string
	BinaryRoot  string
	GomodRoot   string
	HelmRoot    string
	NpmRoot     string
	CargoRoot   string
	FreeBSDRoot string

	// DistfilesRoot roots the DISTDIR FetchDistfiles writes, at
	// <root>/distfiles/@<environment digest>/. DistfilesPortsTree is the ports
	// tree whose distinfo admits each file, and DistfilesUpstream is where a
	// file is fetched from.
	DistfilesRoot      string
	DistfilesPortsTree string
	DistfilesUpstream  string
	// DistfilesEnvironment is the supported client environment every port
	// is read against; see distinfo.Environment.
	DistfilesEnvironment distinfo.EnvironmentSpec
	// distfilesEnv is the environment the first distfiles stage of this
	// Config read, which every later stage must find unchanged; see
	// distfilesEnvironment.
	distfilesEnvMu sync.Mutex
	distfilesEnv   *distinfo.Environment
	// Stdout is where builder output is written; defaults to os.Stdout.
	Stdout io.Writer
	// Force re-fetches even if artifacts already exist on disk.
	Force bool
	// BodegaVersion is the bodega build stamped onto artifacts this Config
	// produces. NewConfig fills it from Version; a Config built by hand leaves
	// it empty, and BuildEnv.Bodega is omitempty, so the field simply vanishes.
	BodegaVersion string
	// BuildEnvInfo is the detected build environment, auto-populated if nil.
	BuildEnvInfo *manifest.BuildEnv
	// AutoImportDeps controls whether discovered dependencies are automatically
	// added to manifests after git fetch. When false, ScanDeps runs but ImportDeps
	// is skipped, allowing the caller to review deps interactively.
	AutoImportDeps bool
	// LastDiscovery holds the result of the most recent ScanDeps call.
	// Used by the TUI to present interactive review when AutoImportDeps is false.
	LastDiscovery *DiscoveryResult
	// Logger is an optional structured build logger. When set, each per-entry
	// stage writes to a dedicated package log in addition to Stdout.
	Logger *logging.BuildLogger
	// AuditDB is an optional audit database. When set, build operations
	// record events to the SQLite audit trail.
	AuditDB *audit.DB
	// policyChecker is the upstream allow-list. NewConfig is the only way to
	// set it, and it takes it as an argument rather than leaving it to the
	// caller, because five of eight call sites left the exported field nil and
	// two of those reached a fetcher. Nil means no allow-list, which is an
	// install with no audit_db to read rules from; policyNotice makes every
	// run in that state say so on its own output.
	policyChecker *policy.Checker
	policyNotice  sync.Once
	// app is the configuration NewConfig was built from, kept for the OSV
	// gate's database and fallback settings. Nil on a Config built by hand,
	// which leaves the gate with no database: it warns rather than passing.
	app *config.Config
	// CargoDLUpstream is the host crate tarballs are fetched from. crates.io
	// splits the sparse index from the download host, and the index host serves
	// no downloads, so composing a download URL from the index root 404s.
	CargoDLUpstream string
	// CargoUpstream is the sparse index host, the other half of that split. A
	// .crate carries Cargo.toml, which is the author's declaration and not the
	// registry's dependency record: workspace, path and git dependencies have
	// no sparse-index shape at all. The index line is the record, so it is
	// fetched from here rather than reconstructed from the tarball.
	CargoUpstream string
	// CratesAPI is the host a crate's publish time is read from, the third
	// crates.io host beside the index and the download one. Empty means
	// crates.io; tests point it at a local server.
	CratesAPI string
}

// PolicyDisabledNotice is what a fetch prints, once per run, when it holds no
// allow-list checker. Fetching proceeds: the allow-list needs an audit
// database to read rules from, so failing closed here would refuse every fetch
// on every install that never configured audit_db, turning an opt-in feature
// into a hard dependency. The unenforced state is announced instead, because
// being invisible is what let it reach two surfaces unnoticed.
const PolicyDisabledNotice = "  policy: no upstream allow-list loaded, so every upstream is permitted. Set audit_db and add rules with `bodega policy add` to enforce one."

// checkPolicy runs the upstream allow-list for (regType, candidate). Returns
// nil if policy is disabled or the candidate is allowed; otherwise returns
// the ViolationError (or a storage error wrapping it).
func (c *Config) checkPolicy(ctx context.Context, regType, candidate string) error {
	if c.policyChecker == nil {
		c.policyNotice.Do(func() { c.logf("%s", PolicyDisabledNotice) })
		return nil
	}
	if candidate == "" {
		return nil
	}
	return c.policyChecker.Check(ctx, regType, candidate)
}

// EnforcePolicy is the builder's admission of one manifest entry at fetch
// time: the upstream allow-list, then the age and OSV checks import runs, with
// the decision written to the admissions table. On a refusal it records an
// audit event and returns the error so the calling Fetch* function can log,
// bump Summary.Failures, and continue to the next entry. Returns nil when the
// entry is admitted, a warn included.
//
// The per-version checks run here as well as at import because this is the
// moment bytes arrive, and an import can be months old: the row a pin attaches
// its object key to should be the decision made when those bytes were fetched.
func (c *Config) EnforcePolicy(ctx context.Context, regType, name string, ve manifest.VersionEntry) error {
	candidate := policy.CandidateFor(regType, name, ve.URL)
	version := ve.Version
	if version == "" {
		version = ve.Ref
	}
	err := c.checkPolicy(ctx, regType, candidate)
	if err != nil && c.AuditDB != nil {
		_ = c.AuditDB.Record(ctx, audit.Event{
			EventType:  audit.EventFetch,
			PkgType:    regType,
			PkgName:    name,
			PkgVersion: version,
			Status:     "policy_violation",
			Details:    fmt.Sprintf("candidate=%s", candidate),
		})
	}
	if c.AuditDB == nil {
		return err
	}

	allow := audit.AdmissionCheck{Check: audit.CheckAllowList, Action: audit.ActionNone,
		Status: audit.CheckNotEvaluated, Detail: "not run: no allow-list loaded"}
	if c.policyChecker != nil {
		hasRules, _ := c.policyChecker.HasRules(ctx, regType)
		allow = admit.AllowListCheck(hasRules, candidate, err)
	}
	res := admit.Fetch(ctx, c.AuditDB, fetchCheckers(c.app, c.AuditDB), regType, name, ve, allow,
		admit.Who{Actor: audit.CurrentActor()}, "")
	if err != nil {
		return err
	}
	for _, w := range res.Warns {
		c.logf("  policy: %s/%s@%s: %s: %s (warn)", regType, name, version, w.Check, w.Reason)
	}
	if res.Block != nil {
		_ = c.AuditDB.Record(ctx, audit.Event{
			EventType:  audit.EventFetch,
			PkgType:    regType,
			PkgName:    name,
			PkgVersion: version,
			Status:     "policy_violation",
			Details:    res.Block.Check + ": " + res.Block.Reason,
		})
		return fmt.Errorf("policy blocked %s@%s: %s: %s", name, version, res.Block.Check, res.Block.Reason)
	}
	return nil
}

// fetchCheckers is admit.VersionCheckers, held in a variable because the age
// gate dates a version against the public registries: a test points it at
// checkers it controls rather than reaching the internet.
var fetchCheckers = admit.VersionCheckers

// pinAdmission attaches an object key to the admission decision for the
// version whose digest was just pinned, or verified against the pin. A pin no
// decision preceded is said out loud: those bytes reached the store with no
// admission behind them, and the row written for them says not_evaluated.
func (c *Config) pinAdmission(ctx context.Context, typ, name, version, key string) {
	if c.AuditDB == nil || key == "" {
		return
	}
	outcome, err := c.AuditDB.PinAdmission(ctx, audit.AdmissionPin{PkgType: typ, PkgName: name, PkgVersion: version, ObjectKey: key})
	switch {
	case err != nil:
		c.logf("  WARNING: %s/%s@%s: admission row not updated with object key %s: %v", typ, name, version, key, err)
	case outcome == audit.PinUnadmitted:
		c.logf("  WARNING: %s/%s@%s: pinned %s with no admission decision on record; recorded it as not_evaluated", typ, name, version, key)
	}
}

// RootFor returns the root a type's fetch writes under: its *_root override
// when set, build_root otherwise. A command that reads a fetched tree back
// resolves it here rather than from BuildRoot, which misses the override.
func (c *Config) RootFor(typ string) string { return c.rootFor(typ) }

// rootFor returns the effective build root for the given source type.
func (c *Config) rootFor(typ string) string {
	switch typ {
	case "apt":
		if c.AptRoot != "" {
			return c.AptRoot
		}
	case "git":
		if c.GitRoot != "" {
			return c.GitRoot
		}
	case "pypi":
		if c.PypiRoot != "" {
			return c.PypiRoot
		}
	case "binary":
		if c.BinaryRoot != "" {
			return c.BinaryRoot
		}
	case "gomod":
		if c.GomodRoot != "" {
			return c.GomodRoot
		}
	case "helm":
		if c.HelmRoot != "" {
			return c.HelmRoot
		}
	case "npm":
		if c.NpmRoot != "" {
			return c.NpmRoot
		}
	case "cargo":
		if c.CargoRoot != "" {
			return c.CargoRoot
		}
	case "freebsd":
		if c.FreeBSDRoot != "" {
			return c.FreeBSDRoot
		}
	case "distfiles":
		if c.DistfilesRoot != "" {
			return c.DistfilesRoot
		}
	}
	return c.BuildRoot
}

// Version is the bodega build every Config from NewConfig stamps onto the
// artifacts it produces. -ldflags bakes the value into package main, which
// nothing under internal/ may import, so main assigns this once at init. It is
// a package variable for the same reason config.StorageDrivers is one: the
// value crosses an import edge that only points the other way.
//
// "unknown" and "dev" are different facts and the default is deliberately not
// "dev". A binary built without -ldflags stamps "dev", because main still ran;
// "unknown" reaches a manifest only if nothing wired main to this at all.
var Version = "unknown"

// NewConfig builds the Config every command and the TUI run on from the
// installed settings.
//
// It exists because the per-type roots were hand-copied into seven struct
// literals and no two carried the same subset: sync and upload named none of
// them, so an install setting apt_root uploaded from build_root, found nothing
// and reported nothing to do. Fields a single caller owns — Stdout, Logger,
// AuditDB, Force — stay the caller's to set; anything read off the
// config file is set here or it reaches one command only.
//
// pol is a parameter rather than one of those fields because it is not a
// single caller's: every Fetch* function gates on it, and a call site that
// forgot it fetched past every rule with no refusal printed and no audit row
// written. Pass policy.CheckerFor(auditDB); a nil checker is the answer only
// where there is no audit database, and PolicyDisabledNotice says so.
func NewConfig(app *config.Config, pol *policy.Checker) *Config {
	return &Config{
		BuildRoot:      app.BuildRoot,
		ManifestDir:    app.ManifestDir,
		Bucket:         app.Bucket,
		Region:         app.Region,
		Verbose:        app.Verbose,
		AptRoot:        app.AptRoot,
		GitRoot:        app.GitRoot,
		PypiRoot:       app.PypiRoot,
		BinaryRoot:     app.BinaryRoot,
		GomodRoot:      app.GomodRoot,
		HelmRoot:       app.HelmRoot,
		NpmRoot:        app.NpmRoot,
		CargoRoot:      app.CargoRoot,
		FreeBSDRoot:    app.FreeBSDRoot,
		DistfilesRoot:  app.DistfilesRoot,
		AutoImportDeps: true,
		BodegaVersion:  Version,
		policyChecker:  pol,
		app:            app,

		CargoDLUpstream: app.CargoDLUpstream,
		CargoUpstream:   app.CargoUpstream,

		DistfilesPortsTree:   app.DistfilesPortsTree,
		DistfilesUpstream:    app.DistfilesUpstream,
		DistfilesEnvironment: app.DistfilesEnvironment(),
	}
}

// ArtifactDir returns the directory a type's artifacts are read from and
// written to, resolved through the same per-type root the *ArtifactPaths
// functions walk. An upload that finds nothing names this path, which is the
// one thing that distinguishes an empty build from a build under a root the
// command never read.
func ArtifactDir(cfg *Config, typ string) string {
	d := buildDirs(cfg.rootFor(typ))
	switch typ {
	case manifest.TypeBinary:
		return d.binaries
	case manifest.TypeGit:
		return d.bundles
	case manifest.TypeApt:
		return d.aptRepo
	case manifest.TypePypi:
		return d.wheels
	case manifest.TypeGomod:
		return d.gomod
	case manifest.TypeHelm:
		return d.charts
	case manifest.TypeNpm:
		return d.npm
	case manifest.TypeCargo:
		return d.cargo
	case manifest.TypeFreeBSD:
		return d.freebsd
	case manifest.TypeDistfiles:
		if dir, err := distdir(cfg, d); err == nil {
			return dir
		}
		return d.distfiles
	}
	return cfg.rootFor(typ)
}

// typeResetPaths lists every path under a type's resolved root that the
// type's builders write and a later build reads back. An unknown type returns
// nil, which TestResetPathsCoverEveryType turns into a failure.
func typeResetPaths(cfg *Config, typ string) []string {
	root := cfg.rootFor(typ)
	d := buildDirs(root)
	switch typ {
	case manifest.TypeBinary:
		return []string{d.binaries}
	case manifest.TypeGit:
		return []string{d.repos, d.sources, d.bundles}
	case manifest.TypeApt:
		return []string{d.sources, d.aptRepo}
	case manifest.TypePypi:
		// The combined and resolved requirement files sit at the root itself,
		// and CheckPypiStage reads them to decide the fetch stage ran. The
		// wheelhouse and the build venv sit there too, outside dirs: the build
		// reads the one and reuses the other.
		return []string{
			d.wheels,
			pypiWheelhouseDir(root),
			pypiVenvDir(root),
			filepath.Join(root, "combined-requirements.txt"),
			filepath.Join(root, "combined-constraints.txt"),
			pypiLockPath(root),
		}
	case manifest.TypeGomod:
		return []string{d.gomod}
	case manifest.TypeHelm:
		return []string{d.charts}
	case manifest.TypeNpm:
		return []string{d.npm}
	case manifest.TypeCargo:
		return []string{d.cargo}
	case manifest.TypeFreeBSD:
		return []string{d.freebsd}
	case manifest.TypeDistfiles:
		// The whole tree, not the @<digest> DISTDIR ArtifactDir names: a
		// changed environment declaration leaves the old digest's files beside
		// the new one.
		return []string{d.distfiles}
	}
	return nil
}

// ResetPath is one path `bodega reset` removes, with the types that write it.
// Two types share a path when neither overrides its root, as apt and git do
// with sources/.
type ResetPath struct {
	Path  string
	Types []string
}

// ResetPaths returns the union of every path each type in manifest.AllTypes
// writes, resolved through the per-type root overrides, sorted by path.
func ResetPaths(cfg *Config) []ResetPath {
	byPath := map[string]*ResetPath{}
	for _, typ := range manifest.AllTypes {
		for _, p := range typeResetPaths(cfg, typ) {
			p = filepath.Clean(p)
			if rp, ok := byPath[p]; ok {
				rp.Types = append(rp.Types, typ)
				continue
			}
			byPath[p] = &ResetPath{Path: p, Types: []string{typ}}
		}
	}
	out := make([]ResetPath, 0, len(byPath))
	for _, rp := range byPath {
		out = append(out, *rp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// stdout returns the configured output writer, falling back to os.Stdout.
func (c *Config) stdout() io.Writer {
	if c.Stdout != nil {
		return c.Stdout
	}
	return os.Stdout
}

// RecordAudit writes an event to the audit database if one is configured.
// Called by builders after each fetch/build/package operation completes.
func (c *Config) RecordAudit(evType audit.EventType, pkgType, name, version, status string, elapsed time.Duration, errVal error) {
	if c.AuditDB == nil {
		return
	}
	details := ""
	if errVal != nil {
		details = errVal.Error()
	}
	_ = c.AuditDB.Record(context.Background(), audit.Event{
		EventType:  evType,
		PkgType:    pkgType,
		PkgName:    name,
		PkgVersion: version,
		Status:     status,
		DurationMs: elapsed.Milliseconds(),
		Details:    details,
	})
}

// entryWriter returns an io.Writer scoped to a single manifest entry. When a
// Logger is configured the output is written to both a dedicated package log
// file and the session log simultaneously. Without a Logger it falls back to
// the regular stdout writer so callers require no special-case logic.
func (c *Config) entryWriter(typ, name string) io.Writer {
	if c.Logger != nil {
		return c.Logger.StartPackage(typ, name)
	}
	return c.stdout()
}

// logf writes a formatted line to the configured output writer.
// The error return from fmt.Fprintf is intentionally ignored: the writer is
// either os.Stdout or an in-memory buffer; neither surfaces actionable errors.
func (c *Config) logf(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(c.stdout(), format+"\n", args...)
}

// Result captures the outcome of building a single entry.
type Result struct {
	Type      string
	Name      string
	Elapsed   time.Duration
	Artifacts []string // absolute paths of produced files
	Err       error
}

// Summary is the aggregate result of a build run.
type Summary struct {
	Results  []Result
	Total    int
	Failures int
}

// Print writes a human-readable summary to w.
// Write errors are intentionally ignored: the writer is always a terminal or
// in-memory buffer where write failures are not recoverable.
func (s *Summary) Print(w io.Writer) {
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "--- Build Summary ---")
	for _, r := range s.Results {
		status := "ok"
		if r.Err != nil {
			status = "FAILED"
		}
		_, _ = fmt.Fprintf(w, "  %-8s %-30s %s  (%s)\n",
			r.Type, r.Name, status, r.Elapsed.Round(time.Millisecond))
		if r.Err != nil {
			_, _ = fmt.Fprintf(w, "           error: %v\n", r.Err)
		}
		for _, a := range r.Artifacts {
			_, _ = fmt.Fprintf(w, "           artifact: %s\n", a)
		}
	}
	_, _ = fmt.Fprintf(w, "\nTotal: %d  Failures: %d\n", s.Total, s.Failures)
}

// HasFailures returns true when at least one entry failed.
func (s *Summary) HasFailures() bool { return s.Failures > 0 }

// LogErrors writes all failed results to the error log with full context.
func (s *Summary) LogErrors(logger *logging.BuildLogger, operation string) {
	if logger == nil {
		return
	}
	for _, r := range s.Results {
		if r.Err != nil {
			logger.Error(operation, r.Type, r.Name, r.Err, "")
		}
	}
}

// dirs returns the canonical sub-directories under BuildRoot.
type dirs struct {
	sources  string
	repos    string
	bundles  string
	wheels   string
	binaries string
	aptRepo  string
	gomod    string
	charts   string
	npm      string
	cargo    string
	freebsd  string

	// distfiles is a DISTDIR: <DIST_SUBDIR>/<file> beneath it, exactly as
	// a client's ports tree lays out its own.
	distfiles string
}

func buildDirs(root string) dirs {
	return dirs{
		sources:  filepath.Join(root, "sources"),
		repos:    filepath.Join(root, "repos"),
		bundles:  filepath.Join(root, "bundles"),
		wheels:   filepath.Join(root, "wheels"),
		binaries: filepath.Join(root, "binaries"),
		aptRepo:  filepath.Join(root, "apt-repo"),
		gomod:    filepath.Join(root, "gomod"),
		charts:   filepath.Join(root, "charts"),
		npm:      filepath.Join(root, "npm"),
		cargo:    filepath.Join(root, "cargo"),
		freebsd:  filepath.Join(root, "freebsd"),

		distfiles: filepath.Join(root, "distfiles"),
	}
}

// GetBuildEnv returns the build environment info, detecting it on first call.
func (c *Config) GetBuildEnv() *manifest.BuildEnv {
	if c.BuildEnvInfo == nil {
		c.BuildEnvInfo = DetectBuildEnv(c.BodegaVersion)
	}
	return c.BuildEnvInfo
}

// mkdirAll creates a directory and all parents, returning an error on failure.
func mkdirAll(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create directory %s: %w", path, err)
	}
	return nil
}

// runCmd executes a command, streaming its combined output to out.
// The command's working directory is set to dir when non-empty.
func runCmd(out io.Writer, dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

// runCmdEnv runs a command with an explicit environment rather than the
// server's own, for a tool that reads configuration out of the environment and
// would otherwise take acquisition instructions from whatever started bodega.
func runCmdEnv(out io.Writer, dir string, env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

// runCmdCapture runs a command and returns its combined output as a string.
func runCmdCapture(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// StageStatus reports which pipeline stages have been completed for a given
// manifest entry by inspecting the filesystem. All fields default to false.
type StageStatus struct {
	// Fetched is true when the fetch stage output is present on disk.
	Fetched bool
	// Built is true when the build stage output is present on disk.
	Built bool
	// Packaged is true when the package stage output is present on disk.
	Packaged bool
}

// ArtifactPath pairs a local filesystem path with its target object key.
// Used by the upload and sync commands to resolve per-entry upload targets.
type ArtifactPath struct {
	// Local is the absolute path on disk.
	Local string
	// ObjectKey is the key within the backend's namespace (no leading slash).
	ObjectKey string
	// Package and Version name the manifest entry this artifact belongs to.
	// The uploader records placement against that entry, so an artifact with
	// no entry — a generated index, a packument — leaves both empty and is
	// routed by its type instead.
	Package string
	Version string
}

// MergeSummaries merges an arbitrary slice of Summary pointers into one.
// Nil entries are silently skipped. This is the exported variant of the
// package-internal mergeSummaries for use by command-layer pipeline helpers.
func MergeSummaries(ss ...*Summary) *Summary {
	out := &Summary{}
	for _, s := range ss {
		if s == nil {
			continue
		}
		out.Results = append(out.Results, s.Results...)
		out.Total += s.Total
		out.Failures += s.Failures
	}
	return out
}
