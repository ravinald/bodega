// Package admit holds the checks a package manifest passes before it is
// written to the store, in one place for every caller that writes one.
//
// The CLI (bodega pkg import) and the mutation API (POST /api/v1/packages)
// each grew their own copy of this sequence and the two had already drifted:
// only the CLI rejected an unknown storage backend, and only the CLI admitted
// cargo. A manifest's fate should not depend on which surface it arrived
// through, so the sequence lives here and the callers keep only their own
// response shaping.
package admit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/integration"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/provenance"

	// The integration types bodega ships register here, because every
	// admission path reaches this package.
	_ "github.com/ravinald/bodega/internal/integration/malwarelist"
	_ "github.com/ravinald/bodega/internal/integration/socket"
)

// Decision is the verdict on one manifest. Conflict with an existing package
// is deliberately not among them: that answer needs the store, which callers
// hold and this package does not.
type Decision int

const (
	// Admitted means every check passed and the caller may write.
	Admitted Decision = iota
	// Invalid means the manifest is malformed or names something no install
	// can resolve. The caller must not write it.
	Invalid
	// PolicyBlocked means the manifest is well-formed but the allow-list or a
	// version check refused it.
	PolicyBlocked
)

func (d Decision) String() string {
	switch d {
	case Admitted:
		return "admitted"
	case Invalid:
		return "invalid"
	case PolicyBlocked:
		return "policy_blocked"
	default:
		return fmt.Sprintf("decision(%d)", int(d))
	}
}

// Result carries the verdict and everything a caller needs to report it.
// Warnings are non-fatal and are populated on an Admitted result too.
type Result struct {
	Decision Decision
	Reason   string
	Warnings []string
	// Admissions are the rows this decision wrote, one per version. Empty
	// when there was no audit database to write them to.
	Admissions []audit.Admission

	// The rest is set on PolicyBlocked only, for a caller that has to tell
	// the person refused which gate said no and how to find the row it wrote.
	// Check is "allow-list", "age" or "osv"; Version is the version refused;
	// Incident is the ID the refusal's audit row carries in its details;
	// Details is the refusing check's structured payload.
	Check    string
	Version  string
	Incident string
	Details  map[string]any
}

// OK reports whether the caller may proceed to write.
func (r Result) OK() bool { return r.Decision == Admitted }

// Who is the caller an admission row attributes its decision to: the OS user
// for the CLI, the identity binding a request resolved to for the API.
type Who struct {
	Actor    string
	Identity string
}

// Admit runs every check a manifest must pass before it is stored, in the
// order the cheapest and most specific failure comes first: structure, then
// the URL allow-list, then the per-version checks that reach the network.
//
// A nil checker or audit DB disables the checks that need them, which is what
// makes this callable from a CLI running against a bare manifest directory.
// actor names who is writing; the API leaves it empty because an HTTP caller
// is not the process owner.
func Admit(
	ctx context.Context,
	checker *policy.Checker,
	adb *audit.DB,
	cfg *config.Config,
	pm *manifest.PackageManifest,
	actor string,
) Result {
	return AdmitAs(ctx, checker, adb, cfg, pm, Who{Actor: actor})
}

// AdmitAs is Admit with the caller's identity as well as its actor, for the
// mutation API, whose caller is a host an identity binding named rather than
// the process owner.
//
// With an audit database it writes one admission row per version for every
// outcome, a clean pass included: a passed admission that leaves nothing
// behind is a version no attestation can cite.
func AdmitAs(
	ctx context.Context,
	checker *policy.Checker,
	adb *audit.DB,
	cfg *config.Config,
	pm *manifest.PackageManifest,
	who Who,
) Result {
	ev := newEvaluation(ctx, adb, pm, time.Now())
	checkers := VersionCheckers(cfg, adb)
	ev.include(ctx, pm, checkers)
	res := Result{Decision: Admitted}

	if err := validate(cfg, pm, &res); err != nil {
		ev.notRun("not run: the manifest is invalid: " + err.Error())
		res = Result{Decision: Invalid, Reason: err.Error(), Warnings: res.Warnings}
		return ev.record(ctx, adb, pm, res, who)
	}
	if blocked := checkAllowList(ctx, checker, adb, pm, who.Actor, ev); blocked != nil {
		blocked.Warnings = res.Warnings
		return ev.record(ctx, adb, pm, *blocked, who)
	}
	if blocked := checkVersions(ctx, adb, pm, who.Actor, audit.EventCreate, &res, checkers, ev); blocked != nil {
		blocked.Warnings = res.Warnings
		return ev.record(ctx, adb, pm, *blocked, who)
	}
	return ev.record(ctx, adb, pm, res, who)
}

// Verdict is what Evaluate concluded about one version.
type Verdict struct {
	Decision Decision
	Reason   string
	Checks   []audit.AdmissionCheck
}

// Evaluate decides on pm, which holds one version, the way Admit would and
// writes nothing: no admission row, no audit event, no provenance pin, since
// no checker's Commit runs, and no integration's last error. The order, every
// enabled integration under its action, the active overrides and the
// version's baseline mark all apply as they do in Admit, malware and invalid
// provenance included, so a preview that goes through here cannot disagree
// with the admission it previews. The mark it reads is the one pm carries,
// so a manifest built outside the store wants CarryBaseline first, as every
// write path does before Admit.
//
// store answers the policy reads, which is how a simulation evaluates a
// policy nobody has written; nil reads adb. adb supplies the overrides, and a
// nil adb runs structure and the allow-list alone, as Admit does.
func Evaluate(ctx context.Context, cfg *config.Config, checker *policy.Checker, adb *audit.DB, store PolicyStore,
	pm *manifest.PackageManifest, now time.Time) Verdict {
	var res Result
	if err := validate(cfg, pm, &res); err != nil {
		return Verdict{Decision: Invalid, Reason: err.Error()}
	}
	if len(pm.Versions) != 1 {
		return Verdict{Decision: Invalid, Reason: fmt.Sprintf("evaluate wants one version, got %d", len(pm.Versions))}
	}
	ev := newEvaluation(ctx, adb, pm, now)
	if adb == nil {
		store = nil
	} else if store == nil {
		store = adb
	}
	var checkers []policy.VersionChecker
	if store != nil {
		ev.readActions(ctx, store, pm.Type)
		checkers = VersionCheckersFrom(cfg, store, readOnlyIntegrations{adb})
		// Age is judged at now, so two evaluations given one now agree on
		// how old a version is.
		for _, c := range checkers {
			if age, ok := c.(*policy.AgeChecker); ok {
				age.Now = func() time.Time { return now }
			}
		}
		ev.include(ctx, pm, checkers)
	}
	// A nil database records nothing, which is what keeps the allow-list's
	// refusal event out of a read-only evaluation.
	if blocked := checkAllowList(ctx, checker, nil, pm, "", ev); blocked != nil {
		return Verdict{Decision: PolicyBlocked, Reason: blocked.Reason, Checks: ev.checks[0]}
	}
	if store == nil {
		return Verdict{Decision: Admitted, Checks: ev.checks[0]}
	}
	ve := &pm.Versions[0]
	combined := policy.Combine(ev.runVersion(ctx, pm, 0, checkers))
	if combined.Blocked() {
		return Verdict{Decision: PolicyBlocked, Checks: ev.checks[0],
			Reason: fmt.Sprintf("policy blocked %s@%s: %s", pm.Name, ve.Version, combined.Reasons())}
	}
	return Verdict{Decision: Admitted, Checks: ev.checks[0]}
}

// Create runs the policy checks `bodega pkg create` answers to: the
// allow-list and the per-version checks.
//
// The structural checks Admit starts with are left out. create assembles an
// entry from prompts and completes some of them after it is stored: an apt
// entry named by package resolves its concrete version afterwards, and
// validate refuses an apt entry with no version. What create shares with
// every other surface is the policy, so that is what runs here, overrides
// included.
func Create(
	ctx context.Context,
	checker *policy.Checker,
	adb *audit.DB,
	cfg *config.Config,
	pm *manifest.PackageManifest,
	who Who,
) Result {
	ev := newEvaluation(ctx, adb, pm, time.Now())
	checkers := VersionCheckers(cfg, adb)
	ev.include(ctx, pm, checkers)
	res := Result{Decision: Admitted}
	if blocked := checkAllowList(ctx, checker, adb, pm, who.Actor, ev); blocked != nil {
		return ev.record(ctx, adb, pm, *blocked, who)
	}
	if blocked := checkVersions(ctx, adb, pm, who.Actor, audit.EventCreate, &res, checkers, ev); blocked != nil {
		blocked.Warnings = res.Warnings
		res = *blocked
	}
	return ev.record(ctx, adb, pm, res, who)
}

// FetchResult is the verdict on one version a fetch is about to bring in.
type FetchResult struct {
	Admission audit.Admission
	// Block is the first per-version check that refused, nil when none did.
	Block *policy.Result
	// Warns are the warn-level results, for a caller that prints them.
	Warns []policy.Result
	// Incident is the ID a refusal hands the person refused, set with Block.
	// The caller writes it into the audit row its refusal records.
	Incident string
	// AuditDetails is the warn and block payload import writes to its
	// policy_warn and policy_violation event rows, incident included, for a
	// caller that writes the same row. Nil on a clean pass.
	AuditDetails map[string]any
}

// Fetch decides on one version a fetch is about to bring in, after the
// caller's own allow-list gate has let it through, and writes the row.
//
// The builder and the proxy each run the allow-list themselves, because each
// answers a refusal in its own way (a failed entry in a build summary, a 403
// with a discovery row) and has already spent the lookup by the time it gets
// here. allow is what that gate concluded, rendered by AllowListCheck, with
// the caller's override and baseline mark already applied: the caller reads
// each once, lets its gate admit past a refusal on that answer, and renders
// allow from the same answer (OverriddenCheck, BaselineCheck), so the row
// cannot record a refusal the gate let through. Fetch never turns allow
// itself. The per-version checks take overrides as every other admission does.
// An allow refused records age and OSV as not evaluated and the decision as
// policy_blocked, so a refusal leaves a row like a pass does. checkers nil
// records them as not evaluated with notRunDetail as the reason: the proxy
// passes nil for a type whose request names no version the checks could date.
func Fetch(
	ctx context.Context,
	adb *audit.DB,
	checkers []policy.VersionChecker,
	typ, name string,
	ve manifest.VersionEntry,
	allow audit.AdmissionCheck,
	who Who,
	notRunDetail string,
) FetchResult {
	if adb == nil {
		return FetchResult{}
	}
	pm := &manifest.PackageManifest{Type: typ, Name: name, Versions: []manifest.VersionEntry{ve}}
	ev := newEvaluation(ctx, adb, pm, time.Now())
	ev.include(ctx, pm, checkers)
	ev.set(0, allow)
	var out FetchResult
	decision := audit.AdmissionAdmitted
	switch {
	case allow.Status == audit.CheckBlock:
		decision = audit.AdmissionPolicyBlocked
		ev.notRunChecks(0, "not run: the allow-list refused this version", ev.versionChecks...)
	case checkers == nil:
		if notRunDetail == "" {
			notRunDetail = "not run"
		}
		ev.notRunChecks(0, notRunDetail, ev.versionChecks...)
	default:
		results := ev.runVersion(ctx, pm, 0, checkers)
		combined := policy.Combine(results)
		if !combined.Blocked() {
			if changed := ev.commit(ctx, pm, checkers); changed != nil {
				results = replaceResults(results, changed[0])
				combined = policy.Combine(results)
			}
		}
		out.Warns = combined.Warns
		out.AuditDetails = combined.AuditDetails()
		if combined.Blocked() {
			b := reportedBlock(combined.Blocks)
			out.Block = &b
			out.Incident = audit.NewIncidentID()
			out.AuditDetails["incident"] = out.Incident
			decision = audit.AdmissionPolicyBlocked
		}
	}
	out.Admission = ev.row(pm, 0, decision, who)
	_ = adb.RecordAdmission(ctx, out.Admission)
	return out
}

// replaceResults is results with each entry of changed in place of the one
// for the same check.
func replaceResults(results, changed []policy.Result) []policy.Result {
	out := append([]policy.Result(nil), results...)
	for _, c := range changed {
		for k := range out {
			if out[k].Check == c.Check {
				out[k] = c
			}
		}
	}
	return out
}

// AllowListCheck renders an allow-list verdict as an admission check.
// listed says whether the type is in listed mode, which is what decides
// between "block" and "none" as the action; candidate is what was checked,
// empty when the entry names nothing the allow-list can rule on; err is
// Check's answer.
func AllowListCheck(listed bool, candidate string, err error) audit.AdmissionCheck {
	c := audit.AdmissionCheck{Check: audit.CheckAllowList, Action: audit.ActionNone, Status: audit.CheckPass}
	if listed {
		c.Action = policy.ActionBlock
	}
	switch {
	case err != nil:
		c.Status = audit.CheckBlock
		c.Detail = err.Error()
	case candidate == "":
		c.Status = audit.CheckNotEvaluated
		c.Detail = "the entry names no upstream the allow-list can rule on"
	case listed:
		c.Detail = "matched: " + candidate
	default:
		c.Detail = "open admission mode, no allow-list rule required: " + candidate
	}
	return c
}

// validate rejects a manifest the rest of bodega cannot act on, and records a
// warning about one it can act on but will not honor.
//
// The split matters. A backend name nothing defines makes the artifact
// unreadable, so it fails. A storage_policy on a whole-directory type is inert
// rather than wrong, and manifests already in the field carry them; failing
// would make pkg edit and pkg import refuse a file that was legal when it was
// written.
func validate(cfg *config.Config, pm *manifest.PackageManifest, res *Result) error {
	if pm.Name == "" {
		return fmt.Errorf("name is required")
	}
	// "." and ".." are the two names SafeName leaves as path syntax; see
	// manifest.ValidatePackageName for what they collide with. Refused here so
	// a bulk import reports the entry as invalid alongside its siblings rather
	// than failing the request at the write.
	if err := manifest.ValidatePackageName(pm.Name); err != nil {
		return err
	}
	if pm.Type == "" {
		return fmt.Errorf("type is required")
	}
	if !manifest.IsKnownType(pm.Type) {
		return fmt.Errorf("unknown type %q — must be one of: %s", pm.Type, strings.Join(manifest.AllTypes, ", "))
	}
	if pm.Type == manifest.TypeGomod {
		if err := manifest.ValidateGomodName(pm.Name); err != nil {
			return err
		}
	}
	// The fetch and the route both read the repository layout off the name,
	// version and classifiers, so an entry no path can carry would be stored
	// and then never fetched or served.
	if pm.Type == manifest.TypeMaven {
		if err := manifest.ValidateMavenName(pm.Name); err != nil {
			return err
		}
		for _, ve := range pm.Versions {
			if err := manifest.ValidateMavenVersion(pm.Name, ve); err != nil {
				return err
			}
		}
	}
	if err := manifest.ValidateBinaryFilenames(pm); err != nil {
		return err
	}
	if err := manifest.ValidateDebGlobs(pm); err != nil {
		return err
	}
	// Only apt and git read dep_policy. Other types ignore it, so refusing a
	// stray value there would reject a manifest whose behavior it cannot change.
	if pm.Type == manifest.TypeApt || pm.Type == manifest.TypeGit {
		if err := manifest.ValidateDepPolicy(pm.Type, pm.Name, pm.DepPolicy); err != nil {
			return err
		}
	}
	// A storage_policy naming nothing fails at the next upload, long after the
	// edit that introduced it and with no obvious connection back to it.
	if err := CheckBackendName(cfg, pm.StoragePolicy); err != nil {
		return fmt.Errorf("storage_policy: %w", err)
	}
	if w := StoragePolicyWarning(pm.Type, pm.StoragePolicy); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	// A group naming nothing is refused on the same grounds as a backend
	// naming nothing: it changes no placement, so the package silently falls
	// through to its type rule and the operator finds out at an upload with no
	// obvious connection back to the edit that typed it.
	if err := CheckGroupNames(cfg, pm.StorageGroups); err != nil {
		return fmt.Errorf("storage_groups: %w", err)
	}
	if w := StorageGroupWarning(pm.Type, GroupRule(cfg, pm.StorageGroups)); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	// A hand-edited storage name that matches no configured backend makes the
	// artifact unreadable: resolution never falls back to another backend, so
	// the entry would 502 rather than serve from somewhere plausible.
	for _, ve := range pm.Versions {
		if err := CheckBackendName(cfg, ve.Storage); err != nil {
			return fmt.Errorf("version %s: %w", versionLabel(ve), err)
		}
		// The attestation endpoint answers an http(s) uri with a redirect
		// whose Location any caller reads, so a credential written into one
		// is published by the only thing the field exists for.
		if manifest.AttestationURIWithheld(ve.Metadata[manifest.MetaAttestationURI]) {
			return fmt.Errorf("version %s: metadata.%s carries userinfo, a query or a fragment, which its redirect would hand to every caller; host the envelope where a plain URL reaches it, or on s3:// where bodega reads it with its own credentials",
				versionLabel(ve), manifest.MetaAttestationURI)
		}
	}
	// An apt entry with no version reaches no index and no verb: the generator
	// refuses to publish it, and remove, delete, hide and freeze all address a
	// version by name. Persisting one leaves 'bodega repair' as its only exit.
	if pm.Type == manifest.TypeApt {
		for _, ve := range pm.Versions {
			if ve.Version == "" {
				return fmt.Errorf("apt/%s has a version entry with no version; give one, or \"*\" to resolve the current upstream", pm.Name)
			}
			// A suite name config.Load refuses can never be served by any
			// configuration, so the entry is unreachable however apt_suites
			// is edited later. An unserved-but-legal suite is not refused:
			// staging an entry before adding its suite is a normal order, and
			// GET /api/v1/status reports what that leaves waiting.
			for _, suite := range ve.Suites {
				if err := config.ValidateAptSuite(suite); err != nil {
					return fmt.Errorf("apt/%s version %s: %w", pm.Name, versionLabel(ve), err)
				}
			}
			if k := manifest.AptIdentityWithheld(ve.Metadata); k != "" {
				return fmt.Errorf("apt/%s version %s: metadata.%s is a URL carrying userinfo, a query or a fragment, and the apt index publishes it to every caller as written; record the architecture, pool path or digest itself",
					pm.Name, versionLabel(ve), k)
			}
		}
	}
	return nil
}

// checkAllowList runs the URL-level allow-list over every version. It is
// cheap and fails fast, so it runs before the checks that reach the network.
// It returns nil when every version passes. A version after the one refused
// is never reached, and its row says so. A refusal an active override names
// is recorded overridden, and one on a baseline version is recorded baseline;
// either way the version goes on to the version checks.
func checkAllowList(ctx context.Context, checker *policy.Checker, adb *audit.DB, pm *manifest.PackageManifest, actor string, ev *evaluation) *Result {
	if checker == nil {
		ev.notRunChecks(-1, "not run: no allow-list loaded", audit.CheckAllowList)
		return nil
	}
	listed, _ := checker.Listed(ctx, pm.Type)
	for i, ve := range pm.Versions {
		candidate := policy.CandidateFor(pm.Type, pm.Name, ve.URL)
		if candidate == "" {
			ev.set(i, AllowListCheck(listed, "", nil))
			continue
		}
		err := checker.Check(ctx, pm.Type, candidate)
		check := AllowListCheck(listed, candidate, err)
		if policy.IsViolation(err) {
			if c, ok := ev.admitPast(pm, i, check); ok {
				ev.set(i, c)
				continue
			}
		}
		ev.set(i, check)
		if err == nil {
			continue
		}
		incident := audit.NewIncidentID()
		if adb != nil {
			_ = adb.Record(ctx, audit.Event{
				EventType:  audit.EventCreate,
				PkgType:    pm.Type,
				PkgName:    pm.Name,
				PkgVersion: ve.Version,
				Actor:      actor,
				Status:     "policy_violation",
				Details:    fmt.Sprintf("candidate=%s incident=%s", candidate, incident),
			})
		}
		ev.notRunAfter(i, "not run: the allow-list refused "+admissionVersion(ve))
		return &Result{Decision: PolicyBlocked, Reason: err.Error(),
			Check: "allow-list", Version: ve.Version, Incident: incident}
	}
	return nil
}

// checkVersions runs the per-version checks (age, OSV, upstream provenance,
// name similarity). They live in the audit database, so with no database
// there is nothing to check against. Warn-level results do not block; they
// are recorded and reported on res, because a gate that answered "I could
// not tell" has to say so where the operator is looking. Recording alone
// leaves an OSV gate with no synced database printing a clean import and
// filing the warning somewhere nobody reads until after the package is in
// the store.
func checkVersions(ctx context.Context, adb *audit.DB, pm *manifest.PackageManifest, actor string, eventType audit.EventType, res *Result, checkers []policy.VersionChecker, ev *evaluation) *Result {
	if adb == nil {
		return nil
	}
	warns := &versionWarnings{}
	defer warns.flush(res)
	decide := func(i int, results []policy.Result) *Result {
		ve := &pm.Versions[i]
		combined := policy.Combine(results)
		warns.add(ve.Version, combined.Warns)
		var incident string
		if details := combined.AuditDetails(); details != nil {
			if combined.Blocked() {
				incident = audit.NewIncidentID()
				details["incident"] = incident
			}
			blob, _ := json.Marshal(details)
			status := "policy_warn"
			if combined.Blocked() {
				status = "policy_violation"
			}
			_ = adb.Record(ctx, audit.Event{
				EventType:  eventType,
				PkgType:    pm.Type,
				PkgName:    pm.Name,
				PkgVersion: ve.Version,
				Actor:      actor,
				Status:     status,
				Details:    string(blob),
			})
		}
		if combined.Blocked() {
			ev.notRunAfter(i, "not run: "+admissionVersion(*ve)+" was refused first")
			block := reportedBlock(combined.Blocks)
			return &Result{Decision: PolicyBlocked,
				Reason: fmt.Sprintf("policy blocked %s@%s: %s", pm.Name, ve.Version, combined.Reasons()),
				Check:  block.Check, Version: ve.Version, Incident: incident, Details: block.Details}
		}
		return nil
	}
	for _, c := range checkers {
		if p, ok := c.(prefetcher); ok {
			p.Prefetch(ctx, pm)
		}
	}
	for i := range pm.Versions {
		if blocked := decide(i, ev.runVersion(ctx, pm, i, checkers)); blocked != nil {
			return blocked
		}
	}
	// Only now is the manifest admitted, so only now may a check write what
	// an admission leaves behind. A verdict the write changes is decided like
	// any other: a pin another admission took first can still refuse this one.
	for i, changed := range ev.commit(ctx, pm, checkers) {
		if changed == nil {
			continue
		}
		if blocked := decide(i, changed); blocked != nil {
			return blocked
		}
	}
	return nil
}

// VersionCheckers are the per-version checks every admission runs: import,
// create, the builder's fetch and the proxy's fill. Each enabled integration
// instance follows the built-in checks, in instance name order.
func VersionCheckers(cfg *config.Config, adb *audit.DB) []policy.VersionChecker {
	// A nil *audit.DB inside the interface is not a nil interface.
	var similarity policy.SimilarityStore
	var store integration.Store
	if adb != nil {
		similarity = adb
		store = adb
	}
	out := []policy.VersionChecker{ageChecker(cfg, adb), OSVChecker(cfg, adb), ProvenanceChecker(cfg, adb),
		policy.NewNameSimilarityChecker(similarity)}
	return appendIntegrations(out, cfg, store)
}

func appendIntegrations(out []policy.VersionChecker, cfg *config.Config, store integration.Store) []policy.VersionChecker {
	if cfg != nil {
		for _, c := range integration.Checks(cfg.Integrations, cfg.LogDir, store) {
			out = append(out, c)
		}
	}
	return out
}

// PolicyStore is every read the per-version checks make of the policy tables.
// *audit.DB is one; `bodega policy simulate` supplies another that answers
// with a policy nobody has written.
type PolicyStore interface {
	policy.AgeStore
	policy.OSVStore
	policy.SimilarityStore
	provenance.Store
}

// VersionCheckersFrom is VersionCheckers reading policy from store and each
// integration's action from integrations, in the same order. A caller that
// must write nothing never calls Commit on the provenance checker it returns,
// and passes integrations through readOnlyIntegrations, since an integration
// records its lookup errors as it checks.
func VersionCheckersFrom(cfg *config.Config, store PolicyStore, integrations integration.Store) []policy.VersionChecker {
	out := []policy.VersionChecker{ageChecker(cfg, store), osvCheckerFrom(cfg, store),
		provenanceCheckerFrom(cfg, store), policy.NewNameSimilarityChecker(store)}
	return appendIntegrations(out, cfg, integrations)
}

// ageChecker is the age gate, dating gems against rubygems_upstream and Maven
// artifacts against maven_upstream. The other registries are dated at their
// public hosts whatever upstream serves them.
func ageChecker(cfg *config.Config, store policy.AgeStore) *policy.AgeChecker {
	c := policy.NewAgeChecker(store)
	if cfg != nil && cfg.RubygemsUpstream != "" {
		c.RubygemsBase = strings.TrimRight(cfg.RubygemsUpstream, "/")
	}
	if cfg != nil && cfg.MavenUpstream != "" {
		c.MavenBase = strings.TrimRight(cfg.MavenUpstream, "/")
	}
	return c
}

// readOnlyIntegrations reads integration policy from store and drops the
// lookup errors an integration check would otherwise record.
type readOnlyIntegrations struct{ integration.Store }

// RecordIntegrationError records nothing.
func (readOnlyIntegrations) RecordIntegrationError(context.Context, string, string) error { return nil }

// ProvenanceChecker builds the upstream provenance check: npm read from the
// configured npm upstream when an entry names no registry, and the Sigstore
// trusted root from sigstore_trusted_root, or TUF when that is unset.
func ProvenanceChecker(cfg *config.Config, adb *audit.DB) *provenance.Checker {
	// A nil *audit.DB inside the interface is not a nil interface.
	var store provenance.Store
	if adb != nil {
		store = adb
	}
	return provenanceCheckerFrom(cfg, store)
}

func provenanceCheckerFrom(cfg *config.Config, store provenance.Store) *provenance.Checker {
	v := NewProvenanceVerifier(cfg)
	if cfg != nil && cfg.NpmUpstream != "" {
		v.NpmRegistry = strings.TrimRight(cfg.NpmUpstream, "/")
	}
	return &provenance.Checker{Store: store, Verifier: v}
}

// NewProvenanceVerifier builds the verifier the provenance check fetches
// through. A test binary replaces it, so the suite never reads a public
// registry, GitHub or Sigstore's TUF repository.
var NewProvenanceVerifier = func(cfg *config.Config) *provenance.Verifier {
	path := ""
	if cfg != nil {
		path = cfg.SigstoreTrustedRoot
	}
	return provenance.NewVerifier(path)
}

// RecordPublished dates every version of pm that arrives without a
// published_at, reading the registry its url names: the read a fetch makes, so
// an imported version reaches the hosted indexes with a time a client's
// release-age cooldown can evaluate. It runs whatever the age policy says,
// because the indexes publish the time whether or not this server gates on it.
//
// It writes only what upstream answered. A version it cannot date stays
// undated and is named in res.Warnings, and the import goes ahead: the
// manifest is good either way. A published_at the caller supplied is kept, so
// an exported manifest imported elsewhere is not re-read, and a version
// existing already holds is skipped, because MergeVersions keeps that entry
// over the incoming one. existing may be nil.
//
// A registry that cannot be reached is tried once per manifest, so an offline
// import of a long version list costs one timeout rather than one per version.
func RecordPublished(ctx context.Context, pm, existing *manifest.PackageManifest, res *Result) {
	if !slices.Contains(policy.AgeEcosystems(), pm.Type) {
		return
	}
	recordPublished(ctx, NewPublishReader(), pm, existing, res)
}

// NewPublishReader builds the reader RecordPublished dates versions with. A
// test binary that imports manifests replaces it, so the suite reads a local
// stub rather than the public registries.
var NewPublishReader = func() *policy.AgeChecker { return policy.NewAgeChecker(nil) }

func recordPublished(ctx context.Context, ac *policy.AgeChecker, pm, existing *manifest.PackageManifest, res *Result) {
	warns := &versionWarnings{}
	defer warns.flush(res)
	unreachable := map[string]error{}
	for i := range pm.Versions {
		ve := &pm.Versions[i]
		if ve.PublishedAt != "" || policy.UndatableVersion(pm.Type, ve.Version) || holdsVersion(existing, ve.Version) {
			continue
		}
		upstream := strings.TrimRight(strings.TrimSpace(ve.URL), "/")
		err, skip := unreachable[upstream]
		if !skip {
			var t time.Time
			t, err = ac.AtUpstream(pm.Type, upstream).PublishedAt(ctx, pm.Type, pm.Name, strings.TrimSpace(ve.Version))
			if err == nil {
				ve.PublishedAt = t.UTC().Format(time.RFC3339)
				continue
			}
			var transport *url.Error
			if errors.As(err, &transport) {
				unreachable[upstream] = err
			}
		}
		warns.add(ve.Version, []policy.Result{{Check: "published_at",
			Reason: "no publish time recorded, so a client's release-age cooldown cannot evaluate this version: " + err.Error()}})
	}
}

func holdsVersion(pm *manifest.PackageManifest, version string) bool {
	if pm == nil {
		return false
	}
	for _, ve := range pm.Versions {
		if ve.Version == version {
			return true
		}
	}
	return false
}

// versionWarnings collects the per-version warns of one manifest into the
// lines a caller prints. A degraded gate gives every version of a package the
// same reason, so the versions are gathered under it: a 40-version import
// states the finding once instead of scrolling it past the operator 40 times.
type versionWarnings struct {
	order    []string
	versions map[string][]string
}

func (w *versionWarnings) add(version string, warns []policy.Result) {
	for _, r := range warns {
		line := r.Check + ": " + r.Reason
		if w.versions == nil {
			w.versions = map[string][]string{}
		}
		if _, seen := w.versions[line]; !seen {
			w.order = append(w.order, line)
		}
		w.versions[line] = append(w.versions[line], version)
	}
}

// flush renders each collected reason onto res. It runs even when a later
// version blocked, so the warning that explains why the gate was degraded is
// not lost behind the block that followed it.
func (w *versionWarnings) flush(res *Result) {
	if res == nil {
		return
	}
	for _, line := range w.order {
		res.Warnings = append(res.Warnings, describeVersions(w.versions[line])+": "+line)
	}
}

// describeVersions names the versions a warning covers, listing at most three
// so one line stays one line.
func describeVersions(versions []string) string {
	const shown = 3
	if len(versions) == 1 {
		return versions[0]
	}
	if len(versions) <= shown {
		return fmt.Sprintf("%d versions (%s)", len(versions), strings.Join(versions, ", "))
	}
	return fmt.Sprintf("%d versions (%s, ...)", len(versions), strings.Join(versions[:shown], ", "))
}

// OSVChecker points the OSV gate at the local database `bodega policy osv
// sync` wrote. The config keys are read here rather than in internal/policy so
// the gate stays usable from a test or a tool that holds no Config; a nil one
// leaves the checker with no database and no fallback, which warns rather than
// passing.
//
// Exported for `bodega policy osv rescan`, which has to answer from the same
// database and the same fallback rule admission answers from. A second copy of
// these four keys is how a rescan starts reporting on data admission never
// read.
func OSVChecker(cfg *config.Config, adb *audit.DB) *policy.OSVChecker {
	// A nil *audit.DB inside the interface is not a nil interface, and the
	// checker reads a nil store as "no rows", which is what a rescan with no
	// audit database has.
	var store policy.OSVStore
	if adb != nil {
		store = adb
	}
	return osvCheckerFrom(cfg, store)
}

func osvCheckerFrom(cfg *config.Config, store policy.OSVStore) *policy.OSVChecker {
	ck := policy.NewOSVChecker(store)
	if cfg == nil {
		return ck
	}
	ck.LocalDB = policy.SharedOSVDatabase(cfg.ResolveOSVDBDir())
	ck.AllowAPIFallback = cfg.OSVAPIFallback
	ck.MaxAge = cfg.ResolveOSVDBMaxAge()
	ck.DefaultAptSuite = cfg.AptCodename
	ck.ServedAptSuites = cfg.ServedAptSuites()
	return ck
}

// CheckBackendName rejects a name no configured backend answers to. The empty
// string and the reserved default always pass: an entry with no name recorded
// is on the default backend, which every install has.
func CheckBackendName(cfg *config.Config, name string) error {
	if name == "" || name == config.DefaultStorageName {
		return nil
	}
	if cfg == nil {
		return nil
	}
	if _, ok := cfg.StorageBackends[name]; !ok {
		return fmt.Errorf("unknown storage backend %q (defined: %s)", name, definedBackendNames(cfg))
	}
	return nil
}

// CheckGroupNames rejects a storage_groups list this install cannot act on: an
// empty entry, a group no storage_by_group key defines, or a membership whose
// groups resolve to two different backends.
//
// The last is the answer to "what does a package in two groups resolve to".
// GroupRule still answers deterministically — first group by name with a rule
// — so nothing downstream has to guess, but a write path answering one of two
// backends an operator meant differently is a coin toss they cannot read off
// the manifest. Refusing at the edit that creates the overlap is where they
// can still fix it, and the message names the winner so a config that already
// has one is describable rather than mysterious.
func CheckGroupNames(cfg *config.Config, groups []string) error {
	if len(groups) == 0 {
		return nil
	}
	for _, g := range groups {
		if strings.TrimSpace(g) == "" {
			return fmt.Errorf("empty group name")
		}
	}
	if cfg == nil {
		return nil
	}
	for _, g := range groups {
		if _, ok := cfg.StorageByGroup[g]; !ok {
			return fmt.Errorf("unknown storage group %q (defined in storage_by_group: %s)", g, definedGroupNames(cfg))
		}
	}

	backends := map[string][]string{}
	for _, g := range groups {
		name := cfg.StorageByGroup[g]
		backends[name] = append(backends[name], g)
	}
	if len(backends) < 2 {
		return nil
	}
	names := make([]string, 0, len(backends))
	for name := range backends {
		names = append(names, name)
	}
	sort.Strings(names)
	var parts []string
	for _, name := range names {
		gs := backends[name]
		sort.Strings(gs)
		parts = append(parts, fmt.Sprintf("%s -> %q", strings.Join(gs, ", "), name))
	}
	return fmt.Errorf("groups resolve to more than one backend (%s); a package is written to one backend, and %q would win by group name — "+
		"drop a group, or point them at the same backend in storage_by_group",
		strings.Join(parts, "; "), GroupRule(cfg, groups))
}

// GroupRule returns the group that decides placement for this membership: the
// first by name that storage_by_group defines. Empty when none does.
//
// It answers with the group rather than the backend because every caller here
// reports to an operator, whose edit is to storage_by_group or to
// storage_groups. It mirrors the resolver's rule deliberately; the resolver
// cannot be called instead, since it takes a built storage connection and
// these checks run before one exists.
func GroupRule(cfg *config.Config, groups []string) string {
	if cfg == nil || len(groups) == 0 || len(cfg.StorageByGroup) == 0 {
		return ""
	}
	sorted := append([]string(nil), groups...)
	sort.Strings(sorted)
	for _, g := range sorted {
		if cfg.StorageByGroup[g] != "" {
			return g
		}
	}
	return ""
}

// definedGroupNames lists the group names an operator may use, sorted.
func definedGroupNames(cfg *config.Config) string {
	if len(cfg.StorageByGroup) == 0 {
		return "none"
	}
	names := make([]string, 0, len(cfg.StorageByGroup))
	for name := range cfg.StorageByGroup {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func versionLabel(ve manifest.VersionEntry) string {
	switch {
	case ve.Version != "":
		return ve.Version
	case ve.Ref != "":
		return ve.Ref
	default:
		return "(unnamed)"
	}
}

// DirectoryPlaced reports whether a type uploads as a whole directory, which
// is what makes a per-package storage policy inert for it.
//
// pypi is the only one. apt and git were here until their uploaders learned to
// walk manifest entries — a .deb has a per-version key through its pool path
// and a bundle through its ref — and both are placed and moved per package
// now. A pypi version has no object key at all: wheels land under one prefix
// and the PEP 503 index is a listing over the whole tree, so a package placed
// on another backend would drop out of the index that finds it.
func DirectoryPlaced(typ string) bool {
	return typ == manifest.TypePypi
}

// NoPerPackagePlacement says why one type cannot carry a per-package
// placement, in whichever terms that type's operator will recognize.
func NoPerPackagePlacement(typ string) string {
	return typ + " wheels upload as a directory with no per-version object key, so one package cannot be placed apart from the rest of its type"
}

// StoragePolicyWarning describes a storage_policy the write path will ignore.
// It is a warning rather than an error because such a manifest is inert, not
// wrong, and refusing one would reject files that were legal when written.
func StoragePolicyWarning(typ, policy string) string {
	if policy == "" || !DirectoryPlaced(typ) {
		return ""
	}
	return fmt.Sprintf("warning: storage_policy %q has no effect for %s: %s. "+
		"Set storage_by_type.%s to place the whole type; 'bodega pkg move' refuses %s for the same reason.",
		policy, typ, NoPerPackagePlacement(typ), typ, typ)
}

// StorageGroupWarning describes a group rule the write path will ignore, on
// the same terms and for the same reason as StoragePolicyWarning. group is the
// group that would have decided; empty means none would, so there is nothing
// to warn about.
func StorageGroupWarning(typ, group string) string {
	if group == "" || !DirectoryPlaced(typ) {
		return ""
	}
	return fmt.Sprintf("warning: storage group %q has no effect for %s: %s. "+
		"Set storage_by_type.%s to place the whole type; 'bodega pkg move' refuses %s for the same reason.",
		group, typ, NoPerPackagePlacement(typ), typ, typ)
}

// definedBackendNames lists the usable backend names for an error message,
// reserved default first.
func definedBackendNames(cfg *config.Config) string {
	names := make([]string, 0, len(cfg.StorageBackends)+1)
	for name := range cfg.StorageBackends {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(append([]string{config.DefaultStorageName}, names...), ", ")
}
