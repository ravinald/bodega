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
	"fmt"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
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
}

// OK reports whether the caller may proceed to write.
func (r Result) OK() bool { return r.Decision == Admitted }

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
	res := Result{Decision: Admitted}

	if err := validate(cfg, pm, &res); err != nil {
		return Result{Decision: Invalid, Reason: err.Error(), Warnings: res.Warnings}
	}
	if err := checkAllowList(ctx, checker, adb, pm, actor); err != nil {
		return Result{Decision: PolicyBlocked, Reason: err.Error(), Warnings: res.Warnings}
	}
	if err := checkVersions(ctx, adb, pm, actor); err != nil {
		return Result{Decision: PolicyBlocked, Reason: err.Error(), Warnings: res.Warnings}
	}
	return res
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
	if pm.Type == "" {
		return fmt.Errorf("type is required")
	}
	if !manifest.IsKnownType(pm.Type) {
		return fmt.Errorf("unknown type %q — must be one of: %s", pm.Type, strings.Join(manifest.AllTypes, ", "))
	}
	// A storage_policy naming nothing fails at the next upload, long after the
	// edit that introduced it and with no obvious connection back to it.
	if err := CheckBackendName(cfg, pm.StoragePolicy); err != nil {
		return fmt.Errorf("storage_policy: %w", err)
	}
	if w := StoragePolicyWarning(pm.Type, pm.StoragePolicy); w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	// A hand-edited storage name that matches no configured backend makes the
	// artifact unreadable: resolution never falls back to another backend, so
	// the entry would 502 rather than serve from somewhere plausible.
	for _, ve := range pm.Versions {
		if err := CheckBackendName(cfg, ve.Storage); err != nil {
			return fmt.Errorf("version %s: %w", versionLabel(ve), err)
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
		}
	}
	return nil
}

// checkAllowList runs the URL-level allow-list over every version. It is
// cheap and fails fast, so it runs before the checks that reach the network.
func checkAllowList(ctx context.Context, checker *policy.Checker, adb *audit.DB, pm *manifest.PackageManifest, actor string) error {
	if checker == nil {
		return nil
	}
	for _, ve := range pm.Versions {
		candidate := policy.CandidateFor(pm.Type, pm.Name, ve.URL)
		if candidate == "" {
			continue
		}
		if err := checker.Check(ctx, pm.Type, candidate); err != nil {
			if adb != nil {
				_ = adb.Record(ctx, audit.Event{
					EventType:  audit.EventCreate,
					PkgType:    pm.Type,
					PkgName:    pm.Name,
					PkgVersion: ve.Version,
					Actor:      actor,
					Status:     "policy_violation",
					Details:    fmt.Sprintf("candidate=%s", candidate),
				})
			}
			return err
		}
	}
	return nil
}

// checkVersions runs the per-version checks (age, OSV). They live in the audit
// database, so with no database there is nothing to check against. Warn-level
// results are recorded and do not block.
func checkVersions(ctx context.Context, adb *audit.DB, pm *manifest.PackageManifest, actor string) error {
	if adb == nil {
		return nil
	}
	checkers := []policy.VersionChecker{
		policy.NewAgeChecker(adb),
		policy.NewOSVChecker(adb),
	}
	for i := range pm.Versions {
		ve := &pm.Versions[i]
		combined := policy.RunChecks(ctx, pm, ve, checkers...)
		if details := combined.AuditDetails(); details != nil {
			blob, _ := json.Marshal(details)
			status := "policy_warn"
			if combined.Blocked() {
				status = "policy_violation"
			}
			_ = adb.Record(ctx, audit.Event{
				EventType:  audit.EventCreate,
				PkgType:    pm.Type,
				PkgName:    pm.Name,
				PkgVersion: ve.Version,
				Actor:      actor,
				Status:     status,
				Details:    string(blob),
			})
		}
		if combined.Blocked() {
			return fmt.Errorf("policy blocked %s@%s: %s", pm.Name, ve.Version, combined.Reasons())
		}
	}
	return nil
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
func DirectoryPlaced(typ string) bool {
	switch typ {
	case manifest.TypeApt, manifest.TypeGit, manifest.TypePypi:
		return true
	}
	return false
}

// NoPerPackagePlacement says why one type cannot carry a per-package
// placement, in whichever terms that type's operator will recognize.
func NoPerPackagePlacement(typ string) string {
	if typ == manifest.TypePypi {
		return "pypi wheels upload as a directory with no per-version object key"
	}
	return typ + " uploads whole directories with SyncDir, so one package cannot be placed apart from the rest of its type"
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
