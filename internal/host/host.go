// Package host implements read-only inspections of the local machine for
// configurations that would silently bypass bodega's supply-chain controls.
//
// Each check returns a Finding. Checks are organised one per file so adding a
// new format (e.g. a future container-runtime check) is an isolated change.
// All checks are read-only and must not modify the host.
package host

import "os"

// exists reports whether path resolves to anything (file, directory, or
// symlink target). Shared by per-format checks across all platforms.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Status is the outcome of a single Check.
type Status string

const (
	StatusOK   Status = "OK"   // Nothing found that undermines bodega's guarantees.
	StatusWarn Status = "WARN" // Configuration detected; operator should review.
	StatusFail Status = "FAIL" // Configuration definitively bypasses bodega controls.
	StatusNA   Status = "N/A"  // Check is not applicable on this platform.
)

// Finding is the result of a single host inspection.
type Finding struct {
	// Check is a short stable identifier (e.g. "snapd", "flatpak", "apt-sources").
	Check string

	// Status is the outcome.
	Status Status

	// Detail is a one-line human-readable description of what was observed.
	Detail string

	// Remediation is an optional one-line hint for how to bring the host into
	// alignment with bodega's threat model.
	Remediation string
}

// IsFinding reports whether the status counts as something the operator
// should act on. Both Warn and Fail count; OK and NA do not.
func (f Finding) IsFinding() bool {
	return f.Status == StatusWarn || f.Status == StatusFail
}

// CheckFunc is the contract every per-format check implements.
type CheckFunc func() Finding

// AllChecks returns the registered checks in the order they should be run.
// Order matters only for output stability — checks are independent.
func AllChecks() []CheckFunc {
	return []CheckFunc{
		CheckSnapd,
		CheckFlatpak,
		CheckHomebrew,
		CheckAptSources,
		CheckPipConfig,
		CheckCargoConfig,
		CheckNpmConfig,
		CheckGoproxyEnv,
	}
}
