package builder

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// SemVer represents a parsed semantic version.
type SemVer struct {
	Major int
	Minor int
	Patch int
	Pre   string // pre-release suffix (e.g. "rc1", "beta.2")
	Raw   string // original string
}

// ParseSemVer parses a version string like "5.2.12", "v1.30.0", "1.0.0-rc1".
// Returns the parsed version and true, or zero value and false if unparseable.
func ParseSemVer(s string) (SemVer, bool) {
	raw := s
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")

	// Split off pre-release suffix.
	pre := ""
	if idx := strings.IndexAny(s, "-+"); idx >= 0 {
		pre = s[idx+1:]
		s = s[:idx]
	}

	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return SemVer{}, false
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return SemVer{}, false
	}

	minor := 0
	if len(parts) >= 2 {
		minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return SemVer{}, false
		}
	}

	patch := 0
	if len(parts) >= 3 {
		patch, err = strconv.Atoi(parts[2])
		if err != nil {
			return SemVer{}, false
		}
	}

	return SemVer{Major: major, Minor: minor, Patch: patch, Pre: pre, Raw: raw}, true
}

// Less returns true if a < b in semver ordering.
func (a SemVer) Less(b SemVer) bool {
	if a.Major != b.Major {
		return a.Major < b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor < b.Minor
	}
	if a.Patch != b.Patch {
		return a.Patch < b.Patch
	}
	// Pre-release versions sort before release (1.0.0-rc1 < 1.0.0).
	if a.Pre != "" && b.Pre == "" {
		return true
	}
	if a.Pre == "" && b.Pre != "" {
		return false
	}
	return a.Pre < b.Pre
}

// Equal returns true if a and b are the same version.
func (a SemVer) Equal(b SemVer) bool {
	return a.Major == b.Major && a.Minor == b.Minor && a.Patch == b.Patch && a.Pre == b.Pre
}

// GTE returns true if a >= b.
func (a SemVer) GTE(b SemVer) bool {
	return a.Equal(b) || !a.Less(b)
}

// FilterVersions applies a version constraint to a list of available versions.
// Returns the filtered list sorted by semver ascending.
func FilterVersions(available []string, constraint, baseVersion string) []string {
	base, baseOK := ParseSemVer(baseVersion)

	var result []SemVer
	for _, v := range available {
		sv, ok := ParseSemVer(v)
		if !ok {
			continue
		}

		switch constraint {
		case manifest.ConstraintExact, "":
			if baseOK && sv.Equal(base) {
				result = append(result, sv)
			}
		case manifest.ConstraintAny:
			result = append(result, sv)
		case manifest.ConstraintCompatible:
			// Same major, >= base version.
			if baseOK && sv.Major == base.Major && sv.GTE(base) {
				result = append(result, sv)
			}
		case manifest.ConstraintPatch:
			// Same major.minor, >= base version.
			if baseOK && sv.Major == base.Major && sv.Minor == base.Minor && sv.GTE(base) {
				result = append(result, sv)
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Less(result[j])
	})

	out := make([]string, len(result))
	for i, sv := range result {
		out[i] = sv.Raw
	}
	return out
}
