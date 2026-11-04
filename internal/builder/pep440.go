package builder

import (
	"sort"

	"github.com/ravinald/bodega/internal/manifest"
)

// PyVersion is a PEP 440 version; see manifest.PyVersion.
type PyVersion = manifest.PyVersion

// ParsePyVersion parses a PEP 440 version string; see manifest.ParsePyVersion.
func ParsePyVersion(s string) (PyVersion, bool) { return manifest.ParsePyVersion(s) }

// SortPyVersions sorts version strings by PEP 440 ordering, ascending.
// Unparseable versions keep lexicographic order and sort first, so the newest
// entry is always the last one.
func SortPyVersions(versions []string) {
	sort.SliceStable(versions, func(i, j int) bool {
		a, aOK := ParsePyVersion(versions[i])
		b, bOK := ParsePyVersion(versions[j])
		switch {
		case aOK && bOK:
			return a.Less(b)
		case aOK != bOK:
			return bOK
		default:
			return versions[i] < versions[j]
		}
	})
}

// FilterPypiVersions applies a manifest version_constraint to an index's
// version list under PEP 440 ordering, newest last.
//
// Pre-release policy: the floating constraints (patch, compatible, any) take a
// pre-release or dev release only when the version the entry names is itself
// one. Otherwise a project publishing 2.0.0rc1 would move every "any" entry
// onto a release candidate nobody approved. exact takes whatever it names,
// pre-release or not, because naming it is the approval.
func FilterPypiVersions(available []string, constraint, baseVersion string) []string {
	base, baseOK := ParsePyVersion(baseVersion)
	allowPre := baseOK && base.IsPreRelease()

	var matched []PyVersion
	for _, v := range available {
		sv, ok := ParsePyVersion(v)
		if !ok {
			continue
		}
		if constraint != manifest.ConstraintExact && constraint != "" && sv.IsPreRelease() && !allowPre {
			continue
		}
		switch constraint {
		case manifest.ConstraintExact, "":
			if baseOK && sv.Equal(base) {
				matched = append(matched, sv)
			}
		case manifest.ConstraintAny:
			matched = append(matched, sv)
		case manifest.ConstraintCompatible:
			if baseOK && sv.Epoch == base.Epoch && sv.ReleaseAt(0) == base.ReleaseAt(0) && !sv.Less(base) {
				matched = append(matched, sv)
			}
		case manifest.ConstraintPatch:
			if baseOK && sv.Epoch == base.Epoch && sv.ReleaseAt(0) == base.ReleaseAt(0) &&
				sv.ReleaseAt(1) == base.ReleaseAt(1) && !sv.Less(base) {
				matched = append(matched, sv)
			}
		}
	}

	sort.SliceStable(matched, func(i, j int) bool { return matched[i].Less(matched[j]) })
	out := make([]string, len(matched))
	for i, sv := range matched {
		out[i] = sv.Raw
	}
	return out
}
