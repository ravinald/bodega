package builder

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// PyVersion is a PEP 440 version: the scheme PyPI actually publishes, which
// semver cannot read. `1.16.0.post1`, `2.0.0rc1`, `1!2.0` and `0.6.dev1` are
// ordinary releases on an index and every one of them is rejected by
// ParseSemVer, so a semver filter silently drops them from the candidate list
// and resolves a pin to an older neighbor with no error.
//
// https://packaging.python.org/en/latest/specifications/version-specifiers/
type PyVersion struct {
	Epoch   int
	Release []int
	PreKind string // "", "a", "b", "rc"
	PreNum  int
	Post    bool
	PostNum int
	Dev     bool
	DevNum  int
	Local   string
	Raw     string
}

// pep440Re is the PEP 440 appendix regex, anchored and with the separator and
// spelling alternatives the spec requires a parser to accept.
var pep440Re = regexp.MustCompile(`^[vV]?(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?` +
	`(?P<dev>[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-zA-Z0-9]+(?:[-_.][a-zA-Z0-9]+)*))?$`)

// preKinds normalizes the spellings PEP 440 treats as the same pre-release
// marker. "c" and "pre" and "preview" are all "rc".
var preKinds = map[string]string{
	"alpha": "a", "a": "a",
	"beta": "b", "b": "b",
	"c": "rc", "pre": "rc", "preview": "rc", "rc": "rc",
}

// ParsePyVersion parses a PEP 440 version string. Returns false for anything
// outside the scheme, which on a real index means a legacy version such as
// pytz's "2011k" — those still resolve, by literal match rather than ordering.
func ParsePyVersion(s string) (PyVersion, bool) {
	m := pep440Re.FindStringSubmatch(strings.TrimSpace(strings.ToLower(s)))
	if m == nil {
		return PyVersion{}, false
	}
	group := func(name string) string { return m[pep440Re.SubexpIndex(name)] }
	atoi := func(v string) int {
		n, _ := strconv.Atoi(v)
		return n
	}

	v := PyVersion{Raw: s, Epoch: atoi(group("epoch")), Local: group("local")}
	for _, part := range strings.Split(group("release"), ".") {
		v.Release = append(v.Release, atoi(part))
	}
	if l := group("pre_l"); l != "" {
		v.PreKind = preKinds[l]
		v.PreNum = atoi(group("pre_n"))
	}
	// An implicit post release: "1.0-1" means "1.0.post1".
	if n := group("post_n1"); n != "" {
		v.Post, v.PostNum = true, atoi(n)
	} else if group("post_l") != "" {
		v.Post, v.PostNum = true, atoi(group("post_n2"))
	}
	if group("dev") != "" {
		v.Dev, v.DevNum = true, atoi(group("dev_n"))
	}
	return v, true
}

// IsPreRelease reports whether a version is a pre-release or a development
// release. A post release is neither: 1.16.0.post1 ships after 1.16.0.
func (v PyVersion) IsPreRelease() bool { return v.PreKind != "" || v.Dev }

// releaseAt returns the nth release segment, zero-padded. PEP 440 compares
// 1.16 and 1.16.0 as the same release.
func (v PyVersion) releaseAt(i int) int {
	if i < len(v.Release) {
		return v.Release[i]
	}
	return 0
}

// Less orders by the PEP 440 comparison key: epoch, then the zero-padded
// release segments, then dev < pre < release < post.
func (v PyVersion) Less(o PyVersion) bool { return v.compare(o) < 0 }

// Equal reports PEP 440 equality, so 1.16 equals 1.16.0 and 1.0RC1 equals
// 1.0.rc1. Local labels are part of the identity.
func (v PyVersion) Equal(o PyVersion) bool { return v.compare(o) == 0 }

func (v PyVersion) compare(o PyVersion) int {
	if c := cmpInt(v.Epoch, o.Epoch); c != 0 {
		return c
	}
	n := max(len(v.Release), len(o.Release))
	for i := 0; i < n; i++ {
		if c := cmpInt(v.releaseAt(i), o.releaseAt(i)); c != 0 {
			return c
		}
	}
	for _, c := range []int{
		cmpInt(v.preRank(), o.preRank()),
		cmpInt(v.PreNum, o.PreNum),
		cmpInt(boolRank(v.Post), boolRank(o.Post)),
		cmpInt(v.PostNum, o.PostNum),
		// An absent dev segment sorts after a present one, so 1.0 beats 1.0.dev9.
		cmpInt(boolRank(!v.Dev), boolRank(!o.Dev)),
		cmpInt(v.DevNum, o.DevNum),
		strings.Compare(v.Local, o.Local),
	} {
		if c != 0 {
			return c
		}
	}
	return 0
}

// preRank orders the pre-release markers, with two sentinels PEP 440 requires:
// a bare dev release sorts before every pre-release of the same release, and a
// version with no pre-release segment sorts after all of them.
func (v PyVersion) preRank() int {
	switch {
	case v.PreKind == "" && !v.Post && v.Dev:
		return -1
	case v.PreKind == "":
		return 4
	case v.PreKind == "a":
		return 1
	case v.PreKind == "b":
		return 2
	default:
		return 3
	}
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

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
			if baseOK && sv.Epoch == base.Epoch && sv.releaseAt(0) == base.releaseAt(0) && !sv.Less(base) {
				matched = append(matched, sv)
			}
		case manifest.ConstraintPatch:
			if baseOK && sv.Epoch == base.Epoch && sv.releaseAt(0) == base.releaseAt(0) &&
				sv.releaseAt(1) == base.releaseAt(1) && !sv.Less(base) {
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
