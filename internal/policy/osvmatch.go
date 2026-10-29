package policy

import (
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// Version orderings an OSV range is evaluated under. OSV declares a range as
// SEMVER or ECOSYSTEM; ECOSYSTEM means "whatever this ecosystem orders by", so
// the ordering is chosen from the ecosystem when the range does not pin it.
const (
	orderSemver   = "semver"
	orderPEP440   = "pep440"
	orderDebian   = "debian"
	orderRubyGems = "rubygems"
	orderMaven    = "maven"
	orderRpm      = "rpm"
)

// osvAffected is the subset of an OSV record's `affected` entry the matcher
// reads. GIT ranges are dropped at sync: they carry commit hashes, which no
// version string an import supplies can be compared against.
type osvAffected struct {
	Versions osvVersions `json:"versions,omitempty"`
	Ranges   []osvRange  `json:"ranges,omitempty"`
}

// osvAffectedList is a record's `affected` entries, shared across the records
// that carry an equal payload. One advisory names every binary package its
// source builds and the archive stores it once per name, so a release arrives
// as many copies of one payload: measured on the 2026-09 export,
// Ubuntu:22.04:LTS is 772,549 record entries over 3,434 distinct payloads,
// 610,349 of them the single payload of an advisory nothing has fixed. npm
// fans its records out barely at all and still takes 228,869 entries over
// 8,316 payloads.
//
// The table is keyed on the raw bytes and compares them in full, which a Go
// map does on every key it returns. A key that compared a hash alone would
// hand one advisory's ranges to another package on a collision, and the gate
// would then answer clean for a version that is affected with no error
// anywhere. See osvSharedAffected for why this runs inside the decode.
type osvAffectedList []osvAffected

func (l *osvAffectedList) UnmarshalJSON(b []byte) error {
	if shared, ok := osvSharedAffected[string(b)]; ok {
		*l = shared
		return nil
	}
	var raw []osvAffected
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*l = raw
	if osvSharedAffected != nil {
		// b is the decoder's buffer, so the key is a copy by construction.
		osvSharedAffected[string(b)] = *l
	}
	return nil
}

// osvVersions is an enumerated version list, canonicalized as it decodes. See
// internOSV for why the decode is where this has to happen.
type osvVersions []string

func (v *osvVersions) UnmarshalJSON(b []byte) error {
	var raw []string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for i, s := range raw {
		raw[i] = internOSV(s)
	}
	*v = raw
	return nil
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

func (r *osvRange) UnmarshalJSON(b []byte) error {
	type raw osvRange
	var v raw
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	v.Type = internOSV(v.Type)
	*r = osvRange(v)
	return nil
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

func (e *osvEvent) UnmarshalJSON(b []byte) error {
	type raw osvEvent
	var v raw
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	v.Introduced, v.Fixed, v.LastAffected = internOSV(v.Introduced), internOSV(v.Fixed), internOSV(v.LastAffected)
	*e = osvEvent(v)
	return nil
}

// osvVersionOrder returns the ordering an ECOSYSTEM range uses for an OSV
// ecosystem. PyPI orders by PEP 440, RubyGems by Gem::Version, Maven by
// Maven's ComparableVersion, Ubuntu and Debian by dpkg's ordering, the
// Enterprise Linux vendors by rpm's, and the rest of what bodega maps order by
// semver, so an unknown ecosystem gets semver rather than an error.
func osvVersionOrder(ecosystem string) string {
	switch {
	case ecosystem == "PyPI":
		return orderPEP440
	case ecosystem == "RubyGems":
		return orderRubyGems
	case ecosystem == "Maven":
		return orderMaven
	case isDistroEcosystem(ecosystem):
		return orderDebian
	case isRpmEcosystem(ecosystem):
		return orderRpm
	}
	return orderSemver
}

// isRpmEcosystem reports whether an OSV ecosystem is an Enterprise Linux
// vendor's, release suffix or not ("Rocky Linux:9",
// "Red Hat:enterprise_linux:9::appstream"), whose versions are
// epoch:version-release.
func isRpmEcosystem(ecosystem string) bool {
	base, _, _ := strings.Cut(ecosystem, ":")
	return slices.Contains(manifest.RpmOSVEcosystems, base)
}

// rpmReleaseEcosystem is the ecosystem an rpm package is looked up under: its
// vendor and the Enterprise Linux major release it was served for, "Rocky
// Linux:9" for a releasever of 9 and of 9.4 alike. "" when either is missing.
//
// A vendor files every release in one export, and a fixed build for 10 says
// nothing about 9: el9's openssl and el10's are different source packages
// with different fixed versions, and a range from one refuses or admits the
// other wrongly.
func rpmReleaseEcosystem(vendor, releasever string) string {
	major, _, _ := strings.Cut(releasever, ".")
	if vendor == "" || major == "" || strings.Trim(major, "0123456789") != "" {
		return ""
	}
	return vendor + ":" + major
}

// rpmRecordedRelease is the release ecosystem an `affected` entry answers for,
// in rpmReleaseEcosystem's form, or "" for one no stock host installs from.
//
// Rocky Linux and AlmaLinux file a release as "Rocky Linux:9". Red Hat files
// the stock release as "Red Hat:enterprise_linux:9::appstream", and its EUS,
// AUS, E4S and layered-product streams under other product names; those carry
// release strings a stock host never installed, so they answer nothing here,
// the same way Ubuntu's FIPS and Realtime streams do not; see
// ubuntuProEcosystem.
func rpmRecordedRelease(recorded string) string {
	parts := strings.Split(recorded, ":")
	if len(parts) < 2 || !slices.Contains(manifest.RpmOSVEcosystems, parts[0]) {
		return ""
	}
	release := parts[1]
	if parts[0] == "Red Hat" {
		if parts[1] != "enterprise_linux" || len(parts) < 3 {
			return ""
		}
		release = parts[2]
	}
	return rpmReleaseEcosystem(parts[0], release)
}

// osvIndexFor names the index a lookup ecosystem is answered from and the key
// a package is filed under there, and reports whether that index must be
// keyed by release.
//
// An rpm release shares its vendor's index, keyed "<major>/<name>", because a
// sync is per vendor: which releases clients will ask /rpm/ for is decided by
// the client's $releasever, not by anything a sync can read.
func osvIndexFor(ecosystem, name string) (index, key string, byRelease bool) {
	if isRpmEcosystem(ecosystem) {
		vendor, major, _ := strings.Cut(ecosystem, ":")
		return vendor, rpmIndexKey(major, name), true
	}
	return ecosystem, osvPackageKey(ecosystem, name), false
}

func rpmIndexKey(major, name string) string {
	return major + "/" + strings.ToLower(name)
}

// rpmAffectsRelease reports whether an API answer's record affects name at
// version in the release ecosystem asked about, judged by the record's own
// entries for that package in that release. api.osv.dev is queried under the
// vendor and matches any release's ranges, and one record can name several
// packages, so its hit alone is not an answer for this one. An entry counts
// only when it is filed under the same index key a local lookup reads, so the
// fallback and the synced database agree on which entries are this package's.
// A range the rpm ordering cannot walk keeps the record: the API placed it,
// and nothing here can say it was wrong.
func rpmAffectsRelease(ecosystem, name, version string, affected []osvRecordedAffected) bool {
	_, want, _ := osvIndexFor(ecosystem, name)
	for _, aff := range affected {
		release := rpmRecordedRelease(aff.Package.Ecosystem)
		if release != ecosystem {
			continue
		}
		if _, key, _ := osvIndexFor(release, aff.Package.Name); key != want {
			continue
		}
		matched, bad := osvAffected{Versions: aff.Versions, Ranges: aff.Ranges}.affects(orderRpm, version)
		if matched || bad != "" {
			return true
		}
	}
	return false
}

// osvRecordedAffected is one `affected` entry as OSV publishes it, with the
// ecosystem string the release is read from.
type osvRecordedAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Versions []string   `json:"versions"`
	Ranges   []osvRange `json:"ranges"`
}

// isDistroEcosystem reports whether an OSV ecosystem is one of the per-release
// Ubuntu or Debian exports ("Ubuntu:22.04:LTS", "Debian:12"), whose versions
// are full distro version strings rather than upstream releases.
func isDistroEcosystem(ecosystem string) bool {
	base, _, _ := strings.Cut(ecosystem, ":")
	return base == "Ubuntu" || base == "Debian"
}

// affects reports whether version falls inside an `affected` entry, by the
// same rule api.osv.dev applies: an enumerated version list is an exact match,
// and a range is walked event by event in version order.
//
// unorderable names a version string that stopped a range from being walked at
// all. It is not a match and it is not a clean answer, so the caller reports it
// instead of counting it either way.
func (a osvAffected) affects(order, version string) (matched bool, unorderable string) {
	for _, v := range a.Versions {
		if v == version {
			return true, ""
		}
		if c, ok := compareVersions(order, v, version); ok && c == 0 {
			return true, ""
		}
	}
	for _, r := range a.Ranges {
		hit, bad := r.affects(order, version)
		if hit {
			return true, ""
		}
		if bad != "" && unorderable == "" {
			unorderable = bad
		}
	}
	return false, unorderable
}

// trimCovered drops the enumerated versions an entry's own ranges already
// place. A distro advisory lists every published revision it covers and then
// bounds the same span with a range, so one Ubuntu release arrives as millions
// of short strings the decoder allocates one at a time; the strings the ranges
// cover carry nothing the ranges do not.
//
// Only the ranges order itself decides are allowed to drop a string.
// osvRange.affects overrides the ecosystem ordering with semver for a SEMVER
// range, so an entry can carry a range that places a string under one ordering
// while the query that reaches it is placed under another: PEP 440 reads
// "1.0.0-1" as post-release 1 and calls it equal to "1.0.0.post1", semver reads
// it as a prerelease below a `fixed: "1.0.0"` bound. Dropping under semver and
// answering under PEP 440 turns that match into a miss, so such a range is left
// out of the decision and its strings are kept.
//
// The drop is a no-op for affects by construction rather than by sampling,
// which is why it is decided per string. Let v be a dropped string and q a
// queried one. If q == v, the ranges match v by the drop condition, so they
// match q. If the ordering reports v and q equal, the range that placed v is
// walked under that same ordering, so q compares identically to v at every one
// of its bounds and the walk returns for q what it returned for v. If the
// ordering cannot place q, q equals no dropped string, because every dropped
// string was orderable. A string the ranges do not place is kept, so a list
// reaching outside its own ranges keeps exactly the strings that reach.
//
// An entry the ordering decides no range of is returned untouched: it is the
// enumerated list or nothing.
func trimCovered(order string, versions []string, ranges []osvRange) []string {
	var covered osvAffected
	for _, r := range ranges {
		if r.Type == "SEMVER" && order != orderSemver {
			continue
		}
		covered.Ranges = append(covered.Ranges, r)
	}
	if len(covered.Ranges) == 0 {
		return versions
	}
	var keep []string
	for _, v := range versions {
		if orderable(order, v) {
			if hit, _ := covered.affects(order, v); hit {
				continue
			}
		}
		keep = append(keep, v)
	}
	return keep
}

// rangeEvent is one event resolved to its version and kind for sorting.
// min marks OSV's `introduced: "0"`, which means "from the beginning" rather
// than the version 0: it has to sort below a prerelease and below a Go
// pseudo-version, both of which compare under 0.0.0 as ordinary versions.
type rangeEvent struct {
	version string
	kind    int // 0 introduced, 1 last_affected, 2 fixed
	min     bool
}

// affects walks a range per the OSV spec: sort the events by version, then
// take the state of the last event at or below the queried version.
// introduced/fixed at the same version sort introduced first, so a range that
// introduces and fixes at one point leaves nothing affected.
//
// A bound the ordering cannot place leaves the whole range unevaluated, which
// is what api.osv.dev does with it: no version of pywidget matches
// PYSEC-2024-325, whose last_affected is "4.1.0-NA", not even one well below
// that bound. Walking such a range on a string comparison instead blocks
// imports OSV calls clean.
func (r osvRange) affects(order, version string) (matched bool, unorderable string) {
	if r.Type == "GIT" {
		return false, ""
	}
	rangeOrder := order
	if r.Type == "SEMVER" {
		rangeOrder = orderSemver
	}
	if !orderable(rangeOrder, version) {
		return false, version
	}

	events := make([]rangeEvent, 0, len(r.Events))
	for _, e := range r.Events {
		switch {
		case e.Introduced != "":
			events = append(events, rangeEvent{e.Introduced, 0, e.Introduced == "0"})
		case e.LastAffected != "":
			events = append(events, rangeEvent{e.LastAffected, 1, false})
		case e.Fixed != "":
			events = append(events, rangeEvent{e.Fixed, 2, false})
		}
	}
	for _, e := range events {
		if !e.min && !orderable(rangeOrder, e.version) {
			return false, e.version
		}
	}

	// Every bound and the queried version parse by here, so the comparisons
	// below cannot report "unordered".
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].min != events[j].min {
			return events[i].min
		}
		if c, _ := compareVersions(rangeOrder, events[i].version, events[j].version); c != 0 {
			return c < 0
		}
		return events[i].kind < events[j].kind
	})

	vulnerable := false
	for _, e := range events {
		c := 1
		if !e.min {
			c, _ = compareVersions(rangeOrder, version, e.version)
		}
		switch e.kind {
		case 0:
			if c >= 0 {
				vulnerable = true
			}
		case 1:
			if c > 0 {
				vulnerable = false
			}
		case 2:
			if c >= 0 {
				vulnerable = false
			}
		}
	}
	return vulnerable, ""
}

// compareVersions returns -1, 0 or 1, and whether both operands could be
// ordered at all. A false second return is not "equal" and not "less": callers
// have to decide what an unorderable version means to them, because the
// string comparison this used to fall back to is an ordering only by accident.
func compareVersions(order, a, b string) (int, bool) {
	switch order {
	case orderPEP440:
		return comparePEP440(a, b)
	case orderDebian:
		return compareDebian(a, b)
	case orderRubyGems:
		return compareGemVersions(a, b)
	case orderMaven:
		return compareMavenVersions(a, b)
	case orderRpm:
		return compareRpmEVR(a, b)
	}
	return compareSemver(a, b)
}

// CompareVersions orders two versions of a bodega package type: semver for
// npm, cargo and gomod, Maven's ComparableVersion for maven, and Gem::Version
// for rubygems. A false second return means one of them cannot be ordered
// under that type's ordering, or that bodega has no ordering for the type, and
// a caller gating on a range has to refuse rather than guess.
func CompareVersions(typ, a, b string) (int, bool) {
	order, ok := packageVersionOrder(typ)
	if !ok {
		return 0, false
	}
	return compareVersions(order, a, b)
}

// ReleaseSegments returns the numeric release a version of typ opens with,
// which is what a range bounded by major or major.minor compares: [1 2 3] for
// semver 1.2.3, [2 0] for Maven 2.0-beta9, [1 0 0] for the gem 1.0.0.pre.
// Trailing zeros may be absent, so a caller compares a missing segment as 0.
func ReleaseSegments(typ, v string) ([]int, bool) {
	order, ok := packageVersionOrder(typ)
	if !ok {
		return nil, false
	}
	switch order {
	case orderMaven:
		root, ok := parseMavenVersion(v)
		if !ok {
			return nil, false
		}
		var out []int
		for _, it := range root.list {
			if it.kind != mavenNumber {
				break
			}
			n := 0
			if it.num != "" {
				var err error
				if n, err = strconv.Atoi(it.num); err != nil {
					return nil, false
				}
			}
			out = append(out, n)
		}
		return out, true
	case orderRubyGems:
		segs, ok := parseGemVersion(v)
		if !ok {
			return nil, false
		}
		var out []int
		for _, s := range segs {
			if s.str != "" {
				break
			}
			out = append(out, s.num)
		}
		return out, true
	case orderRpm:
		// The version's leading dot-separated numbers; the epoch and the
		// release are not release segments.
		_, version, _, ok := splitRpmEVR(v)
		if !ok {
			return nil, false
		}
		var out []int
		for _, seg := range strings.Split(version, ".") {
			n, err := strconv.Atoi(seg)
			if err != nil {
				break
			}
			out = append(out, n)
		}
		return out, len(out) > 0
	}
	sv := parseSemver(v)
	return sv.release, sv.ok
}

// packageVersionOrder maps a bodega package type to its ordering. The types
// absent here have no route that gates on a range, and answering semver for
// them would order a Debian or PEP 440 version by the wrong rules.
func packageVersionOrder(typ string) (string, bool) {
	switch typ {
	case manifest.TypeNpm, manifest.TypeCargo, manifest.TypeGomod, manifest.TypeComposer:
		// A Packagist version is a tag, "v" prefix or not, which semver
		// ordering reads; a dev branch orders against nothing.
		return orderSemver, true
	case manifest.TypeOCI:
		// An image tag is whatever its publisher chose. The numbered ones
		// (17, 1.27.3, v4.1) order as semver; "latest" orders against
		// nothing, and the route compares an exact pin as a string.
		return orderSemver, true
	case manifest.TypeMaven:
		return orderMaven, true
	case manifest.TypeRubygems:
		return orderRubyGems, true
	case manifest.TypeRpm:
		return orderRpm, true
	}
	return "", false
}

// orderable reports whether an ordering can place a version.
func orderable(order, v string) bool {
	switch order {
	case orderPEP440:
		return parsePEP440(v).ok
	case orderDebian:
		return parseDebian(v).ok
	case orderRubyGems:
		_, ok := parseGemVersion(v)
		return ok
	case orderMaven:
		_, ok := parseMavenVersion(v)
		return ok
	case orderRpm:
		_, _, _, ok := splitRpmEVR(v)
		return ok
	}
	return parseSemver(v).ok
}

// splitRpmEVR splits epoch:version-release. The epoch defaults to 0 and the
// release to "", which compares as absent: rpm orders a version with no
// release against the version alone.
func splitRpmEVR(v string) (epoch int, version, release string, ok bool) {
	rest := v
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		n, err := strconv.Atoi(rest[:i])
		if err != nil || n < 0 {
			return 0, "", "", false
		}
		epoch, rest = n, rest[i+1:]
	}
	version = rest
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		version, release = rest[:i], rest[i+1:]
	}
	return epoch, version, release, version != ""
}

// compareRpmEVR orders two RPM versions as rpm does: the epoch numerically,
// then the version, then the release when both carry one, each by rpmvercmp.
func compareRpmEVR(a, b string) (int, bool) {
	ea, va, ra, oka := splitRpmEVR(a)
	eb, vb, rb, okb := splitRpmEVR(b)
	if !oka || !okb {
		return 0, false
	}
	if ea != eb {
		if ea < eb {
			return -1, true
		}
		return 1, true
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c, true
	}
	if ra == "" || rb == "" {
		return 0, true
	}
	return rpmvercmp(ra, rb), true
}

// rpmvercmp is rpm's own comparison of one version or release string
// (rpmio/rpmvercmp.c): runs of digits compare numerically and runs of
// letters lexically, a digit run outranks a letter run, '~' sorts before
// anything including the end of the string, and '^' sorts after the end but
// before anything else.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	isAlnum := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	isAlpha := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		if (i < len(a) && a[i] == '~') || (j < len(b) && b[j] == '~') {
			if i >= len(a) || a[i] != '~' {
				return 1
			}
			if j >= len(b) || b[j] != '~' {
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		if (i < len(a) && a[i] == '^') || (j < len(b) && b[j] == '^') {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		numeric := isDigit(a[i])
		in := isAlpha
		if numeric {
			in = isDigit
		}
		si, sj := i, j
		for i < len(a) && in(a[i]) {
			i++
		}
		for j < len(b) && in(b[j]) {
			j++
		}
		sa, sb := a[si:i], b[sj:j]
		if sb == "" {
			// Unlike segment types: a number is newer than letters.
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				if len(sa) > len(sb) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i < len(a):
		return 1
	}
	return -1
}

// gemVersionPattern is Gem::Version's ANCHORED_VERSION_PATTERN.
var gemVersionPattern = regexp.MustCompile(`^\s*([0-9]+(\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?)?\s*$`)

var gemSegmentPattern = regexp.MustCompile(`[0-9]+|[a-zA-Z]+`)

// gemSegment is one segment of a Gem::Version: a number, or the letters of a
// prerelease marker when str is set.
type gemSegment struct {
	num int
	str string
}

// parseGemVersion returns Gem::Version#canonical_segments. A letter segment
// makes the version a prerelease of the numbers before it, so "1.0.0.rc1"
// sorts below "1.0.0", and a "-" reads as ".pre.", as Gem::Version rewrites
// it. Trailing zeros are dropped from the release and from the prerelease
// part, so "1.0" equals "1" and "1.0.a" equals "1.a".
func parseGemVersion(v string) ([]gemSegment, bool) {
	if !gemVersionPattern.MatchString(v) {
		return nil, false
	}
	v = strings.ReplaceAll(strings.TrimSpace(v), "-", ".pre.")
	var segs []gemSegment
	for _, m := range gemSegmentPattern.FindAllString(v, -1) {
		if n, err := strconv.Atoi(m); err == nil {
			segs = append(segs, gemSegment{num: n})
		} else if m[0] >= '0' && m[0] <= '9' {
			return nil, false
		} else {
			segs = append(segs, gemSegment{str: m})
		}
	}
	split := len(segs)
	for i, s := range segs {
		if s.str != "" {
			split = i
			break
		}
	}
	trim := func(part []gemSegment) []gemSegment {
		for len(part) > 0 && part[len(part)-1] == (gemSegment{}) {
			part = part[:len(part)-1]
		}
		return part
	}
	return append(trim(segs[:split:split]), trim(segs[split:])...), true
}

// compareGemVersions is Gem::Version#<=>: segment by segment, a missing one
// reading as 0, a letter segment below any number, two letter segments by
// byte order.
func compareGemVersions(a, b string) (int, bool) {
	sa, oka := parseGemVersion(a)
	sb, okb := parseGemVersion(b)
	if !oka || !okb {
		return 0, false
	}
	for i := 0; i < len(sa) || i < len(sb); i++ {
		var x, y gemSegment
		if i < len(sa) {
			x = sa[i]
		}
		if i < len(sb) {
			y = sb[i]
		}
		switch {
		case x == y:
			continue
		case x.str != "" && y.str == "":
			return -1, true
		case x.str == "" && y.str != "":
			return 1, true
		case x.str != "":
			return strings.Compare(x.str, y.str), true
		}
		return compareInt(x.num, y.num), true
	}
	return 0, true
}

// mavenItem is one item of a version as Maven's ComparableVersion parses it:
// a number, a qualifier, or a sublist. A '-', and a change between digits and
// letters, open a sublist, which is what places 1.0-alpha1 below 1.0 and
// 31.1-jre above it.
type mavenItem struct {
	kind mavenKind
	num  string // decimal digits without leading zeros; "" is zero
	str  string // qualifier with its aliases resolved; "" is a release
	list []*mavenItem
}

type mavenKind int

const (
	mavenNumber mavenKind = iota
	mavenQualifier
	mavenList
)

// mavenQualifiers are the qualifiers Maven knows, in order; "" is a release.
// An unknown qualifier sorts after all of them, among its kind by spelling.
var mavenQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

const mavenReleaseRank = "5"

// parseMavenVersion builds ComparableVersion's item tree. Maven orders any
// string, so only an empty one or one holding whitespace is refused: neither
// names a version a repository path can carry.
func parseMavenVersion(v string) (*mavenItem, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || strings.ContainsAny(v, " \t\r\n") {
		return nil, false
	}
	root := &mavenItem{kind: mavenList}
	list, stack := root, []*mavenItem{root}
	add := func(it *mavenItem) { list.list = append(list.list, it) }
	open := func() {
		child := &mavenItem{kind: mavenList}
		add(child)
		list = child
		stack = append(stack, child)
	}
	token := func(digits bool, s string) *mavenItem {
		if digits {
			return &mavenItem{kind: mavenNumber, num: strings.TrimLeft(s, "0")}
		}
		return mavenQualifierItem(s, false)
	}
	digits, start := false, 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.' || c == '-':
			if i == start {
				add(&mavenItem{kind: mavenNumber})
			} else {
				add(token(digits, v[start:i]))
			}
			start = i + 1
			if c == '-' {
				open()
			}
		case c >= '0' && c <= '9':
			if !digits && i > start {
				// A qualifier after a '.' opens a sublist as a '-' does, which
				// is what places 2.0.a below 2-1.
				if len(list.list) > 0 {
					open()
				}
				add(mavenQualifierItem(v[start:i], true))
				start = i
				open()
			}
			digits = true
		default:
			if digits && i > start {
				add(token(true, v[start:i]))
				start = i
				open()
			}
			digits = false
		}
	}
	if len(v) > start {
		if !digits && len(list.list) > 0 {
			open()
		}
		add(token(digits, v[start:]))
	}
	for i := len(stack) - 1; i >= 0; i-- {
		stack[i].trimNull()
	}
	return root, true
}

// mavenQualifierItem resolves Maven's aliases: a, b and m directly before a
// digit are alpha, beta and milestone; ga, final and release are a release;
// cr is rc.
func mavenQualifierItem(s string, beforeDigit bool) *mavenItem {
	if beforeDigit && len(s) == 1 {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	switch s {
	case "ga", "final", "release":
		s = ""
	case "cr":
		s = "rc"
	}
	return &mavenItem{kind: mavenQualifier, str: s}
}

func (it *mavenItem) null() bool {
	switch it.kind {
	case mavenNumber:
		return it.num == ""
	case mavenQualifier:
		return it.str == ""
	}
	return len(it.list) == 0
}

// trimNull drops trailing zeros, release qualifiers and empty sublists,
// stopping at the first other number or qualifier, so 1.0.0 is 1 and
// 5.3.18.RELEASE is 5.3.18.
func (it *mavenItem) trimNull() {
	for i := len(it.list) - 1; i >= 0; i-- {
		switch x := it.list[i]; {
		case x.null():
			it.list = append(it.list[:i], it.list[i+1:]...)
		case x.kind != mavenList:
			return
		}
	}
}

func (it *mavenItem) rank() string {
	for i, q := range mavenQualifiers {
		if q == it.str {
			return strconv.Itoa(i)
		}
	}
	return strconv.Itoa(len(mavenQualifiers)) + "-" + it.str
}

// compare is ComparableVersion's Item.compareTo. A nil o is the padding a
// shorter list compares against.
func (it *mavenItem) compare(o *mavenItem) int {
	switch it.kind {
	case mavenNumber:
		switch {
		case o == nil:
			if it.num == "" {
				return 0
			}
			return 1
		case o.kind == mavenNumber:
			if c := compareInt(len(it.num), len(o.num)); c != 0 {
				return c
			}
			return strings.Compare(it.num, o.num)
		}
		return 1
	case mavenQualifier:
		switch {
		case o == nil:
			return strings.Compare(it.rank(), mavenReleaseRank)
		case o.kind == mavenQualifier:
			return strings.Compare(it.rank(), o.rank())
		}
		return -1
	}
	switch {
	case o == nil:
		for _, x := range it.list {
			if c := x.compare(nil); c != 0 {
				return c
			}
		}
		return 0
	case o.kind == mavenNumber:
		return -1
	case o.kind == mavenQualifier:
		return 1
	}
	for i := 0; i < len(it.list) || i < len(o.list); i++ {
		var l, r *mavenItem
		if i < len(it.list) {
			l = it.list[i]
		}
		if i < len(o.list) {
			r = o.list[i]
		}
		c := 0
		switch {
		case l != nil:
			c = l.compare(r)
		case r != nil:
			c = -r.compare(nil)
		}
		if c != 0 {
			return c
		}
	}
	return 0
}

// compareMavenVersions orders two versions as Maven's ComparableVersion does,
// which is the ordering OSV's Maven ECOSYSTEM ranges are written in.
func compareMavenVersions(a, b string) (int, bool) {
	pa, oka := parseMavenVersion(a)
	pb, okb := parseMavenVersion(b)
	if !oka || !okb {
		return 0, false
	}
	return pa.compare(pb), true
}

type semverVersion struct {
	release []int
	pre     []string
	ok      bool
}

// parseSemver accepts more than the semver grammar on purpose: OSV ranges
// carry "0" as the open lower bound and Go module versions arrive with a "v"
// prefix, and both have to order against a three-part release.
func parseSemver(v string) semverVersion {
	s := strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre []string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if s[i+1:] != "" {
			pre = strings.Split(s[i+1:], ".")
		}
		s = s[:i]
	}
	if s == "" {
		return semverVersion{}
	}
	parts := strings.Split(s, ".")
	release := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return semverVersion{}
		}
		release = append(release, n)
	}
	return semverVersion{release: release, pre: pre, ok: true}
}

func compareSemver(a, b string) (int, bool) {
	pa, pb := parseSemver(a), parseSemver(b)
	if !pa.ok || !pb.ok {
		return 0, false
	}
	if c := compareInts(pa.release, pb.release); c != 0 {
		return c, true
	}
	// A release outranks any of its prereleases.
	switch {
	case len(pa.pre) == 0 && len(pb.pre) == 0:
		return 0, true
	case len(pa.pre) == 0:
		return 1, true
	case len(pb.pre) == 0:
		return -1, true
	}
	for i := 0; i < len(pa.pre) && i < len(pb.pre); i++ {
		if c := comparePreIdent(pa.pre[i], pb.pre[i]); c != 0 {
			return c, true
		}
	}
	return compareInt(len(pa.pre), len(pb.pre)), true
}

// comparePreIdent orders two prerelease identifiers: numeric ones compare
// numerically and rank below alphanumeric ones, per semver 11.4.
func comparePreIdent(a, b string) int {
	na, erra := strconv.Atoi(a)
	nb, errb := strconv.Atoi(b)
	switch {
	case erra == nil && errb == nil:
		return compareInt(na, nb)
	case erra == nil:
		return -1
	case errb == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// pep440Pattern is the canonical PEP 440 version regex.
var pep440Pattern = regexp.MustCompile(`^\s*v?(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_.]?dev(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$`)

// pep440Version holds a PEP 440 sort key. Each of pre, post and dev carries a
// rank alongside its value so the infinities the spec sorts by are ordinary
// integer comparisons: an absent pre segment sorts above every pre segment,
// an absent post below every post, and a dev release below its own release.
type pep440Version struct {
	epoch    int
	release  []int
	preRank  int
	preLtr   string
	preNum   int
	postRank int
	postNum  int
	devRank  int
	devNum   int
	ok       bool
}

func parsePEP440(v string) pep440Version {
	m := pep440Pattern.FindStringSubmatch(strings.ToLower(v))
	if m == nil {
		return pep440Version{}
	}
	group := func(name string) string {
		return m[pep440Pattern.SubexpIndex(name)]
	}
	out := pep440Version{ok: true}
	if e := group("epoch"); e != "" {
		out.epoch, _ = strconv.Atoi(e)
	}
	for _, p := range strings.Split(group("release"), ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return pep440Version{}
		}
		out.release = append(out.release, n)
	}

	hasPre, hasPost, hasDev := group("pre") != "", group("post") != "", group("dev") != ""

	switch {
	case hasPre:
		out.preRank = 0
		out.preLtr = normalizePreLetter(group("pre_l"))
		out.preNum, _ = strconv.Atoi(group("pre_n"))
	case !hasPost && hasDev:
		out.preRank = -1 // a dev release precedes every prerelease of the same release
	default:
		out.preRank = 1
	}
	if hasPost {
		out.postRank = 0
		if n := group("post_n1"); n != "" {
			out.postNum, _ = strconv.Atoi(n)
		} else {
			out.postNum, _ = strconv.Atoi(group("post_n2"))
		}
	} else {
		out.postRank = -1
	}
	if hasDev {
		out.devRank = 0
		out.devNum, _ = strconv.Atoi(group("dev_n"))
	} else {
		out.devRank = 1
	}
	return out
}

// normalizePreLetter collapses PEP 440's spellings onto the three that sort:
// a < b < rc.
func normalizePreLetter(l string) string {
	switch l {
	case "alpha":
		return "a"
	case "beta":
		return "b"
	case "c", "pre", "preview":
		return "rc"
	}
	return l
}

func comparePEP440(a, b string) (int, bool) {
	pa, pb := parsePEP440(a), parsePEP440(b)
	if !pa.ok || !pb.ok {
		return 0, false
	}
	if c := compareInt(pa.epoch, pb.epoch); c != 0 {
		return c, true
	}
	if c := compareInts(pa.release, pb.release); c != 0 {
		return c, true
	}
	if c := compareInt(pa.preRank, pb.preRank); c != 0 {
		return c, true
	}
	if pa.preRank == 0 {
		if c := strings.Compare(pa.preLtr, pb.preLtr); c != 0 {
			return c, true
		}
		if c := compareInt(pa.preNum, pb.preNum); c != 0 {
			return c, true
		}
	}
	if c := compareInt(pa.postRank, pb.postRank); c != 0 {
		return c, true
	}
	if pa.postRank == 0 {
		if c := compareInt(pa.postNum, pb.postNum); c != 0 {
			return c, true
		}
	}
	if c := compareInt(pa.devRank, pb.devRank); c != 0 {
		return c, true
	}
	if pa.devRank == 0 {
		return compareInt(pa.devNum, pb.devNum), true
	}
	return 0, true
}

// debianVersion is a distro version string split the way dpkg splits it:
// [epoch:]upstream_version[-debian_revision], with the three parts compared
// separately and in that order.
//
// The revision is where Ubuntu and Debian carry a backported security fix, and
// it is the part every other ordering here throws away. semver reads
// "2.5.0-1+deb12u1" as 2.5.0 with a prerelease and a build tag it discards,
// making it equal to "2.5.0-1", the revision that does not have the fix.
type debianVersion struct {
	epoch    int
	upstream string
	revision string
	ok       bool
}

// parseDebian splits a version per Debian policy 5.6.12. A version that does
// not start with a digit, or carries a character the grammar does not allow,
// is refused rather than guessed at: the matcher reports an unorderable bound
// instead of walking a range on a comparison that means nothing.
func parseDebian(v string) debianVersion {
	s := strings.TrimSpace(v)
	if s == "" {
		return debianVersion{}
	}
	out := debianVersion{ok: true}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		n, err := strconv.Atoi(s[:i])
		if err != nil || n < 0 {
			return debianVersion{}
		}
		out.epoch = n
		s = s[i+1:]
	}
	// The last hyphen splits the revision off, so an upstream version may
	// contain one: "1.0-beta-3" is upstream "1.0-beta", revision "3".
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		out.revision = s[i+1:]
		s = s[:i]
	}
	out.upstream = s
	if s == "" || s[0] < '0' || s[0] > '9' ||
		!debianChars(out.upstream) || !debianChars(out.revision) {
		return debianVersion{}
	}
	return out
}

func debianChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '.' || c == '+' || c == '-' || c == '~' || c == ':':
		default:
			return false
		}
	}
	return true
}

func compareDebian(a, b string) (int, bool) {
	pa, pb := parseDebian(a), parseDebian(b)
	if !pa.ok || !pb.ok {
		return 0, false
	}
	if c := compareInt(pa.epoch, pb.epoch); c != 0 {
		return c, true
	}
	if c := compareDebianPart(pa.upstream, pb.upstream); c != 0 {
		return c, true
	}
	return compareDebianPart(pa.revision, pb.revision), true
}

// debianOrder ranks one byte for dpkg's comparison. `~` sorts below the end of
// the string, which is what makes 1.0~rc1 older than 1.0; letters sort below
// every other punctuation mark; and a digit ties with the end of the string,
// because the digit runs are compared in their own pass.
func debianOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

// compareDebianPart is dpkg's verrevcmp: alternate between a run of non-digits
// compared by debianOrder and a run of digits compared numerically, with
// leading zeros stripped so 1.07 and 1.7 are the same version. Transcribed
// rather than approximated, because an approximation that gets one pair
// backwards reports a patched host as vulnerable.
func compareDebianPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDebianDigit(a[i])) || (j < len(b) && !isDebianDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = debianOrder(a[i])
			}
			if j < len(b) {
				bc = debianOrder(b[j])
			}
			if ac != bc {
				return compareInt(ac, bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && isDebianDigit(a[i]) && j < len(b) && isDebianDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		switch {
		case i < len(a) && isDebianDigit(a[i]):
			return 1
		case j < len(b) && isDebianDigit(b[j]):
			return -1
		case firstDiff != 0:
			return compareInt(firstDiff, 0)
		}
	}
	return 0
}

func isDebianDigit(c byte) bool { return c >= '0' && c <= '9' }

// compareInts compares release segments, treating a missing trailing segment
// as zero so 1.2 and 1.2.0 are the same version.
func compareInts(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := compareInt(x, y); c != 0 {
			return c
		}
	}
	return 0
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
