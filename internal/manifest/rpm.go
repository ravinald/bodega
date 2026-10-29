package manifest

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

// rpm storage keys, all under one repository's tree:
//
//	rpm/<repo>/<releasever>/<basearch>/repomd.xml
//	rpm/<repo>/<releasever>/<basearch>/repodata/<checksum>/<file>
//	rpm/<repo>/<releasever>/<basearch>/packages/<name>/<evr>/<file>
//
// A package is keyed by its name and epoch:version-release rather than by the
// href primary gives it, so the audit and discovery rows ParseKey feeds name
// the package. The href's directory layout is the vendor's and carries
// neither the name nor the epoch.
const (
	RpmPrefix         = "rpm/"
	rpmRepomdFile     = "repomd.xml"
	rpmRepodataMarker = "repodata"
	rpmPackagesMarker = "packages"
)

// ErrRpmKeysListed reports that an rpm version's keys are found by listing
// RpmPrefix rather than built: one version is cached once per repository,
// release and architecture it was pulled under, and an entry records none of
// the three.
var ErrRpmKeysListed = errors.New("rpm objects are keyed by repository, release and architecture, which an entry does not record; list them under " + RpmPrefix)

// RpmOSVEcosystems are the OSV ecosystems that publish advisories against an
// Enterprise Linux vendor's RPM builds. A record's own ecosystem string may
// carry a release after a colon ("Rocky Linux:9").
var RpmOSVEcosystems = []string{"AlmaLinux", "Red Hat", "Rocky Linux"}

// RpmBasearches are the architectures a /rpm/ path may substitute for
// $basearch. Anything else would put caller-chosen text into an upstream URL.
var RpmBasearches = []string{"x86_64", "aarch64", "noarch", "ppc64le", "s390x"}

var (
	rpmRepoNameRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	rpmReleaseverRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
	rpmNameRE       = regexp.MustCompile(`^[A-Za-z0-9_+][A-Za-z0-9._+-]{0,254}$`)
	rpmEVRRE        = regexp.MustCompile(`^([0-9]+:)?[A-Za-z0-9._+~^]+-[A-Za-z0-9._+~^]+$`)
)

// RpmValidRepoName reports whether name can be a key of rpm_upstreams: one
// path segment of letters, digits, '.', '_' and '-', not starting with '.'.
func RpmValidRepoName(name string) bool { return rpmRepoNameRE.MatchString(name) }

// RpmValidReleasever reports whether v can stand for $releasever: "9" or
// "9.4", nothing else.
func RpmValidReleasever(v string) bool { return len(v) <= 16 && rpmReleaseverRE.MatchString(v) }

// RpmValidBasearch reports whether a is one of RpmBasearches.
func RpmValidBasearch(a string) bool { return slices.Contains(RpmBasearches, a) }

// RpmValidName reports whether name is an RPM package name bodega keys.
func RpmValidName(name string) bool {
	return rpmNameRE.MatchString(name) && !strings.Contains(name, "..")
}

// RpmValidEVR reports whether v is an epoch:version-release, the epoch
// optional.
func RpmValidEVR(v string) bool { return len(v) <= 255 && rpmEVRRE.MatchString(v) }

// RpmEVR is the version bodega names an RPM by: epoch:version-release, the
// form `rpm -q --qf '%{EPOCH}:%{VERSION}-%{RELEASE}'` prints, with a zero or
// absent epoch left off as rpm itself leaves it off.
func RpmEVR(epoch, version, release string) string {
	evr := version + "-" + release
	if e := strings.TrimLeft(epoch, "0"); e != "" {
		evr = e + ":" + evr
	}
	return evr
}

// RpmDropEpoch is v without its epoch, for comparing against a version
// reported as version-release alone, as rpm_packages reports it.
func RpmDropEpoch(v string) string {
	if i := strings.IndexByte(v, ':'); i > 0 && strings.Trim(v[:i], "0123456789") == "" {
		return v[i+1:]
	}
	return v
}

func rpmRepoKey(repo, releasever, basearch string) string {
	return RpmPrefix + repo + "/" + releasever + "/" + basearch + "/"
}

// RpmRepomdKey is a repository's repomd.xml. Mutable.
func RpmRepomdKey(repo, releasever, basearch string) string {
	return rpmRepoKey(repo, releasever, basearch) + rpmRepomdFile
}

// RpmMetadataKey is a metadata file repomd.xml names, under the checksum
// repomd.xml gives it. Immutable: a new primary is a new checksum.
func RpmMetadataKey(repo, releasever, basearch, checksum, file string) string {
	return rpmRepoKey(repo, releasever, basearch) + rpmRepodataMarker + "/" + checksum + "/" + file
}

// RpmPackageKey is one package file. Immutable.
func RpmPackageKey(repo, releasever, basearch, name, evr, file string) string {
	return rpmRepoKey(repo, releasever, basearch) + rpmPackagesMarker + "/" + name + "/" + evr + "/" + file
}

// parseRpmKey names the package a key holds; a repomd.xml or metadata key
// names none.
func parseRpmKey(key string) (name, version string) {
	segs := strings.Split(strings.TrimPrefix(key, RpmPrefix), "/")
	if len(segs) != 7 || segs[3] != rpmPackagesMarker || !RpmValidName(segs[4]) || !RpmValidEVR(segs[5]) {
		return "", ""
	}
	return segs[4], segs[5]
}

// RpmFileIdentity splits a package filename, <name>-<version>-<release>.<arch>.rpm,
// into the name and version-release. The filename carries no epoch, and
// neither the version nor the release holds a "-", so the last two separate
// the three.
func RpmFileIdentity(file string) (name, versionRelease string) {
	base, ok := strings.CutSuffix(file, ".rpm")
	if !ok {
		return "", ""
	}
	dot := strings.LastIndexByte(base, '.')
	if dot <= 0 {
		return "", ""
	}
	base = base[:dot]
	rel := strings.LastIndexByte(base, '-')
	if rel <= 0 {
		return "", ""
	}
	ver := strings.LastIndexByte(base[:rel], '-')
	if ver <= 0 || ver == rel-1 || rel == len(base)-1 {
		return "", ""
	}
	return base[:ver], base[ver+1:]
}
