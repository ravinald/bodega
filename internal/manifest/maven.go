package manifest

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// MavenMetadataFile is the per-artifact (and per-SNAPSHOT-version) index a
// Maven client reads to learn which versions exist.
const MavenMetadataFile = "maven-metadata.xml"

// mavenSegmentPattern bounds one path segment of the repository layout. A
// leading dot is refused so "." and ".." can never name a directory, and the
// character set is the union of what groupIds, artifactIds, versions and
// classifiers use on Maven Central.
var mavenSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+-]{0,127}$`)

// mavenSnapshotStamp is the timestamp-buildnumber a deployed SNAPSHOT file
// carries in place of "SNAPSHOT": foo-1.0-20231010.123456-1.jar.
var mavenSnapshotStamp = regexp.MustCompile(`^[0-9]{8}\.[0-9]{6}-[0-9]+`)

// mavenExtensions are the artifact files the route serves. Anything else under
// a version directory 404s, so widening this list is how a new packaging
// becomes reachable.
var mavenExtensions = []string{"jar", "pom", "module", "aar", "war"}

// mavenCompanions are the files published beside an artifact or a metadata
// file that describe it rather than add to it. They share the identity of the
// file they sit beside.
var mavenCompanions = []string{"sha1", "md5", "sha256", "sha512", "asc"}

// MavenPath is one request path in the Maven repository layout, read into the
// coordinate it names.
type MavenPath struct {
	GroupID    string // dotted, as a POM spells it
	ArtifactID string
	Version    string // empty for artifact-level metadata
	Classifier string
	Extension  string // empty for metadata
	Companion  string // empty for the file itself
	Metadata   bool
	// GroupLevelID is the second reading of a maven-metadata.xml outside a
	// SNAPSHOT version: every directory as the groupId, which is the file
	// Maven reads to resolve a plugin prefix. The path cannot tell the two
	// readings apart, so a request names both. Empty for every other path.
	GroupLevelID string
}

// Name is the package identity bodega records: <groupId>:<artifactId>.
func (p MavenPath) Name() string { return p.GroupID + ":" + p.ArtifactID }

// GroupLevelName is the group-level reading as an entry names it,
// <GroupLevelID>:*, and empty when the path has no such reading.
func (p MavenPath) GroupLevelName() string {
	if p.GroupLevelID == "" {
		return ""
	}
	return p.GroupLevelID + ":" + MavenGroupWildcard
}

// Snapshot reports whether the path sits under a -SNAPSHOT version, whose
// files are redeployed under the same name.
func (p MavenPath) Snapshot() bool { return strings.HasSuffix(p.Version, "-SNAPSHOT") }

// Immutable reports whether the bytes at this path can never change: a
// release version's artifact or companion. Metadata and SNAPSHOT files are
// rewritten on every deploy.
func (p MavenPath) Immutable() bool { return !p.Metadata && !p.Snapshot() }

// ParseMavenPath reads a path relative to a repository root. It accepts
//
//	<group dirs>/<artifactId>/maven-metadata.xml[.<companion>]  (or <group dirs>/maven-metadata.xml)
//	<group dirs>/<artifactId>/<version>-SNAPSHOT/maven-metadata.xml[.<companion>]
//	<group dirs>/<artifactId>/<version>/<artifactId>-<version>[-<classifier>].<ext>[.<companion>]
//
// and nothing else. A SNAPSHOT file may spell its version as the timestamped
// form Maven deploys. False means the path names nothing in the layout, which
// the route answers without contacting an upstream.
func ParseMavenPath(p string) (MavenPath, bool) {
	segs := strings.Split(p, "/")
	for _, s := range segs {
		if !mavenSegmentPattern.MatchString(s) {
			return MavenPath{}, false
		}
	}
	if len(segs) < 3 {
		return MavenPath{}, false
	}
	file := segs[len(segs)-1]
	dirs := segs[:len(segs)-1]
	var out MavenPath
	for _, c := range mavenCompanions {
		if base, ok := strings.CutSuffix(file, "."+c); ok {
			file, out.Companion = base, c
			break
		}
	}

	if file == MavenMetadataFile {
		out.Metadata = true
		if last := dirs[len(dirs)-1]; len(dirs) >= 3 && strings.HasSuffix(last, "-SNAPSHOT") {
			out.Version = last
			dirs = dirs[:len(dirs)-1]
		}
		out.ArtifactID = dirs[len(dirs)-1]
		out.GroupID = strings.Join(dirs[:len(dirs)-1], ".")
		if out.Version == "" {
			out.GroupLevelID = strings.Join(dirs, ".")
		}
		return out, true
	}

	if len(dirs) < 3 {
		return MavenPath{}, false
	}
	out.Version = dirs[len(dirs)-1]
	out.ArtifactID = dirs[len(dirs)-2]
	out.GroupID = strings.Join(dirs[:len(dirs)-2], ".")

	rest, ok := strings.CutPrefix(file, out.ArtifactID+"-")
	if !ok {
		return MavenPath{}, false
	}
	if out.Snapshot() {
		base := strings.TrimSuffix(out.Version, "SNAPSHOT")
		if rest, ok = strings.CutPrefix(rest, base); !ok {
			return MavenPath{}, false
		}
		if after, found := strings.CutPrefix(rest, "SNAPSHOT"); found {
			rest = after
		} else if stamp := mavenSnapshotStamp.FindString(rest); stamp != "" {
			rest = rest[len(stamp):]
		} else {
			return MavenPath{}, false
		}
	} else if rest, ok = strings.CutPrefix(rest, out.Version); !ok {
		return MavenPath{}, false
	}

	for _, ext := range mavenExtensions {
		cls, found := strings.CutSuffix(rest, "."+ext)
		if !found {
			continue
		}
		switch {
		case cls == "":
		case strings.HasPrefix(cls, "-") && len(cls) > 1:
			out.Classifier = cls[1:]
		default:
			return MavenPath{}, false
		}
		out.Extension = ext
		return out, true
	}
	return MavenPath{}, false
}

// MavenKey returns the storage key for a repository-relative path. The layout
// is already a safe, unique key once ParseMavenPath accepts it, so it is kept
// whole rather than re-derived from the coordinate.
func MavenKey(repoPath string) string { return mavenPrefix + repoPath }

// MavenArtifactPath is the repository path of a release version's POM, the one
// file every Maven version publishes whatever its packaging.
func MavenArtifactPath(name, version string) (string, bool) {
	group, artifact, ok := strings.Cut(name, ":")
	if !ok || group == "" || artifact == "" || version == "" {
		return "", false
	}
	return strings.ReplaceAll(group, ".", "/") + "/" + artifact + "/" + version + "/" + artifact + "-" + version + ".pom", true
}

// MavenGroupWildcard is the artifactId that makes a <groupId>:* entry: every
// artifact under that one groupId, and none under a groupId nested in it.
const MavenGroupWildcard = "*"

// ValidateMavenName refuses a name that is not <groupId>:<artifactId> or
// <groupId>:*, judged by the segment rule ParseMavenPath applies to a request,
// so no entry is accepted that no request could ever name.
func ValidateMavenName(name string) error {
	group, artifact, ok := strings.Cut(name, ":")
	if !ok || strings.Contains(artifact, ":") {
		return fmt.Errorf("maven %q is not a coordinate; write <groupId>:<artifactId> (org.springframework.boot:spring-boot) or <groupId>:* for every artifact of one groupId", name)
	}
	for _, seg := range strings.Split(group, ".") {
		if !mavenSegmentPattern.MatchString(seg) {
			return fmt.Errorf("maven %q: groupId %q is not dotted segments of letters, digits, '_', '-' or '+'", name, group)
		}
	}
	if artifact != MavenGroupWildcard && (strings.HasPrefix(artifact, ".") || !mavenSegmentPattern.MatchString(artifact)) {
		return fmt.Errorf("maven %q: artifactId %q is not letters, digits, '.', '_', '-' or '+', or the groupId-wide '*'", name, artifact)
	}
	return nil
}

// MavenGroupEntry is the <groupId>:* entry that covers name, and false when
// name is not a coordinate.
func MavenGroupEntry(name string) (string, bool) {
	group, _, ok := strings.Cut(name, ":")
	if !ok || group == "" {
		return "", false
	}
	return group + ":" + MavenGroupWildcard, true
}

// The metadata keys a maven fetch records, read back by MavenVersionFiles so
// every later stage names the same files. MetaMavenExtension is the main
// artifact's extension as the POM's <packaging> decides it, or "pom" for a
// version that publishes its POM alone (a BOM, a parent). MetaMavenModule is
// "true" when the upstream published Gradle module metadata beside the POM.
const (
	MetaMavenExtension = "maven_extension"
	MetaMavenModule    = "maven_module"
)

// MavenChecksumCompanions are the checksum files written beside each fetched
// file. Maven asks for .sha1 and .md5 and Gradle for .sha512 and .sha256, so
// a catalog-mode version holding fewer sends one of them to the upstream.
var MavenChecksumCompanions = []string{"sha1", "md5", "sha256", "sha512"}

// MavenPackagingExtension maps a POM's <packaging> to the extension its main
// artifact is published under. Every packaging a plugin defines that is not
// war or aar (bundle, maven-plugin, ejb, eclipse-plugin) publishes a jar.
func MavenPackagingExtension(packaging string) string {
	switch p := strings.TrimSpace(packaging); p {
	case "pom", "war", "aar":
		return p
	}
	return "jar"
}

// ParseMavenClassifier reads one entry of a version's classifiers list:
// "sources", or "<classifier>@<extension>" for a classified file that is not
// a jar, the notation Gradle writes.
func ParseMavenClassifier(s string) (classifier, extension string, err error) {
	classifier, extension, found := strings.Cut(s, "@")
	if !found {
		extension = "jar"
	}
	if !mavenSegmentPattern.MatchString(classifier) {
		return "", "", fmt.Errorf("maven classifier %q is not letters, digits, '.', '_', '-' or '+'", s)
	}
	if !slices.Contains(mavenExtensions, extension) || extension == "pom" || extension == "module" {
		return "", "", fmt.Errorf("maven classifier %q: extension %q is not one the /maven/ route serves (jar, aar, war)", s, extension)
	}
	return classifier, extension, nil
}

// MavenFilePath is the repository path of one release file of a version.
func MavenFilePath(name, version, classifier, extension string) (string, bool) {
	group, artifact, ok := strings.Cut(name, ":")
	if !ok || group == "" || artifact == "" || artifact == MavenGroupWildcard || version == "" {
		return "", false
	}
	file := artifact + "-" + version
	if classifier != "" {
		file += "-" + classifier
	}
	p := strings.ReplaceAll(group, ".", "/") + "/" + artifact + "/" + version + "/" + file + "." + extension
	if mp, ok := ParseMavenPath(p); !ok || mp.Name() != name || mp.Version != version || mp.Classifier != classifier {
		return "", false
	}
	return p, true
}

// ValidateMavenVersion refuses a version and classifiers no repository path
// could carry, so an entry the fetch cannot address is refused at import.
func ValidateMavenVersion(name string, ve VersionEntry) error {
	if _, artifact, _ := strings.Cut(name, ":"); artifact == MavenGroupWildcard {
		if len(ve.Classifiers) > 0 {
			return fmt.Errorf("maven %s names every artifact of a groupId, so it has no files for classifiers %v to select", name, ve.Classifiers)
		}
		return nil
	}
	if _, ok := MavenArtifactPath(name, ve.Version); !ok || !mavenSegmentPattern.MatchString(ve.Version) {
		return fmt.Errorf("maven %s: version %q is not a repository directory name (letters, digits, '.', '_', '-' or '+')", name, ve.Version)
	}
	for _, c := range ve.Classifiers {
		cls, ext, err := ParseMavenClassifier(c)
		if err != nil {
			return fmt.Errorf("maven %s@%s: %w", name, ve.Version, err)
		}
		if _, ok := MavenFilePath(name, ve.Version, cls, ext); !ok {
			return fmt.Errorf("maven %s@%s: classifier %q names no file the repository layout can hold", name, ve.Version, c)
		}
	}
	return nil
}

// MavenVersionFiles returns the repository paths a fetched version holds,
// its main artifact first: that is the file a version's checksum, purl and
// attestation describe. Before a fetch has recorded the packaging only the
// POM is known, and it comes first instead. Checksum companions are not
// listed; MavenChecksumCompanions names them.
func MavenVersionFiles(name string, ve VersionEntry) ([]string, error) {
	pom, ok := MavenArtifactPath(name, ve.Version)
	if !ok {
		return nil, fmt.Errorf("maven %s@%s: want a <groupId>:<artifactId> name and a version", name, ve.Version)
	}
	var files []string
	if ext := ve.Metadata[MetaMavenExtension]; ext != "" && ext != "pom" {
		main, ok := MavenFilePath(name, ve.Version, "", ext)
		if !ok {
			return nil, fmt.Errorf("maven %s@%s: recorded extension %q names no file the repository layout can hold", name, ve.Version, ext)
		}
		files = append(files, main)
	}
	files = append(files, pom)
	if ve.Metadata[MetaMavenModule] == "true" {
		module, _ := MavenFilePath(name, ve.Version, "", "module")
		files = append(files, module)
	}
	for _, c := range ve.Classifiers {
		cls, ext, err := ParseMavenClassifier(c)
		if err != nil {
			return nil, fmt.Errorf("maven %s@%s: %w", name, ve.Version, err)
		}
		p, ok := MavenFilePath(name, ve.Version, cls, ext)
		if !ok {
			return nil, fmt.Errorf("maven %s@%s: classifier %q names no file the repository layout can hold", name, ve.Version, c)
		}
		files = append(files, p)
	}
	return files, nil
}
