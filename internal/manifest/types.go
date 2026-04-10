// Package manifest defines the unified type system for all package manifests.
// Each package is stored as a per-package JSON file (PackageManifest) containing
// a slice of VersionEntry values, allowing multiple versions to coexist. An
// Index provides fast name-based lookups without loading every manifest, and a
// DependencyGraph tracks inter-package relationships.
package manifest

import "strings"

// CurrentConfigVersion is the schema version written to all manifests.
const CurrentConfigVersion = 2

// Type constants identify the package ecosystem for a manifest.
const (
	TypeApt    = "apt"
	TypeGit    = "git"
	TypePypi   = "pypi"
	TypeBinary = "binary"
	TypeGomod  = "gomod"
	TypeHelm   = "helm"
	TypeNpm    = "npm"
)

// Mode constants control how an entry is served.
const (
	ModeHosted = "hosted" // artifacts built/uploaded to S3, served from S3
	ModeProxy  = "proxy"  // fetched from upstream on cache miss, cached in S3
)

// VersionConstraint constants qualify how Version is matched.
const (
	ConstraintExact      = "exact"      // = : only this exact version
	ConstraintCompatible = "compatible" // ^ : same major version, any minor/patch
	ConstraintPatch      = "patch"      // ~ : same major.minor, any patch
	ConstraintAny        = "any"        // * : all versions
)

// AllTypes is the canonical build order across all supported ecosystems.
var AllTypes = []string{TypeBinary, TypeGit, TypeApt, TypePypi, TypeGomod, TypeHelm, TypeNpm}

// Checksum records an expected digest for integrity verification.
// Algorithm is one of "md5", "sha1", "sha256", or "sha512".
// Value is the lowercase hex-encoded digest string.
type Checksum struct {
	Algorithm string `json:"algorithm"` // "md5", "sha1", "sha256", "sha512"
	Value     string `json:"value"`
}

// BuildEnv captures the build server's environment at the time an artifact
// was produced. Populated automatically — the operator does not set this.
type BuildEnv struct {
	Platform  string `json:"platform"`            // "linux/amd64"
	OSRelease string `json:"os_release,omitempty"` // "Ubuntu 24.04.2 LTS"
	Python    string `json:"python,omitempty"`     // "3.12.3"
	Go        string `json:"go,omitempty"`         // "1.24.2"
	Rust      string `json:"rust,omitempty"`       // "1.78.0"
	Bodega    string `json:"bodega,omitempty"`     // build version
	BuiltAt   string `json:"built_at,omitempty"`  // RFC3339 timestamp
}

// PackageManifest is the on-disk representation of a single package.
// One JSON file is stored per package at {type}/{safeName}/manifest.json.
type PackageManifest struct {
	// ConfigVersion is the schema version; always CurrentConfigVersion on write.
	ConfigVersion int `json:"config_version"`

	// Name is the canonical package name (e.g. "netbox", "lodash").
	Name string `json:"name"`

	// Type is the package ecosystem (e.g. TypeGit, TypeNpm).
	Type string `json:"type"`

	// Description is a short human-readable summary of what the package does.
	Description string `json:"description,omitempty"`

	// DepPolicy controls automatic dependency creation for this package.
	// "none" (default/empty): no auto-discovery. "direct": immediate deps only.
	// "transitive": full recursive closure.
	DepPolicy string `json:"dep_policy,omitempty"`

	// Versions is the ordered list of version entries for this package.
	// Multiple versions may coexist; callers select by VersionEntry.Version.
	Versions []VersionEntry `json:"versions"`
}

// VersionEntry is the unified per-version record used across all package types.
// Fields that are irrelevant to a given ecosystem are left at their zero value
// and omitted from JSON output.
type VersionEntry struct {
	// Version is the version identifier (semver, git ref, chart version, etc.).
	Version string `json:"version,omitempty"`

	// URL is the download, repository, or registry URL.
	URL string `json:"url,omitempty"`

	// Mode controls how the entry is served: ModeHosted (default) or ModeProxy.
	Mode string `json:"mode,omitempty"`

	// VersionConstraint qualifies how Version is matched.
	// One of ConstraintExact (default), ConstraintCompatible, ConstraintPatch, ConstraintAny.
	VersionConstraint string `json:"version_constraint,omitempty"`

	// --- git-specific fields ---

	// Ref is the git ref (tag, branch, or commit SHA). Used as the version identifier
	// for git packages when Version is not explicitly set.
	Ref string `json:"ref,omitempty"`

	// Source controls how a git repository is obtained:
	//   "release" — download the release tarball (smaller, faster)
	//   "clone"   — git clone --bare + bundle (full history)
	Source string `json:"source,omitempty"`

	// --- apt-specific fields ---

	// SourceName is the upstream Debian package / source directory name.
	// Defaults to the package Name when absent.
	SourceName string `json:"source_name,omitempty"`

	// BuildCmd is the shell command executed inside the cloned source directory
	// to produce a .deb file.
	BuildCmd string `json:"build_cmd,omitempty"`

	// DebGlob is a path glob (relative to the source dir) that locates the
	// produced .deb file after building.
	DebGlob string `json:"deb_glob,omitempty"`

	// --- binary-specific fields ---

	// Filename overrides the basename derived from URL when set.
	Filename string `json:"filename,omitempty"`

	// SHA256 is the expected hex digest for binary artifacts.
	SHA256 string `json:"sha256,omitempty"`

	// --- helm-specific fields ---

	// AppVersion is the application version the chart deploys.
	AppVersion string `json:"app_version,omitempty"`

	// --- pypi / cross-type dependency tracking ---

	// RequiredBy lists the packages that depend on this version
	// (e.g. ["netbox"] for a pypi wheel pulled in by netbox).
	RequiredBy []string `json:"required_by,omitempty"`

	// --- integrity ---

	// Checksum is the optional expected digest for the artifact.
	// When nil, no digest verification is performed.
	Checksum *Checksum `json:"checksum,omitempty"`

	// ChecksumVerified is true when the checksum was confirmed against a
	// digest published by the upstream source.
	ChecksumVerified bool `json:"checksum_verified,omitempty"`

	// --- build provenance ---

	// Platform records the target platform for this artifact (e.g. "linux/amd64").
	Platform string `json:"platform,omitempty"`

	// BuildEnv captures the build server's environment at artifact creation time.
	BuildEnv *BuildEnv `json:"build_env,omitempty"`

	// --- lifecycle flags ---

	// Hidden excludes this version from being served to clients.
	Hidden       bool  `json:"hidden,omitempty"`
	ArtifactSize int64 `json:"artifact_size,omitempty"` // bytes, set at fetch time

	// Frozen prevents this version from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`

	// --- optional per-version documentation ---

	// Description overrides the package-level description for this specific version.
	Description string `json:"description,omitempty"`

	// Metadata holds ecosystem-specific key-value pairs (e.g. apt: Architecture,
	// Maintainer, Section, Priority, Installed-Size; npm: license, engines).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// VersionedName returns "name@version" using whichever of Version or Ref is set,
// or just "name" when neither is set.
func (ve VersionEntry) VersionedName(name string) string {
	ver := ve.Version
	if ver == "" {
		ver = ve.Ref
	}
	return versionedName(name, ver)
}

// IsRelease returns true when a git entry should be fetched as a release tarball.
// When Source is explicitly set that value wins. Otherwise the method auto-detects
// from Ref: version-like refs (e.g. v4.5.7, 1.0.0) use release mode, while
// branch-like refs (e.g. main, develop) use clone mode.
func (ve VersionEntry) IsRelease() bool {
	switch ve.Source {
	case "release":
		return true
	case "clone":
		return false
	default:
		return looksLikeVersionTag(ve.Ref)
	}
}

// EffectiveMode returns the entry's mode, defaulting to ModeHosted when unset.
func (ve VersionEntry) EffectiveMode() string {
	if ve.Mode == "" {
		return ModeHosted
	}
	return ve.Mode
}

// DepEdge represents a directed dependency from a parent package to a child package.
// Names are formatted as "type/name" (e.g. "git/netbox").
type DepEdge struct {
	// Parent is the package that depends on Child (e.g. "git/netbox@v4.5.7").
	Parent string `json:"parent"`
	// Child is the package being depended upon (e.g. "pypi/django@5.2.12").
	Child string `json:"child"`
	// Constraint is the version constraint type (e.g. "exact", "patch", "compatible", "any").
	Constraint string `json:"constraint,omitempty"`
	// RawSpec is the original dependency specifier (e.g. "Django==5.2.12").
	RawSpec string `json:"raw_spec,omitempty"`
}

// DependencyGraph is the in-memory representation of the dependency graph
// stored in graph.json on the backend.
type DependencyGraph struct {
	// Edges is the full list of directed dependency relationships.
	Edges []DepEdge `json:"edges"`
}

// Index is the lightweight catalog stored in index.json on the backend.
// It maps each package type to the list of safe names registered under it,
// enabling cheap existence checks and listings without loading every manifest.
type Index struct {
	// ConfigVersion is the schema version of this index file.
	ConfigVersion int `json:"config_version"`

	// Packages maps package type (e.g. "git") to a slice of safe names.
	Packages map[string][]string `json:"packages"`
}

// SafeName converts a package name to a filesystem-safe path component by
// replacing "/" with "--". This is the inverse of unsafeName.
func SafeName(name string) string {
	return strings.ReplaceAll(name, "/", "--")
}

// versionedName returns "name@version" or just "name" when version is empty.
func versionedName(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

// looksLikeVersionTag returns true when ref appears to be a semantic version tag
// rather than a branch name. Matches patterns like "v1.2.3", "1.0.0", "v4.5.7-rc1".
func looksLikeVersionTag(ref string) bool {
	if ref == "" {
		return false
	}
	s := ref
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	// Must start with a digit after the optional 'v' prefix.
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9'
}
