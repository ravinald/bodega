// Package manifest defines the data types for all four source types.
// Each manifest is a JSON object with a config_version key and type-specific fields.
package manifest

// Checksum records an expected digest for integrity verification.
// Algorithm is one of "md5", "sha1", "sha256", or "sha512".
// Value is the lowercase hex-encoded digest string.
type Checksum struct {
	Algorithm string `json:"algorithm"` // "md5", "sha1", "sha256", "sha512"
	Value     string `json:"value"`
}

// BuildEnv captures the build server's environment at the time an artifact
// was produced. Populated automatically -- the operator does not set this.
type BuildEnv struct {
	Platform  string `json:"platform"`              // "linux/amd64"
	OSRelease string `json:"os_release,omitempty"`   // "Ubuntu 24.04.2 LTS"
	Python    string `json:"python,omitempty"`       // "3.12.3"
	Go        string `json:"go,omitempty"`           // "1.24.2"
	Rust      string `json:"rust,omitempty"`         // "1.78.0"
	Bodega    string `json:"bodega,omitempty"`        // build version
	BuiltAt   string `json:"built_at,omitempty"`     // RFC3339 timestamp
}

// CurrentConfigVersion is the schema version written to all manifests.
const CurrentConfigVersion = 1

// AptManifest is the top-level envelope for apt.json.
type AptManifest struct {
	ConfigVersion int        `json:"config_version"`
	Entries       []AptEntry `json:"entries"`
}

// GitManifest is the top-level envelope for git.json.
type GitManifest struct {
	ConfigVersion int        `json:"config_version"`
	Entries       []GitEntry `json:"entries"`
}

// BinaryManifest is the top-level envelope for binary.json.
type BinaryManifest struct {
	ConfigVersion int           `json:"config_version"`
	Entries       []BinaryEntry `json:"entries"`
}

// AptEntry describes a single Debian package to build or download.
type AptEntry struct {
	// Name is the logical name used everywhere in bootstrap (e.g. "amazon-efs-utils").
	Name string `json:"name"`

	// Version pins the package version. Used in S3 paths and build directories
	// to allow multiple versions to coexist.
	Version string `json:"version,omitempty"`

	// SourceName is the upstream package / directory name, defaults to Name when absent.
	SourceName string `json:"source_name,omitempty"`

	// URL is the git repository to clone for a source build. When omitted the
	// package is fetched from the system apt repository.
	URL string `json:"url,omitempty"`

	// BuildCmd is the shell command executed inside the cloned source directory
	// to produce a .deb file.
	BuildCmd string `json:"build_cmd,omitempty"`

	// DebGlob is a path glob (relative to the source dir) used to locate the
	// produced .deb file after building.
	DebGlob string `json:"deb_glob,omitempty"`

	// Checksum is the optional expected digest for the produced artifact.
	// When nil, no verification is performed.
	Checksum *Checksum `json:"checksum,omitempty"`

	// ChecksumVerified is true when the checksum was confirmed against a source-published digest.
	ChecksumVerified bool `json:"checksum_verified,omitempty"`

	// VersionConstraint qualifies how Version is matched: "exact" (default), "any", or "gte".
	VersionConstraint string `json:"version_constraint,omitempty"`

	// Description is a short summary of the package, auto-discovered from upstream.
	Description string `json:"description,omitempty"`
	Platform string `json:"platform,omitempty"`
	BuildEnv *BuildEnv `json:"build_env,omitempty"`

	// Hidden excludes this version from being served to clients.
	Hidden bool `json:"hidden,omitempty"`

	// Frozen prevents this entry from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`
}

// VersionedName returns "name@version" or just "name" if no version is set.
func (e AptEntry) VersionedName() string { return versionedName(e.Name, e.Version) }

// GitEntry describes a git repository to fetch (via release tarball or clone).
type GitEntry struct {
	// Name is the logical name (e.g. "netbox").
	Name string `json:"name"`

	// URL is the remote repository URL.
	URL string `json:"url"`

	// Ref is the git ref (tag, branch, or commit SHA).
	// This also serves as the version identifier.
	Ref string `json:"ref"`

	// Source controls how the repo is obtained:
	//   "release" (default) — download the release tarball (smaller, faster)
	//   "clone"             — git clone --bare + bundle (full history)
	Source string `json:"source,omitempty"`

	// Checksum is the computed digest of the downloaded artifact (tar.gz or bundle).
	Checksum *Checksum `json:"checksum,omitempty"`

	// ChecksumVerified is true when the computed checksum was confirmed against
	// a checksum published by the source (e.g. GitHub release asset).
	ChecksumVerified bool `json:"checksum_verified,omitempty"`

	// Description is a short summary of the package, auto-discovered from upstream.
	Description string `json:"description,omitempty"`
	Platform string `json:"platform,omitempty"`
	BuildEnv *BuildEnv `json:"build_env,omitempty"`

	// Hidden excludes this version from being served to clients.
	Hidden bool `json:"hidden,omitempty"`

	// Frozen prevents this entry from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`
}

// IsRelease returns true when the entry should be fetched as a release tarball.
// When Source is explicitly set, that value is used. Otherwise it auto-detects
// from Ref: version-like refs (e.g. v4.5.7, 1.0.0) use release mode, while
// branch-like refs (e.g. main, develop) use clone mode.
func (e GitEntry) IsRelease() bool {
	switch e.Source {
	case "release":
		return true
	case "clone":
		return false
	default:
		return looksLikeVersionTag(e.Ref)
	}
}

// looksLikeVersionTag returns true if ref appears to be a version tag
// rather than a branch name. Matches patterns like "v1.2.3", "1.0.0",
// "v4.5.7-rc1", etc.
func looksLikeVersionTag(ref string) bool {
	if ref == "" {
		return false
	}
	s := ref
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	// Must start with a digit after optional 'v' prefix.
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9'
}

// VersionedName returns "name@ref".
func (e GitEntry) VersionedName() string { return versionedName(e.Name, e.Ref) }

// PypiManifest is the top-level object in pypi.json.
// The schema differs from the other manifest types — it holds a map of
// "base requirements" references to git repos plus a flat list of extra
// packages.
// PypiPackage describes a single Python package in the pypi manifest.
type PypiPackage struct {
	// Name is the pip package specifier (e.g., "boto3", "social-auth-core[openidconnect]").
	Name string `json:"name"`

	// Version pins the package version. When empty, pip resolves the latest.
	Version string `json:"version,omitempty"`

	// RequiredBy lists what this package is for (e.g., ["netbox"], ["standalone"]).
	// Empty means the package is a general-purpose dependency.
	RequiredBy []string `json:"required_by,omitempty"`

	// Mode controls how this package is served: "hosted" (default) or "proxy".
	// Hosted: wheels are built locally and uploaded to S3.
	// Proxy: on cache miss, fetch from upstream PyPI and cache in S3.
	Mode string `json:"mode,omitempty"`

	// VersionConstraint qualifies how Version is matched: "exact" (default), "any", or "gte".
	VersionConstraint string `json:"version_constraint,omitempty"`

	// Checksum is the optional expected digest for the wheel archive.
	// When nil, no verification is performed.
	Checksum *Checksum `json:"checksum,omitempty"`

	// ChecksumVerified is true when the checksum was confirmed against a source-published digest.
	ChecksumVerified bool `json:"checksum_verified,omitempty"`

	// Description is a short summary of the package, auto-discovered from upstream.
	Description string `json:"description,omitempty"`
	Platform string `json:"platform,omitempty"`
	BuildEnv *BuildEnv `json:"build_env,omitempty"`

	// Hidden excludes this version from being served to clients.
	Hidden bool `json:"hidden,omitempty"`

	// Frozen prevents this individual package from being edited or deleted.
	Frozen bool `json:"frozen,omitempty"`
}

// PypiManifest is the top-level object in pypi.json.
type PypiManifest struct {
	// ConfigVersion is the schema version.
	ConfigVersion int `json:"config_version"`

	// Version labels this wheel set (e.g., "v4.5.5" matching the netbox version).
	Version string `json:"version,omitempty"`

	// BaseRequirements maps a git repo name to the ref whose requirements.txt
	// should be included in the wheel build (e.g. {"netbox": "v4.5.5"}).
	BaseRequirements map[string]string `json:"base_requirements"`

	// Packages is the list of Python packages to build as wheels.
	Packages []PypiPackage `json:"packages"`

	// Hidden excludes this version from being served to clients.
	Hidden bool `json:"hidden,omitempty"`

	// Frozen prevents the entire pypi manifest from being edited.
	Frozen bool `json:"frozen,omitempty"`
}

// BinaryEntry describes a file to download directly from a URL.
type BinaryEntry struct {
	// Name is the logical name (e.g. "awscli-v2").
	Name string `json:"name"`

	// Version pins the binary version. Used in S3 paths to allow multiple
	// versions to coexist.
	Version string `json:"version,omitempty"`

	// URL is the download URL.
	URL string `json:"url"`

	// SHA256 is the expected hex digest; nil means no verification.
	SHA256 *string `json:"sha256"`

	// Checksum is the optional expected digest using an explicit algorithm.
	// When nil, no additional verification is performed beyond SHA256.
	Checksum *Checksum `json:"checksum,omitempty"`

	// ChecksumVerified is true when the checksum was confirmed against a source-published digest.
	ChecksumVerified bool `json:"checksum_verified,omitempty"`

	// Filename overrides the basename of URL when set.
	Filename string `json:"filename,omitempty"`

	// VersionConstraint qualifies how Version is matched: "exact" (default), "any", or "gte".
	VersionConstraint string `json:"version_constraint,omitempty"`

	// Description is a short summary of the package, auto-discovered from upstream.
	Description string `json:"description,omitempty"`
	Platform string `json:"platform,omitempty"`
	BuildEnv *BuildEnv `json:"build_env,omitempty"`

	// Hidden excludes this version from being served to clients.
	Hidden bool `json:"hidden,omitempty"`

	// Frozen prevents this entry from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`
}

// VersionedName returns "name@version" or just "name" if no version is set.
func (e BinaryEntry) VersionedName() string { return versionedName(e.Name, e.Version) }

// Type constants used throughout the codebase.
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

// AllTypes is the canonical build order.
var AllTypes = []string{TypeBinary, TypeGit, TypeApt, TypePypi, TypeGomod, TypeHelm, TypeNpm}

// GomodManifest is the top-level envelope for gomod.json.
type GomodManifest struct {
	ConfigVersion int          `json:"config_version"`
	Entries       []GomodEntry `json:"entries"`
}

// GomodEntry describes a Go module to mirror or proxy.
type GomodEntry struct {
	// Name is the module path (e.g. "github.com/aws/aws-sdk-go-v2").
	Name string `json:"name"`

	// Version is the module version (e.g. "v1.30.0").
	Version string `json:"version"`

	// URL is the upstream GOPROXY URL. When empty, proxy.golang.org is used.
	URL string `json:"url,omitempty"`

	// Mode controls how this entry is served: "hosted" (default) or "proxy".
	Mode string `json:"mode,omitempty"`

	// VersionConstraint qualifies how Version is matched: "exact" (default), "any", or "gte".
	VersionConstraint string `json:"version_constraint,omitempty"`

	// Checksum is the expected digest for the module zip archive.
	// Auto-populated on first fetch if nil.
	Checksum *Checksum `json:"checksum,omitempty"`

	// ChecksumVerified is true when the checksum was confirmed against a source-published digest.
	ChecksumVerified bool `json:"checksum_verified,omitempty"`

	// Description is a short summary of the package, auto-discovered from upstream.
	Description string `json:"description,omitempty"`
	Platform string `json:"platform,omitempty"`
	BuildEnv *BuildEnv `json:"build_env,omitempty"`

	// Hidden excludes this version from being served to clients.
	Hidden bool `json:"hidden,omitempty"`

	// Frozen prevents this entry from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`
}

// VersionedName returns "name@version".
func (e GomodEntry) VersionedName() string { return versionedName(e.Name, e.Version) }

// EffectiveMode returns the entry's mode, defaulting to ModeHosted.
func (e GomodEntry) EffectiveMode() string {
	if e.Mode == "" {
		return ModeHosted
	}
	return e.Mode
}

// HelmManifest is the top-level envelope for helm.json.
type HelmManifest struct {
	ConfigVersion int         `json:"config_version"`
	Entries       []HelmEntry `json:"entries"`
}

// HelmEntry describes a Helm chart to mirror.
type HelmEntry struct {
	// Name is the chart name (e.g. "ingress-nginx").
	Name string `json:"name"`

	// Version is the chart version.
	Version string `json:"version"`

	// URL is the chart repository URL or direct .tgz download URL.
	URL string `json:"url"`

	// AppVersion is the application version the chart deploys.
	AppVersion string `json:"app_version,omitempty"`

	// Mode controls how this entry is served: "hosted" (default) or "proxy".
	Mode string `json:"mode,omitempty"`

	// VersionConstraint qualifies how Version is matched: "exact" (default), "any", or "gte".
	VersionConstraint string `json:"version_constraint,omitempty"`

	// Checksum is the expected digest for the chart .tgz archive.
	// Auto-populated on first fetch if nil.
	Checksum *Checksum `json:"checksum,omitempty"`

	// ChecksumVerified is true when the checksum was confirmed against a source-published digest.
	ChecksumVerified bool `json:"checksum_verified,omitempty"`

	// Description is a short summary of the package, auto-discovered from upstream.
	Description string `json:"description,omitempty"`
	Platform string `json:"platform,omitempty"`
	BuildEnv *BuildEnv `json:"build_env,omitempty"`

	// Hidden excludes this version from being served to clients.
	Hidden bool `json:"hidden,omitempty"`

	// Frozen prevents this entry from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`
}

// VersionedName returns "name@version".
func (e HelmEntry) VersionedName() string { return versionedName(e.Name, e.Version) }

// EffectiveMode returns the entry's mode, defaulting to ModeHosted.
func (e HelmEntry) EffectiveMode() string {
	if e.Mode == "" {
		return ModeHosted
	}
	return e.Mode
}

// NpmManifest is the top-level envelope for npm.json.
type NpmManifest struct {
	ConfigVersion int        `json:"config_version"`
	Entries       []NpmEntry `json:"entries"`
}

// NpmEntry describes an npm package to mirror or proxy.
type NpmEntry struct {
	// Name is the package name (e.g. "lodash" or "@scope/pkg").
	Name string `json:"name"`

	// Version is the semver version.
	Version string `json:"version"`

	// URL is the upstream registry URL. When empty, registry.npmjs.org is used.
	URL string `json:"url,omitempty"`

	// Mode controls how this entry is served: "hosted" (default) or "proxy".
	Mode string `json:"mode,omitempty"`

	// VersionConstraint qualifies how Version is matched: "exact" (default), "any", or "gte".
	VersionConstraint string `json:"version_constraint,omitempty"`

	// Checksum is the expected digest for the npm tarball.
	// Auto-populated on first fetch if nil.
	Checksum *Checksum `json:"checksum,omitempty"`

	// ChecksumVerified is true when the checksum was confirmed against a source-published digest.
	ChecksumVerified bool `json:"checksum_verified,omitempty"`

	// Description is a short summary of the package, auto-discovered from upstream.
	Description string `json:"description,omitempty"`
	Platform string `json:"platform,omitempty"`
	BuildEnv *BuildEnv `json:"build_env,omitempty"`

	// Hidden excludes this version from being served to clients.
	Hidden bool `json:"hidden,omitempty"`

	// Frozen prevents this entry from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`
}

// VersionedName returns "name@version".
func (e NpmEntry) VersionedName() string { return versionedName(e.Name, e.Version) }

// EffectiveMode returns the entry's mode, defaulting to ModeHosted.
func (e NpmEntry) EffectiveMode() string {
	if e.Mode == "" {
		return ModeHosted
	}
	return e.Mode
}

func versionedName(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}
