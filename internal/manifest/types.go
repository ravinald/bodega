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

	// Frozen prevents this entry from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`
}

// IsRelease returns true when the entry should be fetched as a release tarball
// (the default). Returns false only when Source is explicitly "clone".
func (e GitEntry) IsRelease() bool { return e.Source != "clone" }

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

	// RequiredBy lists what this package is for (e.g., ["netbox"], ["standalone"]).
	// Empty means the package is a general-purpose dependency.
	RequiredBy []string `json:"required_by,omitempty"`

	// Checksum is the optional expected digest for the wheel archive.
	// When nil, no verification is performed.
	Checksum *Checksum `json:"checksum,omitempty"`

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

	// Filename overrides the basename of URL when set.
	Filename string `json:"filename,omitempty"`

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

	// Checksum is the expected digest for the module zip archive.
	// Auto-populated on first fetch if nil.
	Checksum *Checksum `json:"checksum,omitempty"`

	// Frozen prevents this entry from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`
}

// VersionedName returns "name@version".
func (e GomodEntry) VersionedName() string { return versionedName(e.Name, e.Version) }

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

	// Checksum is the expected digest for the chart .tgz archive.
	// Auto-populated on first fetch if nil.
	Checksum *Checksum `json:"checksum,omitempty"`

	// Frozen prevents this entry from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`
}

// VersionedName returns "name@version".
func (e HelmEntry) VersionedName() string { return versionedName(e.Name, e.Version) }

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

	// Checksum is the expected digest for the npm tarball.
	// Auto-populated on first fetch if nil.
	Checksum *Checksum `json:"checksum,omitempty"`

	// Frozen prevents this entry from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`
}

// VersionedName returns "name@version".
func (e NpmEntry) VersionedName() string { return versionedName(e.Name, e.Version) }

func versionedName(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}
