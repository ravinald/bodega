// Package manifest defines the unified type system for all package manifests.
// Each package is stored as a per-package JSON file (PackageManifest) containing
// a slice of VersionEntry values, allowing multiple versions to coexist. An
// Index provides fast name-based lookups without loading every manifest, and a
// DependencyGraph tracks inter-package relationships.
package manifest

import (
	"fmt"
	"strings"
)

// CurrentConfigVersion is the schema version written to all manifests.
const CurrentConfigVersion = 1

// Type constants identify the package ecosystem for a manifest.
const (
	TypeApt    = "apt"
	TypeGit    = "git"
	TypePypi   = "pypi"
	TypeBinary = "binary"
	TypeGomod  = "gomod"
	TypeHelm   = "helm"
	TypeNpm    = "npm"
	TypeCargo  = "cargo"

	// TypeFreeBSD is a mirrored FreeBSD pkg repository. Named for the OS
	// rather than for pkg, because "pkg" is already bodega's own subcommand
	// and `bodega pkg create pkg nginx` is a sentence nobody should have to
	// parse.
	TypeFreeBSD = "freebsd"
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
var AllTypes = []string{TypeBinary, TypeGit, TypeApt, TypePypi, TypeGomod, TypeHelm, TypeNpm, TypeCargo, TypeFreeBSD}

// Dependency is one dependency a version declares, recorded in the shape the
// registry protocol publishes rather than the shape the ecosystem's build file
// declares. package.json and Cargo.toml both carry forms no registry serves —
// a workspace member, a path, a git URL — so this holds what a resolver is
// handed, not what an author wrote.
//
// Name and Req are the pair every ecosystem has. The rest are cargo's sparse
// index members, which its protocol requires and npm has no equivalent for.
type Dependency struct {
	Name string `json:"name"`
	Req  string `json:"req"`

	// --- cargo sparse-index members ---

	Features []string `json:"features,omitempty"`
	Optional bool     `json:"optional,omitempty"`

	// DefaultFeatures mirrors cargo's own default of true, so the value worth
	// recording is the one that turns it off. Absent reads as false here and
	// is rendered back into the index line as the member cargo requires.
	DefaultFeatures bool `json:"default_features,omitempty"`

	// Target is the cfg() expression or triple this dependency is conditional
	// on. Empty is cargo's null: the dependency applies everywhere.
	Target string `json:"target,omitempty"`

	// Kind is "normal", "build" or "dev". Empty is cargo's "normal".
	Kind string `json:"kind,omitempty"`
}

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
	Platform  string `json:"platform"`             // "linux/amd64"
	OSRelease string `json:"os_release,omitempty"` // "Ubuntu 24.04.2 LTS"
	Python    string `json:"python,omitempty"`     // "3.12.3"
	Go        string `json:"go,omitempty"`         // "1.24.2"
	Rust      string `json:"rust,omitempty"`       // "1.78.0"
	Bodega    string `json:"bodega,omitempty"`     // build version
	BuiltAt   string `json:"built_at,omitempty"`   // RFC3339 timestamp
}

// PackageManifest is the on-disk representation of a single package.
// One JSON file is stored per package at {type}/{safeName}/manifest.json.
type PackageManifest struct {
	// ConfigVersion is the schema version; always CurrentConfigVersion on write.
	ConfigVersion int `json:"config_version"`

	// Name is the canonical package name (e.g. "widget", "lodash").
	Name string `json:"name"`

	// Type is the package ecosystem (e.g. TypeGit, TypeNpm).
	Type string `json:"type"`

	// Description is a short human-readable summary of what the package does.
	Description string `json:"description,omitempty"`

	// DepPolicy controls automatic dependency creation for this package.
	// "none" (default/empty): no auto-discovery. "direct": immediate deps only.
	// "transitive": full recursive closure.
	DepPolicy string `json:"dep_policy,omitempty"`

	// StoragePolicy names the backend this package's NEXT version should be
	// written to, overriding storage_by_type for this package alone.
	//
	// Future tense, and deliberately not spelled the same as
	// VersionEntry.Storage, which is past tense: this says where new bytes go,
	// that says where existing bytes already are. Setting this moves nothing —
	// 'bodega pkg move' does that. Empty means "no package-level rule", so the
	// type rule decides.
	StoragePolicy string `json:"storage_policy,omitempty"`

	// StorageGroups names the storage groups this package belongs to. A group
	// is resolved to a backend by storage_by_group in the config, and the
	// group rule sits between the type rule and StoragePolicy.
	//
	// Present tense, and the third spelling on purpose: StoragePolicy is
	// future tense (put the next version here) and VersionEntry.Storage is
	// past tense (this version's bytes are here), while this says what the
	// package *is a member of* and names no backend at all. Moving a group's
	// packages is an edit to storage_by_group, not to any manifest, which is
	// the whole reason the level exists. Setting this moves nothing.
	//
	// A list rather than one name because an operator groups by more than one
	// axis — an ecosystem's mirror set and a customer's set — and the two
	// overlap. Resolution is by group name in sort order, first with a rule
	// wins, so it never depends on the order this list happens to be written
	// in; admit refuses a membership whose groups resolve to two backends.
	StorageGroups []string `json:"storage_groups,omitempty"`

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

	// SourcePackage is the Debian source package this binary was built from,
	// as dpkg reports it in ${source:Package}.
	//
	// Separate from SourceName, which every importer fills with the name apt
	// downloads under and 'apt-get download' needs to stay the binary name.
	// This one is what USN and DSA are issued against: one source builds many
	// binaries, and OSV's Ubuntu and Debian ecosystems are keyed on the source
	// alone, so a lookup under "libexpat1" matches nothing while "expat"
	// answers. Empty means no capture recorded it, which is not the same as
	// "equal to the binary name": the OSV gate warns rather than reading an
	// empty answer as clean. See policy.osvLookupFor.
	SourcePackage string `json:"source_package,omitempty"`

	// CaptureSuite is the apt release the host this version was captured on
	// was running, as 'bodega pkg convert apt' records it from --suite or the
	// machine's /etc/os-release.
	//
	// Provenance, not placement: the OSV gate keys a distro advisory on the
	// release because Ubuntu and Debian backport a fix without moving the
	// upstream version, and the index generator ignores this field entirely.
	// Suites is the publishing field and cannot carry the release instead: a
	// server whose apt_codename is a house name serves suites the captured
	// host never named, so writing "noble" into Suites drops the entry out of
	// every generated index. Empty means no capture recorded a release; see
	// policy.osvLookupFor for what the gate does then.
	CaptureSuite string `json:"capture_suite,omitempty"`

	// BuildCmd is the shell command executed inside the cloned source directory
	// to produce a .deb file.
	BuildCmd string `json:"build_cmd,omitempty"`

	// DebGlob is a path glob (relative to the source dir) that locates the
	// produced .deb file after building.
	DebGlob string `json:"deb_glob,omitempty"`

	// Suites lists the apt suites (dists/<suite>/) this .deb is published to.
	// Empty means the server's default suite, so manifests written before the
	// field existed keep serving unchanged. The pool object is shared across
	// every listed suite: a flat pool/ is correct Debian layout.
	Suites []string `json:"suites,omitempty"`

	// --- freebsd-specific fields ---

	// Generated marks a pkg repository whose catalogue bodega builds and
	// signs from the objects stored under it, rather than copying one an
	// upstream published.
	//
	// The two are different products and a client configures for one or the
	// other. A mirrored repository carries FreeBSD's own signature inside
	// packagesite.pkg and its clients set signature_type: FINGERPRINTS
	// against the stock fingerprint; a generated one carries bodega's, and
	// regenerating is what discarded upstream's. So the flag is explicit
	// rather than inferred from an empty URL: an operator who forgets the
	// URL on a mirror would otherwise be served a regenerated catalogue,
	// and the failure a client reports names the signature rather than the
	// configuration that caused it. FreeBSDGenerated refuses the two
	// together for the same reason.
	Generated bool `json:"generated,omitempty"`

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
	// (e.g. ["widget"] for a pypi wheel pulled in by widget).
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

	// --- recorded by the fetch stage, alongside ArtifactSize ---

	// Dependencies is what this version declares it needs, recorded when the
	// artifact was fetched rather than read back per request. A packument
	// lists every version, so answering one metadata request by reading each
	// stored tarball is O(versions x size) on a route every client polls.
	//
	// Empty means no fetch recorded any, which is not the same as "this
	// version has none": an entry written before the field existed carries
	// nothing here until the next fetch runs.
	Dependencies []Dependency `json:"dependencies,omitempty"`

	// ArtifactDigest is the lowercase hex sha256 of the bytes the fetch stage
	// stored. Checksum is what upstream or the operator declared this version
	// should be; this is what bodega actually has.
	//
	// They are separate fields because they can legitimately disagree, and a
	// server that collapsed them would have no way to notice. Where they do,
	// the two records contradict each other about what this version is and
	// nothing here knows which one an operator meant.
	ArtifactDigest string `json:"artifact_digest,omitempty"`

	// Frozen prevents this version from being built, edited, or deleted.
	Frozen bool `json:"frozen,omitempty"`

	// Storage names the backend holding this version's artifact bytes.
	//
	// EMPTY MEANS "default" — NOT "resolve via the config hierarchy". Every
	// artifact uploaded before multi-backend existed lives in the one store now
	// called "default", so the zero value is already correct for everything in
	// the field. If empty meant "resolve now", the moment an operator set
	// storage_by_type.apt = "bulk" every already-uploaded .deb would become
	// unreadable.
	Storage string `json:"storage,omitempty"`

	// --- optional per-version documentation ---

	// Description overrides the package-level description for this specific version.
	Description string `json:"description,omitempty"`

	// Metadata holds ecosystem-specific key-value pairs (e.g. apt: Architecture,
	// Maintainer, Section, Priority, Installed-Size; npm: license, engines).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Public returns a copy of pm fit for the open read routes, which answer every
// caller the same way whatever its address or token: every version's URL, and
// every metadata value written as a URL, goes out through PublicURL, and a
// binary entry gets the filename binaryDownloadName gives it under key, its
// download alias whenever there is a key. pm is not modified, since the store
// may hand the same pointer to the next reader.
func (pm *PackageManifest) Public(key []byte) *PackageManifest {
	if pm == nil {
		return nil
	}
	out := *pm
	out.Versions = make([]VersionEntry, len(pm.Versions))
	for i, ve := range pm.Versions {
		if name, ok := pm.binaryDownloadName(key, i); ok {
			ve.Filename = name
		}
		ve.URL = PublicURL(ve.URL)
		if ve.Metadata != nil {
			md := make(map[string]string, len(ve.Metadata))
			for k, v := range ve.Metadata {
				md[k] = PublicMetadataValue(v)
			}
			ve.Metadata = md
		}
		out.Versions[i] = ve
	}
	return &out
}

// MetaAttestationURI is the metadata key naming a version's attestation
// envelope, which GET .../attestation redirects an http(s) value to.
const MetaAttestationURI = "attestation_uri"

// AttestationURIWithheld reports whether uri is one the attestation endpoint
// would redirect to while carrying something PublicURL withholds. The redirect
// hands its Location to the caller as written and cannot withhold part of it
// without breaking the fetch it exists for, so such a uri is refused at
// admission and never redirected to.
func AttestationURIWithheld(uri string) bool {
	redirected := strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://")
	return redirected && PublicURL(uri) != uri
}

// PublicMetadataValue returns v as a caller with no token may see it: through
// PublicURL when v is written as a URL, and unchanged otherwise.
//
// Metadata is public by contract, since bodega never fetches with a metadata
// value and so has no use for a credential in one. The URL form is the
// exception because it is the one a credential arrives in by accident, pasted
// with the link it authorizes. A value only counts as a URL when a scheme is
// followed by a slash or backslash, or the scheme is http or https, which
// browsers read without one: PublicURL on "Name <a@b>" or "C#" would cut text
// that was never an authority or a query.
func PublicMetadataValue(v string) string {
	if !isURLForm(v) {
		return v
	}
	return PublicURL(v)
}

func isURLForm(v string) bool {
	s := browserTrim(v)
	n := schemeLen(s)
	if n == 0 {
		return strings.HasPrefix(s, "//") || strings.HasPrefix(s, "\\\\")
	}
	if rest := s[n:]; strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, "\\") {
		return true
	}
	scheme := strings.ToLower(s[:n-1])
	return scheme == "http" || scheme == "https"
}

// PublicURL returns raw without the userinfo in its authority and without its
// query or fragment.
//
// A query string is where a token goes when the upstream will not take one in
// the authority (?token=, ?access_token=, a presigned signature), and nothing
// about a parameter's name says whether its value is a secret, so the whole
// query goes rather than a list of names that misses the next spelling. The
// fragment goes with it: no fetch sends one, so nothing bodega does needs it,
// and a value there is no safer to publish than one before it. The cut is at
// the first "?" or "#" after the userinfo is gone, which in a git scp path
// over-cuts a display string and never under-cuts.
//
// The username goes too, not only the password url.URL.Redacted masks: a
// GitHub or GitLab token written as https://<token>@host/ is a bare username
// to that method, which returns it unchanged. The authority is cut by hand
// rather than through url.Parse, which reads "user:secret@host/path" as the
// scheme "user" with an opaque remainder and reports no userinfo at all, and
// which refuses the scp form git accepts.
//
// The readers of a manifest url disagree about where its authority ends, and
// the cut takes the widest of them. A browser strips leading spaces and every
// tab and newline, treats a "\" after the scheme as "/", and finds an
// authority after "https:" with no slashes at all; curl reads a later "\" as
// part of the authority. git's ssh transport ends the host of "ssh://..." at
// the first "/" alone, after percent-decoding it, and the host of the scp form
// "user@host:path" at the first ":", so "?" and "#" end no authority there:
// ssh is handed "a#b@host" and logs in as "a#b". So an authority after slashes,
// or in a string with no scheme, ends at the first "/", and an "@" spelled
// "%40" counts as one. Over-cutting costs a display string, while
// under-cutting publishes the credential, so a scheme followed by no slash is
// dropped with the userinfo: "user:secret@host" has the same form and nothing
// tells the two apart.
func PublicURL(raw string) string {
	s := withoutUserinfo(raw)
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		return s[:i]
	}
	return s
}

func withoutUserinfo(raw string) string {
	s := browserTrim(raw)

	afterScheme := schemeLen(s)
	start := afterScheme
	for start < len(s) && (s[start] == '/' || s[start] == '\\') {
		start++
	}
	slashes := start > afterScheme

	end := indexOrLen(s, start, "/")
	if !slashes && afterScheme > 0 {
		end = indexOrLen(s, start, "/?#")
	}
	cut := afterUserinfo(s[start:end])
	if cut < 0 {
		return raw
	}
	cut += start
	prefix := ""
	if slashes {
		prefix = s[:start]
	}
	if s[start] == '[' && strings.IndexByte(s[start:cut], ']') < 0 {
		prefix += "["
	}
	return prefix + s[cut:]
}

// browserTrim drops what a browser drops from a URL before reading it: every
// tab and newline, and leading spaces and control characters.
func browserTrim(raw string) string {
	s := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, raw)
	return strings.TrimLeftFunc(s, func(r rune) bool { return r <= ' ' })
}

// indexOrLen returns the index of the first byte of s at or past from that is
// in chars, or len(s) when none is.
func indexOrLen(s string, from int, chars string) int {
	if i := strings.IndexAny(s[from:], chars); i >= 0 {
		return from + i
	}
	return len(s)
}

// afterUserinfo returns the offset in authority just past its last "@" or
// "%40", or -1 when it holds neither.
func afterUserinfo(authority string) int {
	at := strings.LastIndexByte(authority, '@')
	if at >= 0 {
		at++
	}
	if enc := strings.LastIndex(strings.ToLower(authority), "%40"); enc >= 0 && enc+3 > at {
		at = enc + 3
	}
	return at
}

// schemeLen returns the length of s's leading "scheme:", or 0 when s opens
// with none (RFC 3986: a letter, then letters, digits, "+", "-" or ".").
func schemeLen(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
		case i > 0 && ('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'):
		case i > 0 && c == ':':
			return i + 1
		default:
			return 0
		}
	}
	return 0
}

// ScopeToVersion returns pm with Versions narrowed to the single entry
// matching v. Result is still a valid PackageManifest so it round-trips
// through import/export. nil for unknown or empty v.
func (pm *PackageManifest) ScopeToVersion(v string) *PackageManifest {
	if pm == nil || v == "" {
		return nil
	}
	for _, ve := range pm.Versions {
		if ve.Version == v || ve.Ref == v {
			scoped := *pm
			scoped.Versions = []VersionEntry{ve}
			return &scoped
		}
	}
	return nil
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

// FreeBSDGenerated reports whether this pkg repository's catalogue is built
// here, and refuses an entry that claims to be both generated and mirrored.
//
// One admission point, because three callers ask and each would act on a
// different guess: the server decides per request whether to serve the stored
// catalogue or the generated one, the fetch stage decides whether there is
// anything upstream to mirror, and the upload decides whether the three root
// files are its to publish. An entry carrying a URL and generated: true
// contradicts itself about which of two signatures a client is meant to
// trust, and nothing downstream can resolve that from the bytes.
//
// proxy is refused with it for the same reason: proxy holds no snapshot and
// fetches every path from upstream on a miss, so a generated catalogue would
// describe objects the store was never asked to keep.
func (ve VersionEntry) FreeBSDGenerated() (bool, error) {
	if !ve.Generated {
		return false, nil
	}
	if ve.URL != "" {
		return false, fmt.Errorf("the entry is marked generated and also records url %q; a generated repository has no upstream catalogue to copy and a mirrored one must not be regenerated — drop the url to generate, or drop generated to mirror", ve.URL)
	}
	if ve.EffectiveMode() == ModeProxy {
		return false, fmt.Errorf("the entry is marked generated and also mode %q; proxy serves every path from upstream and keeps no snapshot, so there is nothing for a generated catalogue to name", ModeProxy)
	}
	return true, nil
}

// EffectiveSuites returns the apt suites this entry is published to, falling
// back to def when the entry names none.
func (ve VersionEntry) EffectiveSuites(def string) []string {
	if len(ve.Suites) > 0 {
		return ve.Suites
	}
	if def == "" {
		return nil
	}
	return []string{def}
}

// InSuite reports whether this entry is published to suite s, treating an
// entry with no suites as belonging to def.
func (ve VersionEntry) InSuite(s, def string) bool {
	for _, x := range ve.EffectiveSuites(def) {
		if x == s {
			return true
		}
	}
	return false
}

// DepEdge represents a directed dependency from a parent package to a child package.
// Names are formatted as "type/name" (e.g. "git/widget").
type DepEdge struct {
	// Parent is the package that depends on Child (e.g. "git/widget@v4.5.7").
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

// CanonicalPypiName applies the PEP 503 rule to a distribution name:
// lowercase, then collapse any run of `-`, `_` and `.` to a single `-`.
//
// One function for the whole tree because the two that preceded it disagreed on
// `.`: the allow-list matcher collapsed `_` alone, so a rule written
// `zope.interface` matched nothing the route spelled `zope-interface`, and a
// distribution cataloged from `pip list` under its published capitalization was
// unreachable by the client that inventory came from.
func CanonicalPypiName(name string) string {
	lower := strings.ToLower(name)
	var b strings.Builder
	b.Grow(len(lower))
	prevSep := false
	for _, r := range lower {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
			}
			prevSep = true
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return b.String()
}

// CanonicalName is the name a manifest of this type is stored and looked up
// under. pypi is canonicalized per PEP 503; every other type is returned
// unchanged, because an npm scope is case-sensitive, a Go module path is not a
// distribution name, and a crate or chart name carries no separator the rule
// would collapse.
func CanonicalName(typ, name string) string {
	if typ == TypePypi {
		return CanonicalPypiName(name)
	}
	return name
}

// ValidatePackageName rejects the two names SafeName cannot make into an
// ordinary path segment.
//
// SafeName collapses "/" to "--", so a name contributes exactly one segment
// and can never add a path level. "." and ".." survive that untouched and are
// then resolved as path syntax: manifestPath("apt", "..") cleans to
// manifest.json at the manifest root, the same file manifestPath("npm", "..")
// cleans to, so two packages of different types share one manifest and the
// second write replaces the first. "." lands at apt/manifest.json, inside the
// type directory where no package belongs.
//
// The fix is a refusal here rather than an encoding in SafeName. SafeName is
// half of a round trip — unsafeName reads a stored segment back into a name —
// so a new encoding would need a matching decode, would not move the manifests
// already written at the colliding path, and would change key derivation that
// cmd/bodega/objectkeys_test.go and placement_test.go pin. Nothing legitimate
// is named "." or "..", so refusing costs nothing and moves nothing.
func ValidatePackageName(name string) error {
	if name == "." || name == ".." {
		return fmt.Errorf("invalid package name %q: it is path syntax, not a name — %q resolves to a manifest path outside its own type directory", name, name)
	}
	return nil
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

// IsKnownType reports whether t names a package ecosystem bodega manages.
// AllTypes is the single gate: a per-caller switch drifts, and the mutation
// API's copy had already lost cargo.
func IsKnownType(t string) bool {
	for _, known := range AllTypes {
		if t == known {
			return true
		}
	}
	return false
}
