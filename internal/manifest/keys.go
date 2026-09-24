package manifest

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Object keys — the one derivation of where an artifact's bytes live.
//
// The uploader (internal/builder), every server handler, 'bodega build status'
// (internal/inventory), 'bodega pkg move' and the delete path all resolve
// through this file. Four independent derivations existed before, and three of
// them probed keys nothing wrote.
//
// Two rules callers must not re-implement:
//
//   - Names arrive canonical, slashes intact ("@example-corp/widget-cli",
//     "example.com/example-corp/widget-sdk"). Each function applies the encoding its
//     ecosystem's layout needs. Passing a pre-encoded name is harmless for the
//     safe-name types (SafeName is idempotent) and wrong for gomod.
//   - gomod alone keeps its slashes. A Go client requests
//     GET /<module>/@v/<version>.zip with the module path verbatim, so there is
//     no point on the wire at which an encoded key could be rewritten back.
//
// This package cannot import internal/storage, so no key here can depend on
// what a backend happens to contain. Resolving an apt entry that predates the
// _pool_path metadata key needs a listing, and that lookup lives in
// internal/inventory behind ErrAptPoolPathUnknown rather than turning every
// other key into a round trip.

// Key prefixes shared by writers, readers and the generated indexes that sit
// alongside the artifacts.
const (
	// AptPrefix roots the whole apt tree; dists/ is generated per request and
	// only pool/ holds uploaded bytes.
	AptPrefix     = "packages/apt/"
	AptPoolPrefix = AptPrefix + "pool/"

	// PypiWheelPrefix is where wheels are synced. They upload as a directory
	// with no per-version key, which is why pypi has no ArtifactKeys answer.
	PypiWheelPrefix = "pypi/wheels/"

	// HelmIndexKey is the generated chart index: regenerable, so it is routed
	// by type rather than by any version's recorded backend.
	HelmIndexKey = "charts/index.yaml"

	// GitPrefix roots the bundle tree. Bundles are synced as a directory, so
	// the prefix is named separately from the per-version key.
	GitPrefix = "repos/"

	// BinaryPrefix roots the direct-download tree. The TUI uploads it as a
	// whole-directory sync, so the prefix is named separately from the
	// per-version key BinaryKey builds.
	BinaryPrefix = "binaries/"

	// FreeBSDPrefix roots the mirrored pkg tree. Everything under it is a
	// byte-exact copy of an upstream repository, keyed by the path that
	// repository serves it at, so the whole subtree diffs against the
	// upstream URL with no decoding step in between.
	FreeBSDPrefix = "freebsd/"

	gomodPrefix      = "gomod/"
	helmPrefix       = "charts/"
	npmPrefix        = "npm/"
	cargoCratePrefix = "cargo/crates/"
	cargoIndexPrefix = "cargo/index/"
)

// ErrPypiNoObjectKey reports that a pypi entry has no per-version object.
// Callers that delete or move an artifact must surface this rather than treat
// it as "nothing to do": the wheels exist, they just are not addressable one
// version at a time.
//
// A manifest entry is not one artifact. One approved version pulls in a whole
// dependency closure, and the closure's members are addressable one file at a
// time through PypiWheelKey — which is what the fetch pins a digest against.
// This sentinel is about the entry, not about the bytes.
var ErrPypiNoObjectKey = errors.New("pypi wheels upload as a directory and have no per-version object key")

// ErrAptPoolPathUnknown reports that an apt entry carries no _pool_path, so
// its .deb can only be found by listing the pool. internal/inventory owns that
// fallback; this package has no backend to ask.
var ErrAptPoolPathUnknown = errors.New("apt entry records no _pool_path")

// FreeBSD catalogue members, served at a repository's root. pkg asks for
// meta.conf first on every update and reads packing_format out of it; the two
// .pkg archives are zstd tarballs carrying FreeBSD's own detached signature
// as members, which is why nothing here may be regenerated.
const (
	FreeBSDMetaFile    = "meta.conf"
	FreeBSDCatalogFile = "packagesite.pkg"
	FreeBSDDataFile    = "data.pkg"
)

// FreeBSDCatalogFiles is the repository root's whole served set, catalogue
// last. Ordering is not cosmetic: a client that reads packagesite.pkg before
// the objects it names installs half a package set, so the mirror writes
// every object first and these afterwards. See FreeBSDArtifactPaths.
var FreeBSDCatalogFiles = []string{FreeBSDMetaFile, FreeBSDDataFile, FreeBSDCatalogFile}

// FreeBSDLegacyRootFiles are the repository-root paths pkg asks for on a
// repository built before 1.17, and that no current one publishes. The route
// answers them 404 by name rather than proxying somebody else's.
//
// They sit beside the served three because both halves state the same fact:
// the repository root is the mirror's own namespace. An object stored under
// one of these names is one no request can ever reach, whatever put it there.
var FreeBSDLegacyRootFiles = []string{"digests.pkg", "digests.txz", "packagesite.txz", "repo.txz"}

// FreeBSDFallbackRootFiles are the repository-root paths pkg asks for when the
// served three are missing, and that a real repository may still publish.
//
// pkg 2.7.5 (libpkg/pkg_repo.c, pkg_repo_fetch_meta and
// pkg_repo_fetch_extract_to_fd) asks for meta.conf and then meta.txz, and for
// each of data and packagesite asks for <name>.pkg and then
// <name>.<packing_format>, where packing_format is whatever meta.conf says
// (tzst, txz, tbz, tgz or tar) and tzst when there is no meta.conf. A mirrored
// repository serves only FreeBSDCatalogFiles, so a request for any of these
// means its catalogue is not there yet, and fetching one from upstream would
// serve upstream's catalogue over this mirror's objects. They are not on
// FreeBSDLegacyRootFiles because pkg 1.17 through 1.20 publish the .tzst pair
// for real, and a proxy-mode entry in front of such a repository needs them
// fetched. packagesite.txz is on that list already and stays refused there.
//
// The data and packagesite names are pkg's defaults. meta.conf's data and
// manifests keys rename them, and pkg asks for <renamed>.pkg and then
// <renamed>.<packing_format>, so a client of a mirror whose meta.conf renames
// them asks for names on no list here, and a hosted entry with
// proxy_cache_enabled fetches those from upstream like any package.
//
// Unlike FreeBSDCatalogFiles, nothing ever writes a file under one of these
// names, so only the name itself is reserved: a package under a directory
// called data.tzst collides with no file this repository serves.
var FreeBSDFallbackRootFiles = []string{
	"meta.txz",
	"data.tzst", "data.txz", "data.tbz", "data.tgz", "data.tar",
	"packagesite.tzst", "packagesite.tbz", "packagesite.tgz", "packagesite.tar",
}

// FreeBSDReservedRoot reports whether a repository-relative path belongs to
// the repository root rather than to a package, and names the file it lands on.
//
// A repopath is untrusted input: it decides an object key, a local path and an
// upstream URL, and a catalogue naming one of these turns a package into
// repository metadata. Every writer would then act on it before the ordering
// that protects a client can apply — the mirror downloads a package over the
// meta.conf in its tree, the upload puts one in the object half of its
// publication and so replaces a served catalogue ahead of the object set, and
// the move copies it out of the source root inside its object loop. Three
// writers, one admission point: the catalogue reader refuses the record, and
// the names live here because this is where the keys those writers collide in
// are built.
//
// For the served and legacy names the first segment decides it, so
// "data.pkg/x.pkg" is refused as data.pkg. A filesystem gives a name to a file
// or to a directory and not to both, and storage.Local is a filesystem. Case
// folds for the same reason: APFS answers "Meta.conf" with meta.conf, so the
// key scheme's case sensitivity is not what decides whether two paths are one
// file. A fallback name is refused as the whole path only, case folded, since
// no file is ever written under it for a directory to collide with; an object
// stored there is still one the route never serves from a hosted entry. A
// package at the repository root is an ordinary layout and stays admitted;
// these names alone are not its to take.
func FreeBSDReservedRoot(repoPath string) (string, bool) {
	first, _, _ := strings.Cut(repoPath, "/")
	for _, name := range FreeBSDCatalogFiles {
		if strings.EqualFold(first, name) {
			return name, true
		}
	}
	for _, name := range FreeBSDLegacyRootFiles {
		if strings.EqualFold(first, name) {
			return name, true
		}
	}
	for _, name := range FreeBSDFallbackRootFiles {
		if strings.EqualFold(repoPath, name) {
			return name, true
		}
	}
	return "", false
}

// FreeBSDRepoPrefix roots one mirrored repository: "freebsd/<abi>/<repo>/".
//
// abi is the ABI directory a pkg client substitutes for ${ABI}
// ("FreeBSD:14:amd64") and is a version here; repo is the repository name
// under it ("latest", "base_latest") and is the package name. Both go in
// literally. An ABI carries colons and a catalogue's repopath carries "~" and
// "$", all three of which S3 accepts in a key and every POSIX filesystem
// accepts in a path, so encoding them would buy nothing and cost a decoder in
// ParseKey, in the route, in the discovery row and in 'bodega pkg move' —
// four places where a wrong decode serves the wrong bytes under a signature
// that still verifies.
func FreeBSDRepoPrefix(abi, repo string) string {
	return FreeBSDPrefix + abi + "/" + repo + "/"
}

// freeBSDABIPattern matches an ABI directory. The colons are literal and are
// the reason this is a pattern rather than a segment check: "FreeBSD:14:amd64"
// is one path segment carrying two of them, and a scheme that rejected the
// colon would fail against every real repository.
var freeBSDABIPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// freeBSDRepoPattern matches a repository directory. One segment, no
// separators: "latest", "quarterly", "base_latest".
var freeBSDRepoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// FreeBSDValidABI reports whether abi is an ABI directory this mirror can key
// and serve.
//
// It lives beside the key scheme rather than in the route, because the route
// is not the only caller: an entry created with an ABI the route will refuse
// is one whose every request 400s, and the form that created it is where that
// is cheap to say.
func FreeBSDValidABI(abi string) bool { return freeBSDABIPattern.MatchString(abi) }

// FreeBSDValidRepo reports whether repo is a repository directory this mirror
// can key and serve. It is the package name for this type.
func FreeBSDValidRepo(repo string) bool { return freeBSDRepoPattern.MatchString(repo) }

// FreeBSDValidRepoPath reports why a repository-relative path is not one this
// mirror can serve, or nil when it is.
//
// One predicate, because a path that fails it is unreachable whichever side
// produced it. The route composes an object key from the request path, and a
// generated catalogue publishes repopath as the only authority on where an
// object lives; a generator admitting a name the route refuses publishes a
// record whose download 400s after `pkg update` has already reported success.
// The two halves have to agree by construction rather than by inspection.
//
// The reserved root files are not checked here, because the route does not
// refuse them: it answers them from the catalogue instead. A caller that
// stores objects checks FreeBSDReservedRoot as well.
func FreeBSDValidRepoPath(repoPath string) error {
	switch {
	case repoPath == "":
		return errors.New("the path is empty, so it names no object")
	case strings.HasPrefix(repoPath, "/"):
		return fmt.Errorf("%q is absolute; a repository path is relative to the repository root", repoPath)
	case strings.Contains(repoPath, `\`):
		return fmt.Errorf("%q holds a backslash, which no pkg repository publishes and no request can spell", repoPath)
	}
	for _, r := range repoPath {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%q holds a control character at U+%04X", repoPath, r)
		}
	}
	for i, seg := range strings.Split(repoPath, "/") {
		switch seg {
		case "":
			return fmt.Errorf("%q holds an empty segment at position %d, so it names no object", repoPath, i)
		case ".", "..":
			return fmt.Errorf("%q holds a %q segment, which no request reaches and which resolves outside the repository", repoPath, seg)
		}
	}
	return nil
}

// FreeBSDKey returns the key one mirrored object is stored under. repoPath is
// the record's own repopath from packagesite.yaml, or one of
// FreeBSDCatalogFiles for a repository-root file.
//
// The layouts observed upstream differ and neither is derivable from a name
// and a version: latest/ publishes at "All/Hashed/<name>-<version>~<hash>.pkg"
// while base_latest/ publishes at the repository root. Only the catalogue
// knows, which is why this takes the path rather than composing one.
func FreeBSDKey(abi, repo, repoPath string) string {
	return FreeBSDRepoPrefix(abi, repo) + repoPath
}

// BinaryKey returns the key for a binary artifact. A versioned entry gets its
// own directory so multiple versions coexist; an entry with no version keeps
// the two-segment layout it was uploaded under.
func BinaryKey(name, version, filename string) string {
	if version == "" {
		return BinaryPrefix + SafeName(name) + "/" + filename
	}
	return BinaryPrefix + SafeName(name) + "/" + version + "/" + filename
}

// BinaryStoredFilename maps the filename a client requested under one binary
// version to the filename its object is stored under: a name some entry of
// that version is stored under is served as asked, and a name
// binaryDownloadNames gave an entry is served from that entry's object.
func (pm *PackageManifest) BinaryStoredFilename(version, requested string) string {
	if pm == nil {
		return requested
	}
	for _, ve := range pm.Versions {
		if ve.Version == version && binaryStoredName(ve) == requested {
			return requested
		}
	}
	for i, name := range pm.binaryDownloadNames() {
		if name == requested && pm.Versions[i].Version == version {
			return binaryStoredName(pm.Versions[i])
		}
	}
	return requested
}

// binaryDownloadNames returns, by index into pm.Versions, the filename the
// read API publishes for each binary entry whose stored name carries
// userinfo: one with no filename whose url has no path, so the object is
// stored under the authority, https://user:secret@host as "user:secret@host".
// The web UI links to filename when one is set and to the url's last segment
// otherwise, and the published url has lost its userinfo, so without a name
// here the link would be "host": another entry of the same version may be
// stored under that name, or redact to it too.
//
// Each name is the redacted segment plus a tag, is stored under by no entry of
// its version, and names no other entry. The tag is the start of the entry's
// artifact_digest, which the read API already publishes, so a link read before
// the manifest changed either reaches the same bytes or none. An entry never
// fetched has no digest, and its tag is its position in pm.Versions, which
// shifts when an earlier entry is removed. The object keeps its stored key, so
// every install's existing copy and its old path still answer.
func (pm *PackageManifest) binaryDownloadNames() map[int]string {
	if pm == nil || pm.Type != TypeBinary {
		return nil
	}
	var names map[int]string
	for i, ve := range pm.Versions {
		if ve.Filename != "" {
			continue
		}
		base := lastSegment(PublicURL(ve.URL))
		if base == lastSegment(ve.URL) {
			continue
		}
		if base == "" {
			base = "download"
		}
		tag := strconv.Itoa(i + 1)
		if len(ve.ArtifactDigest) >= 12 {
			tag = ve.ArtifactDigest[:12]
		}
		name := base + "-" + tag
		for n := 2; pm.binaryNameTaken(ve.Version, name, names); n++ {
			name = base + "-" + tag + "-" + strconv.Itoa(n)
		}
		if names == nil {
			names = make(map[int]string)
		}
		names[i] = name
	}
	return names
}

func (pm *PackageManifest) binaryNameTaken(version, name string, given map[int]string) bool {
	for j, ve := range pm.Versions {
		if ve.Version != version {
			continue
		}
		if binaryStoredName(ve) == name || given[j] == name {
			return true
		}
	}
	return false
}

func binaryStoredName(ve VersionEntry) string {
	if ve.Filename != "" {
		return ve.Filename
	}
	return lastSegment(ve.URL)
}

// GitKey returns the key for a git bundle or release archive. release selects
// the extension: a cloned repo ships as a bundle, a tagged release as the
// upstream tarball.
func GitKey(name, ref string, release bool) string {
	ext := ".bundle"
	if release {
		ext = ".tar.gz"
	}
	safe := SafeName(name)
	return GitPrefix + safe + "/" + safe + "-" + ref + ext
}

// PypiWheelKey returns the key one closure artifact is served under. filename
// is the name the index gave the file, which is what the wheels directory syncs
// under and what a client asks for by name.
func PypiWheelKey(filename string) string {
	return PypiWheelPrefix + filename
}

// AptKey returns the key for a .deb at poolPath, which is relative to
// AptPrefix and is the same string the Packages index publishes as Filename.
func AptKey(poolPath string) string {
	return AptPrefix + poolPath
}

// GomodFileKey returns the key for one file under a module's @v/ directory.
// module keeps its slashes; file is what the Go client asks for verbatim
// ("v1.30.0.zip", "list", "@latest").
func GomodFileKey(module, file string) string {
	return gomodPrefix + module + "/@v/" + file
}

// GomodKey returns the key for one of a module version's three artifacts.
// ext is ".zip", ".info" or ".mod".
func GomodKey(module, version, ext string) string {
	return GomodFileKey(module, version+ext)
}

// GomodListKey returns the key for a module's version list. The list is
// regenerable and names no version, so it is routed by type.
func GomodListKey(module string) string {
	return GomodFileKey(module, "list")
}

// HelmChartKey returns the key for a chart archive. Charts live in one flat
// directory because that is what the generated index.yaml points at.
func HelmChartKey(name, version string) string {
	if version == "" {
		return helmPrefix + SafeName(name) + ".tgz"
	}
	return helmPrefix + SafeName(name) + "-" + version + ".tgz"
}

// NpmTarballKey returns the key for a package tarball. The safe name appears
// twice: once as the directory and once in the filename. A scoped package is
// requested as "@scope/pkg/-/pkg-<version>.tgz" on the wire, so the filename a
// client sees never matches the one stored.
func NpmTarballKey(name, version string) string {
	safe := SafeName(name)
	return npmPrefix + safe + "/" + safe + "-" + version + ".tgz"
}

// NpmPackumentKey returns the key for a cached packument. Regenerable, routed
// by type.
func NpmPackumentKey(name string) string {
	return npmPrefix + SafeName(name) + "/packument.json"
}

// CargoCrateKey returns the key for a .crate tarball.
func CargoCrateKey(name, version string) string {
	return cargoCratePrefix + SafeName(name) + "-" + version + ".crate"
}

// CargoIndexKey returns the key for a cached sparse-index entry, keyed by the
// registry path cargo requested. Regenerable, routed by type.
func CargoIndexKey(indexPath string) string {
	return cargoIndexPrefix + indexPath
}

// ArtifactKeys returns every object key holding this version's bytes, primary
// first.
//
// apt returns ErrAptPoolPathUnknown when the entry predates the _pool_path
// metadata key, and pypi always returns ErrPypiNoObjectKey. Both are sentinels
// rather than an empty slice, because "no key resolved" and "the object is
// gone" are the two states a delete must never confuse.
func ArtifactKeys(pm *PackageManifest, ve VersionEntry) ([]string, error) {
	if pm == nil {
		return nil, errors.New("nil package manifest")
	}
	switch pm.Type {
	case TypeBinary:
		filename := binaryStoredName(ve)
		if filename == "" {
			return nil, fmt.Errorf("binary %s@%s has neither filename nor URL to derive one from", pm.Name, ve.Version)
		}
		return []string{BinaryKey(pm.Name, ve.Version, filename)}, nil

	case TypeGit:
		ref := ve.Ref
		if ref == "" {
			ref = ve.Version
		}
		if ref == "" {
			return nil, fmt.Errorf("git %s records neither ref nor version", pm.Name)
		}
		return []string{GitKey(pm.Name, ref, ve.IsRelease())}, nil

	case TypeApt:
		rel := ve.Metadata["_pool_path"]
		if rel == "" {
			return nil, ErrAptPoolPathUnknown
		}
		return []string{AptKey(rel)}, nil

	case TypeGomod:
		// The .zip is the artifact; .info and .mod are small siblings that must
		// travel with it or the module is unresolvable once moved.
		return []string{
			GomodKey(pm.Name, ve.Version, ".zip"),
			GomodKey(pm.Name, ve.Version, ".info"),
			GomodKey(pm.Name, ve.Version, ".mod"),
		}, nil

	case TypeHelm:
		return []string{HelmChartKey(pm.Name, ve.Version)}, nil

	case TypeNpm:
		return []string{NpmTarballKey(pm.Name, ve.Version)}, nil

	case TypeCargo:
		return []string{CargoCrateKey(pm.Name, ve.Version)}, nil

	case TypeFreeBSD:
		// The repository root, catalogue first: these are the keys this
		// package can name without asking a backend what it holds. The
		// mirrored packages are whatever the catalogue lists, so they are
		// enumerated by listing FreeBSDRepoPrefix — inventory.ArtifactKeys
		// owns that, for the same reason it owns apt's pool listing.
		if ve.Version == "" {
			return nil, fmt.Errorf("freebsd %s records no ABI, so no repository prefix resolves for it", pm.Name)
		}
		return []string{
			FreeBSDKey(ve.Version, pm.Name, FreeBSDCatalogFile),
			FreeBSDKey(ve.Version, pm.Name, FreeBSDDataFile),
			FreeBSDKey(ve.Version, pm.Name, FreeBSDMetaFile),
		}, nil

	case TypePypi:
		return nil, ErrPypiNoObjectKey
	}
	return nil, fmt.Errorf("unknown package type %q", pm.Type)
}

// lastSegment returns the portion of s after the final '/'.
func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// ParseKey inverts the constructors above: given an object key, it returns the
// package type, name and version the key was built from. Names come back
// canonical, with the slashes their encoding collapsed restored, so a name
// returned here is the string the constructor was handed.
//
// A key no constructor could have produced returns three empty strings. An
// empty type is the caller's signal to record the key alone — a checksum row
// with no package identity still verifies the bytes, while a name guessed from
// an unrecognized prefix would hand `bodega pkg checksum clear <type> <name>` rows
// that belong to something else.
//
// The generated siblings each tree carries (charts/index.yaml,
// packument.json, a module's @v/list, the sparse index) come back as their
// type with no version: they are regenerable and never checksummed, but the
// type is still right and an untyped row costs the recovery command its
// filter.
//
// Two layouts are ambiguous by construction and resolve by a rule rather than
// a guess. helm and cargo put name and version in one flat filename separated
// by "-", so the split takes the first "-" that opens a version; see
// splitTrailingVersion for what qualifies and for the two shapes that stay
// ambiguous. apt's version lives inside the filename, and a name bodega never
// built returns empty rather than a guess.
func ParseKey(key string) (typ, name, version string) {
	switch {
	case strings.HasPrefix(key, AptPrefix):
		// dists/ is generated per request; only pool/ holds uploaded bytes.
		if !strings.HasPrefix(key, AptPoolPrefix) {
			return TypeApt, "", ""
		}
		n, v := AptDebIdentity(lastSegment(key))
		return TypeApt, n, v

	case strings.HasPrefix(key, PypiWheelPrefix):
		// <dist>-<version>-<python>-<abi>-<platform>.whl, under an optional
		// version directory the sync writes.
		base := strings.TrimSuffix(lastSegment(key), ".whl")
		if base == lastSegment(key) {
			return TypePypi, "", ""
		}
		parts := strings.SplitN(base, "-", 3)
		if len(parts) < 2 {
			return TypePypi, base, ""
		}
		return TypePypi, parts[0], parts[1]

	case strings.HasPrefix(key, GitPrefix):
		dir, file, ok := strings.Cut(strings.TrimPrefix(key, GitPrefix), "/")
		if !ok {
			return TypeGit, "", ""
		}
		for _, ext := range []string{".bundle", ".tar.gz"} {
			base, found := strings.CutSuffix(file, ext)
			if !found {
				continue
			}
			return TypeGit, unsafeName(dir), strings.TrimPrefix(base, dir+"-")
		}
		return TypeGit, unsafeName(dir), ""

	case strings.HasPrefix(key, BinaryPrefix):
		// <name>/<version>/<file> when versioned, <name>/<file> when not.
		segs := strings.Split(strings.TrimPrefix(key, BinaryPrefix), "/")
		switch len(segs) {
		case 2:
			return TypeBinary, unsafeName(segs[0]), ""
		case 3:
			return TypeBinary, unsafeName(segs[0]), segs[1]
		}
		return TypeBinary, "", ""

	case strings.HasPrefix(key, gomodPrefix):
		rest := strings.TrimPrefix(key, gomodPrefix)
		idx := strings.Index(rest, "/@v/")
		if idx < 0 {
			return TypeGomod, "", ""
		}
		// The module path keeps its slashes, so it is not a safe name.
		module, file := rest[:idx], rest[idx+len("/@v/"):]
		for _, ext := range []string{".zip", ".info", ".mod"} {
			if base, found := strings.CutSuffix(file, ext); found {
				return TypeGomod, module, base
			}
		}
		return TypeGomod, module, "" // list, @latest

	case strings.HasPrefix(key, cargoCratePrefix):
		base, found := strings.CutSuffix(strings.TrimPrefix(key, cargoCratePrefix), ".crate")
		if !found {
			return TypeCargo, "", ""
		}
		n, v := splitTrailingVersion(base)
		// Returned as stored: a crate name holds no slash. See unsafeName.
		return TypeCargo, n, v

	case strings.HasPrefix(key, cargoIndexPrefix):
		// Keyed by the registry path cargo requested. The trailing segment is
		// the crate name by cargo's convention, not by anything constructed
		// here, and config.json sits in the same place.
		return TypeCargo, "", ""

	case strings.HasPrefix(key, helmPrefix):
		if key == HelmIndexKey {
			return TypeHelm, "", ""
		}
		base, found := strings.CutSuffix(strings.TrimPrefix(key, helmPrefix), ".tgz")
		if !found {
			return TypeHelm, "", ""
		}
		n, v := splitTrailingVersion(base)
		// Returned as stored: a chart name holds no slash. See unsafeName.
		return TypeHelm, n, v

	case strings.HasPrefix(key, FreeBSDPrefix):
		// "<abi>/<repo>/<repopath>". The first two segments are fixed by the
		// route a pkg client composes from ${ABI} and its repository name;
		// everything after them is the record's own repopath and may hold any
		// number of segments.
		segs := strings.SplitN(strings.TrimPrefix(key, FreeBSDPrefix), "/", 3)
		if len(segs) < 3 || segs[0] == "" || segs[1] == "" {
			return TypeFreeBSD, "", ""
		}
		return TypeFreeBSD, segs[1], segs[0]

	case strings.HasPrefix(key, npmPrefix):
		dir, file, ok := strings.Cut(strings.TrimPrefix(key, npmPrefix), "/")
		if !ok {
			return TypeNpm, "", ""
		}
		base, found := strings.CutSuffix(file, ".tgz")
		if !found {
			return TypeNpm, unsafeName(dir), "" // packument.json
		}
		return TypeNpm, unsafeName(dir), strings.TrimPrefix(base, dir+"-")
	}
	return "", "", ""
}

// AptDebIdentity splits a pool filename into its package name and version.
//
// Debian names a binary package file <package>_<version>_<arch>.<ext>, with an
// epoch's ":" percent-encoded as "%3a" because ":" is not portable in a
// filename. Source artifacts drop the architecture field. Anything that fits
// neither shape yields two empty strings rather than a guess: this feeds the
// discovery rows an operator promotes from, and a wrong package name there
// produces a manifest entry for a package that does not exist.
func AptDebIdentity(filename string) (name, version string) {
	for _, ext := range []string{".deb", ".udeb", ".ddeb", ".dsc"} {
		if trimmed, found := strings.CutSuffix(filename, ext); found {
			parts := strings.Split(trimmed, "_")
			if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
				return "", ""
			}
			return parts[0], strings.ReplaceAll(strings.ReplaceAll(parts[1], "%3a", ":"), "%3A", ":")
		}
	}
	return "", ""
}

// splitTrailingVersion splits "<name>-<version>" at the first "-" that opens a
// version. helm and cargo both flatten name and version into one filename with
// no separator the name cannot contain, so a rule is the most a reader of the
// key can do.
//
// The anchor is the first such "-" and not the last because a prerelease
// carries one of its own: "cert-manager-1.14.0-rc.1" split at the last "-"
// yields the name "cert-manager-1.14.0", which is a package no operator will
// ever type into `bodega pkg checksum clear`.
//
// A version opens with a digit run that ends its segment, at "." or at the end
// of the string, optionally behind a "v" or "V": helm charts are published
// under a prefixed version often enough that builder.ParseSemVer accepts both
// letters and keeps the prefix, so bodega's own builder writes a chart nothing
// here recognized, leaving "mychart-v1.2.3" whole as a package name. Demanding
// the run end the segment is what leaves a name whose own tail is numeric
// intact: "md-5-0.10.6" splits after "md-5", because "5-" continues into
// another word while "0." does not. Neither ecosystem allows "." in a package
// name, so a dotted digit run can only be the version.
//
// Two shapes stay ambiguous, both of them a name that reads as a version. An
// unversioned chart whose name ends in a digit segment ("md-5") splits, since
// a run ending the string reads the same as a version; charts are the only
// type that can omit a version at all. A name whose own tail is a dotted digit
// run splits there rather than at the version ("foo-2.0-1.0" reads as "foo" at
// "2.0-1.0"), because nothing in the key says which of the two runs the
// uploader meant.
func splitTrailingVersion(base string) (name, version string) {
	for i := 1; i < len(base)-1; i++ {
		if base[i] == '-' && opensVersion(base[i+1:]) {
			return base[:i], base[i+1:]
		}
	}
	return base, ""
}

// opensVersion reports whether s begins with a version: a digit run terminated
// by "." or by the end of s, optionally behind a "v" or "V".
//
// The prefixed form must be dotted where the bare form need not be. Both
// ecosystems version by SemVer, so no legal version is a single component, and
// demanding the "." leaves an unversioned chart named "my-v1" whole instead of
// reading its own tail as a version.
func opensVersion(s string) bool {
	dotted := false
	if len(s) > 1 && (s[0] == 'v' || s[0] == 'V') {
		s, dotted = s[1:], true
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return false
	}
	if dotted {
		return i < len(s) && s[i] == '.'
	}
	return i == len(s) || s[i] == '.'
}

// unsafeName reverses SafeName, restoring the slashes a stored path segment
// collapsed to "--".
//
// Only npm, git and binary reach it, because only their names carry a slash.
// A helm chart name and a cargo crate name cannot, so SafeName is a no-op on
// the way in and this would be lossy on the way out: the chart "foo--bar"
// would come back as "foo/bar".
//
// The cost of that is the recorded identity, not the fetch. Every read path
// runs the name back through SafeName — manifestPath resolves "foo/bar" to
// helm/foo--bar/manifest.json — so the chart was still found and still served.
// What an operator read in `discover list` and promoted from was a chart name
// no repository serves.
func unsafeName(segment string) string {
	return strings.ReplaceAll(segment, "--", "/")
}
