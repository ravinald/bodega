package manifest

import (
	"errors"
	"fmt"
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
//   - Names arrive canonical, slashes intact ("@bitwarden/cli",
//     "github.com/aws/aws-sdk-go-v2"). Each function applies the encoding its
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
var ErrPypiNoObjectKey = errors.New("pypi wheels upload as a directory and have no per-version object key")

// ErrAptPoolPathUnknown reports that an apt entry carries no _pool_path, so
// its .deb can only be found by listing the pool. internal/inventory owns that
// fallback; this package has no backend to ask.
var ErrAptPoolPathUnknown = errors.New("apt entry records no _pool_path")

// BinaryKey returns the key for a binary artifact. A versioned entry gets its
// own directory so multiple versions coexist; an entry with no version keeps
// the two-segment layout it was uploaded under.
func BinaryKey(name, version, filename string) string {
	if version == "" {
		return BinaryPrefix + SafeName(name) + "/" + filename
	}
	return BinaryPrefix + SafeName(name) + "/" + version + "/" + filename
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
		filename := ve.Filename
		if filename == "" {
			filename = lastSegment(ve.URL)
		}
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
// canonical, slashes restored, so a name returned here is the string the
// constructor was handed.
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
// splitTrailingVersion for what qualifies and for the one case that stays
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
		return TypeCargo, unsafeName(n), v

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
		return TypeHelm, unsafeName(n), v

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
// of the string. Demanding the run end the segment is what leaves a name whose
// own tail is numeric intact: "md-5-0.10.6" splits after "md-5", because "5-"
// continues into another word while "0." does not. Neither ecosystem allows
// "." in a package name, so a dotted digit run can only be the version.
//
// One case stays ambiguous: an unversioned chart whose name ends in a digit
// segment ("md-5") splits, since a run ending the string reads the same as a
// version. Charts are the only type that can omit a version at all.
func splitTrailingVersion(base string) (name, version string) {
	for i := 1; i < len(base)-1; i++ {
		if base[i] == '-' && opensVersion(base[i+1:]) {
			return base[:i], base[i+1:]
		}
	}
	return base, ""
}

// opensVersion reports whether s begins with a digit run terminated by "." or
// by the end of s.
func opensVersion(s string) bool {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i > 0 && (i == len(s) || s[i] == '.')
}

// unsafeName reverses SafeName, restoring the slashes a stored path segment
// collapsed to "--".
func unsafeName(segment string) string {
	return strings.ReplaceAll(segment, "--", "/")
}
