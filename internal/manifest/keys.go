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
