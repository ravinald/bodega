package builder

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// npmPackageJSONMaxBytes bounds the one archive entry this reads. A .tgz is
// attacker-supplied as far as this process is concerned — it arrived over the
// network from a URL an entry named — and a tar member declares no length the
// reader can trust, so the read is capped rather than sized from the header.
// A megabyte is far past any real package.json; the largest on the public
// registry are tens of kilobytes.
const npmPackageJSONMaxBytes = 1 << 20

// errNpmPackageJSONMissing is a tarball with no package.json at its root. Not
// fatal to a fetch: the bytes are still the artifact npm asked for, and a
// package with no manifest inside it has no dependencies to declare.
var errNpmPackageJSONMissing = errors.New("the tarball holds no package.json at its root")

// errNpmPackageJSONUnparseable is a package.json that exists and is not JSON
// an object can be read out of. Kept apart from the missing case because the
// two send an operator to different places: one to the registry, the other to
// the package's author.
var errNpmPackageJSONUnparseable = errors.New("the package.json in the tarball is not a JSON object this can read")

// readNpmDependencies reads the runtime dependencies a published tarball
// declares, from package/package.json inside it.
//
// Runtime only. devDependencies are the author's build inputs and npm does not
// install them for a consumer, so publishing them would have every hosted
// package drag a test runner onto the installing host. peerDependencies are
// the consumer's to satisfy and optionalDependencies may legitimately be
// absent, so neither belongs in a list a resolver is told it must fetch.
//
// Root-level only: a package may vendor a bundled dependency with a
// package.json of its own, and a bundled package's dependencies are not the
// archive's.
func readNpmDependencies(tgzPath string) ([]manifest.Dependency, error) {
	base := filepath.Base(tgzPath)

	f, err := os.Open(tgzPath) //nolint:gosec // the path is the fetch's own destination
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%s is not a gzip stream: %w", base, err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: %w", base, errNpmPackageJSONMissing)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: reading the archive: %w", base, err)
		}
		if hdr.Typeflag != tar.TypeReg || !isRootPackageJSON(hdr.Name) {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(tr, npmPackageJSONMaxBytes+1))
		if err != nil {
			return nil, fmt.Errorf("%s: reading package.json: %w", base, err)
		}
		if len(data) > npmPackageJSONMaxBytes {
			return nil, fmt.Errorf("%s: package.json is over %d bytes: %w",
				base, npmPackageJSONMaxBytes, errNpmPackageJSONUnparseable)
		}

		var doc struct {
			Dependencies map[string]string `json:"dependencies"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w (%v)", base, errNpmPackageJSONUnparseable, err)
		}
		return npmDependencyList(doc.Dependencies), nil
	}
}

// npmDependencyList orders a package.json dependency object by name. Go
// randomizes map iteration, so an unsorted list would rewrite the manifest on
// every re-fetch of bytes that never changed.
func npmDependencyList(deps map[string]string) []manifest.Dependency {
	if len(deps) == 0 {
		return nil
	}
	names := make([]string, 0, len(deps))
	for name := range deps {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]manifest.Dependency, 0, len(names))
	for _, name := range names {
		out = append(out, manifest.Dependency{Name: name, Req: deps[name]})
	}
	return out
}

// isRootPackageJSON reports whether a tar entry is the published package's own
// manifest. npm packs as package/package.json; some producers prefix ./ and
// some drop the directory, while a bundled dependency sits further down.
func isRootPackageJSON(name string) bool {
	rel := strings.TrimPrefix(filepath.ToSlash(name), "./")
	rel = strings.Trim(rel, "/")
	return filepath.Base(rel) == "package.json" && strings.Count(rel, "/") <= 1
}
