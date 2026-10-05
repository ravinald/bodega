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

// npmPackageJSON is what a fetch records out of a published tarball's root
// package.json.
type npmPackageJSON struct {
	Dependencies []manifest.Dependency

	// Bin maps a command name to the path npm links it to. npm links
	// executables from the packument's bin, never from the unpacked
	// package.json, so a version published without it installs with nothing
	// in node_modules/.bin.
	Bin map[string]string

	// DroppedBin names each bin entry refused by npmBinUnsafe, one line apiece,
	// for the caller to report against the package and version it knows.
	DroppedBin []string
}

// readNpmPackageJSON reads the runtime dependencies and executables a
// published tarball declares, from package/package.json inside it.
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
func readNpmPackageJSON(tgzPath string) (npmPackageJSON, error) {
	base := filepath.Base(tgzPath)

	f, err := os.Open(tgzPath) //nolint:gosec // the path is the fetch's own destination
	if err != nil {
		return npmPackageJSON{}, err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return npmPackageJSON{}, fmt.Errorf("%s is not a gzip stream: %w", base, err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return npmPackageJSON{}, fmt.Errorf("%s: %w", base, errNpmPackageJSONMissing)
		}
		if err != nil {
			return npmPackageJSON{}, fmt.Errorf("%s: reading the archive: %w", base, err)
		}
		if hdr.Typeflag != tar.TypeReg || !isRootPackageJSON(hdr.Name) {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(tr, npmPackageJSONMaxBytes+1))
		if err != nil {
			return npmPackageJSON{}, fmt.Errorf("%s: reading package.json: %w", base, err)
		}
		if len(data) > npmPackageJSONMaxBytes {
			return npmPackageJSON{}, fmt.Errorf("%s: package.json is over %d bytes: %w",
				base, npmPackageJSONMaxBytes, errNpmPackageJSONUnparseable)
		}

		var doc struct {
			Name         string            `json:"name"`
			Dependencies map[string]string `json:"dependencies"`
			Bin          json.RawMessage   `json:"bin"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return npmPackageJSON{}, fmt.Errorf("%s: %w (%v)", base, errNpmPackageJSONUnparseable, err)
		}
		bin, dropped := npmBinMap(doc.Name, doc.Bin)
		return npmPackageJSON{
			Dependencies: npmDependencyList(doc.Dependencies),
			Bin:          bin,
			DroppedBin:   dropped,
		}, nil
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

// npmBinMap normalizes a package.json bin into the command-to-path map npm
// links from. The string form is one command named for the package's unscoped
// basename, which is how npm reads it; the object form is kept as written.
//
// A bin that is neither form, or an object member that is not a string, is
// dropped and reported rather than failing the read: the dependency record and
// the bytes are still good, and an unreadable bin is a package with no
// executables, not one npm cannot install.
func npmBinMap(pkgName string, raw json.RawMessage) (map[string]string, []string) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var entries map[string]json.RawMessage
	var single string
	switch {
	case json.Unmarshal(raw, &single) == nil:
		cmd := pkgName
		if idx := strings.LastIndex(cmd, "/"); idx >= 0 {
			cmd = cmd[idx+1:]
		}
		quoted, _ := json.Marshal(single)
		entries = map[string]json.RawMessage{cmd: quoted}
	case json.Unmarshal(raw, &entries) == nil:
	default:
		return nil, []string{fmt.Sprintf("bin %s: neither a string nor an object", raw)}
	}

	cmds := make([]string, 0, len(entries))
	for cmd := range entries {
		cmds = append(cmds, cmd)
	}
	sort.Strings(cmds)

	var bin map[string]string
	var dropped []string
	for _, cmd := range cmds {
		var path string
		if err := json.Unmarshal(entries[cmd], &path); err != nil {
			dropped = append(dropped, fmt.Sprintf("bin %q: %s is not a string path", cmd, entries[cmd]))
			continue
		}
		if why := npmBinUnsafe(cmd, path); why != "" {
			dropped = append(dropped, fmt.Sprintf("bin %q -> %q: %s", cmd, path, why))
			continue
		}
		if bin == nil {
			bin = map[string]string{}
		}
		bin[cmd] = path
	}
	return bin, dropped
}

// npmBinUnsafe says why a bin entry cannot be published, or "" when it can.
// npm links node_modules/.bin/<cmd> to <package dir>/<path>, so a command name
// carrying a separator writes outside .bin and a path that is absolute or
// climbs with .. links to a file the package does not contain. Both separators
// are refused because the installing host may be Windows, whoever fetched it.
func npmBinUnsafe(cmd, path string) string {
	switch {
	case cmd == "":
		return "empty command name"
	case strings.ContainsAny(cmd, `/\`):
		return "command name contains a path separator"
	case path == "":
		return "empty path"
	case strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`) ||
		(len(path) >= 2 && path[1] == ':'):
		return "path is absolute"
	}
	for _, seg := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return "path contains a .. segment"
		}
	}
	return ""
}

// isRootPackageJSON reports whether a tar entry is the published package's own
// manifest. npm packs as package/package.json; some producers prefix ./ and
// some drop the directory, while a bundled dependency sits further down.
func isRootPackageJSON(name string) bool {
	rel := strings.TrimPrefix(filepath.ToSlash(name), "./")
	rel = strings.Trim(rel, "/")
	return filepath.Base(rel) == "package.json" && strings.Count(rel, "/") <= 1
}
