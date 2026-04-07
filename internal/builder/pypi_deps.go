package builder

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
)

// PypiDepGraph is the serialised dependency graph produced after a successful
// PackagePypi run. It is written to <wheels-dir>/dep-graph.json and can be
// read back by the TUI for the details pane.
type PypiDepGraph struct {
	// Packages maps normalised package name to its metadata.
	Packages map[string]PypiPackageInfo `json:"packages"`
	// BuiltAt is the UTC timestamp of the build that produced this graph.
	BuiltAt time.Time `json:"built_at"`
}

// PypiPackageInfo holds per-package metadata extracted from wheel metadata and
// the pypi.json manifest.
type PypiPackageInfo struct {
	// Name is the canonical (non-normalised) distribution name from METADATA.
	Name string `json:"name"`
	// Version is the distribution version string from METADATA.
	Version string `json:"version"`
	// Requires is the list of Requires-Dist values from METADATA (raw strings,
	// not further parsed).
	Requires []string `json:"requires,omitempty"`
	// UsedBy lists the names of packages whose Requires-Dist references this
	// package. Populated during graph construction.
	UsedBy []string `json:"used_by,omitempty"`
	// Explicit is true when the package appears in store.Pypi.Packages.
	Explicit bool `json:"explicit,omitempty"`
	// BaseApp is true when the package is a key in store.Pypi.BaseRequirements.
	BaseApp bool `json:"base_app,omitempty"`
}

// ScanWheelMetadata opens every .whl file in wheelDir, reads its METADATA
// file, and constructs a PypiDepGraph. Packages are cross-referenced with
// store.Pypi to tag explicit and base-app entries.
//
// .whl files are standard ZIP archives whose dist-info directory contains a
// METADATA file in RFC 2822 format. Only the Name, Version, and Requires-Dist
// headers are extracted.
func ScanWheelMetadata(wheelDir string, store *manifest.Store) (*PypiDepGraph, error) {
	matches, err := filepath.Glob(filepath.Join(wheelDir, "*.whl"))
	if err != nil {
		return nil, fmt.Errorf("glob wheels in %s: %w", wheelDir, err)
	}

	graph := &PypiDepGraph{
		Packages: make(map[string]PypiPackageInfo, len(matches)),
		BuiltAt:  time.Now().UTC(),
	}

	for _, whlPath := range matches {
		info, err := readWheelMetadata(whlPath)
		if err != nil {
			// Non-fatal: skip malformed wheels rather than aborting the scan.
			continue
		}
		key := normalisePkgName(info.Name)
		graph.Packages[key] = info
	}

	// Tag explicit and base-app packages from the manifest.
	for _, pkg := range store.Pypi.Packages {
		// pkg.Name may include version specifiers (e.g. "requests>=2.0"); strip them.
		name := pkgBaseName(pkg.Name)
		key := normalisePkgName(name)
		if p, ok := graph.Packages[key]; ok {
			p.Explicit = true
			graph.Packages[key] = p
		}
	}
	for repoName := range store.Pypi.BaseRequirements {
		key := normalisePkgName(repoName)
		if p, ok := graph.Packages[key]; ok {
			p.BaseApp = true
			graph.Packages[key] = p
		}
	}

	// Build reverse UsedBy index.
	for key, pkg := range graph.Packages {
		for _, req := range pkg.Requires {
			depName := normalisePkgName(pkgBaseName(req))
			if dep, ok := graph.Packages[depName]; ok {
				dep.UsedBy = appendUniq(dep.UsedBy, key)
				graph.Packages[depName] = dep
			}
		}
	}

	return graph, nil
}

// LoadDepGraph reads a previously saved PypiDepGraph from path.
// Returns (nil, nil) when the file does not exist so callers can treat absence
// as an empty graph without treating it as an error.
func LoadDepGraph(path string) (*PypiDepGraph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read dep graph %s: %w", path, err)
	}
	var g PypiDepGraph
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("parse dep graph %s: %w", path, err)
	}
	return &g, nil
}

// SaveDepGraph serialises graph to path as indented JSON.
func SaveDepGraph(path string, graph *PypiDepGraph) error {
	data, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal dep graph: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write dep graph %s: %w", path, err)
	}
	return nil
}

// readWheelMetadata opens a single .whl (zip) archive and extracts the Name,
// Version, and Requires-Dist fields from its dist-info/METADATA file.
func readWheelMetadata(whlPath string) (PypiPackageInfo, error) {
	r, err := zip.OpenReader(whlPath)
	if err != nil {
		return PypiPackageInfo{}, fmt.Errorf("open wheel %s: %w", whlPath, err)
	}
	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		// The METADATA file lives inside <name>-<version>.dist-info/METADATA.
		if !strings.HasSuffix(f.Name, ".dist-info/METADATA") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return PypiPackageInfo{}, fmt.Errorf("open %s in %s: %w", f.Name, whlPath, err)
		}
		data, readErr := readAll(rc)
		_ = rc.Close()
		if readErr != nil {
			return PypiPackageInfo{}, fmt.Errorf("read %s in %s: %w", f.Name, whlPath, readErr)
		}
		return parseWheelMetadata(string(data)), nil
	}
	return PypiPackageInfo{}, fmt.Errorf("no dist-info/METADATA found in %s", whlPath)
}

// parseWheelMetadata parses the RFC 2822-style METADATA content and extracts
// Name, Version, and Requires-Dist fields.
func parseWheelMetadata(content string) PypiPackageInfo {
	var info PypiPackageInfo
	for _, line := range splitLines(content) {
		switch {
		case strings.HasPrefix(line, "Name: "):
			info.Name = strings.TrimPrefix(line, "Name: ")
		case strings.HasPrefix(line, "Version: "):
			info.Version = strings.TrimPrefix(line, "Version: ")
		case strings.HasPrefix(line, "Requires-Dist: "):
			info.Requires = append(info.Requires, strings.TrimPrefix(line, "Requires-Dist: "))
		}
	}
	return info
}

// normalisePkgName converts a package name to its canonical lower-case,
// hyphen-normalised form as defined by PEP 503.
func normalisePkgName(s string) string {
	s = strings.ToLower(s)
	// Replace underscores and dots with hyphens.
	var b strings.Builder
	for _, r := range s {
		if r == '_' || r == '.' {
			b.WriteRune('-')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// pkgBaseName returns the package name portion of a requirement specifier,
// stripping version constraints, extras, and environment markers.
// e.g. "requests[security]>=2.28.0; python_version>'3.6'" → "requests"
func pkgBaseName(req string) string {
	// Strip environment markers (everything after ';').
	if i := strings.IndexByte(req, ';'); i >= 0 {
		req = req[:i]
	}
	// Strip extras (everything after '[').
	if i := strings.IndexByte(req, '['); i >= 0 {
		req = req[:i]
	}
	// Strip version specifiers (first occurrence of '>', '<', '=', '!', '~').
	for i, r := range req {
		if r == '>' || r == '<' || r == '=' || r == '!' || r == '~' {
			req = req[:i]
			break
		}
	}
	return strings.TrimSpace(req)
}

// appendUniq appends s to slice only when not already present.
func appendUniq(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

// readAll reads all bytes from r into a byte slice.
func readAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
