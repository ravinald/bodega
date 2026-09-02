package hostpkg

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// Entries for types bodega resolves from a flat upstream registry are proxy
// entries. The registry is already known from config (pypi_upstream and its
// siblings), so a name and a version is a complete entry, and an operator who
// wants the bytes pre-fetched flips the entry to hosted and runs the pipeline.
// Guessing hosted here would commit the server to downloading every package on
// every host it imports.
const registryMode = manifest.ModeProxy

// ParsePip converts 'pip list --format=json'. The text form is not accepted:
// it pads columns to the terminal and has no stable field separator.
func ParsePip(r io.Reader) (Result, error) {
	var rows []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r).Decode(&rows); err != nil {
		return Result{}, fmt.Errorf("parse pip list: %w\nexpected JSON: pip list --format=json", err)
	}
	var res Result
	for _, row := range rows {
		if row.Name == "" {
			continue
		}
		res.Packages = append(res.Packages, pkg(manifest.TypePypi, row.Name, row.Version, "", registryMode))
	}
	sortPackages(res.Packages)
	return res, nil
}

// ParseNpm converts 'npm ls --global --json --depth=0'. Depth 0 is what makes
// the output an inventory rather than a dependency tree: npm nests the whole
// closure otherwise, and the nested copies carry the same names.
func ParseNpm(r io.Reader) (Result, error) {
	var doc struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Result{}, fmt.Errorf("parse npm ls: %w\nexpected JSON: npm ls --global --json --depth=0", err)
	}
	var res Result
	for name, dep := range doc.Dependencies {
		if name == "" {
			continue
		}
		res.Packages = append(res.Packages, pkg(manifest.TypeNpm, name, dep.Version, "", registryMode))
	}
	sortPackages(res.Packages)
	return res, nil
}

// ParseGomod converts either 'go version -m <binary>' or 'go list -m all'.
//
// Both are accepted because they answer different questions and an operator
// has reason to use each: 'go version -m' reports what one installed binary
// was built from, 'go list -m all' reports what one module tree requires.
// Both the main module and its dependencies are imported, because a GOPROXY
// that carries a module but not its requirements cannot serve a build.
func ParseGomod(r io.Reader) (Result, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return Result{}, fmt.Errorf("read go module inventory: %w", err)
	}
	text := string(data)
	if strings.Contains(text, "\tmod\t") || strings.Contains(text, "\tdep\t") {
		return parseGoVersionM(text)
	}
	return parseGoListM(text)
}

// parseGoVersionM reads the tab-indented build info 'go version -m' prints.
// Only the mod and dep rows name a module; path, build and the header line
// describe the binary rather than anything a proxy serves.
func parseGoVersionM(text string) (Result, error) {
	var res Result
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Split(strings.TrimPrefix(sc.Text(), "\t"), "\t")
		if len(f) < 3 || (f[0] != "mod" && f[0] != "dep") {
			continue
		}
		name, version := f[1], f[2]
		if name == "" || version == "" || seen[name] {
			continue
		}
		seen[name] = true
		res.Packages = append(res.Packages, pkg(manifest.TypeGomod, name, version, "", registryMode))
	}
	if err := sc.Err(); err != nil {
		return Result{}, fmt.Errorf("scan go version -m output: %w", err)
	}
	sortPackages(res.Packages)
	return res, nil
}

// parseGoListM reads 'go list -m all': one "path version" pair per line. The
// first line is the main module and carries no version, so it is skipped; a
// module bodega cannot name a version for is not something a proxy can serve.
func parseGoListM(text string) (Result, error) {
	var res Result
	seen := map[string]bool{}
	replaced := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		// "path ver => otherpath ver" marks a replace directive. The required
		// module is what a proxy is asked for, so the left side is imported and
		// the replacement is reported rather than silently followed.
		if len(f) > 2 {
			replaced++
		}
		name, version := f[0], f[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		res.Packages = append(res.Packages, pkg(manifest.TypeGomod, name, version, "", registryMode))
	}
	if err := sc.Err(); err != nil {
		return Result{}, fmt.Errorf("scan go list -m output: %w", err)
	}
	if replaced > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%d module(s) carry a replace directive; the required module was imported, not the replacement", replaced))
	}
	sortPackages(res.Packages)
	return res, nil
}

// ParseCargo converts 'cargo install --list'. A crate header is unindented and
// ends in a colon; the indented lines under it name the binaries that crate
// installed and are not packages.
func ParseCargo(r io.Reader) (Result, error) {
	var res Result
	gitSourced := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		f := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ":"))
		if len(f) < 2 || !strings.HasPrefix(f[1], "v") {
			continue
		}
		name, version := f[0], strings.TrimPrefix(f[1], "v")
		// A crate installed from a git URL or a local path carries the source
		// in parentheses. crates.io has no such version, so importing it as a
		// registry entry produces a catalog entry nothing can fetch.
		if len(f) > 2 && strings.HasPrefix(f[2], "(") {
			gitSourced++
			continue
		}
		res.Packages = append(res.Packages, pkg(manifest.TypeCargo, name, version, "", registryMode))
	}
	if err := sc.Err(); err != nil {
		return Result{}, fmt.Errorf("scan cargo install --list output: %w", err)
	}
	if gitSourced > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped %d crate(s) installed from a git or path source; the registry has no such version to serve", gitSourced))
	}
	sortPackages(res.Packages)
	return res, nil
}
