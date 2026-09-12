package hostpkg

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// dpkgInstalled is the only dpkg status that means the package is on the host.
// A removed-but-not-purged package keeps its config files and stays in the
// dpkg database as "deinstall ok config-files", and 'dpkg-query -W' reports it
// with no visible difference in the columns an importer reads. On one Ubuntu
// 22.04 server 774 of 774 rows looked installed and only 635 were; the other
// 139 were superseded kernel images. Mirroring those wastes the pool on
// packages the host does not have and nothing will ever request.
const dpkgInstalled = "install ok installed"

// AptRow is one installed package as the host reports it, before anything
// turns it into a manifest.
//
// The architecture is here and not on the manifest because only a pin needs
// it: matching a host against a served index has to know that an "all" package
// is published under binary-<arch> rather than an index of its own.
type AptRow struct {
	Name    string
	Version string
	Arch    string
	// Source is the Debian source package, from dpkg's ${source:Package}.
	// Empty when the capture did not ask for it, which is every capture taken
	// from 'apt list --installed' and every one taken before bodega asked.
	Source string
}

// AptInventory is one host's installed apt packages and what was dropped
// getting there.
type AptInventory struct {
	Rows     []AptRow
	Warnings []string
}

// ParseApt converts either of apt's two inventory formats, recording no
// release. It is the Parser the type dispatch hands out, and a suite is not a
// thing every manager has; see ParseAptWithSuite for the capture's own.
//
// 'dpkg-query -W' is the documented input because it is machine readable and
// carries the status field. 'apt list --installed' is accepted because it is
// what an operator reaches for, even though apt prints a warning that its CLI
// has no stable interface.
func ParseApt(r io.Reader) (Result, error) {
	return ParseAptWithSuite(r, "")
}

// ParseAptWithSuite is ParseApt with the release the inventory was captured
// on, written onto every entry's CaptureSuite.
//
// The release is the capture's to record and nothing else's. Ubuntu and Debian
// backport a security fix without moving the upstream version, so the
// advisories that settle a version live in the export for its own release, and
// a catalog holding jammy and noble entries at once cannot be answered from
// one server-wide codename: it would be wrong about one of them, in the
// direction that reports a vulnerable host clean. dpkg reports no codename in
// either format, so it comes from the host convert runs on or from --suite.
//
// CaptureSuite and not Suites, which decides which dists/<suite>/ the entry is
// published to: a server whose apt_codename is a house name serves no suite
// the captured host could have named, so recording the release there would
// take every converted entry out of the generated indexes.
//
// An empty suite records none rather than guessing. See policy.osvLookupFor
// for what the OSV gate does with an entry naming no release.
func ParseAptWithSuite(r io.Reader, suite string) (Result, error) {
	inv, err := ParseAptRows(r)
	if err != nil {
		return Result{}, err
	}
	suite = strings.TrimSpace(suite)
	res := Result{Warnings: inv.Warnings}
	for _, row := range inv.Rows {
		pm := pkg(manifest.TypeApt, row.Name, row.Version, "", "")
		pm.Versions[0].SourcePackage = row.Source
		pm.Versions[0].CaptureSuite = suite
		res.Packages = append(res.Packages, pm)
	}
	sortPackages(res.Packages)
	return res, nil
}

// ParseAptRows reads the same two formats ParseApt does and returns the rows
// themselves, architecture included.
//
// ParseApt is built on it so that "installed" means one thing across the
// commands: the status rule and the count it reports live here, and a second
// reader of the same output cannot drift from them.
func ParseAptRows(r io.Reader) (AptInventory, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return AptInventory{}, fmt.Errorf("read apt inventory: %w", err)
	}
	text := string(data)
	if strings.Contains(text, "\t") {
		return parseDpkgQuery(text)
	}
	return parseAptList(text)
}

// parseDpkgQuery reads the tab-separated form:
//
//	name<TAB>version<TAB>arch<TAB>status[<TAB>source]
//
// The source package is last on purpose. dpkg's own field order would put
// ${source:Package} second, and that capture parses with no error and drops
// every row on the host: f[3] is then the architecture, which is not
// dpkgInstalled, so each row counts as present-but-not-installed and the
// operator gets a count with nothing to compare it against. Appending keeps
// the four-field capture taken before this field existed reading unchanged.
func parseDpkgQuery(text string) (AptInventory, error) {
	var res AptInventory
	skipped := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			return AptInventory{}, fmt.Errorf("dpkg-query line has %d fields, want at least 4: %q\n"+
				"expected the format bodega asks for: dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\t${Status}\\t${source:Package}\\n'", len(f), line)
		}
		name, version, arch, status := f[0], f[1], f[2], f[3]
		var source string
		if len(f) > 4 {
			source = strings.TrimSpace(f[4])
		}
		if status != dpkgInstalled {
			skipped++
			continue
		}
		if name == "" || version == "" {
			continue
		}
		res.Rows = append(res.Rows, AptRow{Name: name, Version: version, Arch: arch, Source: source})
	}
	if err := sc.Err(); err != nil {
		return AptInventory{}, fmt.Errorf("scan dpkg-query output: %w", err)
	}
	if skipped > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped %d package(s) present in the dpkg database but not installed (removed, config files retained)", skipped))
	}
	sortRows(res.Rows)
	return res, nil
}

// parseAptList reads the human-facing form:
//
//	name/suite,suite,now version arch [installed,automatic]
//
// The leading "Listing..." line and any apt warning are skipped. The bracketed
// markers are read only to confirm the package is installed: bodega imports
// the whole closure, so [installed,automatic] is kept alongside [installed].
func parseAptList(text string) (AptInventory, error) {
	var res AptInventory
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "Listing") || strings.HasPrefix(line, "WARNING") {
			continue
		}
		slash := strings.IndexByte(line, '/')
		if slash <= 0 {
			continue
		}
		name := line[:slash]
		rest := strings.Fields(line[slash:])
		// rest[0] is the suite list, rest[1] the version, rest[2] the arch.
		if len(rest) < 2 {
			continue
		}
		version := rest[1]
		var arch string
		if len(rest) >= 3 {
			arch = rest[2]
		}
		if !strings.Contains(line, "[installed") && !strings.Contains(line, "[upgradable") {
			continue
		}
		res.Rows = append(res.Rows, AptRow{Name: name, Version: version, Arch: arch})
	}
	if err := sc.Err(); err != nil {
		return AptInventory{}, fmt.Errorf("scan apt list output: %w", err)
	}
	sortRows(res.Rows)
	return res, nil
}

// sortRows orders by name, then architecture, for the same reason
// sortPackages does: an operator diffs one run against the last, and map or
// input order would make every line look changed. Two rows can share a name on
// a multi-arch host, where amd64 and i386 builds of one library are both
// installed.
func sortRows(rows []AptRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].Arch < rows[j].Arch
	})
}
