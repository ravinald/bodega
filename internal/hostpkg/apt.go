package hostpkg

import (
	"bufio"
	"fmt"
	"io"
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

// ParseApt converts either of apt's two inventory formats.
//
// 'dpkg-query -W' is the documented input because it is machine readable and
// carries the status field. 'apt list --installed' is accepted because it is
// what an operator reaches for, even though apt prints a warning that its CLI
// has no stable interface.
func ParseApt(r io.Reader) (Result, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return Result{}, fmt.Errorf("read apt inventory: %w", err)
	}
	text := string(data)
	if strings.Contains(text, "\t") {
		return parseDpkgQuery(text)
	}
	return parseAptList(text)
}

// parseDpkgQuery reads the tab-separated form:
//
//	name<TAB>version<TAB>arch<TAB>status
func parseDpkgQuery(text string) (Result, error) {
	var res Result
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
			return Result{}, fmt.Errorf("dpkg-query line has %d fields, want 4: %q\n"+
				"expected the format bodega asks for: dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\t${Status}\\n'", len(f), line)
		}
		name, version, status := f[0], f[1], f[3]
		if status != dpkgInstalled {
			skipped++
			continue
		}
		if name == "" || version == "" {
			continue
		}
		res.Packages = append(res.Packages, pkg(manifest.TypeApt, name, version, "", ""))
	}
	if err := sc.Err(); err != nil {
		return Result{}, fmt.Errorf("scan dpkg-query output: %w", err)
	}
	if skipped > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped %d package(s) present in the dpkg database but not installed (removed, config files retained)", skipped))
	}
	sortPackages(res.Packages)
	return res, nil
}

// parseAptList reads the human-facing form:
//
//	name/suite,suite,now version arch [installed,automatic]
//
// The leading "Listing..." line and any apt warning are skipped. The bracketed
// markers are read only to confirm the package is installed: bodega imports
// the whole closure, so [installed,automatic] is kept alongside [installed].
func parseAptList(text string) (Result, error) {
	var res Result
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
		if !strings.Contains(line, "[installed") && !strings.Contains(line, "[upgradable") {
			continue
		}
		res.Packages = append(res.Packages, pkg(manifest.TypeApt, name, version, "", ""))
	}
	if err := sc.Err(); err != nil {
		return Result{}, fmt.Errorf("scan apt list output: %w", err)
	}
	sortPackages(res.Packages)
	return res, nil
}
