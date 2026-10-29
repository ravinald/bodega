package hostpkg

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
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
	res.Packages = mergeSameName(res.Packages)
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

// ParseRubygems converts either of the two places a host records its gems:
// 'gem list --local', one line per gem with every installed version in
// parentheses, or a listing of the gem directory's specifications/, one
// <name>-<version>[-<platform>].gemspec per installed version. A line ending
// in .gemspec is read as the second; the two can be concatenated.
//
// A platform build is listed as "1.16.7 x86_64-linux" and recorded as
// "1.16.7-x86_64-linux", the version its gem file names. A default gem ships
// inside Ruby itself rather than being installed from a registry, so it is
// skipped and counted: cataloging one fetches a gem no host ever downloaded.
func ParseRubygems(r io.Reader) (Result, error) {
	var (
		pms        []manifest.PackageManifest
		defaults   int
		unreadable []string
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "***") {
			continue
		}
		if strings.HasSuffix(line, ".gemspec") {
			name, version := manifest.RubygemsGemIdentity(strings.TrimSuffix(path.Base(line), ".gemspec") + ".gem")
			if name == "" {
				unreadable = append(unreadable, line)
				continue
			}
			pms = append(pms, pkg(manifest.TypeRubygems, name, version, "", registryMode))
			continue
		}
		name, list, ok := strings.Cut(line, " (")
		list, closed := strings.CutSuffix(list, ")")
		if !ok || !closed || name == "" {
			unreadable = append(unreadable, line)
			continue
		}
		for _, v := range strings.Split(list, ",") {
			v = strings.TrimSpace(v)
			if strings.HasPrefix(v, "default:") {
				defaults++
				continue
			}
			release, platform, hasPlatform := strings.Cut(v, " ")
			if release == "" {
				continue
			}
			if hasPlatform && platform != "ruby" {
				release += "-" + strings.TrimSpace(platform)
			}
			pms = append(pms, pkg(manifest.TypeRubygems, name, release, "", registryMode))
		}
	}
	if err := sc.Err(); err != nil {
		return Result{}, fmt.Errorf("scan gem list output: %w", err)
	}
	var res Result
	res.Packages = mergeSameName(pms)
	if defaults > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped %d default gem version(s): they ship inside Ruby, so no host downloaded them from a registry", defaults))
	}
	if len(unreadable) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped %d line(s) that are neither 'gem list' output nor a .gemspec file name, first: %q", len(unreadable), unreadable[0]))
	}
	sortPackages(res.Packages)
	return res, nil
}

// freeBSDUnknownRepo is what pkg records for a package installed from a file
// or a ports build rather than from a configured repository.
const freeBSDUnknownRepo = "unknown-repository"

// ParseFreeBSD converts "pkg query '%R\t%q'": the repository each installed
// package came from, and the ABI it was built for.
//
// A freebsd entry is a repository and its versions are ABIs, so the packages
// themselves are not cataloged: every row collapses to the (repository, ABI)
// pair it names. A noarch package reports its ABI with the architecture as
// "*", which is not a directory a pkg client ever substitutes for ${ABI}, so
// those rows add nothing; a repository that shows only noarch rows is
// reported rather than guessed at.
//
// The name is the host's own label for the repository ("FreeBSD-ports"), and
// the URL is empty. pkg records the label on every package and the address
// nowhere a query reaches, so the entry arrives the way a helm one does, with
// a warning naming the command that answers it. Entries import as proxy for
// the reason every registry entry does: hosted would commit the server to
// mirroring a whole FreeBSD repository for each host imported.
func ParseFreeBSD(r io.Reader) (Result, error) {
	var res Result
	type repoABI struct{ repo, abi string }
	seen := map[repoABI]bool{}
	noarchOnly := map[string]bool{}
	unknown, invalid := 0, 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 2 {
			return Result{}, fmt.Errorf("parse pkg query line %q: want 2 tab-separated fields, got %d\nexpected: pkg query '%%R\\t%%q'", line, len(f))
		}
		repo, abi := strings.TrimSpace(f[0]), strings.TrimSpace(f[1])
		switch {
		case repo == "" || repo == freeBSDUnknownRepo:
			unknown++
			continue
		case strings.HasSuffix(abi, ":*"):
			if _, ok := noarchOnly[repo]; !ok {
				noarchOnly[repo] = true
			}
			continue
		case !manifest.FreeBSDValidRepo(repo) || !manifest.FreeBSDValidABI(abi):
			invalid++
			continue
		}
		noarchOnly[repo] = false
		key := repoABI{repo, abi}
		if seen[key] {
			continue
		}
		seen[key] = true
		res.Packages = append(res.Packages, pkg(manifest.TypeFreeBSD, repo, abi, "", registryMode))
	}
	if err := sc.Err(); err != nil {
		return Result{}, fmt.Errorf("scan pkg query output: %w", err)
	}
	res.Packages = mergeSameName(res.Packages)
	sortPackages(res.Packages)

	if unknown > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped %d package(s) installed from a file or a ports build; they name no repository to mirror", unknown))
	}
	if invalid > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped %d package(s) whose repository or ABI is not a directory name bodega can key a mirror under", invalid))
	}
	var bare []string
	for repo, only := range noarchOnly {
		if only {
			bare = append(bare, repo)
		}
	}
	if len(bare) > 0 {
		sort.Strings(bare)
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped repositor(ies) %s: every package from them is noarch (ABI ending in \":*\"), which names no ABI a client requests; "+
				"catalog them with 'bodega pkg create freebsd' and the host's 'pkg config ABI'", strings.Join(bare, ", ")))
	}
	if len(res.Packages) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%d freebsd entr(ies) have no url: pkg records which repository a package came from, not its address. "+
				"Fill each url in from 'pkg -vv' on the host (${ABI} substituted) before importing; "+
				"a repository the host already reads through bodega is one to drop, not import",
			len(res.Packages)))
	}
	return res, nil
}

// mavenRepositoryDir is the directory name the local repository's layout
// starts under: ~/.m2/repository, or whatever maven.repo.local names, which
// ends in it by convention.
const mavenRepositoryDir = "/repository/"

// ParseMaven converts a listing of the POMs in a local Maven repository,
// 'find ~/.m2/repository -name "*.pom"', one path per line: every version a
// Maven build on the host resolved. Gradle keeps its own cache
// (~/.gradle/caches/modules-2) in a hashed layout, so it is not read here.
//
// A path is read relative to its last "/repository/", or as already relative
// when it has none. One that is not <groupId dirs>/<artifactId>/<version>/
// <artifactId>-<version>.pom (a timestamped SNAPSHOT, a stray file) is
// skipped and counted. A SNAPSHOT is skipped as well: it was built on this
// host or redeployed upstream, and either way no registry version names it.
func ParseMaven(r io.Reader) (Result, error) {
	var (
		pms        []manifest.PackageManifest
		snapshots  int
		unreadable []string
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		rel := filepathToSlash(line)
		if i := strings.LastIndex(rel, mavenRepositoryDir); i >= 0 {
			rel = rel[i+len(mavenRepositoryDir):]
		}
		rel = strings.TrimPrefix(rel, "./")
		mp, ok := manifest.ParseMavenPath(rel)
		if !ok || mp.Metadata || mp.Extension != "pom" || mp.Classifier != "" || mp.Companion != "" {
			unreadable = append(unreadable, line)
			continue
		}
		if mp.Snapshot() {
			snapshots++
			continue
		}
		pms = append(pms, pkg(manifest.TypeMaven, mp.Name(), mp.Version, "", registryMode))
	}
	if err := sc.Err(); err != nil {
		return Result{}, fmt.Errorf("scan the local repository listing: %w", err)
	}
	var res Result
	res.Packages = mergeSameName(pms)
	if snapshots > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped %d SNAPSHOT version(s): they are rebuilt under the same name, so no registry version describes them", snapshots))
	}
	if len(unreadable) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped %d line(s) that are not <groupId dirs>/<artifactId>/<version>/<artifactId>-<version>.pom under a local repository, first: %q; list it with: find ~/.m2/repository -name '*.pom'",
			len(unreadable), unreadable[0]))
	}
	sortPackages(res.Packages)
	return res, nil
}

// ParseComposer converts 'composer global show --format=json': the packages
// installed in Composer's global project, which is where a host's PHP tools
// live. A project's own vendor/ is listed by the same command run in it
// without "global", and parses the same way.
//
// The version is the one Packagist lists, "v7.1.5" or "2.0.2", which is what
// a composer entry is keyed by. A branch install reads "dev-master f16e1d5"
// and is skipped and counted: the branch moves, so no version Packagist
// publishes describes what the host has.
func ParseComposer(r io.Reader) (Result, error) {
	var doc struct {
		Installed []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"installed"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Result{}, fmt.Errorf("parse composer show: %w\nexpected JSON: composer global show --format=json", err)
	}
	var (
		pms      []manifest.PackageManifest
		branches []string
	)
	for _, row := range doc.Installed {
		if row.Name == "" || row.Version == "" {
			continue
		}
		if strings.HasPrefix(row.Version, "dev-") || strings.Contains(row.Version, " ") {
			branches = append(branches, row.Name+" "+row.Version)
			continue
		}
		pms = append(pms, pkg(manifest.TypeComposer, row.Name, row.Version, "", registryMode))
	}
	var res Result
	res.Packages = mergeSameName(pms)
	if len(branches) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped %d branch install(s), first: %q; a branch moves, so no version Packagist publishes describes it. Require a tagged release, or catalog it with bodega pkg create",
			len(branches), branches[0]))
	}
	sortPackages(res.Packages)
	return res, nil
}

// filepathToSlash reads a Windows path listing the way the layout is written.
func filepathToSlash(p string) string { return strings.ReplaceAll(p, `\`, "/") }

// rpmPubkey is the name rpm gives each OpenPGP key `rpm --import` loaded.
// It is a header in the database, not a package any repository serves.
const rpmPubkey = "gpg-pubkey"

// ParseRpm converts `rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'`.
// The version is epoch:version-release with a zero or "(none)" epoch left
// off, the form an rpm entry is keyed by. A package installed for two
// architectures (glibc.x86_64 and glibc.i686) is one entry, since the
// architecture is part of the object and not the identity.
func ParseRpm(r io.Reader) (Result, error) {
	var res Result
	invalid := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			return Result{}, fmt.Errorf("parse rpm line %q: want 5 tab-separated fields, got %d\nexpected: rpm -qa --qf '%%{NAME}\\t%%{EPOCH}\\t%%{VERSION}\\t%%{RELEASE}\\t%%{ARCH}\\n'", line, len(f))
		}
		name, epoch := f[0], f[1]
		if name == rpmPubkey {
			continue
		}
		if epoch == "(none)" {
			epoch = ""
		}
		evr := manifest.RpmEVR(epoch, f[2], f[3])
		if !manifest.RpmValidName(name) || !manifest.RpmValidEVR(evr) {
			invalid++
			continue
		}
		res.Packages = append(res.Packages, pkg(manifest.TypeRpm, name, evr, "", registryMode))
	}
	if err := sc.Err(); err != nil {
		return Result{}, fmt.Errorf("scan rpm output: %w", err)
	}
	res.Packages = mergeSameName(res.Packages)
	sortPackages(res.Packages)
	if invalid > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"skipped %d package(s) whose name or epoch:version-release is not one bodega keys an rpm entry by", invalid))
	}
	return res, nil
}
