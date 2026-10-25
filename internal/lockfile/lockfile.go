// Package lockfile reads the dependency pins a project's own package manager
// wrote, so bodega can admit and fetch them before a build asks.
//
// Each parser returns what the lockfile says and nothing it infers. A digest
// stays in the algorithm the lockfile recorded, because the comparison that
// matters is against bytes bodega holds, and translating a digest into another
// algorithm is not possible without those bytes.
package lockfile

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// Format names one lockfile syntax.
type Format string

// The formats prefetch reads: npm's package-lock.json (v2 and v3), a pip
// requirements file pinned with ==, go.sum, Cargo.lock, Bundler's
// Gemfile.lock, Gradle's gradle.lockfile, and the file Maven's
// dependency:list goal writes.
const (
	NpmLock             Format = "package-lock"
	Requirements        Format = "requirements"
	GoSum               Format = "go.sum"
	CargoLock           Format = "cargo.lock"
	GemfileLock         Format = "gemfile.lock"
	GradleLock          Format = "gradle.lockfile"
	MavenDependencyList Format = "dependency-list"
)

// Formats lists every format, in the order --format's help names them.
func Formats() []Format {
	return []Format{NpmLock, Requirements, GoSum, CargoLock, GemfileLock, GradleLock, MavenDependencyList}
}

// Digest is one hash a lockfile records. Value is lowercase hex for the sha
// family and the whole "h1:<base64>" string for a Go module hash, which is a
// hash over the zip's file list rather than over its bytes.
type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// String renders the digest the way it is printed and compared: "sha512:<hex>"
// or "h1:<base64>".
func (d Digest) String() string {
	if d.Algorithm == "h1" {
		return d.Value
	}
	return d.Algorithm + ":" + d.Value
}

// Entry is one (type, name, version) a lockfile pins. Digests holds every hash
// the lockfile accepts for it; pip lists one per distribution file, so any one
// matching is a match. Unsupported is set when the entry names a source bodega
// cannot fetch from, such as a git checkout or a local path, and says why.
// Classifiers is maven's: the classified files of the version the build
// resolved, in manifest.VersionEntry's notation.
type Entry struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Classifiers []string `json:"classifiers,omitempty"`
	Digests     []Digest `json:"digests,omitempty"`
	Line        int      `json:"line,omitempty"`
	Unsupported string   `json:"unsupported,omitempty"`
}

// Detect names the format of path from its file name. requirements files are
// recognized by the requirements*.txt convention pip-compile writes.
func Detect(path string) (Format, error) {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		return NpmLock, nil
	case base == "go.sum":
		return GoSum, nil
	case base == "cargo.lock":
		return CargoLock, nil
	case base == "gemfile.lock" || base == "gems.locked":
		return GemfileLock, nil
	case base == "gradle.lockfile" || base == "buildscript-gradle.lockfile" ||
		strings.HasSuffix(base, ".lockfile") && filepath.Base(filepath.Dir(path)) == "dependency-locks":
		return GradleLock, nil
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return Requirements, nil
	}
	return "", fmt.Errorf("cannot tell the lockfile format of %s from its name; pass --format (%s)", path, formatList())
}

// Sniff names a format a file's contents give away when its name does not.
// The output of Maven's dependency:list goes wherever -DoutputFile says, so
// no name identifies it, but its header line does.
func Sniff(data []byte) (Format, bool) {
	if bytes.Contains(data, []byte(mavenListHeader)) {
		return MavenDependencyList, true
	}
	return "", false
}

// ParseFormat accepts a --format value.
func ParseFormat(s string) (Format, error) {
	for _, f := range Formats() {
		if string(f) == strings.ToLower(s) {
			return f, nil
		}
	}
	return "", fmt.Errorf("unknown lockfile format %q; one of %s", s, formatList())
}

func formatList() string {
	names := make([]string, 0, len(Formats()))
	for _, f := range Formats() {
		names = append(names, string(f))
	}
	return strings.Join(names, ", ")
}

// Parse reads data as format. Entries come back in file order with duplicates
// of one (name, version) folded into the first, its digests unioned.
func Parse(format Format, data []byte) ([]Entry, error) {
	var (
		entries []Entry
		err     error
	)
	switch format {
	case NpmLock:
		entries, err = parseNpm(data)
	case Requirements:
		entries, err = parseRequirements(data)
	case GoSum:
		entries, err = parseGoSum(data)
	case CargoLock:
		entries, err = parseCargo(data)
	case GemfileLock:
		entries, err = parseGemfileLock(data)
	case GradleLock:
		entries, err = parseGradleLock(data)
	case MavenDependencyList:
		entries, err = parseMavenDependencyList(data)
	default:
		return nil, fmt.Errorf("unknown lockfile format %q", format)
	}
	if err != nil {
		return nil, err
	}
	return dedupe(entries), nil
}

func dedupe(in []Entry) []Entry {
	seen := map[string]int{}
	var out []Entry
	for _, e := range in {
		k := e.Type + "\x00" + e.Name + "\x00" + e.Version
		if i, ok := seen[k]; ok {
			for _, d := range e.Digests {
				if !slices.Contains(out[i].Digests, d) {
					out[i].Digests = append(out[i].Digests, d)
				}
			}
			for _, c := range e.Classifiers {
				if !slices.Contains(out[i].Classifiers, c) {
					out[i].Classifiers = append(out[i].Classifiers, c)
				}
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, e)
	}
	return out
}

// sriStrength ranks the algorithms npm's integrity field may carry. npm itself
// verifies against the strongest one present, so that is the one kept.
var sriStrength = map[string]int{"sha1": 1, "sha256": 2, "sha384": 3, "sha512": 4}

func parseNpm(data []byte) ([]Entry, error) {
	var doc struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
			Link      bool   `json:"link"`
			InBundle  bool   `json:"inBundle"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	if doc.LockfileVersion < 2 || doc.Packages == nil {
		return nil, fmt.Errorf("package-lock.json lockfileVersion %d has no \"packages\" map; regenerate it with npm 7 or later (lockfileVersion 2 or 3)", doc.LockfileVersion)
	}
	// Map order is random; the path order is the order npm wrote.
	paths := make([]string, 0, len(doc.Packages))
	for p := range doc.Packages {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	var out []Entry
	for _, p := range paths {
		pkg := doc.Packages[p]
		// "" is the project itself; a link is a workspace member; a bundled
		// dependency arrives inside its parent's tarball. None is fetched.
		if p == "" || pkg.Link || pkg.InBundle {
			continue
		}
		i := strings.LastIndex(p, "node_modules/")
		if i < 0 {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = p[i+len("node_modules/"):]
		}
		e := Entry{Type: manifest.TypeNpm, Name: name, Version: pkg.Version}
		if r := pkg.Resolved; r != "" && !(strings.HasPrefix(r, "https://") || strings.HasPrefix(r, "http://")) {
			e.Unsupported = "resolved from " + r + ", not a registry tarball"
		}
		d, err := parseSRI(pkg.Integrity)
		if err != nil {
			return nil, fmt.Errorf("package-lock.json %s: %w", p, err)
		}
		if d != nil {
			e.Digests = []Digest{*d}
		}
		out = append(out, e)
	}
	return out, nil
}

// parseSRI returns the strongest hash in a Subresource Integrity string, hex
// encoded. An empty string is no digest, not an error.
func parseSRI(sri string) (*Digest, error) {
	var best *Digest
	for _, part := range strings.Fields(sri) {
		alg, b64, ok := strings.Cut(part, "-")
		if !ok || sriStrength[alg] == 0 {
			continue
		}
		// An SRI hash may carry ?options after the base64.
		b64, _, _ = strings.Cut(b64, "?")
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("integrity %q: %w", part, err)
		}
		if best == nil || sriStrength[alg] > sriStrength[best.Algorithm] {
			best = &Digest{Algorithm: alg, Value: hex.EncodeToString(raw)}
		}
	}
	return best, nil
}

var (
	hashOption = regexp.MustCompile(`--hash[= ]([a-z0-9]+):([0-9a-fA-F]+)`)
	pinnedSpec = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;]+)\s*$`)
)

// requirementsIncludes are options that pull in another file. Following them
// would read paths a CI job controls from wherever bodega runs; ignoring them
// would report a partial lockfile as a complete one.
var requirementsIncludes = []string{"-r", "--requirement", "-c", "--constraint", "-e", "--editable"}

func parseRequirements(data []byte) ([]Entry, error) {
	var out []Entry
	for _, ln := range logicalLines(data) {
		text := ln.text
		if i := strings.Index(text, " #"); i >= 0 {
			text = text[:i]
		}
		text = strings.TrimSpace(text)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if strings.HasPrefix(text, "-") {
			opt := strings.Fields(text)[0]
			opt, _, _ = strings.Cut(opt, "=")
			for _, inc := range requirementsIncludes {
				if opt == inc {
					return nil, fmt.Errorf("requirements line %d: %s names another file or an editable source; pass each lockfile to prefetch directly", ln.n, opt)
				}
			}
			continue // --index-url, --require-hashes and the like change nothing about which versions are pinned
		}
		var digests []Digest
		for _, m := range hashOption.FindAllStringSubmatch(text, -1) {
			digests = append(digests, Digest{Algorithm: strings.ToLower(m[1]), Value: strings.ToLower(m[2])})
		}
		spec := hashOption.ReplaceAllString(text, "")
		spec, _, _ = strings.Cut(spec, ";")
		if strings.Contains(spec, " @ ") || strings.Contains(spec, "://") {
			name, _, _ := strings.Cut(spec, "@")
			out = append(out, Entry{Type: manifest.TypePypi, Name: manifest.CanonicalPypiName(strings.TrimSpace(name)),
				Line: ln.n, Digests: digests, Unsupported: "a direct URL reference, not an index release"})
			continue
		}
		m := pinnedSpec.FindStringSubmatch(strings.TrimSpace(spec))
		if m == nil {
			return nil, fmt.Errorf("requirements line %d: %q is not pinned with ==; prefetch reads a lockfile, so every requirement needs one exact version", ln.n, strings.TrimSpace(spec))
		}
		out = append(out, Entry{Type: manifest.TypePypi, Name: manifest.CanonicalPypiName(m[1]), Version: m[3], Digests: digests, Line: ln.n})
	}
	return out, nil
}

type logicalLine struct {
	n    int
	text string
}

// logicalLines joins backslash continuations, which is how pip-compile puts
// each --hash on its own line, and numbers each joined line by where it began.
func logicalLines(data []byte) []logicalLine {
	var (
		out  []logicalLine
		cur  strings.Builder
		from int
	)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if cur.Len() == 0 {
			from = n
		}
		if trimmed := strings.TrimRight(line, " \t"); strings.HasSuffix(trimmed, "\\") {
			cur.WriteString(strings.TrimSuffix(trimmed, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(line)
		out = append(out, logicalLine{n: from, text: cur.String()})
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, logicalLine{n: from, text: cur.String()})
	}
	return out
}

func parseGoSum(data []byte) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 || !strings.HasPrefix(f[2], "h1:") {
			return nil, fmt.Errorf("go.sum line %d: want \"<module> <version> h1:<hash>\", got %q", n, sc.Text())
		}
		// A /go.mod line pins the module's go.mod alone, which the build reads
		// for the module graph without ever downloading the zip.
		if strings.HasSuffix(f[1], "/go.mod") {
			continue
		}
		out = append(out, Entry{Type: manifest.TypeGomod, Name: f[0], Version: f[1], Line: n,
			Digests: []Digest{{Algorithm: "h1", Value: f[2]}}})
	}
	return out, sc.Err()
}

// cratesIO are the two spellings of the crates.io index a Cargo.lock source
// may carry. bodega fetches every crate from its one configured registry, so a
// crate from any other registry would be fetched from the wrong place.
var cratesIO = []string{"registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"}

func parseCargo(data []byte) ([]Entry, error) {
	var (
		out []Entry
		cur *Entry
		src string
	)
	flush := func() {
		if cur == nil {
			return
		}
		// No source is a workspace member: built from the tree, never fetched.
		if src != "" {
			if !slices.Contains(cratesIO, src) {
				cur.Unsupported = "source " + src + " is not crates.io"
			}
			out = append(out, *cur)
		}
		cur, src = nil, ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			flush()
			if line == "[[package]]" {
				cur = &Entry{Type: manifest.TypeCargo, Line: n}
			}
			continue
		}
		if cur == nil {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if !strings.HasPrefix(val, `"`) {
			continue // dependencies = [ ... ] spans lines and names nothing fetched here
		}
		val = strings.Trim(val, `"`)
		switch strings.TrimSpace(key) {
		case "name":
			cur.Name = val
		case "version":
			cur.Version = val
		case "source":
			src = val
		case "checksum":
			cur.Digests = []Digest{{Algorithm: "sha256", Value: strings.ToLower(val)}}
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for _, e := range out {
		if e.Name == "" || e.Version == "" {
			return nil, fmt.Errorf("line %d of Cargo.lock: a [[package]] with a source has no name or version", e.Line)
		}
	}
	return out, nil
}

// rubygemsOrg are the spellings of rubygems.org a Gemfile.lock GEM remote may
// carry. bodega fetches every gem from its one configured registry, so a gem
// locked against any other source would be fetched from the wrong place.
var rubygemsOrg = []string{"https://rubygems.org", "http://rubygems.org"}

// foreignGemRemotes returns the remotes that are not rubygems.org. Bundler
// writes every global source of a Gemfile into one GEM section and records no
// remote per spec, so a single foreign remote taints the whole section: a
// private gem whose name is also taken on rubygems.org would otherwise be
// fetched and pinned from the public registry.
func foreignGemRemotes(remotes []string) []string {
	var foreign []string
	for _, r := range remotes {
		if !slices.Contains(rubygemsOrg, strings.TrimRight(r, "/")) {
			foreign = append(foreign, r)
		}
	}
	return foreign
}

var (
	gemSpecLine     = regexp.MustCompile(`^    ([^\s(]+) \(([^)\s]+)\)$`)
	gemChecksumLine = regexp.MustCompile(`^  ([^\s(]+) \(([^)\s]+)\)(?: (\S+))?$`)
)

// parseGemfileLock reads the specs: of each GEM section and the CHECKSUMS
// section Bundler 2.5 and later writes. A spec's version keeps its platform
// suffix ("1.16.7-x86_64-linux"), because that is the gem file bodega fetches
// and the version a manifest entry records.
//
// A GIT spec is reported unsupported, since bodega fetches gems and not
// checkouts. A PATH spec is the project's own tree, never fetched, and is
// left out the way Cargo.lock's workspace members are.
func parseGemfileLock(data []byte) ([]Entry, error) {
	var (
		out     []Entry
		section string
		remotes []string
		inSpecs bool
		start   int
		sums    = map[string][]Digest{}
	)
	flush := func() {
		if section != "GEM" && section != "GIT" {
			return
		}
		reason := ""
		if section == "GIT" {
			reason = "git source " + strings.Join(remotes, ", ") + " is a checkout, not a published gem"
		} else if foreign := foreignGemRemotes(remotes); len(foreign) > 0 {
			reason = "source " + strings.Join(foreign, ", ") + " is not rubygems.org, and Gemfile.lock does not say which of the GEM section's remotes each spec came from"
		} else if len(remotes) == 0 {
			reason = "GEM section names no remote, so its source cannot be confirmed as rubygems.org"
		}
		for i := start; i < len(out); i++ {
			out[i].Unsupported = reason
		}
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		raw := strings.TrimRight(sc.Text(), "\r")
		if raw == "" {
			continue
		}
		if raw[0] != ' ' {
			flush()
			section, remotes, inSpecs, start = strings.TrimSpace(raw), nil, false, len(out)
			continue
		}
		switch section {
		case "GEM", "GIT", "PATH":
			if r, ok := strings.CutPrefix(raw, "  remote: "); ok {
				remotes = append(remotes, strings.TrimSpace(r))
				continue
			}
			if raw == "  specs:" {
				inSpecs = true
				continue
			}
			if !inSpecs || section == "PATH" {
				continue
			}
			m := gemSpecLine.FindStringSubmatch(raw)
			if m == nil {
				continue // a dependency line, indented six, names no pin
			}
			out = append(out, Entry{Type: manifest.TypeRubygems, Name: m[1], Version: m[2], Line: n})
		case "CHECKSUMS":
			m := gemChecksumLine.FindStringSubmatch(raw)
			if m == nil {
				return nil, fmt.Errorf("line %d of Gemfile.lock: CHECKSUMS entry %q is not <name> (<version>) <algorithm>=<digest>", n, strings.TrimSpace(raw))
			}
			if m[3] == "" {
				continue // Bundler writes none for a gem it did not download
			}
			key := m[1] + "\x00" + m[2]
			for _, item := range strings.Split(m[3], ",") {
				alg, val, ok := strings.Cut(item, "=")
				if !ok || alg == "" || val == "" {
					return nil, fmt.Errorf("line %d of Gemfile.lock: checksum %q is not <algorithm>=<digest>", n, item)
				}
				sums[key] = append(sums[key], Digest{Algorithm: strings.ToLower(alg), Value: strings.ToLower(val)})
			}
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Digests = sums[out[i].Name+"\x00"+out[i].Version]
	}
	return out, nil
}

// mavenSnapshotReason marks a -SNAPSHOT pin. Its files are redeployed under
// the same name, so a digest pinned today describes nothing tomorrow.
const mavenSnapshotReason = "a -SNAPSHOT is redeployed under the same name, so no digest can be pinned; serve it in proxy mode"

// mavenEntry builds one maven pin, refusing a coordinate no repository path
// could carry with the line it came from.
func mavenEntry(file string, n int, group, artifact, version string) (Entry, error) {
	name := group + ":" + artifact
	e := Entry{Type: manifest.TypeMaven, Name: name, Version: version, Line: n}
	if strings.HasSuffix(version, "-SNAPSHOT") {
		e.Unsupported = mavenSnapshotReason
		return e, nil
	}
	if err := manifest.ValidateMavenName(name); err != nil || strings.HasSuffix(name, ":"+manifest.MavenGroupWildcard) {
		return Entry{}, fmt.Errorf("line %d of %s: %q is not a <groupId>:<artifactId> coordinate", n, file, name)
	}
	if err := manifest.ValidateMavenVersion(name, manifest.VersionEntry{Version: version}); err != nil {
		return Entry{}, fmt.Errorf("line %d of %s: %w", n, file, err)
	}
	return e, nil
}

// gradleLockLine is one dependency gradle.lockfile pins:
// <group>:<artifact>:<version>=<configurations>. The per-configuration
// lockfiles Gradle wrote before 6.0 carry the coordinate alone.
var gradleLockLine = regexp.MustCompile(`^([^:=\s]+):([^:=\s]+):([^:=\s]+)(?:=(\S*))?$`)

// parseGradleLock reads gradle.lockfile. Gradle records no digest in it (that
// is verification-metadata.xml's job), so every entry is compared with
// nothing and pinned by the fetch.
func parseGradleLock(data []byte) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		m := gradleLockLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("line %d of gradle.lockfile: %q is not <group>:<artifact>:<version>=<configurations>", n, line)
		}
		e, err := mavenEntry("gradle.lockfile", n, m[1], m[2], m[3])
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// mavenListHeader opens each module's list in dependency:list output.
const mavenListHeader = "The following files have been resolved:"

// mavenScopes are the scopes dependency:list appends to a coordinate. A field
// matching one ends the coordinate; anything after it is the artifact's file
// name, which -DoutputAbsoluteArtifactFilename adds.
var mavenScopes = []string{"compile", "provided", "runtime", "test", "system", "import"}

// parseMavenDependencyList reads what 'mvn dependency:list -DoutputFile=<f>'
// writes, or the same list copied from a console log with its [INFO]
// prefixes. Each line under the header is
//
//	<groupId>:<artifactId>:<type>[:<classifier>]:<version>[:<scope>]
//
// optionally followed by " -- module <name>" (Maven 3.9 and plugin 3.x) and
// " (optional)". A blank line ends a module's list; a multi-module build
// appends one list per module.
func parseMavenDependencyList(data []byte) ([]Entry, error) {
	const file = "the dependency:list output"
	var (
		out     []Entry
		inList  bool
		sawList bool
	)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		line = strings.TrimSpace(strings.TrimPrefix(line, "[INFO]"))
		if line == mavenListHeader {
			inList, sawList = true, true
			continue
		}
		if !inList {
			continue
		}
		if line == "" {
			inList = false
			continue
		}
		if line == "none" {
			continue
		}
		coord, _, _ := strings.Cut(line, " -- ")
		fields := strings.Fields(coord)
		parts := strings.Split(fields[0], ":")
		for i := 4; i < len(parts) && i <= 5; i++ {
			if slices.Contains(mavenScopes, parts[i]) {
				parts = parts[:i]
				break
			}
		}
		var group, artifact, typ, classifier, version string
		switch len(parts) {
		case 4:
			group, artifact, typ, version = parts[0], parts[1], parts[2], parts[3]
		case 5:
			group, artifact, typ, classifier, version = parts[0], parts[1], parts[2], parts[3], parts[4]
		default:
			return nil, fmt.Errorf("line %d of %s: %q is not <groupId>:<artifactId>:<type>[:<classifier>]:<version>[:<scope>]", n, file, fields[0])
		}
		e, err := mavenEntry(file, n, group, artifact, version)
		if err != nil {
			return nil, err
		}
		ext := manifest.MavenPackagingExtension(typ)
		if typ == "test-jar" && classifier == "" {
			classifier = "tests"
		}
		if classifier != "" && e.Unsupported == "" {
			spec := classifier
			if ext != "jar" {
				spec += "@" + ext
			}
			if _, _, err := manifest.ParseMavenClassifier(spec); err != nil {
				return nil, fmt.Errorf("line %d of %s: %w", n, file, err)
			}
			e.Classifiers = []string{spec}
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !sawList {
		return nil, fmt.Errorf("%s has no %q line; write it with mvn dependency:list -DoutputFile=<file>", file, mavenListHeader)
	}
	return out, nil
}
