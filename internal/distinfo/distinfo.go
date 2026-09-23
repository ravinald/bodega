// Package distinfo reads the digests a FreeBSD ports tree pins for every
// distfile, and the redistribution limits its ports declare.
//
// This is what separates the distfiles type from binary. A binary entry pins
// whatever its first fetch returned, so a poisoned first fetch is served
// faithfully forever and bodega is the only party that ever vouched for the
// bytes. A distfile's SHA256 and size are already written down in
// <category>/<port>/distinfo, git-tracked in the ports tree before bodega
// fetches anything, and the client's own `make checksum` compares against the
// same line. A distfiles mirror therefore admits bytes against a digest it did
// not produce and cannot be talked into producing. Folding this type into
// binary, or into the checksum table's first-fetch pin, would keep every
// feature and drop that one property with no test noticing.
package distinfo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
)

// Entry is one distfile as the ports tree pins it.
type Entry struct {
	// Name is the string inside the distinfo line's parentheses:
	// "${DIST_SUBDIR}/<file>" when the port sets DIST_SUBDIR, "<file>" when
	// it does not. It is the object key under manifest.DistfilesPrefix and
	// the path under DISTDIR, so it is never split.
	Name   string
	SHA256 string // lowercase hex
	Size   int64

	// Ports lists every origin whose distinfo names this file, sorted.
	Ports []string

	// Restricted is empty when the file may be redistributed, and otherwise
	// names the port and the variable that forbids it.
	Restricted string
}

// ErrNotListed reports a name no distinfo in the tree carries. With no digest
// to hold the bytes to, the mirror refuses rather than falling back to
// pinning the first fetch.
var ErrNotListed = errors.New("no distinfo in the ports tree lists this distfile")

// ErrRestricted reports a distfile a port marks RESTRICTED or NO_CDROM.
var ErrRestricted = errors.New("the port forbids redistributing this distfile")

// ErrUnusable reports a name the tree pins in a way no digest can be taken
// from: two distinfo files pinning it to different bytes, which happens when a
// tree is read partway through an update, or a distinfo line that does not
// parse. Neither case says which bytes a client holds, so neither is admitted.
var ErrUnusable = errors.New("the ports tree does not pin this distfile to one digest")

// ErrNotReady reports that the first read of the ports tree has not finished,
// or has failed. A cold walk of a full tree takes the better part of a minute.
var ErrNotReady = errors.New("the distinfo index is not loaded yet")

// Index is every distfile one ports tree pins, keyed by distinfo name.
type Index struct {
	entries map[string]*Entry
	refused map[string]string // name -> why ErrUnusable
}

// Lookup returns the entry for name, or an error wrapping ErrNotListed,
// ErrUnusable or ErrRestricted. A restricted entry is returned alongside its
// error so a caller can report which port forbade it.
func (ix *Index) Lookup(name string) (Entry, error) {
	if why, ok := ix.refused[name]; ok {
		return Entry{}, fmt.Errorf("%w: %s: %s", ErrUnusable, name, why)
	}
	e, ok := ix.entries[name]
	if !ok {
		return Entry{}, fmt.Errorf("%w: %s", ErrNotListed, name)
	}
	if e.Restricted != "" {
		return *e, fmt.Errorf("%w: %s: %s", ErrRestricted, name, e.Restricted)
	}
	return *e, nil
}

// Len is the number of distfiles the index can admit or refuse by name.
func (ix *Index) Len() int { return len(ix.entries) + len(ix.refused) }

// Parse reads one distinfo file into the entries it pins and the names it
// mentions without pinning. Lines other than SHA256 and SIZE (TIMESTAMP,
// blank lines) are skipped.
//
// A bad line costs its own name and nothing else. The tree carries at least
// one distinfo with a SIZE line missing its "=", and refusing the whole file,
// or the whole tree, over it would refuse thousands of distfiles to protect
// one. A line too broken to name its file is dropped, which leaves that file
// with half a pin and so refuses it all the same.
func Parse(r io.Reader) (entries map[string]Entry, unusable map[string]string, err error) {
	sums := map[string]string{}
	sizes := map[string]int64{}
	unusable = map[string]string{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		field, rest, ok := strings.Cut(line, " (")
		if !ok || (field != "SHA256" && field != "SIZE") {
			continue
		}
		// The last ") = ", not the first: a filename may hold parentheses.
		i := strings.LastIndex(rest, ") = ")
		if i < 0 {
			if j := strings.LastIndex(rest, ")"); j > 0 && manifest.DistfilesValidName(rest[:j]) == nil {
				unusable[rest[:j]] = fmt.Sprintf("line %d does not parse: %q", n, line)
			}
			continue
		}
		name, val := rest[:i], strings.TrimSpace(rest[i+len(") = "):])
		// A name that is not a legal key is never recorded, not even as
		// unusable: it would reach an object key and a DISTDIR path.
		if manifest.DistfilesValidName(name) != nil {
			continue
		}
		switch field {
		case "SHA256":
			if !isSHA256(val) {
				unusable[name] = fmt.Sprintf("line %d: %q is not a SHA256 digest", n, val)
				continue
			}
			sums[name] = strings.ToLower(val)
		case "SIZE":
			sz, err := strconv.ParseInt(val, 10, 64)
			if err != nil || sz < 0 {
				unusable[name] = fmt.Sprintf("line %d: %q is not a size", n, val)
				continue
			}
			sizes[name] = sz
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	entries = make(map[string]Entry, len(sums))
	for name, sum := range sums {
		if _, bad := unusable[name]; bad {
			continue
		}
		// Both halves or nothing. bsd.port.mk has written SIZE beside SHA256
		// for as long as SHA256 has existed, and admitting on the digest alone
		// would accept a file no client's `make checksum` has seen described.
		sz, ok := sizes[name]
		if !ok {
			unusable[name] = "a SHA256 line and no SIZE line"
			continue
		}
		entries[name] = Entry{Name: name, SHA256: sum, Size: sz}
	}
	for name := range sizes {
		if _, ok := sums[name]; !ok {
			if _, bad := unusable[name]; !bad {
				unusable[name] = "a SIZE line and no SHA256 line"
			}
		}
	}
	return entries, unusable, nil
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// Ports forbid redistributing a distfile in three spellings, and a mirror has
// to read all of them:
//
//   - RESTRICTED or NO_CDROM, set directly.
//   - LICENSE_PERMS (or LICENSE_PERMS_<lic>) lacking dist-mirror or dist-sell.
//     Mk/bsd.licenses.mk is default-deny: its own comment says a port with
//     dist-mirror "is not RESTRICTED" and one with dist-sell "does not need
//     to set NO_CDROM", and it moves the distfiles onto RESTRICTED_FILES when
//     either is missing. This is the common form: on the 15.1 test tree 2
//     ports set RESTRICTED or NO_CDROM literally, and hundreds set
//     LICENSE_PERMS without one of the two.
//   - LICENSE naming a license whose default permissions in
//     Mk/bsd.licenses.db.mk lack either, such as the CC-BY-NC family.
//
// All three are read lexically, at any indentation, so an assignment inside
// an .if counts. That over-refuses a port that sets one only under a
// condition. Evaluating a port needs make and the whole of Mk/, which a Linux
// server has neither of, so wherever the lexical read cannot say what a port
// declares, the port is refused rather than admitted: a LICENSE or
// LICENSE_PERMS value holding a make variable, a license the database does not
// know that no LICENSE_PERMS describes, and a quoted .include whose path does
// not resolve. A mirror that under-refuses redistributes something it may
// not; one that over-refuses sends that client to the port's own sites.
var (
	restrictionVar  = regexp.MustCompile(`(?m)^[ \t]*(RESTRICTED|NO_CDROM)[ \t]*[?:+!]?=[ \t]*(.*)$`)
	licensePermsVar = regexp.MustCompile(`(?m)^[ \t]*(LICENSE_PERMS\S*?)[ \t]*[?:+!]?=[ \t]*(.*)$`)
	licenseVar      = regexp.MustCompile(`(?m)^[ \t]*LICENSE[ \t]*[?:+!]?=[ \t]*(.*)$`)
	licenseDBPerms  = regexp.MustCompile(`(?m)^_LICENSE_PERMS_([A-Za-z0-9.+-]+)[ \t]*[?:]?=[ \t]*(.*)$`)
	licenseDBList   = regexp.MustCompile(`(?m)^_LICENSE_LIST[ \t]*\+?=[ \t]*(.*)$`)
	varReference    = regexp.MustCompile(`\$\{([A-Za-z_.][A-Za-z0-9_.]*)((?::H)*)\}`)
)

// masterDirVar matches a slave port naming its master relative to itself,
// which is how nearly every slave in the tree spells it. A slave reads the
// master's distinfo, so a slave that is restricted restricts those names.
var masterDirVar = regexp.MustCompile(`(?m)^[ \t]*MASTERDIR[ \t]*[?:]?=[ \t]*\$\{\.CURDIR\}/(\S+)`)

// withholdsDistfiles reports whether a permission list, as bsd.licenses.mk
// reads one, fails to grant both dist-mirror and dist-sell.
func withholdsDistfiles(perms string) bool {
	if strings.Contains(perms, "$") {
		return true
	}
	have := map[string]bool{}
	for _, tok := range strings.Fields(perms) {
		have[tok] = true
	}
	return !have["dist-mirror"] || !have["dist-sell"] || have["no-dist-mirror"] || have["no-dist-sell"]
}

// licenseDB is what Mk/bsd.licenses.db.mk says about each license it knows.
type licenseDB struct {
	known  map[string]bool
	denied map[string]bool // default permissions withhold redistribution
}

// loadLicenseDB reads the license names bsd.licenses.db.mk defines, and which
// of them withhold redistribution by default. A license is known by being on
// _LICENSE_LIST; only those whose permissions differ from
// _LICENSE_PERMS_DEFAULT carry a _LICENSE_PERMS_<lic> line of their own, and
// a .for loop gives the rest the default.
func loadLicenseDB(portsTree string) (licenseDB, error) {
	file := filepath.Join(portsTree, "Mk", "bsd.licenses.db.mk")
	b, err := os.ReadFile(file) //nolint:gosec // G304: a fixed file under the configured ports tree.
	if err != nil {
		return licenseDB{}, fmt.Errorf("read %s: %w; distfiles_ports_tree must name the root of a FreeBSD ports tree", file, err)
	}
	db := licenseDB{known: map[string]bool{}, denied: map[string]bool{}}
	b = joinContinuations(b)
	for _, m := range licenseDBList.FindAllSubmatch(b, -1) {
		for _, lic := range strings.Fields(string(m[1])) {
			db.known[lic] = true
		}
	}
	for _, m := range licenseDBPerms.FindAllSubmatch(b, -1) {
		if string(m[1]) == "DEFAULT" {
			continue
		}
		db.known[string(m[1])] = true
		if withholdsDistfiles(string(m[2])) {
			db.denied[string(m[1])] = true
		}
	}
	return db, nil
}

func joinContinuations(b []byte) []byte {
	return []byte(strings.ReplaceAll(string(b), "\\\n", " "))
}

// restriction names why a port's Makefiles forbid redistributing its
// distfiles, or cannot be read to say that they do not, or returns "".
func restriction(origin string, makefile []byte, db licenseDB) string {
	if m := restrictionVar.FindSubmatch(makefile); m != nil {
		return fmt.Sprintf("%s sets %s=%s", origin, m[1], strings.TrimSpace(string(m[2])))
	}
	perms := map[string]bool{}
	for _, m := range licensePermsVar.FindAllSubmatch(makefile, -1) {
		perms[string(m[1])] = true
		if withholdsDistfiles(string(m[2])) {
			return fmt.Sprintf("%s sets %s=%s, which withholds dist-mirror or dist-sell, or cannot be read without make", origin, m[1], strings.TrimSpace(string(m[2])))
		}
	}
	for _, m := range licenseVar.FindAllSubmatch(makefile, -1) {
		for _, lic := range strings.Fields(string(m[1])) {
			switch {
			case strings.Contains(lic, "$"):
				return fmt.Sprintf("%s sets LICENSE=%s, which cannot be evaluated without make, so its redistribution terms cannot be established", origin, strings.TrimSpace(string(m[1])))
			case db.denied[lic]:
				return fmt.Sprintf("%s is licensed %s, whose default permissions in Mk/bsd.licenses.db.mk withhold dist-mirror or dist-sell", origin, lic)
			case !db.known[lic] && !perms["LICENSE_PERMS_"+lic] && !perms["LICENSE_PERMS"]:
				return fmt.Sprintf("%s is licensed %s, which Mk/bsd.licenses.db.mk does not define and no LICENSE_PERMS describes, so its redistribution terms cannot be established", origin, lic)
			}
		}
	}
	return ""
}

// maxIncludeDepth bounds how far quoted includes are followed. The deepest
// chain in the tree is a handful of files; anything past this is a cycle
// the visited set did not catch or a tree built to exhaust the reader.
const maxIncludeDepth = 16

// maxPathValues bounds how many values one include path may expand to before
// it is treated as unresolvable.
const maxPathValues = 16

var (
	conditionalOpen  = regexp.MustCompile(`^[ \t]*\.[ \t]*(if|ifdef|ifndef|ifmake|ifnmake|for)\b`)
	conditionalClose = regexp.MustCompile(`^[ \t]*\.[ \t]*(endif|endfor)\b`)
	assignment       = regexp.MustCompile(`^[ \t]*([A-Za-z_.][A-Za-z0-9_.]*)[ \t]*([?:+!]?)=[ \t]*(.*?)[ \t]*$`)
	includeDirective = regexp.MustCompile(`^[ \t]*\.[ \t]*(-?include|sinclude|dinclude)[ \t]+"([^"]*)"`)
)

// stripComments removes make comments: from an unescaped '#' to the end of
// the line. A trailing comment on `LICENSE= GPLv2 # only` would otherwise be
// read as a second license named "#".
func stripComments(b []byte) []byte {
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		for j := 0; j < len(l); j++ {
			if l[j] == '#' && (j == 0 || l[j-1] != '\\') {
				lines[i] = l[:j]
				break
			}
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// portText is the text a port's restriction is read from: every Makefile and
// Makefile.* in its directory, and every file those reach through a quoted
// .include, with continuations joined and comments removed. unresolved is
// non-empty when an include could not be followed, and names it.
//
// Includes are followed because a port can set NO_CDROM or LICENSE in any file
// it includes, not only in files named Makefile*, and a slave port's
// restrictions usually live in the master it includes. Lines are read in
// order, as make reads them, so an include sees the assignments above it.
// Conditionals are not evaluated. An assignment inside one adds a possible
// value rather than replacing the current one, and an include whose path has
// several possible values reads every one that exists, so a restriction in any
// branch is seen. Only .CURDIR, .PARSEDIR, PORTSDIR, variables the port
// assigns and the :H modifier are understood.
//
// The port is unresolved, and so refused, when an include path holds anything
// else, leaves the tree, or names no file where the include is unconditional.
// A missing file under a conditional include is skipped: make reaches that
// line only when its guard, usually exists(), holds. Angle-bracket includes
// and anything under Mk/ are the framework, whose license handling the
// database read models.
func portText(tree, dir string, own []string) (text []byte, unresolved string) {
	if realTree, err := filepath.EvalSymlinks(tree); err == nil {
		tree = realTree
	}
	visited := map[string]bool{}
	vars := map[string][]string{
		".CURDIR":   {dir},
		"PORTSDIR":  {tree},
		"MASTERDIR": {"${.CURDIR}"},
		"FILESDIR":  {"${MASTERDIR}/files"},
	}
	// definite records variables some unconditional assignment has set, which
	// is what makes a later ?= a no-op. The two defaults above are ?= in
	// bsd.port.mk and so are not definite.
	definite := map[string]bool{".CURDIR": true, "PORTSDIR": true}
	var buf []byte

	assign := func(name, op, val string, conditional bool) {
		if op == "!" {
			val = "$(shell)" // a command's output: never resolvable here
		}
		switch {
		case op == "+":
			cur := vars[name]
			if len(cur) == 0 {
				cur = []string{""}
			}
			out := make([]string, 0, len(cur))
			for _, c := range cur {
				out = append(out, strings.TrimSpace(c+" "+val))
			}
			if conditional {
				out = append(out, cur...)
			}
			vars[name] = capValues(dedupe(out))
		case op == "?" && definite[name]:
		case conditional:
			vars[name] = capValues(dedupe(append(vars[name], val)))
		default:
			vars[name] = []string{val}
			definite[name] = true
		}
	}

	var read func(file string, depth int) string
	read = func(file string, depth int) string {
		if visited[file] {
			return ""
		}
		visited[file] = true
		b, err := os.ReadFile(file) //nolint:gosec // G304: resolved and confined under the configured ports tree.
		if err != nil {
			return fmt.Sprintf("cannot read %s: %v", file, err)
		}
		b = stripComments(joinContinuations(b))
		buf = append(append(buf, b...), '\n')
		nesting := 0
		for _, line := range strings.Split(string(b), "\n") {
			directive := strings.HasPrefix(strings.TrimLeft(line, " \t"), ".")
			if !directive && !strings.Contains(line, "=") {
				continue
			}
			switch {
			case directive && conditionalOpen.MatchString(line):
				nesting++
				continue
			case directive && conditionalClose.MatchString(line):
				if nesting > 0 {
					nesting--
				}
				continue
			}
			if !directive {
				if m := assignment.FindStringSubmatch(line); m != nil {
					assign(m[1], m[2], m[3], nesting > 0)
				}
				continue
			}
			m := includeDirective.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			optional := m[1] != "include" || nesting > 0
			raw := m[2]
			if depth >= maxIncludeDepth {
				return fmt.Sprintf("%s includes %q past a depth of %d", file, raw, maxIncludeDepth)
			}
			scope := make(map[string][]string, len(vars)+1)
			for k, v := range vars {
				scope[k] = v
			}
			scope[".PARSEDIR"] = []string{filepath.Dir(file)}
			paths, ok := expandMakePath(raw, scope, 0)
			if !ok {
				return fmt.Sprintf("%s includes %q, which cannot be resolved without make", file, raw)
			}
			var found []string
			for _, p := range paths {
				candidates := []string{p}
				if !filepath.IsAbs(p) {
					candidates = []string{filepath.Join(filepath.Dir(file), p), filepath.Join(dir, p)}
				}
				for _, c := range candidates {
					c = filepath.Clean(c)
					if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() {
						found = append(found, c)
						break
					}
				}
			}
			if len(found) == 0 {
				if optional {
					continue
				}
				return fmt.Sprintf("%s includes %q, which does not exist", file, raw)
			}
			for _, f := range found {
				real, err := filepath.EvalSymlinks(f)
				if err != nil {
					return fmt.Sprintf("%s includes %q: %v", file, raw, err)
				}
				rel, err := filepath.Rel(tree, real)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
					return fmt.Sprintf("%s includes %q, which leaves the ports tree", file, raw)
				}
				if rel == "Mk" || strings.HasPrefix(rel, "Mk"+string(filepath.Separator)) {
					continue
				}
				if why := read(real, depth+1); why != "" {
					return why
				}
			}
		}
		return ""
	}

	for _, f := range own {
		real := f
		if r, err := filepath.EvalSymlinks(f); err == nil {
			real = r
		}
		if why := read(real, 0); why != "" {
			return buf, why
		}
	}
	return buf, ""
}

// capValues replaces a value set past maxPathValues with one value no path
// can resolve. Each conditional += doubles a set, and ports append to
// CONFIGURE_ARGS under dozens of conditionals; nothing includes a path built
// from one, and a path that did would be refused rather than enumerated.
func capValues(vals []string) []string {
	if len(vals) > maxPathValues {
		return []string{"$(too many values)"}
	}
	return vals
}

func dedupe(vals []string) []string {
	seen := map[string]bool{}
	out := vals[:0]
	for _, v := range vals {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// expandMakePath substitutes ${VAR} and ${VAR:H} references in an include
// path, returning every value the path can take. It reports false for a
// reference to a variable with no value here, for any "$" left that is not
// one of those two forms, and for a path with more than maxPathValues values.
func expandMakePath(s string, vars map[string][]string, depth int) ([]string, bool) {
	if depth > 8 {
		return nil, false
	}
	loc := varReference.FindStringSubmatchIndex(s)
	if loc == nil {
		if strings.Contains(s, "$") {
			return nil, false
		}
		return []string{s}, true
	}
	name := s[loc[2]:loc[3]]
	heads := strings.Count(s[loc[4]:loc[5]], ":H")
	vals, ok := vars[name]
	if !ok || len(vals) == 0 {
		return nil, false
	}
	var out []string
	for _, v := range vals {
		expanded, ok := expandMakePath(v, vars, depth+1)
		if !ok {
			return nil, false
		}
		for _, e := range expanded {
			for range heads {
				e = path.Dir(filepath.ToSlash(e))
			}
			rest, ok := expandMakePath(s[:loc[0]]+filepath.FromSlash(e)+s[loc[1]:], vars, depth+1)
			if !ok {
				return nil, false
			}
			out = append(out, rest...)
			if len(out) > maxPathValues {
				return nil, false
			}
		}
	}
	return dedupe(out), true
}

// Load walks <portsTree>/<category>/<port>/distinfo* and returns the index.
// A tree with no distinfo at all fails, because it is not a ports tree and
// every request would 404 with nothing saying why.
func Load(portsTree string) (*Index, error) {
	cats, err := os.ReadDir(portsTree)
	if err != nil {
		return nil, fmt.Errorf("read ports tree %s: %w", portsTree, err)
	}
	db, err := loadLicenseDB(portsTree)
	if err != nil {
		return nil, err
	}
	ix := &Index{entries: map[string]*Entry{}, refused: map[string]string{}}
	byPort := map[string][]string{}   // origin -> names its distinfo pins
	restricted := map[string]string{} // origin -> reason
	for _, cat := range cats {
		if !cat.IsDir() || strings.HasPrefix(cat.Name(), ".") || cat.Name() == "distfiles" || cat.Name() == "packages" {
			continue
		}
		ports, err := os.ReadDir(filepath.Join(portsTree, cat.Name()))
		if err != nil {
			return nil, fmt.Errorf("read category %s: %w", cat.Name(), err)
		}
		for _, p := range ports {
			if !p.IsDir() {
				continue
			}
			origin := cat.Name() + "/" + p.Name()
			dir := filepath.Join(portsTree, cat.Name(), p.Name())
			files, err := os.ReadDir(dir)
			if err != nil {
				return nil, fmt.Errorf("read port %s: %w", origin, err)
			}
			var own []string
			for _, f := range files {
				n := f.Name()
				switch {
				case f.IsDir():
				case n == "distinfo" || strings.HasPrefix(n, "distinfo."):
					if err := ix.addDistinfo(filepath.Join(dir, n), origin, byPort); err != nil {
						return nil, err
					}
				case n == "Makefile" || strings.HasPrefix(n, "Makefile."):
					own = append(own, filepath.Join(dir, n))
				}
			}
			makefiles, unresolved := portText(portsTree, dir, own)
			why := restriction(origin, makefiles, db)
			if why == "" && unresolved != "" {
				why = fmt.Sprintf("%s: %s, so its redistribution terms cannot be established", origin, unresolved)
			}
			if why != "" {
				restricted[origin] = why
				// A slave reads its master's distinfo, so its restriction
				// has to reach the names filed under the master.
				if mm := masterDirVar.FindSubmatch(makefiles); mm != nil {
					master := path.Clean(origin + "/" + string(mm[1]))
					if !strings.HasPrefix(master, "..") && strings.Count(master, "/") == 1 {
						if _, ok := restricted[master]; !ok {
							restricted[master] = why
						}
					}
				}
			}
		}
	}
	if ix.Len() == 0 {
		return nil, fmt.Errorf("%s holds no <category>/<port>/distinfo; distfiles_ports_tree must name the root of a FreeBSD ports tree", portsTree)
	}
	// Sorted, so a distfile two restricted ports share names the same one on
	// every read.
	origins := make([]string, 0, len(restricted))
	for origin := range restricted {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	for _, origin := range origins {
		why := restricted[origin]
		for _, name := range byPort[origin] {
			if e, ok := ix.entries[name]; ok && e.Restricted == "" {
				e.Restricted = why
			}
		}
	}
	return ix, nil
}

func (ix *Index) addDistinfo(file, origin string, byPort map[string][]string) error {
	f, err := os.Open(file) //nolint:gosec // G304: file is a distinfo under the configured ports tree.
	if err != nil {
		return fmt.Errorf("open %s: %w", file, err)
	}
	defer f.Close()
	parsed, unusable, err := Parse(f)
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	for name, why := range unusable {
		ix.refused[name] = origin + "/" + filepath.Base(file) + ": " + why
		delete(ix.entries, name)
	}
	for name, e := range parsed {
		byPort[origin] = append(byPort[origin], name)
		if _, bad := ix.refused[name]; bad {
			continue
		}
		have, ok := ix.entries[name]
		if !ok {
			e.Ports = []string{origin}
			ix.entries[name] = &e
			continue
		}
		if have.SHA256 != e.SHA256 || have.Size != e.Size {
			ix.refused[name] = fmt.Sprintf("%s and %s pin different digests", strings.Join(have.Ports, ","), origin)
			delete(ix.entries, name)
			continue
		}
		have.Ports = append(have.Ports, origin)
		sort.Strings(have.Ports)
	}
	return nil
}

// Tree is an Index over one ports tree, read in the background and re-read
// once it is older than ttl, so a server neither waits out a cold walk at
// startup nor holds a request while a stale index reloads. A reload that fails
// keeps the previous index: a server that refused every distfile because a
// `git pull` was halfway through would turn a transient state into an outage.
type Tree struct {
	root string
	ttl  time.Duration
	logf func(format string, args ...any)

	mu      sync.Mutex
	ix      *Index
	loadErr error
	loaded  time.Time
	loading bool

	ready     chan struct{} // closed when the first read finishes, either way
	readyOnce sync.Once
}

// NewTree starts the first read of root and returns at once. logf receives
// one line per completed or failed read; nil discards them.
func NewTree(root string, ttl time.Duration, logf func(format string, args ...any)) *Tree {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	t := &Tree{root: root, ttl: ttl, logf: logf, ready: make(chan struct{})}
	t.mu.Lock()
	t.startLoadLocked()
	t.mu.Unlock()
	return t
}

// Root is the ports tree this index reads.
func (t *Tree) Root() string { return t.root }

func (t *Tree) startLoadLocked() {
	if t.loading {
		return
	}
	t.loading = true
	t.loaded = time.Now()
	go func() {
		start := time.Now()
		ix, err := Load(t.root)
		t.mu.Lock()
		defer t.mu.Unlock()
		defer t.readyOnce.Do(func() { close(t.ready) })
		t.loading = false
		t.loaded = time.Now()
		if err != nil {
			t.loadErr = err
			t.logf("distinfo: reading %s failed after %s, keeping the previous index: %v", t.root, time.Since(start).Round(time.Millisecond), err)
			return
		}
		t.ix, t.loadErr = ix, nil
		t.logf("distinfo: indexed %d distfiles from %s in %s", ix.Len(), t.root, time.Since(start).Round(time.Millisecond))
	}()
}

// Wait blocks until the first read has finished, for a caller with nothing to
// serve until it has. It returns the read's error, if any.
func (t *Tree) Wait() error {
	<-t.ready
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ix != nil {
		return nil
	}
	return t.loadErr
}

// firstReadWait is how long a lookup waits for the first read before
// answering ErrNotReady. A warm tree reads in about a second, so a request that
// arrives soon after startup is answered rather than refused; a cold one does
// not hold a client for the better part of a minute.
const firstReadWait = 5 * time.Second

// Lookup answers from the current index, starting a background re-read when
// it is stale. Before the first read completes it waits up to firstReadWait,
// then returns ErrNotReady.
func (t *Tree) Lookup(name string) (Entry, error) {
	select {
	case <-t.ready:
	case <-time.After(firstReadWait):
	}
	t.mu.Lock()
	if t.ttl > 0 && time.Since(t.loaded) > t.ttl {
		t.startLoadLocked()
	}
	ix, loadErr := t.ix, t.loadErr
	t.mu.Unlock()
	if ix == nil {
		if loadErr != nil {
			return Entry{}, fmt.Errorf("%w: reading %s failed: %v", ErrNotReady, t.root, loadErr)
		}
		return Entry{}, fmt.Errorf("%w: still reading %s", ErrNotReady, t.root)
	}
	return ix.Lookup(name)
}

// Names lists every distfile the index can answer for, sorted.
func (ix *Index) Names() []string {
	out := make([]string, 0, ix.Len())
	for n := range ix.entries {
		out = append(out, n)
	}
	for n := range ix.refused {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
