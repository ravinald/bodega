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
	unowned []string
}

// Unowned lists the restricted ports whose distinfo the reader could not
// place, each with its restriction and why. Any of them may read any distinfo
// in the tree, so while the list is not empty every distfile is refused.
func (ix *Index) Unowned() []string { return ix.unowned }

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
	// refName finds the name of every ${...} reference, whatever follows the
	// name. It matches more than expandMakePath will expand, which is the
	// direction readsTainted needs.
	refName = regexp.MustCompile(`\$\{([A-Za-z_.][A-Za-z0-9_.]*)`)
)

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
	conditionalElse  = regexp.MustCompile(`^[ \t]*\.[ \t]*(else|elif[a-z]*)\b`)
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
//
// The property the reader keeps is that at every include, the values it holds
// for each variable in the path include every value make could give it there.
// Conditionals are not evaluated, so an assignment under one, or in a file
// included under one, adds a possible value rather than replacing the current
// one, and an include whose path has several possible values reads every one
// that exists. A := is expanded where it stands, as make does. A file included
// twice is read twice, each time with the variables in force at that include,
// because the second read can reach a different file. Wherever the reader
// cannot keep the property it makes the variable unreadable instead: a !=, a
// += or := inside a .for whose iterations it does not count, an assignment to
// a name built from variables it cannot expand, an .undef it cannot place, and
// a ::= or :_= modifier, which assigns while it expands. Only .CURDIR,
// .PARSEDIR, PORTSDIR, variables the port assigns, variables the supported
// environment declares, .for variables, and the :H, :tl, :tu, :tA and :C
// modifiers are understood.
//
// Three states have to match make's for that property to hold. A variable an
// .undef may have removed is no longer definitely set, so a later ?= may take
// effect. A .for variable is substituted into the loop body's text, as make
// does, holding every word of the loop's list, so it shadows an outer variable
// of the same name inside the body and nowhere else. And an assignment whose
// name is computed reaches the restriction decision, not only later includes:
// a resolved name is appended to the text restriction reads, and one that
// cannot be resolved but could name a restriction variable refuses the port.
//
// The port is unresolved, and so refused, when an include path holds anything
// else, reads an unreadable variable, includes itself, reaches more than
// maxIncludeReads files, or names no file where the include is unconditional.
// A missing file under a conditional include is skipped: make reaches that
// line only when its guard, usually exists(), holds. That holds inside the
// tree only, because the tree is the one input the server and the client
// share. A path outside it is on the client host, and whether it exists there
// is something only env can say: a file env declares is read as each of its
// alternatives, and one it does not declare refuses the port, whether or not
// the server happens to hold a file at that path. A path the server finds
// through a symlink out of the tree refuses as well. Angle-bracket includes and
// anything under Mk/ are the framework, whose license handling the database
// read models.
//
// A port's restriction covers every distinfo its fetch may read, which is
// ${DISTINFO_FILE}, by default ${MASTERDIR}/distinfo. A slave's names sit in
// its master's distinfo, and a port may point DISTINFO_FILE at any other
// port's. Both are resolved from the variables the walk holds, at every
// framework include and at the end, because a port may reassign either after
// including bsd.port.mk and make reads them lazily. The whole path has to
// resolve, because a reference after the last "/" may expand to more
// separators and "..", and Load then restricts every distinfo* in its
// directory. owners lists those directories; ownerUnknown is non-empty when
// one of them cannot be resolved, or when the read stopped before the end, and
// says which.
func portText(tree, dir string, own []string, env *Environment) (p portRead) {
	given := tree
	if realTree, err := filepath.EvalSymlinks(tree); err == nil {
		tree = realTree
	}
	r := &makeReader{
		tree:      tree,
		treeGiven: given,
		dir:       dir,
		env:       env,
		texts:     map[string][]byte{},
		open:      map[string]bool{},
		vars: map[string][]string{
			".CURDIR":   {dir},
			"PORTSDIR":  {tree},
			treeVarName: dedupe([]string{tree, given}),
		},
		distinfo: map[string]bool{},
	}
	// A declared variable is set before the port's first line, as make.conf
	// sets one: an assignment in the port replaces it and a ?= does not.
	for name, vals := range env.vars {
		r.vars[name] = append([]string(nil), vals...)
	}
	for _, f := range own {
		real := f
		if rf, err := filepath.EvalSymlinks(f); err == nil {
			real = rf
		}
		// A Makefile.* another Makefile already included was read in the
		// context make reads it in; reading it again from the top would
		// apply its assignments a second time with nothing to justify it.
		if _, reached := r.texts[real]; reached {
			continue
		}
		if why := r.read(source{path: real, key: real}, 0, false, false, false); why != "" {
			p.unresolved = why
			r.ownerUnknown = "its Makefiles were not read to the end, so where its distinfo is set cannot be established"
			break
		}
	}
	if p.unresolved == "" {
		p.unresolved = r.taintedRestriction()
	}
	r.framework(false)
	p.text = r.buf
	p.ownerUnknown = r.ownerUnknown
	for d := range r.distinfo {
		p.owners = append(p.owners, d)
	}
	sort.Strings(p.owners)
	return p
}

// portRead is what portText learns about one port.
type portRead struct {
	text         []byte
	unresolved   string
	owners       []string
	ownerUnknown string
}

// maxIncludeReads bounds how many files one port's includes may read, counting
// a file once per include that reaches it. The deepest port in the tree reads
// a handful; a tree built so that every file includes the next one twice would
// otherwise read 2^maxIncludeDepth.
const maxIncludeReads = 256

// unreadable is the value of a variable the reader cannot follow. It holds a
// "$" no reference matches, so expandMakePath refuses any path that reads it.
const unreadable = "$(unreadable)"

// undefined stands among a variable's values for the paths on which make holds
// it undefined: before an assignment make may skip, or after an .undef make may
// run. It is kept apart from "" because ?= assigns on those paths and not on
// one where the variable is set to nothing, and apart from unreadable because
// ?= resolves it. A path reading it refuses, as one reading a variable the
// port never set does: make would expand it to nothing unless make.conf or the
// environment set it, and the reader sees neither.
const undefined = "$(undefined)"

var (
	undefDirective     = regexp.MustCompile(`^[ \t]*\.[ \t]*undef[ \t]+(.*?)[ \t]*$`)
	forDirective       = regexp.MustCompile(`^[ \t]*\.[ \t]*for[ \t]+(.*?)[ \t]+in\b[ \t]*(.*)$`)
	modifierAssignment = regexp.MustCompile(`::[?+!]?=`)
	underscoreModifier = regexp.MustCompile(`:_(?:=([^:}]*))?[:}]`)
	frameworkInclude   = regexp.MustCompile(`^[ \t]*\.[ \t]*(-?include|sinclude|dinclude)[ \t]+<`)
	anyReference       = regexp.MustCompile(`\$\{[^{}$]*\}|\$\([^()$]*\)|\$[A-Za-z0-9_.]`)
)

// makeReader holds one port's walk through its Makefiles: the variables as
// far as the walk has read, and the text every file contributed.
type makeReader struct {
	tree, dir string
	treeGiven string // tree as configured, before its symlinks were resolved
	env       *Environment
	buf       []byte
	texts     map[string][]byte // source key -> its text, read once however often it is included
	open      map[string]bool   // source keys being read now, which an include of would recurse
	reads     int
	loops     int // .for directives read, which keeps each one's bound names distinct

	// vars holds every value each variable may have at the line being read.
	// A variable absent here is undefined on every path.
	vars map[string][]string
	// tainted matches names some assignment may have written without the
	// reader knowing which: a computed name, or a ::= modifier.
	tainted []taintedName

	distinfo     map[string]bool // every directory DISTINFO_FILE may name a file in
	ownerUnknown string
}

type taintedName struct {
	re   *regexp.Regexp
	name string // as the Makefile spells it
}

func (r *makeReader) set(name string, vals []string, conditional bool) {
	if conditional {
		vals = append(r.prior(name), vals...)
	}
	r.vars[name] = capValues(dedupe(vals))
}

// prior is every value name may hold on a path that skips the assignment
// being read: undefined when nothing has set it yet.
func (r *makeReader) prior(name string) []string {
	cur, ok := r.vars[name]
	if !ok {
		return []string{undefined}
	}
	return append([]string(nil), cur...)
}

// assign applies one assignment. conditional is whether make may skip it,
// looping whether make may run it more than once.
func (r *makeReader) assign(name, op, val, parseDir string, conditional, looping bool) {
	switch {
	case op == "!":
		r.set(name, []string{unreadable}, conditional)
	case looping && (op == "+" || op == ":"):
		r.set(name, []string{unreadable}, conditional)
	case op == "+":
		cur := r.prior(name)
		out := make([]string, 0, len(cur))
		for _, c := range cur {
			if c == undefined {
				out = append(out, val)
				continue
			}
			out = append(out, strings.TrimSpace(c+" "+val))
		}
		if conditional {
			out = append(out, cur...)
		}
		r.vars[name] = capValues(dedupe(out))
	case op == ":":
		r.set(name, r.expandNow(val, parseDir), conditional)
	case op == "?":
		// Assigns on the paths where name is undefined, and only those.
		cur := r.prior(name)
		out := make([]string, 0, len(cur)+1)
		took := false
		for _, c := range cur {
			if c == undefined {
				took = true
				if !conditional {
					continue
				}
			}
			out = append(out, c)
		}
		if took {
			out = append(out, val)
		}
		r.vars[name] = capValues(dedupe(out))
	default:
		r.set(name, []string{val}, conditional)
	}
}

// expandNow is a := right-hand side as make holds it after the assignment:
// expanded against the variables in force now, or unreadable where the
// reader cannot do that.
func (r *makeReader) expandNow(val, parseDir string) []string {
	if !strings.Contains(val, "$") {
		return []string{val}
	}
	scope := r.scope(parseDir)
	if r.readsTainted(val, scope) {
		return []string{unreadable}
	}
	vals, ok := expandMakePath(val, scope, 0)
	if !ok {
		return []string{unreadable}
	}
	return vals
}

func (r *makeReader) scope(parseDir string) map[string][]string {
	scope := make(map[string][]string, len(r.vars)+1)
	for k, v := range r.vars {
		scope[k] = v
	}
	scope[".PARSEDIR"] = []string{parseDir}
	// Nothing but the port and the framework sets these, so where neither has
	// make holds them undefined and expands them to nothing. The same holds
	// for a variable the environment declares undefined. Any other variable
	// the reader has no value for may come from Mk/ or make.conf, and stays
	// unresolvable.
	names := []string{"MASTERDIR", "FILESDIR"}
	for name := range r.env.undefined {
		names = append(names, name)
	}
	for _, name := range names {
		vals := r.prior(name)
		for i, v := range vals {
			if v == undefined {
				vals[i] = ""
			}
		}
		scope[name] = dedupe(vals)
	}
	return scope
}

// taint records that name, which may be built from variables, was written to
// with a value the reader does not follow.
func (r *makeReader) taint(name string) {
	// Innermost references first, so ${"${A}":?B:C} is one reference.
	literal := strings.ReplaceAll(name, "$$", "\x01")
	for prev := ""; prev != literal; {
		prev = literal
		literal = anyReference.ReplaceAllString(literal, "\x00")
	}
	literal = strings.ReplaceAll(literal, "\x01", "$")
	if strings.Contains(literal, "$") {
		r.tainted = append(r.tainted, taintedName{regexp.MustCompile(`.*`), name})
		return
	}
	parts := strings.Split(literal, "\x00")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	r.tainted = append(r.tainted, taintedName{regexp.MustCompile(`^` + strings.Join(parts, `.*`) + `$`), name})
}

// taintedRestriction names a write the reader could not follow that may have
// been to a variable restriction reads, or returns "". It runs once the port
// is read, because which LICENSE_PERMS_<lic> the framework reads depends on a
// LICENSE the port may set after the write. Such a write refuses the port
// whether or not anything later reads it: it may be the restriction itself.
func (r *makeReader) taintedRestriction() string {
	names := []string{"RESTRICTED", "NO_CDROM", "LICENSE", "LICENSE_PERMS"}
	for _, m := range licenseVar.FindAllSubmatch(r.buf, -1) {
		for _, lic := range strings.Fields(string(m[1])) {
			names = append(names, "LICENSE_PERMS_"+lic)
		}
	}
	for _, t := range r.tainted {
		for _, n := range names {
			if t.re.MatchString(n) {
				return fmt.Sprintf("an assignment to %q may set %s, and cannot be followed without make", t.name, n)
			}
		}
	}
	return ""
}

// readsTainted reports whether s reads, directly or through the values of the
// variables it reads, any variable a tainted pattern matches.
func (r *makeReader) readsTainted(s string, vars map[string][]string) bool {
	if len(r.tainted) == 0 {
		return false
	}
	seen := map[string]bool{}
	var walk func(string, int) bool
	walk = func(s string, depth int) bool {
		if depth > 8 {
			return true
		}
		for _, m := range refName.FindAllStringSubmatch(s, -1) {
			name := m[1]
			if seen[name] {
				continue
			}
			seen[name] = true
			for _, t := range r.tainted {
				if t.re.MatchString(name) {
					return true
				}
			}
			for _, v := range vars[name] {
				if walk(v, depth+1) {
					return true
				}
			}
		}
		return false
	}
	return walk(s, 0)
}

// framework applies the defaults bsd.port.mk gives a port's own directories
// with ?=, which is when make applies them: at the framework include, not
// before it. A slave that sets MASTERDIR under .if and .else would otherwise
// appear to include itself.
func (r *makeReader) framework(conditional bool) {
	r.assign("MASTERDIR", "?", "${.CURDIR}", "", conditional, false)
	r.assign("FILESDIR", "?", "${MASTERDIR}/files", "", conditional, false)
	r.assign("PKGDIR", "?", "${MASTERDIR}", "", conditional, false)
	r.assign("DISTINFO_FILE", "?", "${MASTERDIR}/distinfo", "", conditional, false)
	r.noteDistinfo()
}

// noteDistinfo records every directory DISTINFO_FILE may name a file in now,
// or why it cannot say. A path on which DISTINFO_FILE is still undefined names
// nothing yet: a later framework include, or the end of the read, gives it
// the default.
func (r *makeReader) noteDistinfo() {
	if r.ownerUnknown != "" {
		return
	}
	scope := r.scope(r.dir)
	if r.readsTainted("${DISTINFO_FILE}", scope) {
		r.ownerUnknown = "an assignment the reader cannot follow may set DISTINFO_FILE or a variable it reads"
		return
	}
	for _, v := range r.vars["DISTINFO_FILE"] {
		if v == undefined {
			continue
		}
		dirs, ok := r.expandDir(v, scope)
		if !ok {
			r.ownerUnknown = fmt.Sprintf("DISTINFO_FILE=%s names a directory that cannot be resolved without make", v)
			return
		}
		for _, d := range dirs {
			if !filepath.IsAbs(d) {
				d = filepath.Join(r.dir, d)
			}
			r.distinfo[filepath.Clean(d)] = true
		}
	}
}

// expandDir resolves the directory of every path v can take. The whole path
// has to resolve: a reference after the last literal "/" may expand to more
// separators and "..", so the text before it bounds nothing.
func (r *makeReader) expandDir(v string, scope map[string][]string) ([]string, bool) {
	if r.readsTainted(v, scope) {
		return nil, false
	}
	paths, ok := expandMakePath(v, scope, 0)
	if !ok {
		return nil, false
	}
	for i, p := range paths {
		paths[i] = filepath.Dir(p)
	}
	return paths, true
}

// source is one file make may read at an include: a file in the tree, read
// from disk, or one alternative the environment declares for a client-host
// path, whose text is the operator's snapshot. key tells two alternatives for
// one path apart.
type source struct {
	path      string // as make names it, which is what .PARSEDIR and relative includes see
	key       string
	declared  bool   // text is a snapshot; path is on the client and is never opened here
	text      []byte // the snapshot, when declared
	framework bool   // under Mk/
}

// read reads src as make would reach it: conditional when make may skip it
// on some path the reader has not forked, guarded when some enclosing .if in
// an including file decides whether make reaches it at all, looping when an
// enclosing .for may read it more than once.
//
// An .if chain forks the variables rather than marking what it holds as
// conditional: each branch starts from the values in force at the .if, and at
// the .endif every branch's values are merged, with the values from before
// the .if as one more branch when there is no .else. So an assignment and the
// include after it in one branch see the assignment alone, and an exhaustive
// .if/.else leaves no path on which a variable both branches set is still
// undefined. Conditions are still not evaluated: every branch is read.
func (r *makeReader) read(src source, depth int, conditional, guarded, looping bool) string {
	file := src.path
	if r.open[src.key] {
		return fmt.Sprintf("%s includes itself, which cannot be resolved without make", file)
	}
	if r.reads++; r.reads > maxIncludeReads {
		return fmt.Sprintf("%s is one of more than %d files its includes reach", file, maxIncludeReads)
	}
	b, seen := r.texts[src.key]
	if !seen {
		raw := src.text
		if !src.declared {
			var err error
			raw, err = os.ReadFile(file) //nolint:gosec // G304: resolved and confined under the configured ports tree.
			if err != nil {
				return fmt.Sprintf("cannot read %s: %v", file, err)
			}
		}
		b = stripComments(joinContinuations(raw))
		r.texts[src.key] = b
		r.buf = append(append(r.buf, b...), '\n')
	}
	r.open[src.key] = true
	defer delete(r.open, src.key)
	parseDir := filepath.Dir(file)

	var blocks []block // innermost last
	inFor := func() bool {
		for _, k := range blocks {
			if k.loop {
				return true
			}
		}
		return false
	}
	inIf := func() bool {
		for _, k := range blocks {
			if k.chain != nil {
				return true
			}
		}
		return false
	}
	// Only a .for that may run no iteration makes what its body does
	// conditional; an .if chain forks instead.
	skippable := func() bool {
		for _, k := range blocks {
			if k.loop && k.mayBeEmpty {
				return true
			}
		}
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = bindLoopVars(line, blocks)
		for _, name := range modifierTargets(line) {
			r.taint(name)
		}
		directive := strings.HasPrefix(strings.TrimLeft(line, " \t"), ".")
		if !directive && !strings.Contains(line, "=") {
			continue
		}
		cond := conditional || skippable()
		guard := guarded || cond || inIf()
		loop := looping || inFor()
		if directive {
			if m := forDirective.FindStringSubmatch(line); m != nil {
				blocks = append(blocks, r.bindFor(m[1], m[2], parseDir))
				continue
			}
			if m := conditionalOpen.FindStringSubmatch(line); m != nil {
				if m[1] == "for" {
					return fmt.Sprintf("%s has a .for the reader cannot parse: %q", file, strings.TrimSpace(line))
				}
				blocks = append(blocks, block{chain: &ifChain{before: copyVars(r.vars)}})
				continue
			}
			if m := conditionalElse.FindStringSubmatch(line); m != nil {
				if len(blocks) == 0 || blocks[len(blocks)-1].chain == nil {
					return fmt.Sprintf("%s has a .%s the reader cannot match to an .if", file, m[1])
				}
				c := blocks[len(blocks)-1].chain
				if c.sawElse {
					return fmt.Sprintf("%s has a .%s after an .else", file, m[1])
				}
				c.branches = append(c.branches, r.vars)
				r.vars = copyVars(c.before)
				c.sawElse = m[1] == "else"
				continue
			}
			if m := conditionalClose.FindStringSubmatch(line); m != nil {
				if len(blocks) == 0 {
					return fmt.Sprintf("%s has an .%s the reader cannot match", file, m[1])
				}
				top := blocks[len(blocks)-1]
				if (m[1] == "endif") != (top.chain != nil) {
					return fmt.Sprintf("%s closes a block with an .%s that does not match it", file, m[1])
				}
				if c := top.chain; c != nil {
					branches := append(c.branches, r.vars)
					if !c.sawElse {
						branches = append(branches, c.before)
					}
					r.vars = mergeVars(branches)
				}
				blocks = blocks[:len(blocks)-1]
				continue
			}
			if m := undefDirective.FindStringSubmatch(line); m != nil {
				for _, name := range strings.Fields(m[1]) {
					switch {
					case strings.Contains(name, "$"):
						r.taint(name)
					case cond:
						r.set(name, []string{undefined}, true)
					default:
						delete(r.vars, name)
					}
				}
				continue
			}
			if why := r.include(file, line, depth, cond, guard, loop); why != "" {
				return why
			}
			continue
		}
		if m := assignment.FindStringSubmatch(line); m != nil {
			r.assign(m[1], m[2], m[3], parseDir, cond, loop)
			continue
		}
		if name, op, val, ok := computedAssignment(line); ok {
			names, ok := expandMakePath(name, r.scope(parseDir), 0)
			if !ok || r.readsTainted(name, r.vars) {
				r.taint(name)
				continue
			}
			for _, n := range names {
				r.assign(n, op, val, parseDir, cond || len(names) > 1, loop)
				r.buf = append(r.buf, n+op+"=\t"+val+"\n"...)
			}
		}
	}
	return ""
}

// block is one open .if or .for. A .for maps each variable it binds to the
// name its words are held under in the reader's variables. A .for whose list
// cannot be empty runs its body at least once, so only one that may be empty
// makes what its body does conditional.
type block struct {
	loop       bool
	mayBeEmpty bool
	bound      map[string]string
	chain      *ifChain // an .if and the .elif and .else that follow it
}

// ifChain is what an open .if chain has seen: the variables when it opened,
// and each branch's variables as that branch ended.
type ifChain struct {
	before   map[string][]string
	branches []map[string][]string
	sawElse  bool
}

func copyVars(vars map[string][]string) map[string][]string {
	out := make(map[string][]string, len(vars))
	for k, v := range vars {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// mergeVars is every value each variable may hold after one of branches has
// run. A variable some branch leaves undefined is undefined on that path.
func mergeVars(branches []map[string][]string) map[string][]string {
	names := map[string]bool{}
	for _, b := range branches {
		for k := range b {
			names[k] = true
		}
	}
	out := make(map[string][]string, len(names))
	for k := range names {
		var vals []string
		for _, b := range branches {
			v, ok := b[k]
			if !ok {
				v = []string{undefined}
			}
			vals = append(vals, v...)
		}
		out[k] = capValues(dedupe(vals))
	}
	return out
}

// bindFor opens a .for. Its variables are bound under names no Makefile can
// write, to every word the list can hold: a superset of what any one
// iteration substitutes. A list the reader cannot expand binds them to
// unreadable, so a path or name built from one refuses.
func (r *makeReader) bindFor(vars, list, parseDir string) block {
	var words []string
	mayBeEmpty := true
	switch {
	case !strings.Contains(list, "$"):
		words = strings.Fields(list)
		mayBeEmpty = len(words) == 0
	case r.readsTainted(list, r.scope(parseDir)):
	default:
		if vals, ok := expandMakePath(list, r.scope(parseDir), 0); ok {
			mayBeEmpty = false
			for _, v := range vals {
				fields := strings.Fields(v)
				mayBeEmpty = mayBeEmpty || len(fields) == 0
				words = append(words, fields...)
			}
		}
	}
	words = capValues(dedupe(words))
	if len(words) == 0 {
		words = []string{unreadable}
	}
	r.loops++
	b := block{loop: true, mayBeEmpty: mayBeEmpty, bound: map[string]string{}}
	for _, v := range strings.Fields(vars) {
		name := fmt.Sprintf(".bodega.for%d.%s", r.loops, v)
		r.vars[name] = words
		b.bound[v] = name
	}
	return b
}

// bindLoopVars substitutes each ${var} and ${var:...} a .for binds with the
// name its words are held under. make substitutes a loop's variables into the
// text of its whole body, nested loops included, before reading it: so the
// outermost loop binds first and wins over an inner one of the same name, and
// a variable the body reaches only through another variable's value is the
// global one. A one-character variable is also substituted where it is
// written $v, as make does. $(var) is left as it is: the path expansion does
// not follow it, so it refuses.
func bindLoopVars(line string, blocks []block) string {
	if !strings.Contains(line, "$") {
		return line
	}
	for i := range blocks {
		for v, name := range blocks[i].bound {
			line = strings.ReplaceAll(line, "${"+v+"}", "${"+name+"}")
			line = strings.ReplaceAll(line, "${"+v+":", "${"+name+":")
			if len(v) == 1 {
				line = substituteShort(line, v[0], "${"+name+"}")
			}
		}
	}
	return line
}

// substituteShort replaces each $c reference with ref, leaving $$, which make
// reads as a literal dollar, alone.
func substituteShort(line string, c byte, ref string) string {
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		if line[i] == '$' && i+1 < len(line) {
			if line[i+1] == '$' {
				b.WriteString("$$")
				i++
				continue
			}
			if line[i+1] == c {
				b.WriteString(ref)
				i++
				continue
			}
		}
		b.WriteByte(line[i])
	}
	return b.String()
}

// computedAssignment splits a line assigning to a name built from variable
// references. The name is read with its braces balanced, because a modifier
// inside one may hold spaces or an "=" and still be part of the name.
func computedAssignment(line string) (name, op, val string, ok bool) {
	i := len(line) - len(strings.TrimLeft(line, " \t"))
	start, depth, sawRef := i, 0, false
	for ; i < len(line); i++ {
		c := line[i]
		if c == '$' && i+1 < len(line) && (line[i+1] == '{' || line[i+1] == '(') {
			depth++
			sawRef = true
			i++
			continue
		}
		if c == '$' {
			sawRef = true
		}
		if depth > 0 {
			if c == '}' || c == ')' {
				depth--
			}
			continue
		}
		if strings.ContainsRune(" \t=?:+!", rune(c)) {
			break
		}
	}
	if !sawRef || depth > 0 || i == start {
		return "", "", "", false
	}
	name = line[start:i]
	rest := strings.TrimLeft(line[i:], " \t")
	if len(rest) > 0 && strings.ContainsRune("?:+!", rune(rest[0])) {
		op, rest = rest[:1], rest[1:]
	}
	if !strings.HasPrefix(rest, "=") {
		return "", "", "", false
	}
	return name, op, strings.TrimSpace(rest[1:]), true
}

// modifierTargets names every variable a ::=, ::?=, ::+=, ::!= or :_=
// modifier on line assigns to. A target the reader cannot name comes back as
// "${}", which taints every name.
func modifierTargets(line string) []string {
	if !strings.Contains(line, "::") && !strings.Contains(line, ":_") {
		return nil
	}
	var out []string
	for _, m := range modifierAssignment.FindAllStringSubmatchIndex(line, -1) {
		open := strings.LastIndex(line[:m[0]], "${")
		if open < 0 || strings.ContainsAny(line[open+2:m[0]], "${}:") {
			out = append(out, "${}")
			continue
		}
		out = append(out, line[open+2:m[0]])
	}
	for _, m := range underscoreModifier.FindAllStringSubmatch(line, -1) {
		switch {
		case m[1] == "":
			out = append(out, "_")
		case strings.Contains(m[1], "$"):
			out = append(out, "${}")
		default:
			out = append(out, m[1])
		}
	}
	return out
}

// include follows one .include line of file, if it is a quoted one.
func (r *makeReader) include(file, line string, depth int, conditional, guarded, looping bool) string {
	if frameworkInclude.MatchString(line) {
		r.framework(conditional)
		return ""
	}
	m := includeDirective.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	optional := m[1] != "include" || guarded
	raw := m[2]
	if depth >= maxIncludeDepth {
		return fmt.Sprintf("%s includes %q past a depth of %d", file, raw, maxIncludeDepth)
	}
	scope := r.scope(filepath.Dir(file))
	if r.readsTainted(raw, scope) {
		return fmt.Sprintf("%s includes %q, which reads a variable assigned in a way that cannot be followed without make", file, raw)
	}
	paths, ok := expandMakePath(raw, scope, 0)
	if !ok {
		return fmt.Sprintf("%s includes %q, which cannot be resolved without make", file, raw)
	}
	var found []source
	maybeNone := false // some value of the path reads no file
	for _, p := range paths {
		candidates := []string{p}
		if !filepath.IsAbs(p) {
			candidates = []string{filepath.Join(filepath.Dir(file), p), filepath.Join(r.dir, p)}
		}
		srcs, none, why := r.locate(candidates)
		if why != "" {
			return fmt.Sprintf("%s includes %q: %s", file, raw, why)
		}
		found = append(found, srcs...)
		maybeNone = maybeNone || none
	}
	if len(found) == 0 {
		if optional {
			return ""
		}
		return fmt.Sprintf("%s includes %q, which does not exist", file, raw)
	}
	// Several sources means make reads one of them, and an optional include
	// that may find nothing reads none, so each is read as something make may
	// skip. A mandatory include that finds nothing stops make, so that path
	// reaches no fetch and asks nothing of the ones that do.
	conditional = conditional || len(found) > 1 || (optional && maybeNone)
	for _, f := range found {
		if f.framework {
			r.framework(conditional)
			continue
		}
		if why := r.read(f, depth+1, conditional, guarded, looping); why != "" {
			return why
		}
	}
	return ""
}

// locate is what make may read for one include path: the first candidate
// that exists, trying the next only where this one may be missing. none
// reports that every candidate may be missing.
func (r *makeReader) locate(candidates []string) (srcs []source, none bool, why string) {
	for _, c := range candidates {
		got, absent, why := r.lookup(filepath.Clean(c))
		if why != "" {
			return nil, false, why
		}
		srcs = append(srcs, got...)
		if !absent {
			return srcs, false, ""
		}
	}
	return srcs, true, ""
}

// lookup says what make finds at path p on a supported client. Inside the
// tree the server's copy answers, because the tree is the input both sides
// share. Outside it only the environment answers, and a path it does not
// declare cannot be answered at all: the server's own filesystem says nothing
// about a client's.
func (r *makeReader) lookup(p string) (srcs []source, absent bool, why string) {
	if !r.inTree(p) {
		f, ok := r.env.files[p]
		if !ok {
			return nil, false, fmt.Sprintf("%s leaves the ports tree, and the supported environment does not declare it, so what a client reads there cannot be established", p)
		}
		for i, text := range f.texts {
			srcs = append(srcs, source{path: p, key: fmt.Sprintf("%s\x00%d", p, i), declared: true, text: text})
		}
		return srcs, f.absent, ""
	}
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		// Missing in the tree, unless a symlink on the way out of it means
		// the client resolves the name somewhere the tree does not cover.
		if real, ok := r.resolveExisting(p); ok && !r.underReal(real) {
			return nil, false, fmt.Sprintf("%s leaves the ports tree", p)
		}
		return nil, true, ""
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return nil, false, fmt.Sprintf("%s: %v", p, err)
	}
	if !r.underReal(real) {
		return nil, false, fmt.Sprintf("%s leaves the ports tree", p)
	}
	rel, _ := filepath.Rel(r.tree, real)
	fw := rel == "Mk" || strings.HasPrefix(rel, "Mk"+string(filepath.Separator))
	return []source{{path: real, key: real, framework: fw}}, false, ""
}

// inTree reports whether p names a path under the tree as configured or as
// resolved, before any symlink below it is followed.
func (r *makeReader) inTree(p string) bool {
	return within(r.tree, p) || within(r.treeGiven, p)
}

func (r *makeReader) underReal(p string) bool { return within(r.tree, p) }

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// resolveExisting resolves the symlinks of the longest prefix of p that
// exists, and appends the rest.
func (r *makeReader) resolveExisting(p string) (string, bool) {
	rest := ""
	for dir := p; ; {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(real, rest), true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
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

// treeVarName holds the tree root, resolved and as configured, among a
// reader's variables, under a name no Makefile can write, for :tA to confine
// itself to.
const treeVarName = ".bodega.tree"

// expandMakePath substitutes ${VAR} references in an include path, with the
// modifiers modifier understands, returning every value the path can take. It
// reports false for a reference to a variable with no value here, for any "$"
// that does not start one of those references, and for a path with more than
// maxPathValues values.
func expandMakePath(s string, vars map[string][]string, depth int) ([]string, bool) {
	if depth > 8 {
		return nil, false
	}
	start := strings.IndexByte(s, '$')
	if start < 0 {
		return []string{s}, true
	}
	name, mods, end, ok := parseRef(s, start)
	if !ok {
		return nil, false
	}
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
			for _, m := range mods {
				if e, ok = m.apply(e, vars); !ok {
					return nil, false
				}
			}
			rest, ok := expandMakePath(s[:start]+e+s[end:], vars, depth+1)
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

// modifier is one variable modifier the reader applies as make does. Any other
// modifier refuses the reference: :M, :N and :S would each need their own
// model, and :sh, ::= and :_= run or assign things.
type modifier struct {
	op                 string // "H", "tl", "tu", "tA" or "C"
	re                 *regexp.Regexp
	repl               string
	global, one, whole bool
}

// parseRef reads the ${NAME:mod:...} reference at s[i], returning the index
// just past it. ok is false for anything else.
func parseRef(s string, i int) (name string, mods []modifier, end int, ok bool) {
	if !strings.HasPrefix(s[i:], "${") {
		return "", nil, 0, false
	}
	j := i + 2
	k := j
	for k < len(s) && (s[k] == '_' || s[k] == '.' || isAlpha(s[k]) || (k > j && isDigit(s[k]))) {
		k++
	}
	if k == j {
		return "", nil, 0, false
	}
	name = s[j:k]
	for k < len(s) {
		switch s[k] {
		case '}':
			return name, mods, k + 1, true
		case ':':
			m, next, ok := parseModifier(s, k+1)
			if !ok {
				return "", nil, 0, false
			}
			mods = append(mods, m)
			k = next
		default:
			return "", nil, 0, false
		}
	}
	return "", nil, 0, false
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// parseModifier reads one modifier starting at s[k], just past its ":", and
// returns the index of the ":" or "}" that ends it.
func parseModifier(s string, k int) (modifier, int, bool) {
	ends := func(at int) bool { return at < len(s) && (s[at] == ':' || s[at] == '}') }
	for _, op := range []string{"tA", "tl", "tu", "H"} {
		if strings.HasPrefix(s[k:], op) && ends(k+len(op)) {
			return modifier{op: op}, k + len(op), true
		}
	}
	if k+1 >= len(s) || s[k] != 'C' {
		return modifier{}, 0, false
	}
	delim := s[k+1]
	if isAlpha(delim) || isDigit(delim) || strings.IndexByte("\\${}(): \t", delim) >= 0 {
		return modifier{}, 0, false
	}
	pat, next, ok := modifierPart(s, k+2, delim)
	if !ok {
		return modifier{}, 0, false
	}
	repl, next, ok := modifierPart(s, next, delim)
	if !ok {
		return modifier{}, 0, false
	}
	m := modifier{op: "C", repl: repl}
	for ; next < len(s) && strings.IndexByte("1gW", s[next]) >= 0; next++ {
		switch s[next] {
		case '1':
			m.one = true
		case 'g':
			m.global = true
		case 'W':
			m.whole = true
		}
	}
	if !ends(next) {
		return modifier{}, 0, false
	}
	if m.re, ok = compileERE(pat); !ok {
		return modifier{}, 0, false
	}
	// A reference to a group the pattern does not have is an error in make.
	for i := 0; i+1 < len(repl); i++ {
		if repl[i] == '\\' {
			if isDigit(repl[i+1]) && int(repl[i+1]-'0') > m.re.NumSubexp() {
				return modifier{}, 0, false
			}
			i++
		}
	}
	return m, next, true
}

// modifierPart reads a :C pattern or replacement up to an unescaped delim. A
// backslash before delim yields delim; any other backslash is kept for the
// pattern or the replacement to read. A "$" refuses: make expands it first.
func modifierPart(s string, k int, delim byte) (string, int, bool) {
	var b strings.Builder
	for ; k < len(s); k++ {
		switch c := s[k]; {
		case c == delim:
			return b.String(), k + 1, true
		case c == '$':
			return "", 0, false
		case c == '\\' && k+1 < len(s) && s[k+1] == delim:
			b.WriteByte(delim)
			k++
		case c == '\\' && k+1 < len(s):
			b.WriteByte(c)
			b.WriteByte(s[k+1])
			k++
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, false
}

// compileERE compiles a :C pattern where Go's POSIX mode is known to read it as
// make's regcomp(3) does, and refuses it otherwise. Go reads a backslash inside
// a bracket, and before a letter or digit, where POSIX does not; and a pattern
// matching the empty string substitutes between characters, which the two
// libraries place differently.
func compileERE(pat string) (*regexp.Regexp, bool) {
	inBracket := false
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		switch {
		case inBracket && c == '\\':
			return nil, false
		case inBracket && c == '[' && i+1 < len(pat) && strings.IndexByte(":.=", pat[i+1]) >= 0:
			j := strings.Index(pat[i+2:], string(pat[i+1])+"]")
			if j < 0 {
				return nil, false
			}
			i += j + 3
		case inBracket && c == ']':
			inBracket = false
		case c == '\\':
			if i+1 >= len(pat) || isAlpha(pat[i+1]) || isDigit(pat[i+1]) {
				return nil, false
			}
			i++
		case c == '[':
			inBracket = true
			if i+1 < len(pat) && pat[i+1] == '^' {
				i++
			}
			if i+1 < len(pat) && pat[i+1] == ']' {
				i++
			}
		}
	}
	if inBracket {
		return nil, false
	}
	re, err := regexp.CompilePOSIX(pat)
	if err != nil || re.MatchString("") {
		return nil, false
	}
	return re, true
}

// apply is m applied to one value, as make applies it.
func (m modifier) apply(v string, vars map[string][]string) (string, bool) {
	switch m.op {
	case "H":
		return filepath.FromSlash(path.Dir(filepath.ToSlash(v))), true
	case "tl":
		return strings.ToLower(v), true
	case "tu":
		return strings.ToUpper(v), true
	case "tA":
		return realpathInTree(v, vars)
	}
	if m.whole {
		out, _ := m.substitute(v)
		return out, true
	}
	words := strings.Fields(v)
	done := false
	for i, w := range words {
		if done {
			break
		}
		var changed bool
		words[i], changed = m.substitute(w)
		done = m.one && changed
	}
	return strings.Join(words, " "), true
}

// substitute replaces the first match in w, or every one under g.
func (m modifier) substitute(w string) (string, bool) {
	matches := m.re.FindAllStringSubmatchIndex(w, -1)
	if len(matches) == 0 {
		return w, false
	}
	if !m.global {
		matches = matches[:1]
	}
	var b strings.Builder
	last := 0
	for _, loc := range matches {
		b.WriteString(w[last:loc[0]])
		for i := 0; i < len(m.repl); i++ {
			c := m.repl[i]
			switch {
			case c == '&':
				b.WriteString(w[loc[0]:loc[1]])
			case c == '\\' && i+1 < len(m.repl) && isDigit(m.repl[i+1]):
				n := int(m.repl[i+1] - '0')
				if loc[2*n] >= 0 {
					b.WriteString(w[loc[2*n]:loc[2*n+1]])
				}
				i++
			case c == '\\' && i+1 < len(m.repl):
				b.WriteByte(m.repl[i+1])
				i++
			default:
				b.WriteByte(c)
			}
		}
		last = loc[1]
	}
	b.WriteString(w[last:])
	return b.String(), true
}

// realpathInTree is :tA, which make answers with realpath(3) relative to the
// directory it runs in, leaving the value alone when that fails. It is
// answered only for a path inside the tree: anywhere else realpath would read
// the server's filesystem in place of the client's.
func realpathInTree(v string, vars map[string][]string) (string, bool) {
	cur, roots := vars[".CURDIR"], vars[treeVarName]
	if len(cur) != 1 || len(roots) == 0 || strings.ContainsAny(v, " \t") {
		return "", false
	}
	inside := func(p string) bool {
		for _, root := range roots {
			if within(root, p) {
				return true
			}
		}
		return false
	}
	p := v
	if !filepath.IsAbs(p) {
		p = filepath.Join(cur[0], p)
	}
	p = filepath.Clean(p)
	if !inside(p) {
		return "", false
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return v, true
	}
	if !inside(real) {
		return "", false
	}
	return real, true
}

// Load is LoadIn with the empty environment: no variable declared and no file
// outside the tree readable.
func Load(portsTree string) (*Index, error) { return LoadIn(portsTree, nil) }

// LoadIn walks <portsTree>/<category>/<port>/distinfo* and returns the index,
// reading every port as a client in env would. A tree with no distinfo at all
// fails, because it is not a ports tree and every request would 404 with
// nothing saying why.
func LoadIn(portsTree string, env *Environment) (*Index, error) {
	if env == nil {
		env = emptyEnvironment()
	}
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
	var unowned []string              // restricted ports whose distinfo cannot be placed
	var unownedOrigins []string
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
			pr := portText(portsTree, dir, own, env)
			why := restriction(origin, pr.text, db)
			if why == "" && pr.unresolved != "" {
				why = fmt.Sprintf("%s: %s, so its redistribution terms cannot be established", origin, pr.unresolved)
			}
			if why == "" {
				continue
			}
			owners, strays := portOrigins(portsTree, pr.owners)
			if pr.ownerUnknown == "" && len(strays) > 0 {
				pr.ownerUnknown = fmt.Sprintf("its DISTINFO_FILE may name a file in %s, which is not a <category>/<port> directory of the tree, so bodega indexes nothing there to restrict", strings.Join(strays, ", "))
			}
			if pr.ownerUnknown != "" {
				unowned = append(unowned, fmt.Sprintf("%s (%s): %s", origin, why, pr.ownerUnknown))
				unownedOrigins = append(unownedOrigins, origin)
			}
			for _, owner := range append([]string{origin}, owners...) {
				if _, ok := restricted[owner]; !ok {
					restricted[owner] = why
				}
			}
		}
	}
	if ix.Len() == 0 {
		return nil, fmt.Errorf("%s holds no <category>/<port>/distinfo; distfiles_ports_tree must name the root of a FreeBSD ports tree", portsTree)
	}
	ix.unowned = unowned
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
	// A distinfo nobody can place may be any distinfo in the tree: a value
	// the reader cannot resolve may hold "/" and "..", and one set by a file
	// outside the tree (the aspell dictionaries read ${LOCALBASE}/etc) is
	// fixed only by what the environment declares for that file. Refusing
	// only the port's own directory would refuse nothing for a slave with no
	// distinfo of its own, so every name is refused rather than guessed at.
	if len(unownedOrigins) > 0 {
		why := fmt.Sprintf("%s is restricted or unreadable and reads a distinfo bodega cannot place, so it may obtain any distfile in the tree", unownedOrigins[0])
		if n := len(unownedOrigins) - 1; n > 0 {
			why = fmt.Sprintf("%s and %d more ports are restricted or unreadable and read a distinfo bodega cannot place, so any of them may obtain any distfile in the tree", unownedOrigins[0], n)
		}
		for _, e := range ix.entries {
			if e.Restricted == "" {
				e.Restricted = why
			}
		}
	}
	return ix, nil
}

// portOrigins maps each directory to the <category>/<port> origin it names in
// tree. Load indexes no distinfo anywhere else, so any other directory comes
// back in strays: a restricted port reading a distinfo there may list names a
// port Load does index also lists, and dropping the directory would drop the
// restriction from them.
func portOrigins(tree string, dirs []string) (origins, strays []string) {
	if real, err := filepath.EvalSymlinks(tree); err == nil {
		tree = real
	}
	for _, d := range dirs {
		if real, err := filepath.EvalSymlinks(d); err == nil {
			d = real
		}
		rel, err := filepath.Rel(tree, d)
		rel = filepath.ToSlash(rel)
		if err == nil && strings.Count(rel, "/") == 1 && !strings.HasPrefix(rel, ".") {
			origins = append(origins, rel)
			continue
		}
		strays = append(strays, d)
	}
	return origins, strays
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
// to read the tree keeps the previous index: a server that refused every
// distfile because a `git pull` was halfway through would turn a transient
// state into an outage.
//
// The environment is the opposite case. Its snapshots are read at every load
// and held to the digest of the first read, and a load that cannot read them,
// or finds them changed, drops the index and refuses everything until a load
// finds the first bytes again or bodega restarts and adopts the new ones. An
// index admitted against bytes that are no longer the declared ones is not the
// declared environment's decision, and the operator changing a snapshot in
// place is the case where refusing is cheap and admitting is not.
type Tree struct {
	root string
	env  EnvironmentSpec
	ttl  time.Duration
	logf func(format string, args ...any)

	envDigest string // of the first environment read, which every later one must match

	mu      sync.Mutex
	ix      *Index
	loadErr error
	loaded  time.Time
	loading bool

	ready     chan struct{} // closed when the first read finishes, either way
	readyOnce sync.Once
}

// NewTree is NewTreeIn with the empty environment.
func NewTree(root string, ttl time.Duration, logf func(format string, args ...any)) *Tree {
	return NewTreeIn(root, EnvironmentSpec{}, ttl, logf)
}

// NewTreeIn starts the first read of root against env and returns at once.
// logf receives one line per completed or failed read; nil discards them.
func NewTreeIn(root string, env EnvironmentSpec, ttl time.Duration, logf func(format string, args ...any)) *Tree {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	t := &Tree{root: root, env: env, ttl: ttl, logf: logf, ready: make(chan struct{})}
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
		env, err := t.env.Load()
		if err == nil {
			t.mu.Lock()
			if t.envDigest == "" {
				t.envDigest = env.Digest()
			}
			if env.Digest() != t.envDigest {
				err = fmt.Errorf("the declared environment is no longer the one bodega started with: its digest was %s and is now %s, because a snapshot changed; restart bodega to admit against the new bytes", t.envDigest, env.Digest())
			}
			t.mu.Unlock()
		}
		if err != nil {
			t.mu.Lock()
			defer t.mu.Unlock()
			defer t.readyOnce.Do(func() { close(t.ready) })
			t.loading = false
			t.loaded = time.Now()
			t.ix, t.loadErr = nil, err
			t.logf("distinfo: refusing every distfile: %v", err)
			return
		}
		ix, err := LoadIn(t.root, env)
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
		t.logf("distinfo: indexed %d distfiles from %s against environment %s in %s", ix.Len(), t.root, env.Digest(), time.Since(start).Round(time.Millisecond))
		if u := ix.Unowned(); len(u) > 0 {
			t.logf("distinfo: refusing every distfile: %d restricted ports read a distinfo bodega cannot place, and any of them may obtain any distfile in the tree: %s", len(u), strings.Join(u, "; "))
		}
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
