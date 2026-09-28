package host

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

// pkgReposDirs are pkg's default REPOS_DIR, in the order pkg.conf(5) reads
// them: the base system's definitions, then the local ones that override
// them. A repository defined in both is merged key by key, the later value
// winning, which is how "FreeBSD-ports: { enabled: no }" in the second
// directory switches off the definition in the first.
var pkgReposDirs = []string{"/etc/pkg", pkgrepos.ClientReposDir}

// upstreamPkgTags are the repository names FreeBSD's base system has shipped
// in /etc/pkg/FreeBSD.conf: one ports repository and its kmods companion
// before the 15 split, and ports, ports-kmods and base from it.
var upstreamPkgTags = map[string]bool{
	"FreeBSD":             true,
	"FreeBSD-kmods":       true,
	"FreeBSD-ports":       true,
	"FreeBSD-ports-kmods": true,
	"FreeBSD-base":        true,
}

// pkgRepo is one repository as pkg sees it after every file is merged.
type pkgRepo struct {
	Name    string
	URL     string
	Enabled bool
	// Base is set when any definition of this name came from /etc/pkg/,
	// which only the base system writes.
	Base bool
	// From is the last file that set a key on this repository.
	From string
}

// upstream reports whether the repository fetches from FreeBSD's own
// servers: a name the base system defines, or a URL at pkg.FreeBSD.org under
// any name.
func (r pkgRepo) upstream() bool {
	return r.Base || upstreamPkgTags[r.Name] || strings.EqualFold(pkgURLHost(r.URL), "pkg.FreeBSD.org")
}

// bodega reports whether the repository's URL is one of bodega's pkg routes:
// /freebsd/<abi>/<repo> as published, or /freebsd-profile/<profile>/<abi>/<repo>
// filtered for a profile. The host is not compared, because doctor runs
// without knowing which URL clients reach bodega at.
func (r pkgRepo) bodega() bool {
	u, err := url.Parse(strings.TrimPrefix(r.URL, "pkg+"))
	if err != nil || u.Host == "" || strings.EqualFold(u.Hostname(), "pkg.FreeBSD.org") {
		return false
	}
	p := u.Path
	return strings.Contains(p, "/freebsd/") || strings.Contains(p, "/freebsd-profile/")
}

func pkgURLHost(raw string) string {
	u, err := url.Parse(strings.TrimPrefix(raw, "pkg+"))
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// CheckPkgRepos reports whether pkg on this FreeBSD host can fetch from
// FreeBSD's own repositories, and whether it reads a bodega one at all.
func CheckPkgRepos() Finding { return checkPkgReposLookup("", runtime.GOOS, os.LookupEnv) }

func checkPkgRepos(root, goos string) Finding {
	return checkPkgReposEnv(root, goos, func(string) string { return "" })
}

func checkPkgReposEnv(root, goos string, getenv func(string) string) Finding {
	return checkPkgReposLookup(root, goos, nonEmpty(getenv))
}

// nonEmpty adapts a getenv that cannot tell an unset variable from an empty
// one, treating empty as unset.
func nonEmpty(getenv func(string) string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v := getenv(k)
		return v, v != ""
	}
}

func checkPkgReposLookup(root, goos string, lookup func(string) (string, bool)) Finding {
	f := Finding{Check: "pkg-repos"}
	if goos != "freebsd" {
		f.Status = StatusNA
		f.Detail = "pkg repositories are FreeBSD-only; check not applicable on this platform"
		return f
	}
	remediation := "bodega doctor --write-pkg-repo --url <bodega> writes " + pkgrepos.ClientConfPath + " with the bodega repository and the overrides that disable upstream; confirm with pkg -vv"
	repos, rejected, err := loadPkgRepos(root, lookup)
	var unmodeled pkgUnmodeled
	if errors.As(err, &unmodeled) {
		f.Status = StatusWarn
		f.Detail = unmodeled.Error() + ", so doctor cannot establish which repositories pkg reads"
		f.Remediation = "replace it with plain repository objects in the default REPOS_DIR; " + remediation
		return f
	}
	if err != nil {
		f.Status = StatusSkip
		f.Detail = err.Error()
		f.Remediation = "run doctor as a user that can read /etc/pkg, " + pkgrepos.ClientReposDir + ", " + pkgConfPath + " and " + pkgReposState + ", or fix the file pkg would also fail to parse"
		return f
	}

	var upstream, bodega, unresolved []string
	for _, r := range repos {
		if !r.Enabled {
			continue
		}
		// A base tag redefined with a bodega URL is a bodega repository:
		// the URL decides where pkg fetches from, not the name. A host pkg
		// fills in from a variable (pkg.${OSNAME}.org is pkg.FreeBSD.org)
		// decides neither way.
		switch {
		case pkgURLUnresolved(r.URL):
			unresolved = append(unresolved, fmt.Sprintf("%s (%s, set in %s)", r.Name, r.URL, r.From))
		case r.bodega():
			bodega = append(bodega, r.Name)
		case r.upstream():
			upstream = append(upstream, fmt.Sprintf("%s (%s, set in %s)", r.Name, r.URL, r.From))
		}
	}

	var problems []string
	if len(upstream) > 0 {
		problems = append(problems, "upstream repository enabled: "+strings.Join(upstream, ", "))
	}
	if len(unresolved) > 0 {
		problems = append(problems, "enabled repository whose host doctor cannot resolve: "+strings.Join(unresolved, ", "))
	}
	if len(bodega) == 0 {
		problems = append(problems, "no enabled repository points at a bodega /freebsd/ URL")
	}
	if len(problems) > 0 {
		if len(rejected) > 0 {
			problems = append(problems, "pkg rejects and ignores "+strings.Join(rejected, ", "))
		}
		f.Status = StatusWarn
		f.Detail = strings.Join(problems, "; ")
		f.Remediation = remediation
		return f
	}
	f.Status = StatusOK
	f.Detail = "pkg reads only bodega repositories: " + strings.Join(bodega, ", ")
	return f
}

// pkgURLUnresolved reports whether a repository URL's host is not a literal
// doctor can compare: one holding a UCL variable, or one that does not parse.
func pkgURLUnresolved(raw string) bool {
	rest := strings.TrimPrefix(raw, "pkg+")
	if _, after, ok := strings.Cut(rest, "://"); ok {
		rest = after
	}
	host, _, _ := strings.Cut(rest, "/")
	if strings.Contains(host, "$") {
		return true
	}
	_, err := url.Parse(strings.TrimPrefix(raw, "pkg+"))
	return err != nil
}

// pkgUnmodeled is a repository file doctor cannot read the way pkg does: a
// UCL directive it does not evaluate, or an include pkg itself would reject.
// Either leaves the loaded repositories unknown, which is not a clean host.
type pkgUnmodeled struct{ msg string }

func (e pkgUnmodeled) Error() string { return e.msg }

// uclIncludeDepth bounds include nesting, so a file including itself is
// reported instead of recursing.
const uclIncludeDepth = 16

const (
	// pkgConfPath is pkg's own configuration, which can move REPOS_DIR and
	// PKG_DBDIR or define repositories inline.
	pkgConfPath = "/usr/local/etc/pkg.conf"
	// pkgReposState holds one empty file per repository name under enable/
	// and disable/, which pkg applies after every repository file.
	pkgReposState = "/var/db/pkg/repos_state"
)

// pkgConfOverrides are the pkg.conf keys, and the environment variables of
// the same name, that change which repositories pkg reads or where it keeps
// repos_state. doctor reads only the defaults, so any of them set leaves the
// repository set unknown.
var pkgConfOverrides = []string{"REPOS_DIR", "REPOSITORIES", "PKG_DBDIR"}

// loadPkgRepos returns the repositories pkg reads, merged the way pkg 2.8.4
// does in libpkg/pkg_config.c, measured with pkg -vv on 15.1: directories in
// order, the files pkg's configfile() selects within one in lexical order,
// then the repos_state overrides. A later object with a known name updates
// that repository with the keys it sets, compared case-sensitively; an
// object add_repo rejects changes nothing, and a new name with no url
// creates nothing. Within one file and the files it includes, libucl keeps
// the first object of a name and drops later ones. A missing directory is
// nothing to read; an unreadable or unparseable file is an error, because
// the repositories in it are exactly the ones in question. rejected names
// each object pkg refuses, for the detail.
func loadPkgRepos(root string, lookup func(string) (string, bool)) (repos []pkgRepo, rejected []string, err error) {
	if err := pkgConfDefaults(root, lookup); err != nil {
		return nil, nil, err
	}
	byName := map[string]*pkgRepo{}
	var order []string
	for _, dir := range pkgReposDirs {
		full := filepath.Join(root, dir)
		entries, err := os.ReadDir(full)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", dir, err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() && pkgConfigFile(e.Name()) {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			objs, err := readUCLFile(root, filepath.Join(dir, n), nil)
			if err != nil {
				return nil, nil, err
			}
			// seen holds whether the kept entry of each name was a scalar.
			// libucl keeps the first of two objects, measured; a scalar and
			// an object under one name become an implicit array nobody
			// measured, so that is refused rather than guessed at.
			seen := map[string]bool{}
			for _, o := range objs {
				if scalar, dup := seen[o.name]; dup {
					if scalar || o.scalar {
						return nil, nil, pkgUnmodeled{o.from + ": " + o.name + " is both a scalar and an object in one file, which doctor does not merge"}
					}
					continue
				}
				seen[o.name] = o.scalar
				if o.scalar {
					continue
				}
				r, ok := byName[o.name]
				acc, err := o.accept(ok)
				if err != nil {
					return nil, nil, err
				}
				if acc.rejected != "" {
					rejected = append(rejected, o.name+" in "+o.from+" ("+acc.rejected+")")
				}
				if !acc.apply {
					continue
				}
				if !ok {
					r = &pkgRepo{Name: o.name, Enabled: true}
					byName[o.name] = r
					order = append(order, o.name)
				}
				if dir == "/etc/pkg" {
					r.Base = true
				}
				r.From = o.from
				if acc.url != nil {
					r.URL = *acc.url
				}
				if acc.enabled != nil {
					r.Enabled = *acc.enabled
				}
			}
		}
	}
	for _, n := range order {
		if err := applyReposState(root, byName[n]); err != nil {
			return nil, nil, err
		}
		repos = append(repos, *byName[n])
	}
	return repos, rejected, nil
}

// pkgConfigFile is pkg's configfile(): a name ending in .conf, longer than
// that suffix, and not starting with a dot. pkg never opens a hidden file,
// though one named by an .include is read like any other.
func pkgConfigFile(name string) bool {
	return !strings.HasPrefix(name, ".") && len(name) > len(".conf") && strings.HasSuffix(name, ".conf")
}

// pkgConfDefaults returns an error unless pkg reads its default REPOS_DIR,
// defines no repository in pkg.conf, and keeps repos_state at its default
// path. pkg upper-cases pkg.conf keys before matching them, and lets an
// environment variable of the same name replace each, empty included: pkg
// tests getenv for NULL, not for an empty string.
func pkgConfDefaults(root string, lookup func(string) (string, bool)) error {
	for _, k := range pkgConfOverrides {
		if v, ok := lookup(k); ok {
			return pkgUnmodeled{fmt.Sprintf("the environment sets %s=%q, which pkg reads in place of its default", k, v)}
		}
	}
	objs, err := readUCLFile(root, pkgConfPath, nil)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, o := range objs {
		if slices.Contains(pkgConfOverrides, strings.ToUpper(o.name)) {
			return pkgUnmodeled{o.from + " sets " + o.name + ", which doctor does not follow"}
		}
	}
	return nil
}

// applyReposState applies pkg's per-repository override: a file of the
// repository's name under enable/ turns it on, else one under disable/
// turns it off, whatever the repository files said. pkg tests each with
// faccessat(F_OK), which follows symlinks.
func applyReposState(root string, r *pkgRepo) error {
	for _, st := range []struct {
		dir string
		on  bool
	}{{"enable", true}, {"disable", false}} {
		p := filepath.Join(pkgReposState, st.dir, r.Name)
		_, err := os.Stat(filepath.Join(root, p))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat %s: %w", p, err)
		}
		r.Enabled, r.From = st.on, p
		return nil
	}
	return nil
}

// uclAccepted is what pkg's add_repo does with one object: apply it or not,
// and which of the two keys doctor reads it sets.
type uclAccepted struct {
	apply bool
	// url and enabled are nil when the object leaves them unset, which
	// keeps what an earlier file set.
	url      *string
	enabled  *bool
	rejected string
}

// pkgRepoKeyKinds are the keys add_repo type-checks, matched without regard
// to case, and the one UCL type each must have. A key of any other type
// makes add_repo return before it applies anything, enabled included.
// enabled itself takes any type and is true only as a boolean true; keys
// not listed are ignored.
var pkgRepoKeyKinds = map[string]uclKind{
	"url":             uclString,
	"pubkey":          uclString,
	"mirror_type":     uclString,
	"signature_type":  uclString,
	"fingerprints":    uclString,
	"type":            uclString,
	"ssh_args":        uclString,
	"ip_version":      uclInt,
	"priority":        uclInt,
	"env":             uclObjectKind,
	"rwhich_database": uclBool,
}

// accept decides the object the way add_repo does. exists is whether pkg
// already holds a repository of this name. add_repo matches key names
// without regard to case, in the order libucl kept them, so of two
// spellings of one key the later wins. A value whose UCL type doctor
// cannot assign is an error, since the type alone decides whether pkg
// applies the object.
func (o uclObject) accept(exists bool) (uclAccepted, error) {
	var a uclAccepted
	// sigType is nil when the object sets no signature_type: pkg checks
	// presence, and rejects a present empty string like any other value.
	var sigType *string
	for _, kv := range o.keys {
		k := strings.ToLower(kv.key)
		if k == "enabled" {
			e := kv.val.enables()
			a.enabled = &e
			continue
		}
		want, ok := pkgRepoKeyKinds[k]
		if !ok {
			continue
		}
		if kv.val.kind == uclUnknown {
			return a, pkgUnmodeled{fmt.Sprintf("%s: %s: %s is a value libucl may type as a number or a string, and pkg applies %q only when it is %s", o.from, kv.key, kv.val.s, o.name, want)}
		}
		if kv.val.kind != want {
			a.rejected = kv.key + " must be " + want.String() + ", not " + kv.val.kind.String()
			return a, nil
		}
		switch k {
		case "url":
			u := kv.val.s
			a.url = &u
		case "signature_type":
			st := kv.val.s
			sigType = &st
		}
	}
	if !exists && a.url == nil {
		return a, nil
	}
	if sigType != nil && !slices.ContainsFunc([]string{"pubkey", "fingerprints", "none"}, func(s string) bool { return strings.EqualFold(s, *sigType) }) {
		a.rejected = fmt.Sprintf("signature_type %q is not pubkey, fingerprints or none", *sigType)
		return a, nil
	}
	a.apply = true
	return a, nil
}

// readUCLFile parses one repository file and splices in what its .include
// directives name, at their position, as libucl does. stack holds the files
// being read, outermost first.
func readUCLFile(root, path string, stack []string) ([]uclObject, error) {
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		if len(stack) > 0 {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, pkgUnmodeled{stack[len(stack)-1] + " includes " + path + ", which does not exist; pkg rejects the whole file"}
			}
			return nil, fmt.Errorf("read %s, which %s includes: %w", path, stack[len(stack)-1], err)
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	stmts, err := parseUCL(string(data))
	if err != nil {
		var u pkgUnmodeled
		if errors.As(err, &u) {
			return nil, pkgUnmodeled{path + ": " + u.msg}
		}
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	stack = append(stack, path)
	var out []uclObject
	for _, st := range stmts {
		if st.directive == "" {
			st.obj.from = path
			out = append(out, st.obj)
			continue
		}
		inc, err := uclIncludePath(st)
		if err != nil {
			return nil, pkgUnmodeled{path + ": " + err.Error()}
		}
		if len(stack) >= uclIncludeDepth {
			return nil, pkgUnmodeled{path + " includes " + inc + " past " + fmt.Sprint(uclIncludeDepth) + " levels of nesting"}
		}
		objs, err := readUCLFile(root, inc, stack)
		if err != nil {
			return nil, err
		}
		out = append(out, objs...)
	}
	return out, nil
}

// uclIncludePath returns the file a top-level directive includes, or why
// doctor does not follow it. Only the plain form is followed: .include with
// no parameters and an absolute path holding no variable. pkg resolves a
// relative path against its working directory and expands ${ABI} and the
// like, and .try_include fails in pkg 2.8 even when the file exists, so none
// of those names a file doctor can read as pkg would.
func uclIncludePath(st uclStmt) (string, error) {
	if st.directive != ".include" {
		return "", fmt.Errorf("line %d: %s is a UCL directive doctor does not evaluate", st.line, st.directive)
	}
	switch p := st.arg; {
	case !filepath.IsAbs(p):
		return "", fmt.Errorf("line %d: .include %q is relative, and pkg resolves it against its working directory", st.line, p)
	case strings.Contains(p, "$"):
		return "", fmt.Errorf("line %d: .include %q holds a variable pkg expands and doctor does not", st.line, p)
	default:
		return filepath.Clean(p), nil
	}
}

// uclKind is the UCL type libucl gives a value, which is what add_repo
// checks. uclUnknown is a bare value libucl's number lexer may or may not
// accept (1k, 0x10, 1.5, 1e3, +1): doctor does not reproduce that lexer.
type uclKind int

const (
	uclString uclKind = iota
	uclInt
	uclBool
	uclNull
	uclObjectKind
	uclArray
	uclUnknown
)

func (k uclKind) String() string {
	return [...]string{"a string", "an integer", "a boolean", "null", "an object", "an array", "an untyped value"}[k]
}

// uclScalar is a value as written, with the type libucl gives it: an
// unquoted yes is a boolean and a quoted "yes" a string, and pkg treats the
// two differently.
type uclScalar struct {
	s    string
	kind uclKind
}

var uclIntLit = regexp.MustCompile(`^-?[0-9]+$`)

// bareKind types an unquoted value: a boolean word in any case, null, a
// plain decimal integer, or a string when it cannot start a number.
func bareKind(s string) uclKind {
	if s == "" {
		return uclUnknown
	}
	switch strings.ToLower(s) {
	case "yes", "no", "true", "false", "on", "off":
		return uclBool
	}
	switch {
	case s == "null":
		return uclNull
	case strings.EqualFold(s, "null"):
		return uclUnknown
	case uclIntLit.MatchString(s):
		return uclInt
	case strings.ContainsRune("0123456789-+.", rune(s[0])):
		return uclUnknown
	}
	return uclString
}

// enables reports how pkg reads a present enabled key. Measured on pkg 2.8.4:
// only an unquoted yes, true or on in any case enables; no, false, off, every
// number (1 included), and every quoted or other bare string disables.
func (v uclScalar) enables() bool {
	if v.kind != uclBool {
		return false
	}
	switch strings.ToLower(v.s) {
	case "yes", "true", "on":
		return true
	}
	return false
}

type uclKV struct {
	key string
	val uclScalar
}

// uclObject is one top-level entry in a pkg repository file. keys holds
// each key spelling once, first value kept, in the order libucl stores them.
// Nested values are kept as empty scalars of their kind: no key doctor reads
// the content of is one. scalar marks an entry that is not an object, which
// pkg ignores in a repository file and doctor needs only the name of in
// pkg.conf.
type uclObject struct {
	name   string
	keys   []uclKV
	from   string
	scalar bool
}

// uclStmt is one top-level statement: an object, or a directive and the
// quoted path after it.
type uclStmt struct {
	obj       uclObject
	directive string
	arg       string
	line      int
}

// parseUCL reads the subset of UCL pkg repository files are written in:
// top-level "name: { key: value, ... }" objects, with #, // and /* */
// comments, quoted or bare scalars, ':' or '=' or nothing between key and
// value, and ',' or ';' between pairs. A top-level key starting with '.' is
// a directive and is returned for the caller to follow or refuse; one inside
// an object is refused here.
func parseUCL(src string) ([]uclStmt, error) {
	p := &uclParser{src: src}
	var out []uclStmt
	for {
		p.skip()
		if p.eof() {
			return out, nil
		}
		line := p.line()
		name, err := p.key()
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(name, ".") {
			p.skip()
			if c := p.peek(); c != '"' && c != '\'' {
				return nil, pkgUnmodeled{fmt.Sprintf("line %d: %s is a UCL directive doctor does not evaluate", line, name)}
			}
			arg, err := p.quoted()
			if err != nil {
				return nil, err
			}
			p.term()
			out = append(out, uclStmt{directive: name, arg: arg, line: line})
			continue
		}
		p.sep()
		if p.peek() != '{' {
			if _, err := p.value(); err != nil {
				return nil, err
			}
			p.term()
			out = append(out, uclStmt{obj: uclObject{name: name, scalar: true}, line: line})
			continue
		}
		p.pos++
		o := uclObject{name: name}
		have := map[string]bool{}
		for {
			p.skip()
			if p.eof() {
				return nil, fmt.Errorf("object %q is not closed", name)
			}
			if p.peek() == '}' {
				p.pos++
				break
			}
			kline := p.line()
			k, err := p.key()
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(k, ".") {
				return nil, pkgUnmodeled{fmt.Sprintf("line %d: %s inside object %q is a UCL directive doctor does not evaluate", kline, k, name)}
			}
			p.sep()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			if !have[k] {
				have[k] = true
				o.keys = append(o.keys, uclKV{k, v})
			}
			p.term()
		}
		p.term()
		out = append(out, uclStmt{obj: o, line: line})
	}
}

type uclParser struct {
	src string
	pos int
}

func (p *uclParser) eof() bool { return p.pos >= len(p.src) }

func (p *uclParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.src[p.pos]
}

func (p *uclParser) line() int { return strings.Count(p.src[:p.pos], "\n") + 1 }

// skip passes whitespace and comments.
func (p *uclParser) skip() {
	for !p.eof() {
		rest := p.src[p.pos:]
		switch {
		case strings.ContainsRune(" \t\r\n", rune(rest[0])):
			p.pos++
		case rest[0] == '#' || strings.HasPrefix(rest, "//"):
			if i := strings.IndexByte(rest, '\n'); i >= 0 {
				p.pos += i + 1
			} else {
				p.pos = len(p.src)
			}
		case strings.HasPrefix(rest, "/*"):
			if i := strings.Index(rest[2:], "*/"); i >= 0 {
				p.pos += i + 4
			} else {
				p.pos = len(p.src)
			}
		default:
			return
		}
	}
}

// sep passes the optional ':' or '=' between a key and its value.
func (p *uclParser) sep() {
	p.skip()
	if c := p.peek(); c == ':' || c == '=' {
		p.pos++
	}
	p.skip()
}

// term passes the optional ',' or ';' after a value.
func (p *uclParser) term() {
	p.skip()
	if c := p.peek(); c == ',' || c == ';' {
		p.pos++
	}
}

func (p *uclParser) key() (string, error) {
	if c := p.peek(); c == '"' || c == '\'' {
		return p.quoted()
	}
	start := p.pos
	for !p.eof() && !strings.ContainsRune(" \t\r\n:={}[],;#\"'", rune(p.peek())) {
		p.pos++
	}
	if p.pos == start {
		return "", fmt.Errorf("line %d: expected a key, found %q", p.line(), p.peek())
	}
	return p.src[start:p.pos], nil
}

// value returns a scalar, or an empty one of its kind after passing a
// nested object or array.
func (p *uclParser) value() (uclScalar, error) {
	switch c := p.peek(); c {
	case '"', '\'':
		s, err := p.quoted()
		return uclScalar{s: s, kind: uclString}, err
	case '{':
		return uclScalar{kind: uclObjectKind}, p.nested()
	case '[':
		return uclScalar{kind: uclArray}, p.nested()
	case 0:
		return uclScalar{}, fmt.Errorf("line %d: expected a value, found end of file", p.line())
	}
	if strings.HasPrefix(p.src[p.pos:], "<<") {
		return uclScalar{}, pkgUnmodeled{fmt.Sprintf("line %d: a heredoc value is UCL syntax doctor does not read", p.line())}
	}
	start := p.pos
	for !p.eof() && !strings.ContainsRune(" \t\r\n,;}]#", rune(p.peek())) {
		p.pos++
	}
	s := p.src[start:p.pos]
	return uclScalar{s: s, kind: bareKind(s)}, nil
}

func (p *uclParser) quoted() (string, error) {
	q, start := p.peek(), p.line()
	p.pos++
	var b strings.Builder
	for !p.eof() {
		c := p.src[p.pos]
		p.pos++
		switch {
		case c == q:
			return b.String(), nil
		case c == '\\' && !p.eof():
			b.WriteByte(p.src[p.pos])
			p.pos++
		default:
			b.WriteByte(c)
		}
	}
	return "", fmt.Errorf("line %d: string is not closed", start)
}

func (p *uclParser) nested() error {
	start, depth := p.line(), 0
	for !p.eof() {
		switch p.peek() {
		case '"', '\'':
			if _, err := p.quoted(); err != nil {
				return err
			}
			continue
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		}
		p.pos++
		if depth == 0 {
			return nil
		}
	}
	return fmt.Errorf("line %d: object or array is not closed", start)
}

// makeConfSites are the variables clientconf.MakeConf assigns and the route
// each must end with, read out of the rendered file so the check and the
// renderer cannot disagree about either.
func makeConfSites() (names []string, route string) {
	for _, l := range strings.Split(clientconf.MakeConf("").Content, "\n") {
		name, val, ok := strings.Cut(l, "?=")
		if !ok {
			continue
		}
		names = append(names, strings.TrimSpace(name))
		route = strings.TrimSpace(val)
	}
	return names, route
}

// distfilesEnvVar is the variable the client check defines, which is how an
// included file is recognized as that check wherever it was installed.
const distfilesEnvVar = "BODEGA_DISTFILES_ENV"

// distSubdirVar is the other variable the route expands. A port that does
// not set it takes whatever make.conf or the environment gave it.
const distSubdirVar = "DIST_SUBDIR"

var (
	makeAssign    = regexp.MustCompile(`^([^\s:?!+=]+)\s*([:?!+]?=)\s*(.*)$`)
	makeDirective = regexp.MustCompile(`^\.\s*([a-z-]+)\s*(.*)$`)
	makeReadonly  = regexp.MustCompile(`^\.(NO)?READONLY\s*:(.*)$`)
	makeVarRef    = regexp.MustCompile(`\$(\{[^}]*\}?|\([^)]*\)?|.?)`)
	// servedEnvValue is the value the client check bodega serves gives
	// distfilesEnvVar: one of two literal words whatever the drift is.
	// TestCheckMakeConfWalksTheServedClientCheck holds it to distinfo.
	servedEnvValue = regexp.MustCompile(`^\$\{"\$\{BODEGA_DISTFILES_DRIFT:M\*\}" == "":\?[0-9a-f]+:unsupported\}$`)
)

// CheckMakeConf reports whether ports on this FreeBSD host fetch distfiles
// through bodega, comparing make.conf with what clientconf.MakeConf renders.
func CheckMakeConf() Finding { return checkMakeConfLookup("", runtime.GOOS, os.LookupEnv) }

func checkMakeConf(root, goos string, getenv func(string) string) Finding {
	return checkMakeConfLookup(root, goos, nonEmpty(getenv))
}

func checkMakeConfLookup(root, goos string, lookup func(string) (string, bool)) Finding {
	f := Finding{Check: "make-conf"}
	if goos != "freebsd" {
		f.Status = StatusNA
		f.Detail = "make.conf is read by FreeBSD's ports framework; check not applicable on this platform"
		return f
	}
	names, route := makeConfSites()
	// make reads MAKEFLAGS from the environment before any makefile: its
	// assignments are command-line variables, which beat every makefile
	// assignment, and its flags hold for the whole run.
	mfEnv, _ := lookup("MAKEFLAGS")
	flags := parseMakeFlags(mfEnv, true)

	// sys.mk assigns __MAKE_CONF?=/etc/make.conf and includes it only when it
	// exists, so an environment value replaces the default, an empty one
	// names no file, and a command-line one replaces both.
	path, shown := "/etc/make.conf", "/etc/make.conf"
	if env, ok := lookup("__MAKE_CONF"); ok {
		path, shown = env, env+" (named by __MAKE_CONF)"
	}
	f.Remediation = "end " + shown + " with the FreeBSD ports lines under Client configuration in docs/usage.md: " +
		strings.Join(names, " and ") + " set to <bodega>" + route + ", then .include of " + clientconf.DistfilesCheckPath
	switch {
	case slices.Contains(flags.assigns, "__MAKE_CONF"):
		f.Status = StatusWarn
		f.Detail = "the environment's MAKEFLAGS assigns __MAKE_CONF, so doctor cannot establish which make.conf make reads"
		f.Remediation = "remove __MAKE_CONF from MAKEFLAGS and run doctor again"
		return f
	case path == "":
		f.Status = StatusWarn
		f.Detail = "__MAKE_CONF is set and empty, so make reads no make.conf and " + strings.Join(names, ", ") + " stay at the ports' own sites"
		f.Remediation = "unset __MAKE_CONF, or point it at a make.conf; then " + f.Remediation
		return f
	case !filepath.IsAbs(path):
		f.Status = StatusWarn
		f.Detail = "__MAKE_CONF=" + path + " is relative, and make resolves it against whatever directory it runs in"
		f.Remediation = "set __MAKE_CONF to an absolute path and run doctor again"
		return f
	}
	data, err := os.ReadFile(filepath.Join(root, path))
	if errors.Is(err, fs.ErrNotExist) {
		f.Status = StatusWarn
		f.Detail = path + " does not exist, so " + strings.Join(names, ", ") + " stay at the ports' own sites and no client check is included"
		return f
	}
	if err != nil {
		f.Status = StatusSkip
		f.Detail = "read " + path + ": " + err.Error()
		f.Remediation = "run doctor as a user that can read " + path
		return f
	}

	w := &makeWalk{root: root, sites: map[string]*siteValue{}, env: map[string]string{}}
	for _, n := range append([]string{distfilesEnvVar, distSubdirVar}, names...) {
		if v, ok := lookup(n); ok {
			w.env[n] = v
		}
		v := w.fromEnv(n)
		w.sites[n] = &v
	}
	w.applyFlags(flags, "the environment's MAKEFLAGS", false)
	stmts := makeStatements(string(data))
	if err := w.file(path, stmts, false, nil); err != nil {
		f.Status = StatusSkip
		f.Detail = err.Error()
		f.Remediation = "run doctor as a user that can read " + path + " and every file it includes"
		return f
	}
	w.settleEnv()

	failed := append([]string(nil), w.problems...)
	for _, n := range names {
		if msg := siteProblem(n, w.sites[n], route); msg != "" {
			failed = append(failed, msg)
		}
	}
	switch sub := w.sites[distSubdirVar]; {
	case sub.why() != "":
		failed = append(failed, distSubdirVar+", which the route expands, may be set: "+sub.why())
	case sub.set:
		failed = append(failed, distSubdirVar+"="+sub.val+" is set in "+sub.from+", and the route expands it for every port that does not set its own")
	}
	if msg := checkInclude(root, path, stmts, w.sites[distfilesEnvVar]); msg != "" {
		failed = append(failed, msg)
	}

	if len(failed) > 0 {
		f.Status = StatusWarn
		f.Detail = path + ": " + strings.Join(failed, "; ")
		return f
	}
	f.Remediation = ""
	f.Status = StatusOK
	f.Detail = path + " sends " + strings.Join(names, " and ") + " to bodega's distfiles route and ends by including the client check"
	return f
}

// siteValue is what doctor knows of one tracked variable at a point in the
// read, with two kinds of uncertainty kept apart. unknown says why the value
// cannot be established, and an assignment that later takes effect clears
// it. pinned says why doctor cannot establish that a later assignment or
// .undef takes effect at all: an input it did not read may have made the
// variable read-only or a command-line variable. Nothing clears pinned.
// readonly is a .READONLY doctor read, under which make ignores every
// assignment and .undef, measured with bmake on 15.1. env marks a value from
// the environment, and final one assigned while reading the last include of
// make.conf or anything that include reads.
type siteValue struct {
	val, from string
	set       bool
	unknown   string
	pinned    string
	readonly  bool
	env       bool
	final     bool
}

func (v *siteValue) undetermined(why string) { v.unknown = why }

func (v *siteValue) pin(why string) {
	if v.pinned == "" {
		v.pinned = why
	}
}

// why returns why the value cannot be established, or "".
func (v *siteValue) why() string {
	if v.pinned != "" {
		return v.pinned
	}
	return v.unknown
}

// makeWalk follows make.conf the way make reads it: statement by statement,
// into each include at its position, through conditionals. It never runs a
// shell assignment or expands a variable. A conditional whose test is not an
// integer literal, and every .for body, is a branch of unknown state: an
// assignment to a site variable inside one leaves that variable undetermined
// rather than taken or skipped.
type makeWalk struct {
	root  string
	sites map[string]*siteValue
	// env holds the environment's value of each tracked variable it sets,
	// empty included: make treats an empty one as defined.
	env      map[string]string
	problems []string
	// final is set while reading the last include of make.conf and every
	// file it includes.
	final bool
	// envFirst is whether make runs with -e: 1 yes, -1 maybe, 0 no.
	// envFirstWhy names what passed it.
	envFirst    int
	envFirstWhy string
}

// fromEnv is a tracked variable with no makefile value: the environment's,
// or unset.
func (w *makeWalk) fromEnv(n string) siteValue {
	if v, ok := w.env[n]; ok {
		return siteValue{val: v, from: "the environment", set: true, env: true}
	}
	return siteValue{}
}

// makeIncludeDepth bounds include nesting, so a file including itself is
// reported instead of recursing.
const makeIncludeDepth = 16

var makeIntCond = regexp.MustCompile(`^\d+$`)

var (
	makeFlagsLine   = regexp.MustCompile(`^\.(MAKEFLAGS|MFLAGS)\s*:(.*)$`)
	makeFlagsTarget = regexp.MustCompile(`(^|\s)\.(MAKEFLAGS|MFLAGS)(\s|:|$)`)
)

// condFrame is one open .if or .for. state is the branch being read: 1 taken,
// 0 skipped, -1 unknown. seen records whether an earlier branch was taken
// (1) or might have been (-1), which decides every later .elif and .else.
type condFrame struct {
	state, seen int
	loop        bool
}

func (w *makeWalk) file(path string, stmts []string, unknown bool, stack []string) error {
	stack = append(stack, path)
	var frames []condFrame
	for i, st := range stmts {
		// active is 1, 0 or -1 as for condFrame, across every open frame and
		// the include that led here.
		active := 1
		if unknown {
			active = -1
		}
		for _, fr := range frames {
			if fr.state == 0 {
				active = 0
				break
			}
			if fr.state == -1 {
				active = -1
			}
		}

		if m := makeDirective.FindStringSubmatch(st); m != nil {
			dir, arg := m[1], strings.TrimSpace(m[2])
			switch dir {
			case "if", "ifdef", "ifndef", "ifmake", "ifnmake":
				fr := condFrame{state: -1}
				if dir == "if" && makeIntCond.MatchString(arg) {
					fr.state = 0
					if strings.Trim(arg, "0") != "" {
						fr.state = 1
					}
				}
				fr.seen = fr.state
				frames = append(frames, fr)
				continue
			case "elif", "elifdef", "elifndef", "elifmake", "elifnmake", "else":
				if len(frames) == 0 || frames[len(frames)-1].loop {
					w.problems = append(w.problems, path+" has ."+dir+" with no open .if")
					continue
				}
				fr := &frames[len(frames)-1]
				switch {
				case fr.seen == 1:
					fr.state = 0
				case fr.seen == -1:
					fr.state = -1
				case dir == "else":
					fr.state = 1
				case dir == "elif" && makeIntCond.MatchString(arg):
					fr.state = 0
					if strings.Trim(arg, "0") != "" {
						fr.state = 1
					}
				default:
					fr.state = -1
				}
				if fr.state != 0 && fr.seen != 1 {
					fr.seen = fr.state
				}
				continue
			case "endif", "endfor":
				if len(frames) == 0 || frames[len(frames)-1].loop != (dir == "endfor") {
					w.problems = append(w.problems, path+" has ."+dir+" with nothing open for it to close")
					continue
				}
				frames = frames[:len(frames)-1]
				continue
			case "for":
				frames = append(frames, condFrame{state: -1, seen: -1, loop: true})
				continue
			}
			if active == 0 {
				continue
			}
			switch dir {
			case "include", "sinclude", "-include", "dinclude":
				// checkInclude reports the final include of make.conf itself.
				// Everything read beneath it is final too, and the flag is the
				// parent's again once the include returns.
				final := len(stack) == 1 && i == len(stmts)-1
				parent := w.final
				w.final = parent || final
				err := w.include(path, dir, arg, active == -1, !final, stack)
				w.final = parent
				if err != nil {
					return err
				}
			case "undef":
				w.undef(arg, path, active == -1)
			case "export", "export-env", "export-literal", "unexport", "unexport-env", "info", "warning", "error":
			default:
				w.touch(st, "."+dir+" in "+path+" is a directive doctor does not evaluate")
			}
			continue
		}
		if active == 0 {
			continue
		}

		if ro := makeReadonly.FindStringSubmatch(st); ro != nil {
			w.readonly(st, path, ro[1] == "", strings.Fields(ro[2]), active == -1)
			continue
		}
		m := makeAssign.FindStringSubmatch(st)
		if m == nil {
			switch mf := makeFlagsLine.FindStringSubmatch(st); {
			case mf != nil:
				w.applyFlags(parseMakeFlags(mf[2], false), "."+mf[1]+" in "+path, active == -1)
			case makeFlagsTarget.MatchString(st):
				w.pinAll(path + " passes make flags on " + st + ", which doctor does not read")
			default:
				// A dependency line: .READONLY, .MAKEFLAGS and .NOREADONLY can
				// pin or release a variable for every line after them.
				w.touch(st, "a line in "+path+" doctor does not evaluate names it: "+st)
			}
			continue
		}
		name, op, val := m[1], m[2], m[3]
		if strings.Contains(name, "$") {
			for _, v := range w.sites {
				if !v.readonly {
					v.undetermined(path + " assigns the computed name " + name + ", which doctor does not expand")
				}
			}
			continue
		}
		if v := w.sites[name]; v != nil {
			w.assign(v, op, val, path, active == -1)
		}
	}
	if len(frames) > 0 {
		w.problems = append(w.problems, path+" ends with a conditional or loop still open, which make refuses")
	}
	return nil
}

// assign applies one assignment to a tracked variable. from names where it
// was made; unknown is whether make may not have read it.
func (w *makeWalk) assign(v *siteValue, op, val, from string, unknown bool) {
	if v.pinned != "" || v.readonly {
		return
	}
	if unknown {
		v.undetermined("assigned under a conditional or loop doctor does not evaluate in " + from)
		return
	}
	switch op {
	case "?=":
		if v.unknown != "" {
			return
		}
		if !v.set {
			*v = siteValue{val: val, from: from, set: true, final: w.final}
		}
	case "+=":
		if v.unknown != "" {
			return
		}
		if v.env {
			v.undetermined(from + " appends to a value from the environment")
			return
		}
		if v.set {
			val = v.val + " " + val
		}
		*v = siteValue{val: val, from: from, set: true, final: w.final}
	case "!=":
		v.undetermined("set in " + from + " from a shell command doctor does not run")
	case ":=", "::=":
		if strings.Contains(val, "$") {
			v.undetermined("set in " + from + " with :=, which expands variables doctor does not")
			return
		}
		*v = siteValue{val: val, from: from, set: true, final: w.final}
	default:
		*v = siteValue{val: val, from: from, set: true, final: w.final}
	}
}

// undef applies .undef. It removes a makefile's value and leaves the
// environment's visible, measured with bmake on 15.1, and bmake expands its
// argument, so a name doctor cannot expand may have removed any makefile
// value.
func (w *makeWalk) undef(arg, path string, unknown bool) {
	if strings.Contains(arg, "$") {
		for _, v := range w.sites {
			if v.set && !v.env && !v.readonly {
				v.undetermined(".undef " + arg + " in " + path + " names variables doctor does not expand")
			}
		}
		return
	}
	for _, n := range strings.Fields(arg) {
		v := w.sites[n]
		if v == nil || v.pinned != "" || v.readonly {
			continue
		}
		if unknown {
			v.undetermined(".undef under a conditional doctor does not evaluate in " + path)
			continue
		}
		*v = w.fromEnv(n)
	}
}

// readonly applies a .READONLY or .NOREADONLY line (on is which) to the
// tracked variables it names. Measured with bmake on 15.1, .READONLY with
// no sources pins nothing and .NOREADONLY with none releases everything.
// Under a conditional doctor does not evaluate, either may or may not have
// happened, so whether a later assignment takes effect is unknown for every
// variable it could have changed.
func (w *makeWalk) readonly(line, path string, on bool, names []string, unknown bool) {
	directive := map[bool]string{true: ".READONLY", false: ".NOREADONLY"}[on]
	if slices.ContainsFunc(names, func(n string) bool { return strings.Contains(n, "$") }) {
		w.pinAll(directive + " in " + path + " names variables doctor does not expand")
		return
	}
	if unknown {
		if !on && len(names) == 0 {
			for _, v := range w.sites {
				if v.readonly {
					v.pin(directive + " under a conditional doctor does not evaluate in " + path)
				}
			}
			return
		}
		w.touch(line, directive+" under a conditional doctor does not evaluate in "+path)
		return
	}
	if !on && len(names) == 0 {
		for _, v := range w.sites {
			v.readonly = false
		}
	}
	for _, n := range names {
		if v := w.sites[n]; v != nil {
			v.readonly = on
		}
	}
}

// touch pins every site variable a line names: a line doctor does not
// evaluate may have assigned it, made it read-only or made it a command-line
// variable.
func (w *makeWalk) touch(line, why string) {
	words := strings.FieldsFunc(line, func(r rune) bool {
		return !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	for n, v := range w.sites {
		if slices.Contains(words, n) {
			v.pin(why)
		}
	}
}

// pinAll pins every site variable, for an input doctor did not read that
// could have done anything to any of them.
func (w *makeWalk) pinAll(why string) {
	for _, v := range w.sites {
		v.pin(why)
	}
}

// makeFlags is what one MAKEFLAGS value or .MAKEFLAGS line passes make, in
// the subset doctor models. unmodeled names the first word or flag outside
// it.
type makeFlags struct {
	envFirst  bool
	defines   []string
	assigns   []string
	unmodeled string
}

// makeInertFlags take no argument and change no variable's value or
// precedence; makeInertArgFlags do the same and take one. Every other flag
// is outside what doctor models: -I, -m and -r move or drop the files make
// reads, and -C and -f add or relocate makefiles.
const (
	makeInertFlags    = "BNSWXiknqstw"
	makeInertArgFlags = "JTVdjv"
)

// parseMakeFlags reads words the way bmake reads MAKEFLAGS and .MAKEFLAGS,
// measured on 15.1: clusters of flags after a dash, name=value assignments,
// and "--". bmake reads a first word with no dash as flags only in the
// environment's MAKEFLAGS (bare); anywhere else it is a target.
func parseMakeFlags(s string, bare bool) makeFlags {
	var fl makeFlags
	words := strings.Fields(s)
	dashDash := false
	for i := 0; i < len(words); i++ {
		word := words[i]
		if strings.ContainsAny(word, "$\"'\\") {
			fl.unmodeled = word
			return fl
		}
		if eq := strings.IndexByte(word, '='); eq > 0 && (dashDash || word[0] != '-') {
			fl.assigns = append(fl.assigns, strings.TrimRight(word[:eq], "+:?!"))
			continue
		}
		var cluster string
		switch {
		case !dashDash && word == "--":
			dashDash = true
			continue
		case !dashDash && len(word) > 1 && word[0] == '-':
			cluster = word[1:]
		case !dashDash && i == 0 && bare:
			cluster = word
		default:
			fl.unmodeled = word
			return fl
		}
		for j := 0; j < len(cluster); j++ {
			c := cluster[j]
			switch {
			case c == 'e':
				fl.envFirst = true
			case strings.IndexByte(makeInertFlags, c) >= 0:
			case c == 'D' || strings.IndexByte(makeInertArgFlags, c) >= 0:
				arg := cluster[j+1:]
				if arg == "" {
					if i+1 >= len(words) {
						fl.unmodeled = "-" + string(c) + " with no argument"
						return fl
					}
					i++
					arg = words[i]
				}
				if c == 'D' {
					if strings.ContainsAny(arg, "$\"'\\") {
						fl.unmodeled = "-D " + arg
						return fl
					}
					fl.defines = append(fl.defines, arg)
				}
				j = len(cluster)
			default:
				fl.unmodeled = "-" + string(c)
				return fl
			}
		}
	}
	return fl
}

// applyFlags applies what one MAKEFLAGS value or .MAKEFLAGS line passes.
// from names it; unknown is whether make may not have read it. -D sets a
// global, which a later assignment replaces and which beats the environment;
// an assignment is a command-line variable, which nothing after it replaces.
func (w *makeWalk) applyFlags(fl makeFlags, from string, unknown bool) {
	if fl.unmodeled != "" {
		w.pinAll(from + " passes " + fl.unmodeled + ", which doctor does not model")
	}
	for _, n := range fl.assigns {
		if v := w.sites[n]; v != nil {
			v.pin(from + " names it")
		}
	}
	for _, n := range fl.defines {
		if v := w.sites[n]; v != nil {
			w.assign(v, "=", "1", "-D in "+from, unknown)
		}
	}
	switch {
	case !fl.envFirst || w.envFirst == 1:
	case unknown:
		if w.envFirst == 0 {
			w.envFirst, w.envFirstWhy = -1, from+" may pass -e"
		}
	default:
		w.envFirst, w.envFirstWhy = 1, from+" passes -e"
	}
}

// settleEnv applies -e, under which a recipe expands a variable from the
// environment ahead of any makefile assignment. make -V prints the makefile's
// value either way, measured with bmake on 15.1, and it is the recipe's value
// that decides where fetch goes, so the environment's is the one checked.
func (w *makeWalk) settleEnv() {
	for n, v := range w.sites {
		ev, ok := w.env[n]
		if !ok || v.pinned != "" {
			continue
		}
		switch w.envFirst {
		case 1:
			*v = siteValue{val: ev, from: "the environment, above make.conf because " + w.envFirstWhy, set: true, env: true}
		case -1:
			v.pin("the environment sets it, and " + w.envFirstWhy + ", which would put the environment above make.conf")
		}
	}
}

// include follows one include directive. A path doctor cannot resolve pins
// every site variable, since the file could assign any of them, make it
// read-only or pass it on a .MAKEFLAGS line. A missing file is a problem for
// .include, which make treats as fatal, and nothing for the soft forms or a
// branch make may not take.
func (w *makeWalk) include(from, dir, arg string, unknown, report bool, stack []string) error {
	inc, why := makeIncludePath(from, arg)
	if why != "" {
		w.pinAll(from + " includes " + why)
		return nil
	}
	for _, s := range stack {
		if s == inc {
			w.pinAll(from + " includes " + inc + ", which is already being read")
			return nil
		}
	}
	if len(stack) >= makeIncludeDepth {
		w.pinAll(from + " includes " + inc + " past " + fmt.Sprint(makeIncludeDepth) + " levels of nesting")
		return nil
	}
	data, err := os.ReadFile(filepath.Join(w.root, inc))
	if errors.Is(err, fs.ErrNotExist) {
		if dir == "include" && report && !unknown {
			w.problems = append(w.problems, from+" includes "+inc+", which does not exist")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s, which %s includes: %w", inc, from, err)
	}
	return w.file(inc, makeStatements(string(data)), unknown, stack)
}

// makeIncludePath resolves an include argument, or returns why doctor does
// not: an unquoted or variable path. A relative "path" is read beside the
// including file and <path> under /usr/share/mk, the first place make looks
// for each.
func makeIncludePath(from, arg string) (path, why string) {
	if len(arg) < 2 || !((arg[0] == '"' && arg[len(arg)-1] == '"') || (arg[0] == '<' && arg[len(arg)-1] == '>')) {
		return "", arg + ", which is not a quoted path"
	}
	inc := arg[1 : len(arg)-1]
	if strings.Contains(inc, "$") {
		return "", inc + ", whose variables doctor does not expand"
	}
	switch {
	case filepath.IsAbs(inc):
		return filepath.Clean(inc), ""
	case arg[0] == '<':
		return filepath.Join("/usr/share/mk", inc), ""
	default:
		return filepath.Join(filepath.Dir(from), inc), ""
	}
}

// siteProblem returns why one site variable does not send every fetch to
// bodega, or "". The only variables its value may reference are the two the
// route itself holds; any other could expand to more sites, so the words
// doctor sees would not be the sites make uses.
func siteProblem(name string, v *siteValue, route string) string {
	switch {
	case v.why() != "":
		return name + " cannot be established: " + v.why()
	case !v.set:
		return name + " is not set"
	}
	rest := v.val
	for _, ph := range makeVarRef.FindAllString(route, -1) {
		rest = strings.ReplaceAll(rest, ph, "")
	}
	if refs := makeVarRef.FindAllString(rest, -1); len(refs) > 0 {
		return name + "=" + v.val + " (set in " + v.from + ") references " + strings.Join(refs, ", ") +
			", which doctor does not expand, so the sites it holds cannot be established"
	}
	if !sitesAt(v.val, route) {
		return name + "=" + v.val + " (set in " + v.from + ") does not end every site in " + route
	}
	return ""
}

// sitesAt reports whether every site in a make value is a host part
// followed by route. One site that is not is a fallback do-fetch.sh will try.
func sitesAt(v, route string) bool {
	sites := strings.Fields(v)
	if len(sites) == 0 {
		return false
	}
	for _, s := range sites {
		if len(s) <= len(route) || !strings.HasSuffix(s, route) {
			return false
		}
	}
	return true
}

// checkInclude inspects the last statement of make.conf. It returns the
// failed condition, or "" when the last statement includes the client
// check: a file whose own active lines set distfilesEnvVar, to a value that
// expands to one word. The file is recognized by what it defines rather
// than where it lives, since the check is delivered both as a copy and from
// a distfiles mount. env is that variable's state after makeWalk read the
// whole of make.conf, so an assignment in a branch make skips, one it may
// skip, and one a later .undef removed all fail here. makeWalk has already
// read the file, so an unreadable one has already been reported.
func checkInclude(root, confPath string, stmts []string, env *siteValue) string {
	if len(stmts) == 0 {
		return "the file is empty, so it includes no client check"
	}
	last := stmts[len(stmts)-1]
	m := makeDirective.FindStringSubmatch(last)
	if m == nil || (m[1] != "include" && m[1] != "sinclude" && m[1] != "-include" && m[1] != "dinclude") {
		return "the last line is " + last + ", not an .include of the client check"
	}
	inc, why := makeIncludePath(confPath, strings.TrimSpace(m[2]))
	if why != "" {
		return "the last line includes " + why
	}
	if _, err := os.Stat(filepath.Join(root, inc)); errors.Is(err, fs.ErrNotExist) {
		return "the last line includes " + inc + ", which does not exist"
	}
	notCheck := "the last line includes " + inc + ", which "
	switch {
	case env.why() != "":
		return notCheck + "doctor cannot establish defines " + distfilesEnvVar + ": " + env.why()
	case !env.set:
		return notCheck + "does not define " + distfilesEnvVar + " on any line make reads, and so is not the client check"
	case !env.final:
		return notCheck + "does not set " + distfilesEnvVar + "; its value comes from " + env.from + ", so the included file is not the client check"
	case !oneWord(env.val):
		return notCheck + "sets " + distfilesEnvVar + "=" + env.val + ", which doctor cannot establish expands to one word"
	}
	return ""
}

// oneWord reports whether a value of distfilesEnvVar expands to exactly one
// word: a literal with no space or variable, or the value the served check
// computes.
func oneWord(v string) bool {
	if servedEnvValue.MatchString(v) {
		return true
	}
	return v != "" && !strings.ContainsAny(v, " \t$")
}

// makeStatements splits a makefile into logical lines: continuations
// joined, comments and blank lines dropped. Conditionals are kept as
// statements and not evaluated.
func makeStatements(src string) []string {
	var out []string
	var cur strings.Builder
	for _, l := range strings.Split(src, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.HasSuffix(l, "\\") {
			cur.WriteString(strings.TrimSuffix(l, "\\") + " ")
			continue
		}
		cur.WriteString(l)
		s := stripMakeComment(cur.String())
		cur.Reset()
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if s := strings.TrimSpace(stripMakeComment(cur.String())); s != "" {
		out = append(out, s)
	}
	return out
}

func stripMakeComment(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] != '\\') {
			return s[:i]
		}
	}
	return s
}
