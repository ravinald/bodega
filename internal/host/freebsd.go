package host

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/distinfo"
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

	for _, r := range repos {
		why, unknown := pkgURLInvalid(r.URL)
		switch {
		case unknown:
			f.Status = StatusWarn
			f.Detail = fmt.Sprintf("repository %s (set in %s) has url %q, %s, so doctor cannot establish that pkg starts", r.Name, r.From, r.URL, why)
			f.Remediation = "write the url's scheme literally; " + remediation
			return f
		case why != "":
			f.Status = StatusWarn
			f.Detail = fmt.Sprintf("pkg refuses to start: repository %s (set in %s) has url %q, %s; pkg checks every repository, disabled ones included, and every pkg command exits 1", r.Name, r.From, r.URL, why)
			f.Remediation = "give every repository a url with one of pkg's schemes (" + strings.Join(pkgValidURLSchemes, ", ") + "), or remove the object that sets this one; " + remediation
			return f
		}
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

// pkgValidURLSchemes is pkg's default VALID_URL_SCHEME.
var pkgValidURLSchemes = []string{"pkg+http", "pkg+https", "https", "http", "file", "ssh", "tcp"}

// pkgURLInvalid returns why pkg refuses to start with a repository of this
// url, or "". After merging every file and applying repos_state, pkg checks
// each repository's url, disabled ones included: it must hold ":/", and one
// valid scheme must begin with what precedes it, because pkg compares with
// strncmp over that length. So "htt://" and ":/" pass and "HTTPS://" and ""
// fail, measured with pkg 2.8.4 on 15.1. unknown is set when pkg expands a
// variable before the ":/" that doctor does not.
func pkgURLInvalid(raw string) (why string, unknown bool) {
	scheme, _, found := strings.Cut(raw, ":/")
	switch {
	case strings.Contains(scheme, "$"):
		return "whose scheme holds a variable pkg expands", true
	case !found:
		return `which pkg rejects as an invalid url: it holds no ":/"`, false
	case !slices.ContainsFunc(pkgValidURLSchemes, func(v string) bool { return strings.HasPrefix(v, scheme) }):
		return "which pkg rejects as an invalid scheme " + scheme, false
	}
	return "", false
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
// the same name, that change which repositories pkg reads, where it keeps
// repos_state, or which repository urls it starts with. doctor reads only
// the defaults, so any of them set leaves the repository set unknown.
var pkgConfOverrides = []string{"REPOS_DIR", "REPOSITORIES", "PKG_DBDIR", "VALID_URL_SCHEME"}

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
		if kv.val.escaped && (k == "url" || k == "signature_type") {
			return a, pkgUnmodeled{fmt.Sprintf("%s: %s of %q holds an escape libucl decodes and doctor does not", o.from, kv.key, o.name)}
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
// checks. uclUnknown is a bare number libucl accepts in a form whose type
// doctor does not assign (1.5, 1e3); uclNumber refuses the forms whose
// acceptance doctor cannot decide (1k, 0x10, +1).
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
	// escaped marks a quoted value holding an escape, whose decoded text
	// doctor does not claim to know.
	escaped bool
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
// an object is refused here. A lexical error anywhere fails the whole file,
// as it does in libucl, however many objects parsed cleanly before it.
func parseUCL(src string) ([]uclStmt, error) {
	p := &uclParser{src: src}
	out, err := p.stmts()
	if p.err != nil {
		return nil, p.err
	}
	return out, err
}

func (p *uclParser) stmts() ([]uclStmt, error) {
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
			arg, escaped, err := p.quoted()
			if err != nil {
				return nil, err
			}
			if escaped {
				return nil, pkgUnmodeled{fmt.Sprintf("line %d: the path %s names holds an escape doctor does not decode", line, name)}
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
	// err is the first lexical error, which skip cannot return.
	err error
	// depth is how many nested values enclose pos.
	depth int
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
			i := strings.Index(rest[2:], "*/")
			switch {
			case i < 0:
				p.fail(fmt.Errorf("line %d: unfinished multiline comment", p.line()))
			case strings.Contains(rest[2:2+i], "/*") || strings.Contains(rest[2:2+i], `"`):
				// libucl nests comments and reads a quote inside one as the
				// start of a string that can hide the */.
				p.fail(pkgUnmodeled{fmt.Sprintf("line %d: a comment holding /* or a quote, which libucl nests or reads as a string", p.line())})
			default:
				p.pos += i + 4
			}
		default:
			return
		}
	}
}

// fail records the first lexical error and ends the input there.
func (p *uclParser) fail(err error) {
	if p.err == nil {
		p.err = err
	}
	p.pos = len(p.src)
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
		line := p.line()
		k, escaped, err := p.quoted()
		if err == nil && escaped {
			err = pkgUnmodeled{fmt.Sprintf("line %d: the key %q holds an escape doctor does not decode", line, k)}
		}
		return k, err
	}
	start := p.pos
	for !p.eof() && !strings.ContainsRune(" \t\r\n:={}[],;#\"'", rune(p.peek())) {
		p.pos++
	}
	if p.pos == start {
		return "", fmt.Errorf("line %d: expected a key, found %q", p.line(), p.peek())
	}
	k := p.src[start:p.pos]
	if why := uclBareToken(k); why != "" {
		return "", pkgUnmodeled{fmt.Sprintf("line %d: the key %s %s", p.line(), k, why)}
	}
	if c := p.peek(); c == '"' || c == '\'' || c == '{' || c == '[' {
		return "", pkgUnmodeled{fmt.Sprintf("line %d: the key %s runs into %q with no space, which doctor does not lex", p.line(), k, c)}
	}
	return k, nil
}

// uclBareToken returns why doctor does not read an unquoted key or value as
// the text it spells, or "". A quote, an opener or a backslash inside one is
// a byte libucl may read as structure or an escape rather than as text, and
// "/*" may open a comment: libucl discarded a whole file over "abc{" where
// the same bytes quoted parsed, measured with pkg 2.8.4 on 15.1. doctor
// refuses the token at every depth rather than guess which it is.
func uclBareToken(s string) string {
	if strings.ContainsAny(s, "\"'{[\\") || strings.Contains(s, "/*") {
		return "holds a quote, an opener, a backslash or /* outside quotes, which libucl may read as structure"
	}
	return ""
}

// value returns a scalar, or an empty one of its kind after passing a
// nested object or array.
func (p *uclParser) value() (uclScalar, error) {
	switch c := p.peek(); c {
	case '"', '\'':
		s, escaped, err := p.quoted()
		return uclScalar{s: s, kind: uclString, escaped: escaped}, err
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
	if s == "" {
		p.fail(fmt.Errorf("line %d: string value must not be empty", p.line()))
	}
	if why := uclBareToken(s); why != "" {
		return uclScalar{}, pkgUnmodeled{fmt.Sprintf("line %d: the value %s %s", p.line(), s, why)}
	}
	switch why, fatal := uclNumber(s); {
	case fatal:
		return uclScalar{}, fmt.Errorf("line %d: the value %s %s", p.line(), s, why)
	case why != "":
		return uclScalar{}, pkgUnmodeled{fmt.Sprintf("line %d: the value %s %s", p.line(), s, why)}
	}
	return uclScalar{s: s, kind: bareKind(s)}, nil
}

var uclFloatLit = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// uclNumber decides whether libucl accepts a bare token that may start a
// number, whatever key it sits under. libucl converts the digits it lexes
// with strtoimax or strtod and discards the whole file when either reports
// ERANGE, before it looks at what follows the digits, measured with pkg
// 2.8.4 on 15.1: 9223372036854775808 and 1e999 each discarded a file where
// 9223372036854775807 and 1e3 parsed. doctor checks the range of a plain
// decimal integer or float and returns pkgUnmodeled for every other form
// (hex, time and size suffixes, a sign it does not lex), since the prefix
// libucl converts in those is one doctor does not reproduce. Validity is
// separate from type: a valid float is still a value whose type pkg's key
// checks doctor does not claim. fatal marks a token libucl rejects; a why
// without it is one doctor cannot decide.
func uclNumber(s string) (why string, fatal bool) {
	if s == "" || !strings.ContainsRune("0123456789-+.", rune(s[0])) {
		return "", false
	}
	switch {
	case uclIntLit.MatchString(s):
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			return "is out of range for libucl's integers, and libucl discards the file", true
		}
		return "", false
	case uclFloatLit.MatchString(s):
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return "is out of range for libucl's floats, and libucl discards the file", true
		}
		// strtod reports ERANGE on underflow as well, which Go's parser
		// rounds away without an error.
		if mant, _, _ := strings.Cut(strings.ToLower(s), "e"); (f == 0 && strings.Trim(mant, "-0.") != "") || (f != 0 && math.Abs(f) < 0x1p-1022) {
			return "underflows a double, which strtod may report as out of range", false
		}
		return "", false
	}
	return "may start a number in a form doctor does not lex, and libucl discards the file when that number is out of range", false
}

// quoted returns a quoted string and whether it held an escape. libucl
// decodes escapes differently in the two quote styles and accepts ones it
// does not define, measured with pkg 2.8.4, so a string holding one has a
// value doctor does not claim to know. A double-quoted string may not hold a
// control character, newline included; libucl rejects the file.
func (p *uclParser) quoted() (s string, escaped bool, err error) {
	q, start := p.peek(), p.line()
	p.pos++
	var b strings.Builder
	for !p.eof() {
		c := p.src[p.pos]
		p.pos++
		switch {
		case c == q:
			return b.String(), escaped, nil
		case c == '\\' && !p.eof():
			escaped = true
			b.WriteByte(p.src[p.pos])
			p.pos++
		case c < 0x20 && q == '"':
			return "", false, fmt.Errorf("line %d: control character %#02x in a string", p.line(), c)
		case c < 0x20 && c != '\n':
			escaped = true
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return "", false, fmt.Errorf("line %d: string is not closed", start)
}

// uclNestDepth bounds how deep doctor follows nested values.
const uclNestDepth = 32

// nested parses an object or array value with the grammar the top level
// uses, whatever key it sits under: libucl rejects the whole file over a
// malformed value pkg would never read. Measured with pkg 2.8.4 on 15.1,
// libucl accepts "{ a x }", "{ a: x b: y }", "[a b]", trailing separators
// and comments inside either, and rejects an empty value, a closer that does
// not match its opener, and "[ , ]" while accepting "[a,,b]". doctor keeps
// to the forms it measured: a separator where an array element belongs is
// refused as unmodeled rather than guessed at, and value refuses a bare
// token it does not lex at this depth as at every other.
func (p *uclParser) nested() error {
	open, start := p.peek(), p.line()
	closer := byte('}')
	if open == '[' {
		closer = ']'
	}
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > uclNestDepth {
		return pkgUnmodeled{fmt.Sprintf("line %d: values nested past %d levels", start, uclNestDepth)}
	}
	p.pos++
	for {
		p.skip()
		switch c := p.peek(); {
		case p.eof():
			return fmt.Errorf("line %d: object or array is not closed", start)
		case c == closer:
			p.pos++
			return nil
		case c == '}' || c == ']':
			return fmt.Errorf("line %d: %q closes a value opened with %q", p.line(), c, open)
		case open == '[' && (c == ',' || c == ';'):
			return pkgUnmodeled{fmt.Sprintf("line %d: an array holds an empty element, which libucl accepts or rejects by position", p.line())}
		}
		if open == '{' {
			kline := p.line()
			k, err := p.key()
			if err != nil {
				return err
			}
			if strings.HasPrefix(k, ".") {
				return pkgUnmodeled{fmt.Sprintf("line %d: %s inside a nested object is a UCL directive doctor does not evaluate", kline, k)}
			}
			p.sep()
		}
		if _, err := p.value(); err != nil {
			return err
		}
		p.term()
	}
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
	makeAssign    = regexp.MustCompile(`^([^\s:?!+=]+)\s*(::=|[:?!+]?=)\s*(.*)$`)
	makeDirective = regexp.MustCompile(`^\.\s*([a-z-]+)\s*(.*)$`)
	makeReadonly  = regexp.MustCompile(`^\.(NO)?READONLY\s*:(.*)$`)
	// makeExportCompat is bmake's "export name=value" without the dot.
	makeExportCompat = regexp.MustCompile(`^export\s+([^\s:?!+=]+\s*[:?!+]?=.*)$`)
	makeVarRef       = regexp.MustCompile(`\$(\{[^}]*\}?|\([^)]*\)?|.?)`)
	// servedEnvValue is the value the client check bodega serves gives
	// distfilesEnvVar: one of two literal words whatever the drift is.
	// TestCheckMakeConfWalksTheServedClientCheck holds it to distinfo.
	servedEnvValue = regexp.MustCompile(`^\$\{"\$\{BODEGA_DISTFILES_DRIFT:M\*\}" == "":\?[0-9a-f]+:unsupported\}$`)
)

// CheckMakeConf reports whether ports on this FreeBSD host fetch distfiles
// through bodega, comparing make.conf with what clientconf.MakeConf renders.
func CheckMakeConf() Finding {
	return checkMakeConfEnviron("", runtime.GOOS, os.LookupEnv, os.Environ())
}

func checkMakeConf(root, goos string, getenv func(string) string) Finding {
	return checkMakeConfLookup(root, goos, nonEmpty(getenv))
}

func checkMakeConfLookup(root, goos string, lookup func(string) (string, bool)) Finding {
	return checkMakeConfEnviron(root, goos, lookup, nil)
}

// checkMakeConfEnviron is the check with the whole environment as well,
// which the served client check hands to make as text: its "env" output is
// expanded again, so every value in it is make syntax make may evaluate.
func checkMakeConfEnviron(root, goos string, lookup func(string) (string, bool), environ []string) Finding {
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
	posix, hook, mode := makeSysSkipsConfWhy(lookup, flags), makeSysHookWhy(root), makeSysModeWhy(lookup, flags)
	switch sys := makeSysPathWhy(root, lookup, flags); {
	case sys != "":
		f.Status = StatusWarn
		f.Detail = sys + ", and a sys.mk other than /usr/share/mk/sys.mk can select a different make.conf and change the fetch sites before or after it, so doctor cannot establish what ports fetch from"
		f.Remediation = "unset MAKESYSPATH, remove it from MAKEFLAGS and move any share/mk out of the ports tree; then run doctor again"
		return f
	case mode != "":
		f.Status = StatusWarn
		f.Detail = mode + ", so doctor cannot establish which make.conf make reads, whether it reads one, or what ports fetch from"
		f.Remediation = "unset the DIRDEPS_BUILD, META_MODE and AUTO_OBJ controls (MK_, WITH_ and WITHOUT_ forms) and bsd.mkopt.mk's option lists in the environment and MAKEFLAGS; then run doctor again"
		return f
	case posix != "":
		f.Status = StatusWarn
		f.Detail = posix + ", and " + makeStockSysPath + "/sys.mk reads make.conf only when %POSIX is undefined, so make reads no make.conf and " + strings.Join(names, ", ") + " stay at the ports' own sites"
		f.Remediation = "unset %POSIX and remove it from MAKEFLAGS; then run doctor again"
		return f
	case hook != "":
		f.Status = StatusWarn
		f.Detail = hook + ", so doctor cannot establish what ports fetch from"
		f.Remediation = "move the local sys.mk hooks out of " + makeStockSysPath + ", or carry their settings in make.conf; then run doctor again"
		return f
	case slices.Contains(flags.assigns, "__MAKE_CONF"):
		f.Status = StatusWarn
		f.Detail = "the environment's MAKEFLAGS assigns __MAKE_CONF, so doctor cannot establish which make.conf make reads"
		f.Remediation = "remove __MAKE_CONF from MAKEFLAGS and run doctor again"
		return f
	case slices.ContainsFunc(flags.defines, func(d string) bool { n, _, _ := strings.Cut(d, "="); return n == "__MAKE_CONF" }):
		// -D sets a global of 1 that sys.mk's ?= keeps, so make reads a file
		// named 1 in its working directory, or the environment's under -e.
		f.Status = StatusWarn
		f.Detail = "the environment's MAKEFLAGS defines __MAKE_CONF with -D, which replaces the path sys.mk would read, so doctor cannot establish which make.conf make reads"
		f.Remediation = "remove -D __MAKE_CONF from MAKEFLAGS and run doctor again"
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

	w := &makeWalk{root: root, sites: map[string]*siteValue{}, env: map[string]string{},
		vars: map[string]*makeVar{}, lookup: lookup, environ: environ, read: []string{path}}
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
	w.settleExpansions()
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
	// group is whether a dependency line has opened a group that tab-led
	// lines attach to: 1 yes, 0 no, -1 maybe. Only an assignment closes
	// one; directives and includes, in either direction, leave it open.
	group int
	// envChanged says, per tracked variable, why the environment make
	// consults may no longer hold what env recorded at the start.
	envChanged map[string]string
	// vars is every value any variable may hold, tracked or not, for
	// classifying what expanding it does. lookup and environ are the
	// environment make starts with, and read every file doctor read, in the
	// spelling make lists it in .MAKE.MAKEFILES.
	vars    map[string]*makeVar
	lookup  func(string) (string, bool)
	environ []string
	read    []string
}

// fromEnv is a tracked variable with no makefile value: the environment's,
// or unset.
func (w *makeWalk) fromEnv(n string) siteValue {
	if why, ok := w.envChanged[n]; ok {
		return siteValue{unknown: why}
	}
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

// condActive is 1, 0 or -1 as for condFrame, across every frame given and
// the include that led here.
func condActive(frames []condFrame, unknown bool) int {
	active := 1
	if unknown {
		active = -1
	}
	for _, fr := range frames {
		if fr.state == 0 {
			return 0
		}
		if fr.state == -1 {
			active = -1
		}
	}
	return active
}

func (w *makeWalk) file(path string, stmts []makeStmt, unknown bool, stack []string) error {
	stack = append(stack, path)
	var frames []condFrame
	for i, stmt := range stmts {
		st := stmt.text
		active := condActive(frames, unknown)

		if stmt.recipe {
			w.recipe(st, path, active)
			if active != 0 {
				w.evaluate(st, "a command in "+path)
			}
			continue
		}
		if m := makeDirective.FindStringSubmatch(st); m != nil {
			dir, arg := m[1], strings.TrimSpace(m[2])
			switch dir {
			case "if", "ifdef", "ifndef", "ifmake", "ifnmake":
				if active != 0 {
					w.evaluate(makeCondText(arg), "."+dir+" in "+path)
				}
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
				if fr.seen != 1 && dir != "else" && condActive(frames[:len(frames)-1], unknown) != 0 {
					w.evaluate(makeCondText(arg), "."+dir+" in "+path)
				}
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
				if active != 0 {
					// .for substitutes each word of its list into the body,
					// which make then parses: a "$" in a word is syntax.
					_, list, _ := strings.Cut(arg, " in ")
					if e := w.evaluate(list, ".for in "+path); e.dollar != "" {
						w.unsettled(".for in " + path + " substitutes words that may hold " + e.dollar + " into its body")
					}
				}
				frames = append(frames, condFrame{state: -1, seen: -1, loop: true})
				continue
			}
			if active == 0 {
				continue
			}
			w.evaluate(arg, "."+dir+" in "+path)
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
			case "export", "export-env", "export-literal", "export-all", "unexport", "unexport-env":
				w.export(dir, arg, path)
			case "info", "warning", "error":
			default:
				w.pinAll("." + dir + " in " + path + " is a directive doctor does not evaluate")
			}
			continue
		}
		if active == 0 {
			continue
		}

		if m := makeExportCompat.FindStringSubmatch(st); m != nil {
			w.evaluate(st, "export in "+path)
			w.exportCompat(st, m[1], path)
			continue
		}
		if ro := makeReadonly.FindStringSubmatch(st); ro != nil {
			w.evaluate(st, path)
			w.setGroup(1, active)
			w.readonly(st, path, ro[1] == "", strings.Fields(ro[2]), active == -1)
			continue
		}
		m := makeAssign.FindStringSubmatch(st)
		if m == nil {
			w.evaluate(st, "a dependency line in "+path)
			w.dependency(st, path, active)
			continue
		}
		w.setGroup(0, active)
		name, op, val := m[1], m[2], m[3]
		if !strings.Contains(name, "$") {
			w.record(name, op, val, path)
		}
		switch {
		case strings.Contains(name, "$"):
			// The name may expand to one of make's own controls, the export
			// list among them, so both a value and its precedence are open.
			why := path + " assigns the computed name " + name + ", which doctor does not expand"
			w.pinAll(why)
			w.envMayChange(why)
		case name == ".MAKE.EXPORTED":
			w.envMayChange(path + " assigns .MAKE.EXPORTED, make's list of exported variables")
		case strings.HasPrefix(name, "."):
			w.pinAll(path + " assigns " + name + ", a variable make reads as a control doctor does not model")
		default:
			if v := w.sites[name]; v != nil {
				w.assign(v, op, val, path, active == -1)
			}
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

// export applies an export-family directive, read or maybe read. Each one
// changes the process environment while make reads makefiles: .unexport-env
// clears it, .export-env and .export-literal write a value that later
// assignments do not follow, and .export writes one they do. A recipe under
// -e, and any lookup a makefile value no longer shadows, reads that
// environment rather than the one doctor started with, measured with bmake on
// 15.1. doctor does not replay the changes; every variable the directive can
// reach has an environment value it no longer knows.
func (w *makeWalk) export(dir, arg, path string) {
	why := "." + strings.TrimSpace(dir+" "+arg) + " in " + path + " changes the environment make reads"
	names := strings.Fields(arg)
	all := dir == "unexport-env" || dir == "export-all" || len(names) == 0 || strings.Contains(arg, "$")
	w.envChangedFor(why, func(n string) bool { return all || slices.Contains(names, n) })
}

// envMayChange records that an operation doctor does not replay may have
// written any tracked variable into the environment: an assignment to the
// export list, or to a name doctor cannot expand.
func (w *makeWalk) envMayChange(why string) {
	w.envChangedFor(why, func(string) bool { return true })
}

func (w *makeWalk) envChangedFor(why string, reaches func(string) bool) {
	if w.envChanged == nil {
		w.envChanged = map[string]string{}
	}
	for n, v := range w.sites {
		if !reaches(n) {
			continue
		}
		if _, ok := w.envChanged[n]; !ok {
			w.envChanged[n] = why
		}
		if v.env {
			v.undetermined(why)
		}
	}
}

// exportCompat applies "export name=value", which bmake accepts for other
// makes' sake: it assigns and exports, and leaves the dependency group as
// it was, measured with bmake on 15.1. doctor does not model the assignment
// half, so every variable it names is pinned, and a name doctor cannot
// expand could be any of them.
func (w *makeWalk) exportCompat(line, arg, path string) {
	why := "export in " + path + " assigns and exports in a form doctor does not evaluate: " + line
	if name, _, _ := strings.Cut(arg, "="); strings.Contains(name, "$") {
		w.pinAll(why)
	} else {
		w.touch(line, why)
	}
	w.envMayChange(why)
}

// makeInertTargets are the special targets that attach attributes or
// commands to other targets and change no variable, precedence or included
// file. Every other special target (.OBJDIR, .PATH, .POSIX, .SHELL,
// .SYSPATH and any bmake adds) is a control doctor does not model.
var makeInertTargets = map[string]bool{
	".BEGIN": true, ".DEFAULT": true, ".DELETE_ON_ERROR": true, ".END": true,
	".ERROR": true, ".IGNORE": true, ".INTERRUPT": true, ".MAIN": true,
	".NOPATH": true, ".NOTPARALLEL": true, ".NO_PARALLEL": true, ".ORDER": true,
	".PHONY": true, ".PRECIOUS": true, ".SILENT": true, ".STALE": true,
	".SUFFIXES": true, ".WAIT": true,
}

// dependency applies a line that is neither an assignment nor a directive.
// bmake refuses one with no dependency operator ("Invalid line"). One with
// an operator opens a dependency group, and its targets may be controls: a
// target list doctor cannot expand, or a special target it does not model,
// may have changed any tracked variable.
func (w *makeWalk) dependency(line, path string, active int) {
	targets, _, found := strings.Cut(line, ":")
	if bang, _, ok := strings.Cut(line, "!"); ok && len(bang) < len(targets) {
		targets, found = bang, true
	}
	switch {
	case strings.Contains(targets, "$"):
		w.pinAll(path + " has a dependency line whose targets doctor does not expand: " + line)
	case !found:
		w.problems = append(w.problems, path+" has a line make refuses as invalid: "+line)
		return
	}
	w.setGroup(1, active)
	if mf := makeFlagsLine.FindStringSubmatch(line); mf != nil {
		w.applyFlags(parseMakeFlags(mf[2], false), "."+mf[1]+" in "+path, active == -1)
		return
	}
	if makeFlagsTarget.MatchString(line) {
		w.pinAll(path + " passes make flags on " + line + ", which doctor does not read")
		return
	}
	for _, t := range strings.Fields(targets) {
		if strings.HasPrefix(t, ".") && !makeInertTargets[t] {
			w.pinAll(path + " names the special target " + t + ", a control doctor does not model: " + line)
			return
		}
	}
	w.touch(line, "a line in "+path+" doctor does not evaluate names it: "+line)
}

// setGroup records a line that opens (1) or closes (0) the dependency group
// under a branch that is taken (active 1) or may be (-1).
func (w *makeWalk) setGroup(to, active int) {
	switch {
	case active == 1:
		w.group = to
	case active == -1 && w.group != to:
		w.group = -1
	}
}

// recipe applies a tab-led line: a shell command, which assigns nothing, or
// a fatal error when no dependency group is open.
func (w *makeWalk) recipe(line, path string, active int) {
	switch {
	case active == 0 || w.group == 1:
	case active == 1 && w.group == 0:
		w.problems = append(w.problems, path+" has a tab-led line outside any target, which make refuses as an unassociated shell command: "+line)
	default:
		w.problems = append(w.problems, path+" has a tab-led line doctor cannot establish follows a target, and make refuses it if none is open: "+line)
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
	for _, d := range append(append([]string(nil), fl.assigns...), fl.defines...) {
		if n, _, _ := strings.Cut(d, "="); strings.HasPrefix(n, ".") {
			why := from + " sets " + n + ", a variable make reads as a control doctor does not model"
			w.pinAll(why)
			w.envMayChange(why)
		}
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
		if v.pinned != "" || w.envFirst == 0 {
			continue
		}
		if why, ok := w.envChanged[n]; ok {
			v.pin(why + ", and " + w.envFirstWhy + ", which would put the environment above make.conf")
			continue
		}
		ev, ok := w.env[n]
		if !ok {
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
		if further := w.includeSearch(arg); further != "" {
			w.pinAll(from + " includes " + arg + ", which is not at " + inc + ", and make " + further)
			return nil
		}
		if dir == "include" && report && !unknown {
			w.problems = append(w.problems, from+" includes "+inc+", which does not exist")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s, which %s includes: %w", inc, from, err)
	}
	w.read = append(w.read, inc)
	return w.file(inc, makeStatements(string(data)), unknown, stack)
}

// makeStockSysPath is where FreeBSD's make finds sys.mk when nothing
// replaces its search.
const makeStockSysPath = "/usr/share/mk"

// makeSysPathWhy returns why doctor cannot establish that make reads the
// stock sys.mk, which is what reads make.conf, or "". MAKESYSPATH replaces
// the search, and so does a MAKESYSPATH assignment in MAKEFLAGS, which make
// exports. Unset, FreeBSD's make searches ".../share/mk:/usr/share/mk": the
// first share/mk in the working directory or any parent comes first. That
// was measured with bmake on 15.1, where a share/mk/sys.mk in a parent of
// the working directory replaced the stock one. doctor cannot know every
// directory make runs in, so it checks the one fetch runs in: each port
// directory under PORTSDIR, /usr/ports by default, its category and the
// tree itself, and every parent up to the one holding /usr/share/mk.
// -m in MAKEFLAGS is refused later with every flag doctor does not model.
func makeSysPathWhy(root string, lookup func(string) (string, bool), fl makeFlags) string {
	if v, ok := lookup("MAKESYSPATH"); ok && v != makeStockSysPath {
		return "MAKESYSPATH=" + v + " replaces the directories make searches for sys.mk"
	}
	if slices.Contains(fl.assigns, "MAKESYSPATH") {
		return "the environment's MAKEFLAGS assigns MAKESYSPATH, which make exports and searches for sys.mk"
	}
	ports := "/usr/ports"
	if v, ok := lookup("PORTSDIR"); ok {
		ports = v
	}
	if !filepath.IsAbs(ports) {
		return "PORTSDIR=" + ports + " is relative, so doctor cannot establish which directories make searches for sys.mk"
	}
	ports = filepath.Clean(ports)
	var dirs []string
	for d := ports; d != "/usr"; d = filepath.Dir(d) {
		dirs = append(dirs, filepath.Join(d, "share/mk"))
		if d == "/" {
			break
		}
	}
	unreadable := func(dir string, err error) string {
		if err == nil || errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return ""
		}
		return "doctor cannot read " + dir + " (" + err.Error() + "), where make run in the ports tree may find a share/mk ahead of " + makeStockSysPath
	}
	cats, err := os.ReadDir(filepath.Join(root, ports))
	if why := unreadable(ports, err); why != "" {
		return why
	}
	for _, c := range cats {
		cat := filepath.Join(ports, c.Name())
		dirs = append(dirs, filepath.Join(cat, "share/mk"))
		ents, err := os.ReadDir(filepath.Join(root, cat))
		if why := unreadable(cat, err); why != "" {
			return why
		}
		for _, e := range ents {
			dirs = append(dirs, filepath.Join(cat, e.Name(), "share/mk"))
		}
	}
	for _, d := range dirs {
		fi, err := os.Stat(filepath.Join(root, d))
		if why := unreadable(d, err); why != "" {
			return why
		}
		if err == nil && fi.IsDir() {
			return "make run in the ports tree finds " + d + " through its default search .../share/mk ahead of " + makeStockSysPath
		}
	}
	return ""
}

// makeSysSkipsConfWhy returns why the stock sys.mk may skip make.conf, or
// "". It includes make.conf only in the branch taken when %POSIX is
// undefined, and make defines a variable from an environment entry of any
// value, an empty one included, from -D in any flag form and from a
// command-line assignment, measured with bmake on 15.1. A -D argument is cut
// at its first = so that a spelling make might read as a different name
// still warns.
func makeSysSkipsConfWhy(lookup func(string) (string, bool), fl makeFlags) string {
	const posix = "%POSIX"
	if _, ok := lookup(posix); ok {
		return "the environment defines " + posix
	}
	if slices.Contains(fl.assigns, posix) {
		return "the environment's MAKEFLAGS assigns " + posix
	}
	if slices.ContainsFunc(fl.defines, func(d string) bool { n, _, _ := strings.Cut(d, "="); return n == posix }) {
		return "the environment's MAKEFLAGS defines " + posix + " with -D"
	}
	return ""
}

// makeSysModeIncludes are the stock files sys.mk includes ahead of make.conf
// when bsd.mkopt.mk turns the option on. doctor models none of them:
// sys.dirdeps.mk assigns to names it reads from TARGET_SPEC_VARS, which can
// be __MAKE_CONF or %POSIX, and the other two carry their own includes and
// hooks. So the system stage doctor certifies is the one where all three
// resolve to "no", which is FreeBSD's default.
var makeSysModeIncludes = []struct{ opt, file string }{
	{"DIRDEPS_BUILD", "sys.dirdeps.mk"},
	{"META_MODE", "meta.sys.mk"},
	{"AUTO_OBJ", "auto.obj.mk"},
}

// makeSysOptionLists are what bsd.mkopt.mk loops over to assign MK_ names.
// A value from outside, in the environment or MAKEFLAGS, can turn on an
// option the stock lists leave off, so any definition of one leaves the
// modes undetermined.
var makeSysOptionLists = []string{
	"__DEFAULT_YES_OPTIONS", "__DEFAULT_NO_OPTIONS", "__DEFAULT_DEPENDENT_OPTIONS",
	"__REQUIRED_OPTIONS", "__SINGLE_OPTIONS", "BROKEN_OPTIONS", "BROKEN_SINGLE_OPTIONS",
}

// makeSysModeWhy returns why sys.mk may include a system makefile doctor
// does not model before make.conf, or "". It follows bsd.mkopt.mk as the
// stock sys.mk lists the options, measured with bmake on 15.1: a defined
// MK_ name wins, DIRDEPS_BUILD is on when WITH_ is defined and WITHOUT_ is
// not, and META_MODE and AUTO_OBJ are off when WITHOUT_ is defined, on when
// only WITH_ is, and follow DIRDEPS_BUILD otherwise. defined() counts an
// empty environment entry, -D in any flag form and a command-line
// assignment. A command-line MK_ value is one doctor does not read, and an
// environment MK_ value other than "no" either turns the option on or stops
// make at bsd.mkopt.mk's check, so both warn.
func makeSysModeWhy(lookup func(string) (string, bool), fl makeFlags) string {
	flagged := func(n string) string {
		if slices.Contains(fl.assigns, n) {
			return "the environment's MAKEFLAGS assigns " + n
		}
		if slices.ContainsFunc(fl.defines, func(d string) bool { dn, _, _ := strings.Cut(d, "="); return dn == n }) {
			return "the environment's MAKEFLAGS defines " + n + " with -D"
		}
		return ""
	}
	defined := func(n string) (string, bool) {
		if why := flagged(n); why != "" {
			return why, true
		}
		if _, ok := lookup(n); ok {
			return "the environment defines " + n, true
		}
		return "", false
	}
	for _, n := range makeSysOptionLists {
		if why, ok := defined(n); ok {
			return why + ", which bsd.mkopt.mk reads to decide the MK_ options sys.mk includes system makefiles on"
		}
	}
	type mode struct {
		on  bool
		why string
	}
	resolve := func(opt string, dflt mode) mode {
		mk := "MK_" + opt
		if why := flagged(mk); why != "" {
			return mode{true, why}
		}
		if v, ok := lookup(mk); ok {
			return mode{v != "no", "the environment sets " + mk + "=" + v}
		}
		with, hasWith := defined("WITH_" + opt)
		without, hasWithout := defined("WITHOUT_" + opt)
		switch {
		case hasWithout:
			return mode{false, without}
		case hasWith:
			return mode{true, with}
		}
		return dflt
	}
	dirdeps := resolve("DIRDEPS_BUILD", mode{})
	for _, m := range makeSysModeIncludes {
		got := dirdeps
		if m.opt != "DIRDEPS_BUILD" {
			got = resolve(m.opt, dirdeps)
		}
		if got.on {
			return got.why + ", which turns on MK_" + m.opt + ", so sys.mk includes " +
				filepath.Join(makeStockSysPath, m.file) + " ahead of make.conf, and doctor does not model what that file assigns or includes"
		}
	}
	return ""
}

// makeSysHooks are the files the stock sys.mk reads from its own directory
// when they exist, one before make.conf and one after. FreeBSD ships
// neither, and doctor does not read them, so either can change the fetch
// sites or their precedence.
var makeSysHooks = []string{"local.sys.env.mk", "local.sys.mk"}

// makeSysHookWhy returns why a local sys.mk hook stands in the way, or "".
func makeSysHookWhy(root string) string {
	for _, h := range makeSysHooks {
		p := filepath.Join(makeStockSysPath, h)
		_, err := os.Stat(filepath.Join(root, p))
		switch {
		case err == nil:
			return "sys.mk reads " + p + ", which doctor does not inspect"
		case !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR):
			return "doctor cannot stat " + p + " (" + err.Error() + "), which sys.mk reads when it exists"
		}
	}
	return ""
}

// includeSearch returns where else make looks for an include whose first
// candidate is missing, or "" when there is nowhere: a missing first
// candidate proves the include absent only then. make looks for a relative
// "file" beside the including makefile, then in each -I directory and the
// system makefile directory, and a run from another directory finds it
// there as well, measured with bmake on 15.1; doctor knows neither the -I
// list nor where make runs. A <file> is looked for in the system directory
// alone, which MAKESYSPATH replaces.
func (w *makeWalk) includeSearch(arg string) string {
	inc := arg[1 : len(arg)-1]
	switch {
	case filepath.IsAbs(inc):
		return ""
	case arg[0] == '"':
		return "goes on to search the -I directories, the system makefile directory and the directory it runs in, so doctor cannot establish which file it reads"
	}
	if v, ok := w.lookup("MAKESYSPATH"); ok {
		return "searches MAKESYSPATH=" + v + " for it, which doctor does not follow"
	}
	return ""
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
func checkInclude(root, confPath string, stmts []makeStmt, env *siteValue) string {
	if len(stmts) == 0 {
		return "the file is empty, so it includes no client check"
	}
	last := stmts[len(stmts)-1].text
	if stmts[len(stmts)-1].recipe {
		return "the last line is " + last + ", which is tab-led, so make reads it as a shell command rather than an .include"
	}
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

// makeStmt is one logical line of a makefile. recipe marks a line whose
// first byte is a tab: bmake reads it as a shell command of the open
// dependency group, or refuses the makefile when none is open, and never as
// an assignment or a directive, measured with bmake on 15.1. A line indented
// with a space, even one followed by a tab, is read like an unindented one.
type makeStmt struct {
	text   string
	recipe bool
}

// makeStatements splits a makefile into logical lines: continuations
// joined, comments and blank lines dropped, a tab-led line marked before
// its indentation is trimmed. A tab-led command keeps its "#": make
// expands the whole command, comment and continuations included, before the
// shell sees it, so a comment there can hold live expressions. A tab-led
// line whose text opens with "#" is dropped whole, inside a target or not.
// Both measured with bmake on 15.1. Conditionals are kept as statements and
// not evaluated.
func makeStatements(src string) []makeStmt {
	var out []makeStmt
	var cur strings.Builder
	flush := func() {
		raw := cur.String()
		cur.Reset()
		recipe := strings.HasPrefix(raw, "\t")
		if !recipe || strings.HasPrefix(strings.TrimLeft(raw, " \t"), "#") {
			raw = stripMakeComment(raw)
		}
		if s := strings.TrimSpace(raw); s != "" {
			out = append(out, makeStmt{text: s, recipe: recipe})
		}
	}
	for _, l := range strings.Split(src, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.HasSuffix(l, "\\") {
			cur.WriteString(strings.TrimSuffix(l, "\\") + " ")
			continue
		}
		cur.WriteString(l)
		flush()
	}
	flush()
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

// makeEffect is what expanding a piece of make text may do besides produce
// a string. effect names why it may assign, append to or delete a variable,
// which can reach a tracked value or one of make's controls whatever the
// line it sits on assigns. dollar names why its result may hold a "$":
// harmless where the result is compared or printed, and syntax again
// wherever make expands it a second time, which a := or != value, a .for
// list and a :@ loop variable each are.
type makeEffect struct{ effect, dollar string }

func (e *makeEffect) add(o makeEffect) {
	if e.effect == "" {
		e.effect = o.effect
	}
	if e.dollar == "" {
		e.dollar = o.dollar
	}
}

// makeVar is every value one variable may hold, from every assignment make
// may have read. raw values are expanded on each lookup: what =, ?= and +=
// store, and the modeled output of a command the served check runs. stored
// is what := and any other != leave: text expanded once already, whose "$"
// make evaluates on the next lookup (.MAKE.SAVE_DOLLARS is false by
// default, so := turns "$$" into one). patterns marks a variable only ever
// set to the served check's list of :N patterns built from .MAKE.MAKEFILES.
type makeVar struct {
	raw      []string
	stored   []makeEffect
	patterns bool
	set      bool
}

var (
	// makeLoopMod is ":@var@body@". The body is text make expands once per
	// word, not modifiers, so the modifier scans below skip it.
	makeLoopMod     = regexp.MustCompile(`:@([^@]*)@[^@]*@`)
	makeIndirectMod = regexp.MustCompile(`^:\$\{([A-Za-z0-9_.]+)\}(:|$)`)
	makeShellMod    = regexp.MustCompile(`:(sh(:|$)|!)`)
	makeEmptyCall   = regexp.MustCompile(`empty\s*\(`)
	// makeCleanPath is a makefile path that, joined into a modifier list,
	// holds no separator, expression or escape.
	makeCleanPath = regexp.MustCompile(`^/[A-Za-z0-9._/+@%,=-]+$`)
)

// record keeps what one assignment may leave in a variable, and evaluates
// the text := and != expand as they are read.
func (w *makeWalk) record(name, op, val, path string) {
	v := w.vars[name]
	if v == nil {
		v = &makeVar{}
		w.vars[name] = v
	}
	first := !v.set
	v.set = true
	where := "the assignment to " + name + " in " + path
	patterns := false
	switch op {
	case ":=", "::=":
		e := w.evaluate(val, where)
		v.stored = append(v.stored, makeEffect{dollar: e.dollar})
		patterns = servedModel().read != "" && val == servedModel().read
	case "!=":
		w.evaluate(val, where)
		if out, ok := w.commandOutput(val); ok {
			v.raw = append(v.raw, out...)
		} else {
			v.stored = append(v.stored, makeEffect{dollar: "the output of a shell command doctor does not run, assigned in " + path})
		}
	default:
		v.raw = append(v.raw, val)
	}
	v.patterns = patterns && (first || v.patterns)
}

// evaluate classifies text make expands where it is read, and leaves every
// tracked value and its precedence unsettled when the expansion may assign.
func (w *makeWalk) evaluate(text, where string) makeEffect {
	e := w.classify(text, &makeExpansion{seen: map[string]bool{}})
	if e.effect != "" {
		w.unsettled(where + " expands an expression that may assign a variable: " + e.effect)
	}
	return e
}

// unsettled records an operation doctor does not replay that may have
// changed any tracked value, its precedence, or the environment.
func (w *makeWalk) unsettled(why string) {
	w.pinAll(why)
	w.envMayChange(why)
}

// settleExpansions classifies what a lookup of every variable make.conf
// leaves a value for would do, and every value in the environment. The ports
// framework expands the ones it reads in an order doctor does not model,
// some of them before it builds the site list.
func (w *makeWalk) settleExpansions() {
	names := make([]string, 0, len(w.vars))
	for n := range w.vars {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if e := w.expandVar(n, &makeExpansion{seen: map[string]bool{}}); e.effect != "" {
			w.unsettled("expanding " + n + " may assign a variable: " + e.effect)
			return
		}
	}
	for _, kv := range w.environ {
		n, val, _ := strings.Cut(kv, "=")
		if e := w.classify(val, &makeExpansion{seen: map[string]bool{}}); e.effect != "" {
			w.unsettled("the environment's " + n + " may assign a variable wherever make expands it: " + e.effect)
			return
		}
	}
}

// makeExpansion carries one classification: the variables being expanded,
// which make refuses to re-enter, and what each finished one does.
type makeExpansion struct {
	seen map[string]bool
	done map[string]makeEffect
}

// classify reads text the way make expands it and never runs any of it.
// doctor models a subset: plain references, literal names, and modifiers
// that only filter or rewrite the value. An assignment modifier (::=, ::?=,
// ::+=, ::!=, :_), a :@ loop over a tracked or control variable or over
// words that may hold "$", a modifier list computed from a value doctor
// cannot establish, and a lookup by a computed name are effects; the served
// check's own :N list and its commands are modeled by what they read.
func (w *makeWalk) classify(s string, x *makeExpansion) makeEffect {
	var e makeEffect
	for i := 0; i < len(s); {
		if s[i] != '$' {
			i++
			continue
		}
		sub, next := w.dollarExpr(s, i, x)
		e.add(sub)
		i = next
	}
	return e
}

// dollarExpr classifies the expression starting at s[i], a "$", and returns
// the index after it.
func (w *makeWalk) dollarExpr(s string, i int, x *makeExpansion) (makeEffect, int) {
	if i+1 >= len(s) {
		return makeEffect{}, len(s)
	}
	switch c := s[i+1]; c {
	case '$':
		return makeEffect{dollar: `"$$", which expands to "$"`}, i + 2
	case '{', '(':
		return w.braced(s, i, x)
	default:
		return w.expandVar(string(c), x), i + 2
	}
}

func (w *makeWalk) braced(s string, i int, x *makeExpansion) (makeEffect, int) {
	open, closer := s[i+1], byte('}')
	if open == '(' {
		closer = ')'
	}
	var e makeEffect
	computed := false
	j := i + 2
	for j < len(s) && s[j] != closer && s[j] != ':' {
		if s[j] == '$' {
			sub, next := w.dollarExpr(s, j, x)
			e.add(sub)
			computed, j = true, next
			continue
		}
		j++
	}
	name, modStart, depth := s[i+2:j], j, 0
	for j < len(s) {
		if s[j] == '$' {
			sub, next := w.dollarExpr(s, j, x)
			e.add(sub)
			j = next
			continue
		}
		if s[j] == open {
			depth++
		} else if s[j] == closer {
			if depth == 0 {
				break
			}
			depth--
		}
		j++
	}
	if j >= len(s) {
		e.add(makeEffect{effect: "the expression " + s[i:] + " is not closed"})
		return e, len(s)
	}
	mods, text := s[modStart:j], s[i:j+1]

	// ${cond:?a:b} evaluates its name as a condition and looks nothing up.
	cond := strings.HasPrefix(mods, ":?")
	var val makeEffect
	switch {
	case cond:
		e.add(makeEffect{effect: w.classify(makeCondText(name), x).effect})
	case computed:
		e.add(makeEffect{effect: text + " looks up a variable by a name doctor does not expand"})
	case name != "":
		val = w.expandVar(name, x)
		e.add(makeEffect{effect: val.effect})
	}
	res := val.dollar

	chain := makeLoopMod.ReplaceAllString(mods, ":@")
	if strings.Contains(chain, "::") || strings.Contains(chain, ":_") {
		e.add(makeEffect{effect: text + " holds an assignment modifier"})
	}
	loops := makeLoopMod.FindAllStringSubmatch(mods, -1)
	if strings.Count(mods, ":@") > len(loops) {
		e.add(makeEffect{effect: text + " holds a :@ loop doctor does not parse"})
	}
	for _, m := range loops {
		switch v := m[1]; {
		case v == "" || strings.Contains(v, "$") || strings.HasPrefix(v, ".") || w.sites[v] != nil:
			e.add(makeEffect{effect: text + " binds and then deletes the loop variable " + v + ", which doctor tracks or make reads as a control"})
		case res != "":
			e.add(makeEffect{effect: text + " binds " + v + " to words that may hold " + res + ", which make expands again"})
		}
	}
	for k := 0; ; k++ {
		at := strings.Index(chain[k:], ":$")
		if at < 0 {
			break
		}
		k += at
		if m := makeIndirectMod.FindStringSubmatch(chain[k:]); m == nil || !w.patternsSafe(m[1]) {
			e.add(makeEffect{effect: text + " applies modifiers computed from a value doctor cannot establish"})
			break
		}
	}
	switch {
	case mods == ":sh" && w.stableView(name):
		// The served check's view of its mounts prints fixed words, mount
		// names from the table root keeps, and the ports tree path it read.
		res = w.expandVar("_BODEGA_DISTFILES_TREE", x).dollar
	case makeShellMod.MatchString(chain):
		res = "the output of the shell command in " + text
	case cond:
		res = ""
	}
	e.add(makeEffect{dollar: res})
	return e, j + 1
}

// expandVar classifies one lookup: every value the variable may hold in a
// makefile, and the environment's.
func (w *makeWalk) expandVar(name string, x *makeExpansion) makeEffect {
	if e, ok := x.done[name]; ok {
		return e
	}
	if x.seen[name] {
		return makeEffect{effect: name + " expands itself, which make refuses"}
	}
	x.seen[name] = true
	defer delete(x.seen, name)
	var e makeEffect
	if v := w.vars[name]; v != nil {
		for _, r := range v.raw {
			e.add(w.classify(r, x))
		}
		for _, st := range v.stored {
			if st.dollar != "" {
				e.add(makeEffect{effect: name + " holds " + st.dollar + ", which make evaluates when it looks " + name + " up", dollar: st.dollar})
			}
		}
	}
	if w.lookup != nil {
		if ev, ok := w.lookup(name); ok {
			e.add(w.classify(ev, x))
		}
	}
	if x.done == nil {
		x.done = map[string]makeEffect{}
	}
	x.done[name] = e
	return e
}

// patternsSafe reports whether a variable used as a modifier list holds the
// served check's :N patterns and nothing else, over makefile paths that
// cannot split into further modifiers. make lists every file it read: the
// ones doctor read, and those under /usr/share/mk that sys.mk reads.
func (w *makeWalk) patternsSafe(name string) bool {
	v := w.vars[name]
	if v == nil || !v.patterns {
		return false
	}
	for _, p := range w.read {
		if !makeCleanPath.MatchString(p) {
			return false
		}
	}
	return true
}

// stableView reports whether a variable holds the served check's view of
// its mounts and nothing else.
func (w *makeWalk) stableView(name string) bool {
	v, stable := w.vars[name], servedModel().stable
	if v == nil || stable == "" || len(v.stored) > 0 || len(v.raw) == 0 {
		return false
	}
	for _, r := range v.raw {
		if r != stable {
			return false
		}
	}
	return true
}

// commandOutput models what a command the served check assigns with !=
// prints, as text make expands on lookup, or reports that doctor does not.
func (w *makeWalk) commandOutput(cmd string) ([]string, bool) {
	m := servedModel()
	switch cmd {
	case "":
		return nil, false
	case m.env:
		return w.environ, true
	case m.conf:
		// grep -l prints the names of makefiles make read.
		return w.read, true
	}
	if _, ok := m.measure.path(cmd); ok {
		return nil, true // a digest or one of three fixed words
	}
	if p, ok := m.writers.path(cmd); ok {
		return []string{p}, true // components of the declared path
	}
	return nil, false
}

// makeCondText rewrites each empty(...) in a condition as the expression it
// expands, so classify reads it.
func makeCondText(s string) string {
	var b strings.Builder
	for {
		loc := makeEmptyCall.FindStringIndex(s)
		if loc == nil {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:loc[0]])
		depth, j := 0, loc[1]
		for ; j < len(s); j++ {
			if s[j] == '(' {
				depth++
			} else if s[j] == ')' {
				if depth == 0 {
					break
				}
				depth--
			}
		}
		b.WriteString("${" + s[loc[1]:j] + "}")
		if j >= len(s) {
			return b.String()
		}
		s = s[j+1:]
	}
}

// servedCommands is the served client check's commands, read from a check
// distinfo renders for a sentinel environment so doctor and the generator
// cannot disagree about their text.
type servedCommands struct {
	env, conf, stable, read string
	measure, writers        pathTemplate
}

// pathTemplate matches a per-file command with the declared path in each
// place the sentinel sat.
type pathTemplate struct{ re *regexp.Regexp }

func newPathTemplate(cmd, sentinel string) pathTemplate {
	quoted := strings.ReplaceAll(regexp.QuoteMeta(cmd), regexp.QuoteMeta(sentinel), `(/[A-Za-z0-9._/+@%,=-]+)`)
	return pathTemplate{regexp.MustCompile("^" + quoted + "$")}
}

// path returns the declared path cmd was rendered for, when it matches and
// names one path throughout.
func (t pathTemplate) path(cmd string) (string, bool) {
	if t.re == nil {
		return "", false
	}
	m := t.re.FindStringSubmatch(cmd)
	if len(m) < 2 {
		return "", false
	}
	for _, p := range m[2:] {
		if p != m[1] {
			return "", false
		}
	}
	return m[1], true
}

var servedModel = sync.OnceValue(func() servedCommands {
	var m servedCommands
	const sentinel = "/bodega-doctor/sentinel"
	env, err := distinfo.EnvironmentSpec{Files: map[string][]string{sentinel: {os.DevNull}}}.Load()
	if err != nil {
		return m
	}
	for _, st := range makeStatements(string(env.ClientCheck())) {
		a := makeAssign.FindStringSubmatch(st.text)
		if a == nil {
			continue
		}
		switch a[1] + a[2] {
		case "_BODEGA_DISTFILES_ENVIRON!=":
			m.env = a[3]
		case "_BODEGA_DISTFILES_CONF!=":
			m.conf = a[3]
		case "_BODEGA_DISTFILES_STABLE=":
			m.stable = a[3]
		case "_BODEGA_DISTFILES_READ:=":
			m.read = a[3]
		case "_BODEGA_DISTFILES_F0!=":
			m.measure = newPathTemplate(a[3], sentinel)
		case "_BODEGA_DISTFILES_W0!=":
			m.writers = newPathTemplate(a[3], sentinel)
		}
	}
	return m
})
