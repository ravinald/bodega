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
func CheckPkgRepos() Finding { return checkPkgRepos("", runtime.GOOS) }

func checkPkgRepos(root, goos string) Finding {
	f := Finding{Check: "pkg-repos"}
	if goos != "freebsd" {
		f.Status = StatusNA
		f.Detail = "pkg repositories are FreeBSD-only; check not applicable on this platform"
		return f
	}
	remediation := "bodega doctor --write-pkg-repo --url <bodega> writes " + pkgrepos.ClientConfPath + " with the bodega repository and the overrides that disable upstream; confirm with pkg -vv"
	repos, err := loadPkgRepos(root)
	var unmodeled pkgUnmodeled
	if errors.As(err, &unmodeled) {
		f.Status = StatusWarn
		f.Detail = unmodeled.Error() + ", so doctor cannot establish which repositories pkg reads"
		f.Remediation = "replace it with plain repository objects; " + remediation
		return f
	}
	if err != nil {
		f.Status = StatusSkip
		f.Detail = err.Error()
		f.Remediation = "run doctor as a user that can read /etc/pkg and " + pkgrepos.ClientReposDir + ", or fix the file pkg would also fail to parse"
		return f
	}

	var upstream, bodega []string
	for _, r := range repos {
		if !r.Enabled {
			continue
		}
		// A base tag redefined with a bodega URL is a bodega repository:
		// the URL decides where pkg fetches from, not the name.
		switch {
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
	if len(bodega) == 0 {
		problems = append(problems, "no enabled repository points at a bodega /freebsd/ URL")
	}
	if len(problems) > 0 {
		f.Status = StatusWarn
		f.Detail = strings.Join(problems, "; ")
		f.Remediation = remediation
		return f
	}
	f.Status = StatusOK
	f.Detail = "pkg reads only bodega repositories: " + strings.Join(bodega, ", ")
	return f
}

// pkgUnmodeled is a repository file doctor cannot read the way pkg does: a
// UCL directive it does not evaluate, or an include pkg itself would reject.
// Either leaves the loaded repositories unknown, which is not a clean host.
type pkgUnmodeled struct{ msg string }

func (e pkgUnmodeled) Error() string { return e.msg }

// uclIncludeDepth bounds include nesting, so a file including itself is
// reported instead of recursing.
const uclIncludeDepth = 16

// loadPkgRepos reads every *.conf under pkgReposDirs and merges the
// repositories the way pkg 2.8 does, measured with pkg -vv on 15.1:
// directories in order, files within one in lexical order, and each later
// file's keys replacing earlier ones per repository name, compared
// case-sensitively. Within one file and the files it includes, libucl keeps
// the first object of a name and drops later ones. A missing directory is
// nothing to read; an unreadable or unparseable file is an error, because the
// repositories in it are exactly the ones in question.
func loadPkgRepos(root string) ([]pkgRepo, error) {
	byName := map[string]*pkgRepo{}
	var order []string
	for _, dir := range pkgReposDirs {
		full := filepath.Join(root, dir)
		entries, err := os.ReadDir(full)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", dir, err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			objs, err := readUCLFile(root, filepath.Join(dir, n), nil)
			if err != nil {
				return nil, err
			}
			seen := map[string]bool{}
			for _, o := range objs {
				if seen[o.name] {
					continue
				}
				seen[o.name] = true
				r, ok := byName[o.name]
				if !ok {
					r = &pkgRepo{Name: o.name, Enabled: true}
					byName[o.name] = r
					order = append(order, o.name)
				}
				if dir == "/etc/pkg" {
					r.Base = true
				}
				r.From = o.from
				// pkg matches key names case-insensitively, in the order
				// libucl kept them, so a later spelling wins.
				for _, kv := range o.keys {
					switch strings.ToLower(kv.key) {
					case "url":
						r.URL = kv.val.s
					case "enabled":
						r.Enabled = kv.val.enables()
					}
				}
			}
		}
	}
	out := make([]pkgRepo, 0, len(order))
	for _, n := range order {
		out = append(out, *byName[n])
	}
	return out, nil
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

// uclScalar is a scalar as written, keeping whether it was quoted: libucl
// types an unquoted yes as a boolean and a quoted "yes" as a string, and pkg
// treats the two differently.
type uclScalar struct {
	s      string
	quoted bool
}

// enables reports how pkg reads a present enabled key. Measured on pkg 2.8.4:
// only an unquoted yes, true or on in any case enables; no, false, off, every
// number (1 included), and every quoted or other bare string disables.
func (v uclScalar) enables() bool {
	if v.quoted {
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

// uclObject is one top-level object in a pkg repository file. keys holds
// each key spelling once, first value kept, in the order libucl stores them.
// Nested values are kept as empty scalars: no key doctor reads is one.
type uclObject struct {
	name string
	keys []uclKV
	from string
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

// value returns a scalar, or an empty one after passing a nested object or
// array.
func (p *uclParser) value() (uclScalar, error) {
	switch c := p.peek(); c {
	case '"', '\'':
		s, err := p.quoted()
		return uclScalar{s: s, quoted: true}, err
	case '{', '[':
		return uclScalar{quoted: true}, p.nested()
	case 0:
		return uclScalar{}, fmt.Errorf("line %d: expected a value, found end of file", p.line())
	}
	start := p.pos
	for !p.eof() && !strings.ContainsRune(" \t\r\n,;}]#", rune(p.peek())) {
		p.pos++
	}
	return uclScalar{s: p.src[start:p.pos]}, nil
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

var (
	makeAssign    = regexp.MustCompile(`^([^\s:?!+=]+)\s*([:?!+]?=)\s*(.*)$`)
	makeDirective = regexp.MustCompile(`^\.\s*([a-z-]+)\s*(.*)$`)
	definesEnv    = regexp.MustCompile(`(?m)^\s*` + distfilesEnvVar + `\s*[:?!+]?=`)
)

// CheckMakeConf reports whether ports on this FreeBSD host fetch distfiles
// through bodega, comparing make.conf with what clientconf.MakeConf renders.
func CheckMakeConf() Finding { return checkMakeConf("", runtime.GOOS, os.Getenv) }

func checkMakeConf(root, goos string, getenv func(string) string) Finding {
	f := Finding{Check: "make-conf"}
	if goos != "freebsd" {
		f.Status = StatusNA
		f.Detail = "make.conf is read by FreeBSD's ports framework; check not applicable on this platform"
		return f
	}
	// sys.mk reads ${__MAKE_CONF} in place of /etc/make.conf when it is set,
	// so the one it names is the only one make reads.
	path, shown := "/etc/make.conf", "/etc/make.conf"
	if env := getenv("__MAKE_CONF"); env != "" {
		path, shown = env, env+" (named by __MAKE_CONF)"
	}
	names, route := makeConfSites()
	f.Remediation = "end " + shown + " with the FreeBSD ports lines under Client configuration in docs/usage.md: " +
		strings.Join(names, " and ") + " set to <bodega>" + route + ", then .include of " + clientconf.DistfilesCheckPath
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

	w := &makeWalk{root: root, sites: map[string]*siteValue{}}
	for _, n := range names {
		w.sites[n] = &siteValue{}
	}
	stmts := makeStatements(string(data))
	if err := w.file(path, stmts, false, nil); err != nil {
		f.Status = StatusSkip
		f.Detail = err.Error()
		f.Remediation = "run doctor as a user that can read " + path + " and every file it includes"
		return f
	}

	failed := append([]string(nil), w.problems...)
	for _, n := range names {
		v := w.sites[n]
		switch {
		case v.unknown != "":
			failed = append(failed, n+" cannot be established: "+v.unknown)
		case !v.set:
			failed = append(failed, n+" is not set")
		case !sitesAt(v.val, route):
			failed = append(failed, n+"="+v.val+" (set in "+v.from+") does not end every site in "+route)
		}
	}
	if msg := checkInclude(root, path, stmts); msg != "" {
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

// siteValue is what doctor knows of one site variable at a point in the
// read. unknown, when set, says why the value cannot be established, and a
// plain assignment later clears it; sticky keeps it, for a variable a line
// doctor does not evaluate may have pinned.
type siteValue struct {
	val, from string
	set       bool
	unknown   string
	sticky    bool
}

func (v *siteValue) undetermined(why string) {
	if v.unknown == "" || !v.sticky {
		v.unknown = why
	}
}

// makeWalk follows make.conf the way make reads it: statement by statement,
// into each include at its position, through conditionals. It never runs a
// shell assignment or expands a variable. A conditional whose test is not an
// integer literal, and every .for body, is a branch of unknown state: an
// assignment to a site variable inside one leaves that variable undetermined
// rather than taken or skipped.
type makeWalk struct {
	root     string
	sites    map[string]*siteValue
	problems []string
}

// makeIncludeDepth bounds include nesting, so a file including itself is
// reported instead of recursing.
const makeIncludeDepth = 16

var makeIntCond = regexp.MustCompile(`^\d+$`)

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
				final := len(stack) == 1 && i == len(stmts)-1
				if err := w.include(path, dir, arg, active == -1, !final, stack); err != nil {
					return err
				}
			case "undef":
				for _, n := range strings.Fields(arg) {
					if v := w.sites[n]; v != nil {
						if active == -1 {
							v.undetermined(".undef under a conditional doctor does not evaluate in " + path)
						} else if v.unknown == "" || !v.sticky {
							*v = siteValue{}
						}
					}
				}
			case "export", "export-env", "export-literal", "unexport", "unexport-env", "info", "warning", "error":
			default:
				w.touch(st, "."+dir+" in "+path+" is a directive doctor does not evaluate")
			}
			continue
		}
		if active == 0 {
			continue
		}

		m := makeAssign.FindStringSubmatch(st)
		if m == nil {
			// A dependency line: .READONLY, .MAKEFLAGS and .NOREADONLY can pin
			// or release a variable for every line after them.
			w.touch(st, "a line in "+path+" doctor does not evaluate names it: "+st)
			continue
		}
		name, op, val := m[1], m[2], m[3]
		if strings.Contains(name, "$") {
			for _, v := range w.sites {
				v.undetermined(path + " assigns the computed name " + name + ", which doctor does not expand")
			}
			continue
		}
		v := w.sites[name]
		if v == nil {
			continue
		}
		if v.sticky {
			continue
		}
		if active == -1 {
			v.undetermined("assigned under a conditional or loop doctor does not evaluate in " + path)
			continue
		}
		switch op {
		case "?=":
			if v.unknown != "" {
				continue
			}
			if !v.set {
				*v = siteValue{val: val, from: path, set: true}
			}
		case "+=":
			if v.unknown != "" {
				continue
			}
			if v.set {
				val = v.val + " " + val
			}
			*v = siteValue{val: val, from: path, set: true}
		case "!=":
			v.undetermined("set in " + path + " from a shell command doctor does not run")
		case ":=", "::=":
			if strings.Contains(val, "$") {
				v.undetermined("set in " + path + " with :=, which expands variables doctor does not")
				continue
			}
			*v = siteValue{val: val, from: path, set: true}
		default:
			*v = siteValue{val: val, from: path, set: true}
		}
	}
	if len(frames) > 0 {
		w.problems = append(w.problems, path+" ends with a conditional or loop still open, which make refuses")
	}
	return nil
}

// touch marks every site variable a line names as undetermined for the rest
// of the read: a line doctor does not evaluate may have pinned it.
func (w *makeWalk) touch(line, why string) {
	words := strings.FieldsFunc(line, func(r rune) bool {
		return !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	for n, v := range w.sites {
		if slices.Contains(words, n) {
			v.undetermined(why)
			v.sticky = true
		}
	}
}

// include follows one include directive. A path doctor cannot resolve
// leaves every site variable undetermined, since the file could assign any
// of them. A missing file is a problem for .include, which make treats as
// fatal, and nothing for the soft forms or a branch make may not take.
func (w *makeWalk) include(from, dir, arg string, unknown, report bool, stack []string) error {
	inc, why := makeIncludePath(from, arg)
	if why != "" {
		for _, v := range w.sites {
			v.undetermined(from + " includes " + why)
		}
		return nil
	}
	for _, s := range stack {
		if s == inc {
			for _, v := range w.sites {
				v.undetermined(from + " includes " + inc + ", which is already being read")
			}
			return nil
		}
	}
	if len(stack) >= makeIncludeDepth {
		for _, v := range w.sites {
			v.undetermined(from + " includes " + inc + " past " + fmt.Sprint(makeIncludeDepth) + " levels of nesting")
		}
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

// sitesAt reports whether every site in a make value ends with route. One
// site that does not is a fallback do-fetch.sh will try.
func sitesAt(v, route string) bool {
	sites := strings.Fields(v)
	if len(sites) == 0 {
		return false
	}
	for _, s := range sites {
		if !strings.HasSuffix(s, route) {
			return false
		}
	}
	return true
}

// checkInclude inspects the last statement of make.conf. It returns the
// failed condition, or "" when the last statement includes a file defining
// distfilesEnvVar. The file is recognized by what it defines rather than
// where it lives, since the check is delivered both as a copy and from a
// distfiles mount. makeWalk has already read it, so an unreadable one has
// already been reported.
func checkInclude(root, confPath string, stmts []string) string {
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
	data, err := os.ReadFile(filepath.Join(root, inc))
	if errors.Is(err, fs.ErrNotExist) {
		return "the last line includes " + inc + ", which does not exist"
	}
	if err != nil || !definesEnv.Match(data) {
		return "the last line includes " + inc + ", which does not define " + distfilesEnvVar + " and so is not the client check"
	}
	return ""
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
