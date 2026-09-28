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
	repos, err := loadPkgRepos(root)
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
		f.Remediation = "bodega doctor --write-pkg-repo --url <bodega> writes " + pkgrepos.ClientConfPath + " with the bodega repository and the overrides that disable upstream; confirm with pkg -vv"
		return f
	}
	f.Status = StatusOK
	f.Detail = "pkg reads only bodega repositories: " + strings.Join(bodega, ", ")
	return f
}

// loadPkgRepos reads every *.conf under pkgReposDirs and merges the
// repositories the way pkg does: directories in order, files within one in
// lexical order, later keys replacing earlier ones per repository. A missing
// directory is nothing to read; an unreadable or unparseable file is an
// error, because the repositories in it are exactly the ones in question.
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
			shown := filepath.Join(dir, n)
			data, err := os.ReadFile(filepath.Join(full, n))
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", shown, err)
			}
			objs, err := parseUCLObjects(string(data))
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", shown, err)
			}
			for _, o := range objs {
				r, ok := byName[o.name]
				if !ok {
					r = &pkgRepo{Name: o.name, Enabled: true}
					byName[o.name] = r
					order = append(order, o.name)
				}
				if dir == "/etc/pkg" {
					r.Base = true
				}
				r.From = shown
				if v, ok := o.keys["url"]; ok {
					r.URL = v
				}
				if v, ok := o.keys["enabled"]; ok {
					r.Enabled = uclTrue(v)
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

// uclTrue reads a UCL boolean. Anything that is not a recognized false reads
// as enabled, since pkg's default for a repository is enabled and a value
// doctor misreads should cost a warning rather than an OK.
func uclTrue(v string) bool {
	switch strings.ToLower(v) {
	case "no", "false", "off":
		return false
	}
	return true
}

// uclObject is one top-level object in a pkg repository file, with its
// scalar keys lowercased. Nested values are skipped: no key doctor reads is
// one.
type uclObject struct {
	name string
	keys map[string]string
}

// parseUCLObjects reads the subset of UCL pkg repository files are written
// in: top-level "name: { key: value, ... }" objects, with #, // and /* */
// comments, quoted or bare scalars, ':' or '=' or nothing between key and
// value, and ',' or ';' between pairs.
func parseUCLObjects(src string) ([]uclObject, error) {
	p := &uclParser{src: src}
	var out []uclObject
	for {
		p.skip()
		if p.eof() {
			return out, nil
		}
		name, err := p.key()
		if err != nil {
			return nil, err
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
		o := uclObject{name: name, keys: map[string]string{}}
		for {
			p.skip()
			if p.eof() {
				return nil, fmt.Errorf("object %q is not closed", name)
			}
			if p.peek() == '}' {
				p.pos++
				break
			}
			k, err := p.key()
			if err != nil {
				return nil, err
			}
			p.sep()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			o.keys[strings.ToLower(k)] = v
			p.term()
		}
		p.term()
		out = append(out, o)
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

// value returns a scalar, or "" after passing a nested object or array.
func (p *uclParser) value() (string, error) {
	switch c := p.peek(); c {
	case '"', '\'':
		return p.quoted()
	case '{', '[':
		return "", p.nested()
	case 0:
		return "", fmt.Errorf("line %d: expected a value, found end of file", p.line())
	}
	start := p.pos
	for !p.eof() && !strings.ContainsRune(" \t\r\n,;}]#", rune(p.peek())) {
		p.pos++
	}
	return p.src[start:p.pos], nil
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

	stmts := makeStatements(string(data))
	vals := map[string]*string{}
	for _, s := range stmts {
		m := makeAssign.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		name, op, v := m[1], m[2], m[3]
		cur := vals[name]
		switch op {
		case "?=":
			if cur == nil {
				vals[name] = &v
			}
		case "+=":
			if cur != nil {
				v = *cur + " " + v
			}
			vals[name] = &v
		case "!=":
			// The shell command's output is unknowable here; treat it as
			// a value that is not bodega's route.
			unknown := "!" + v
			vals[name] = &unknown
		default:
			vals[name] = &v
		}
	}

	var failed []string
	for _, n := range names {
		v := vals[n]
		switch {
		case v == nil:
			failed = append(failed, n+" is not set")
		case !sitesAt(*v, route):
			failed = append(failed, n+"="+*v+" does not end every site in "+route)
		}
	}
	if msg, skip := checkInclude(root, path, stmts); skip {
		f.Status = StatusSkip
		f.Detail = msg
		f.Remediation = "run doctor as a user that can read the file " + path + " includes"
		return f
	} else if msg != "" {
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
// distfilesEnvVar; skip is set when that file exists and cannot be read.
func checkInclude(root, confPath string, stmts []string) (msg string, skip bool) {
	if len(stmts) == 0 {
		return "the file is empty, so it includes no client check", false
	}
	last := stmts[len(stmts)-1]
	m := makeDirective.FindStringSubmatch(last)
	if m == nil || (m[1] != "include" && m[1] != "sinclude" && m[1] != "-include") {
		return "the last line is " + last + ", not an .include of the client check", false
	}
	arg := strings.TrimSpace(m[2])
	if len(arg) < 2 || !((arg[0] == '"' && arg[len(arg)-1] == '"') || (arg[0] == '<' && arg[len(arg)-1] == '>')) {
		return "the last line includes " + arg + ", which is not a quoted path", false
	}
	inc := arg[1 : len(arg)-1]
	if strings.Contains(inc, "$") {
		return "the last line includes " + inc + ", whose variables doctor does not expand", false
	}
	switch {
	case filepath.IsAbs(inc):
	case arg[0] == '<':
		inc = filepath.Join("/usr/share/mk", inc)
	default:
		inc = filepath.Join(filepath.Dir(confPath), inc)
	}
	data, err := os.ReadFile(filepath.Join(root, inc))
	if errors.Is(err, fs.ErrNotExist) {
		return "the last line includes " + inc + ", which does not exist", false
	}
	if err != nil {
		return "read " + inc + ", which " + confPath + " includes last: " + err.Error(), true
	}
	if !definesEnv.Match(data) {
		return "the last line includes " + inc + ", which does not define " + distfilesEnvVar + " and so is not the client check", false
	}
	return "", false
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
