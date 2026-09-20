package builder

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// hasInstallableRequirements reports whether the generated requirements file
// contains any line pip would treat as an install target. Blank lines, comment
// lines and options are not targets: counting one builds a venv, runs pip
// wheel over a file naming nothing, and produces zero wheels without an error
// anywhere.
//
// A leading dash is never a target here because the generated file includes no
// other file. An application's requirements arrive inlined, so an install
// target it names is present as its own line rather than behind an `-r`, and
// the only option carrying a path is the `-c` naming the generated constraint
// file, which by definition requests no installs.
func hasInstallableRequirements(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		return true, nil
	}
	return false, scanner.Err()
}

// pypiWheelsDir returns the local wheels directory.
func pypiWheelsDir(d dirs) string {
	return d.wheels
}

// pypiPipPassthrough are the variables the build environment carries through.
// Everything else is dropped, PIP_* above all: pip reads those as
// configuration at a precedence above the requirements file, so a
// PIP_INDEX_URL in the environment bodega was started with moves acquisition
// without appearing in any file a requirements reader could examine.
//
// https://pip.pypa.io/en/stable/topics/configuration/
var pypiPipPassthrough = []string{
	"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "no_proxy",
}

// pypiPipEnv is the environment every pip invocation in a build runs under.
func pypiPipEnv() []string {
	env := []string{"PIP_CONFIG_FILE=" + os.DevNull}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains(pypiPipPassthrough, name) {
			env = append(env, kv)
		}
	}
	return env
}

// pypiSelectedIndex reads the index out of the generated requirements file.
//
// The build takes the index from the file the fetch wrote rather than from the
// manifest, so an entry edited between the two stages cannot leave pip pointed
// somewhere the resolution never read.
func pypiSelectedIndex(reqPath string) (string, error) {
	data, err := os.ReadFile(reqPath)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "--index-url "); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("%s names no --index-url — re-run 'fetch pypi'", reqPath)
}

// defaultPypiIndex is the index a pypi entry resolves against when it names no
// URL of its own.
const defaultPypiIndex = "https://pypi.org"

// pypiOfferedMax caps how many versions an unresolvable-version error prints.
// A popular distribution offers hundreds, and an error nobody can read at 03:00
// is not a better error than a vague one.
const pypiOfferedMax = 5

// resolvePypiVersion returns the concrete version an entry resolves to, read
// off the index that will serve it. The empty string means the entry names no
// version, so the caller writes a bare requirement and lets pip resolve it
// inside the closure the base requirements already constrain.
//
// Resolution happens here rather than being left to pip because the manifest is
// the record of what was approved: an unpinned requirement line let pip take
// whatever was newest, and a 1.16.0 entry produced a 1.17.0 wheel with nothing
// reporting the substitution.
func resolvePypiVersion(root, name string, ve manifest.VersionEntry) (string, error) {
	want := strings.TrimSpace(ve.Version)
	if want == "" || want == "*" {
		return "", nil
	}

	available, err := pypiVersionsAt(root, name)
	if err != nil {
		return "", fmt.Errorf("pypi %s: reading %s to resolve %s: %w", name, root, want, err)
	}

	constraint := ve.VersionConstraint
	if constraint == "" {
		constraint = manifest.ConstraintExact
	}

	// Literal match before the PEP 440 filter, for the legacy versions that
	// predate the scheme: pytz shipped "2011k", which no parser will order but
	// an index plainly offers and an entry may plainly name.
	if constraint == manifest.ConstraintExact {
		for _, v := range available {
			if v == want {
				return v, nil
			}
		}
	}
	if matches := FilterPypiVersions(available, constraint, want); len(matches) > 0 {
		return matches[len(matches)-1], nil
	}

	return "", fmt.Errorf("pypi %s: version_constraint %q on %s resolves to nothing; the index at %s offers %s",
		name, constraint, want, root, pypiOffered(available))
}

// pypiIndexRoot returns the one index every pypi entry resolves and downloads
// against, read from the `url` of whichever entries name one.
//
// One index for the whole type rather than one per entry: a fetch writes a
// single requirements file and pip honors one --index-url across all of it, so
// resolving each entry against its own origin and then downloading everything
// from pip's default is how a version gets approved on one index and fetched
// from another. Two entries naming different origins is a configuration this
// shape cannot satisfy, so it fails rather than picking a winner.
func pypiIndexRoot(ctx context.Context, store *manifest.Store) (string, error) {
	named := make(map[string][]string)
	for _, name := range store.ListPackages(manifest.TypePypi) {
		pm, err := store.GetPackage(ctx, manifest.TypePypi, name)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			if root := strings.TrimRight(strings.TrimSpace(ve.URL), "/"); root != "" {
				named[root] = append(named[root], name)
			}
		}
	}
	switch len(named) {
	case 0:
		return defaultPypiIndex, nil
	case 1:
		for root := range named {
			return root, nil
		}
	}
	roots := make([]string, 0, len(named))
	for root, pkgs := range named {
		roots = append(roots, fmt.Sprintf("%s (%s)", root, strings.Join(pkgs, ", ")))
	}
	sort.Strings(roots)
	return "", fmt.Errorf("pypi entries name %d different indexes and one fetch can use one: %s",
		len(named), strings.Join(roots, "; "))
}

// pypiIndexLine renders the pip option that points the wheel build at the same
// index the resolution read.
//
// The default index is written out like any other. Leaving it unsaid used to
// let a deployment point pip at its own mirror through pip.conf, but the build
// now runs with that configuration switched off, so an unsaid default is no
// longer a passthrough: it is an index nothing states and nothing enforces. A
// deployment with a mirror names it on the manifest entry.
func pypiIndexLine(root string) string {
	return "--index-url " + pypiIndexURL(root) + "\n"
}

// pypiIndexURL is the simple-index URL pip is pointed at for an index root.
func pypiIndexURL(root string) string {
	return strings.TrimRight(root, "/") + "/simple/"
}

// pypiReader flattens an application's requirements files into lines bodega
// writes itself.
//
// Checking a file and then telling pip to read that same file leaves two
// parsers over one set of bytes, and every difference between them is an
// acquisition instruction the resolver approved one index against and pip
// carried out against another. So the reader emits what it read: the generated
// file holds the logical lines this parsed, includes resolved in place, and
// pip never opens an application's file at all. A construct this cannot read
// still fails the fetch, but a construct it reads wrongly now produces a wrong
// requirement rather than a silent change of origin.
//
// Rejecting rather than rewriting an origin: the file belongs to the
// application, and editing one out hides the disagreement instead of settling
// it.
type pypiReader struct {
	indexRoot string
	// requirements and constraints are kept apart because a constraint
	// restricts a version without requesting the package. Flattening the two
	// together installs whatever an application only meant to bound.
	requirements []string
	constraints  []string
}

func (r *pypiReader) read(path string, constraint bool, seen map[string]bool) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if seen[abs] {
		return nil
	}
	seen[abs] = true

	data, err := pypiRequirementBytes(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	lines, err := pypiLogicalLines(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, line := range lines {
		inc, err := pypiLineSource(path, r.indexRoot, line.text)
		if err != nil {
			return err
		}
		if inc.path == "" {
			if constraint {
				r.constraints = append(r.constraints, line.text)
			} else {
				r.requirements = append(r.requirements, line.text)
			}
			continue
		}
		next := inc.path
		if !filepath.IsAbs(next) {
			next = filepath.Join(filepath.Dir(path), next)
		}
		// A constraint file's includes stay constraints however deep they go.
		if err := r.read(next, constraint || inc.constraint, seen); err != nil {
			return fmt.Errorf("%s line %d includes %s: %w", path, line.n, inc.path, err)
		}
		if inc.unusable != "" {
			return fmt.Errorf("%s line %d %s", path, line.n, inc.unusable)
		}
	}
	return nil
}

// pypiInclude names a file one logical line pulls in, and whether its contents
// are constraints rather than requirements.
//
// unusable carries why the include cannot be reproduced, when it cannot. The
// reader still follows the file before reporting it: an origin named inside is
// the more useful thing to say, and saying the shape is wrong first would hide
// it behind a lesser diagnosis.
type pypiInclude struct {
	path       string
	constraint bool
	unusable   string
}

// pypiLine is one logical line and the physical line it starts on, so a
// rejection can say where to go and not just what is wrong.
type pypiLine struct {
	n    int
	text string
}

// pypiBOMs are the byte-order marks pip decodes a requirements file by, in
// pip's own order: BOM_UTF16_LE is a prefix of BOM_UTF32_LE, so the longer one
// has to be tested first.
var pypiBOMs = []struct {
	bytes    string
	encoding string
}{
	{"\xef\xbb\xbf", "utf-8"},
	{"\xff\xfe\x00\x00", "utf-32-le"},
	{"\x00\x00\xfe\xff", "utf-32-be"},
	{"\xff\xfe", "utf-16-le"},
	{"\xfe\xff", "utf-16-be"},
}

// pypiCodingRe matches a PEP 263 encoding declaration, the way pip does.
var pypiCodingRe = regexp.MustCompile(`coding[:=]\s*([-\w.]+)`)

// pypiEnvVarRe matches the one environment-variable form pip expands.
var pypiEnvVarRe = regexp.MustCompile(`\$\{[A-Z0-9_]+\}`)

// pypiUTF8Aliases are the encoding names a PEP 263 declaration may carry
// without changing what the bytes mean. ASCII is here because it is a subset:
// a file that decodes as ASCII decodes identically as UTF-8, and one that does
// not makes pip fail loudly rather than read something else.
var pypiUTF8Aliases = map[string]bool{
	"utf-8": true, "utf8": true, "utf_8": true, "u8": true, "utf": true,
	"ascii": true, "us-ascii": true, "usascii": true, "ansi_x3.4-1968": true,
}

// pypiLineBreaks are the separators Python's str.splitlines splits on beyond
// \n and \r\n. pip calls splitlines on the decoded file, so every one of these
// starts a line for pip that a reader splitting on \n never sees at all.
var pypiLineBreaks = []struct{ seq, name string }{
	{"\v", `\v`}, {"\f", `\f`}, {"\x1c", `\x1c`}, {"\x1d", `\x1d`},
	{"\x1e", `\x1e`}, {"\u0085", `\u0085`}, {"\u2028", `\u2028`}, {"\u2029", `\u2029`},
}

// pypiRequirementBytes reads a requirements file and refuses the encodings pip
// would decode differently from the bytes on disk.
//
// pip decodes the whole file before it reads a line of it: a byte-order mark,
// or a `# -*- coding: ... -*-` comment in the first two lines, selects the
// codec for everything after. A reader working on raw bytes and a pip decoding
// UTF-16 do not disagree about one option, they disagree about every byte, and
// the UTF-16 spelling of `://` appears nowhere in those bytes, so no amount of
// token matching finds an index hidden in one.
//
// https://pip.pypa.io/en/stable/reference/requirements-file-format/#encoding
func pypiRequirementBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, bom := range pypiBOMs {
		if strings.HasPrefix(string(data), bom.bytes) {
			return nil, fmt.Errorf(
				"line 1 opens on a %s byte-order mark; pip decodes the whole file as %s and this reads it as UTF-8, so save it as UTF-8 without a mark",
				bom.encoding, bom.encoding)
		}
	}
	for n, line := range strings.SplitN(string(data), "\n", 3) {
		if n > 1 || !strings.HasPrefix(line, "#") {
			break
		}
		m := pypiCodingRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if !pypiUTF8Aliases[strings.ToLower(m[1])] {
			return nil, fmt.Errorf(
				"line %d declares coding %s, which pip decodes the whole file by and this reads as UTF-8; save it as UTF-8 and drop the declaration",
				n+1, m[1])
		}
	}
	if !utf8.Valid(data) {
		return nil, errors.New("holds bytes that are not UTF-8; pip falls back to the locale encoding and reads different text than this does, so save it as UTF-8")
	}
	return data, nil
}

// pypiLogicalLines returns the lines pip parses, not the lines the file holds.
//
// pip joins a line ending in a backslash onto the next one with no separator
// and strips comments afterward, so `--index-` and `url https://elsewhere/`
// on consecutive lines are one --index-url option by the time any of it is
// read. A checker working on physical lines sees two fragments, matches
// neither, and passes the origin through.
//
// Before any of that pip splits the decoded text with str.splitlines, which
// breaks on eight separators beyond \n and \r\n. Each one is a line pip reads
// and this does not, so they are refused here rather than reproduced: an
// application has no reason to separate requirements with a form feed, and
// matching Python's line-breaking table is a standing obligation rather than a
// fix.
func pypiLogicalLines(data []byte) ([]pypiLine, error) {
	text := string(data)
	for _, br := range pypiLineBreaks {
		if i := strings.Index(text, br.seq); i >= 0 {
			return nil, fmt.Errorf(
				"line %d holds a %s, which pip reads as the start of another line and this does not; separate lines with a newline",
				strings.Count(text[:i], "\n")+1, br.name)
		}
	}
	var (
		lines   []pypiLine
		pending []string
		start   int
	)
	flush := func(n int, line string) {
		if len(pending) > 0 {
			line = strings.Join(pending, "") + line
			pending = nil
			n = start
		}
		if line = strings.TrimSpace(pypiStripComment(line)); line != "" {
			lines = append(lines, pypiLine{n: n, text: line})
		}
	}
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		if cr := strings.IndexByte(line, '\r'); cr >= 0 {
			// A CR ends a line for pip wherever it sits. One at the end of a
			// physical line is an ordinary CRLF file; one anywhere else hides
			// every line after it inside what this reads as a single line.
			if cr != len(line)-1 {
				return nil, fmt.Errorf(
					"line %d holds a carriage return mid-line, which pip reads as the start of another line and this does not; separate lines with a newline",
					n)
			}
			line = line[:cr]
		}
		// A comment never continues, however it ends: pip tests the comment
		// first, so a trailing backslash inside one joins nothing, and the
		// space it inserts is what keeps the comment separable afterward.
		if comment := pypiCommentOnly(line); comment || !strings.HasSuffix(line, `\`) {
			if comment {
				line = " " + line
			}
			flush(n, line)
			continue
		}
		if len(pending) == 0 {
			start = n
		}
		pending = append(pending, strings.Trim(line, `\`))
	}
	if len(pending) > 0 {
		flush(0, "")
	}
	for _, line := range lines {
		if v := pypiEnvVarRe.FindString(line.text); v != "" {
			return nil, fmt.Errorf(
				"line %d expands %s, which pip replaces from its own environment and this cannot see; write the value, or name the index in the manifest",
				line.n, v)
		}
	}
	return lines, nil
}

// pypiStripComment drops a comment, which pip recognizes at the start of a line
// or after whitespace. A `#` with no space in front of it belongs to the token
// it sits in, as in --hash=sha256:....
func pypiStripComment(line string) string {
	for i := range len(line) {
		if line[i] != '#' {
			continue
		}
		if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
			return line[:i]
		}
	}
	return line
}

// pypiCommentOnly reports whether a line carries nothing but a comment.
func pypiCommentOnly(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

// pypiOptionClass says what an option does to the origin bytes arrive from.
type pypiOptionClass int

const (
	pypiOptionInert   pypiOptionClass = iota // decides nothing about the origin
	pypiOptionIndex                          // selects the index
	pypiOptionOrigin                         // adds or replaces an origin
	pypiOptionInclude                        // pulls in a file pip parses the same way
	pypiOptionDirect                         // names something pip downloads without an index
)

// pypiOption is one option pip accepts inside a requirements file.
type pypiOption struct {
	long  string
	short string
	value bool
	class pypiOptionClass
}

// pypiReqOptions is every option pip reads from a requirements file, classified
// by what it does to acquisition. The list is exhaustive on purpose: anything
// absent from it is refused rather than ignored, because optparse resolves an
// unambiguous prefix (`--index-u`) to its full option, so an origin can be
// named in spellings no list of exact tokens will ever match.
var pypiReqOptions = []pypiOption{
	{long: "--index-url", short: "-i", value: true, class: pypiOptionIndex},
	{long: "--extra-index-url", value: true, class: pypiOptionOrigin},
	{long: "--find-links", short: "-f", value: true, class: pypiOptionOrigin},
	{long: "--no-index", class: pypiOptionOrigin},
	{long: "--trusted-host", value: true, class: pypiOptionOrigin},
	{long: "--requirement", short: "-r", value: true, class: pypiOptionInclude},
	{long: "--constraint", short: "-c", value: true, class: pypiOptionInclude},
	{long: "--editable", short: "-e", value: true, class: pypiOptionDirect},
	{long: "--pre", class: pypiOptionInert},
	{long: "--prefer-binary", class: pypiOptionInert},
	{long: "--require-hashes", class: pypiOptionInert},
	{long: "--no-binary", value: true, class: pypiOptionInert},
	{long: "--only-binary", value: true, class: pypiOptionInert},
	{long: "--hash", value: true, class: pypiOptionInert},
	{long: "--config-settings", short: "-C", value: true, class: pypiOptionInert},
	{long: "--global-option", value: true, class: pypiOptionInert},
	{long: "--use-feature", value: true, class: pypiOptionInert},
}

// pypiLineSource checks one logical line for anything that decides where pip
// downloads from, and reports the file it pulls in when it pulls one in.
func pypiLineSource(path, indexRoot, line string) (pypiInclude, error) {
	var inc pypiInclude
	args, optionsText := breakPypiArgsOptions(line)
	for _, arg := range args {
		if u := pypiURLToken(arg); u != "" {
			return inc, fmt.Errorf("%s names %s, which pip downloads without asking the %s the manifest approved",
				path, u, indexRoot)
		}
	}
	opts, err := pypiShlex(optionsText)
	if err != nil {
		return inc, fmt.Errorf("%s: %s %w; pip splits options the same way and fails the file, so fix the quoting",
			path, optionsText, err)
	}

	// An include is reproduced by inlining the file it names, so it has to be
	// the only thing on its line: anything beside it would be dropped when the
	// line is replaced by what it pulled in.
	var beside string
	for i := 0; i < len(opts); i++ {
		// optparse discards a token that is not an option and keeps reading
		// the ones after it, so a stray value decides no origin.
		if !strings.HasPrefix(opts[i], "-") {
			continue
		}
		opt, value, attached, err := cutRequirementOption(opts[i])
		if err != nil {
			return inc, fmt.Errorf("%s: %w", path, err)
		}
		if opt.value && !attached && i+1 < len(opts) {
			i++
			value = opts[i]
		}

		if opt.class != pypiOptionInclude {
			beside = opt.long
		}

		switch opt.class {
		case pypiOptionIndex:
			if !sameIndexRoot(value, indexRoot) {
				return inc, fmt.Errorf("%s names %s %s and the manifest resolved against %s; one fetch downloads from one index",
					path, opt.long, value, indexRoot)
			}
		case pypiOptionOrigin:
			return inc, fmt.Errorf("%s names %s%s, which acquires outside the %s the manifest approved",
				path, opt.long, pypiValueSuffix(value), indexRoot)
		case pypiOptionDirect:
			if u := pypiURLToken(value); u != "" {
				return inc, fmt.Errorf("%s names %s %s, which pip downloads without asking the %s the manifest approved",
					path, opt.long, u, indexRoot)
			}
		case pypiOptionInclude:
			if value == "" {
				continue
			}
			// An include on a line that also names a requirement is one pip
			// ignores, because a requirement line's options are scoped to that
			// requirement. Inlining it would install what pip would not, and
			// dropping it would leave its origin unexamined.
			switch {
			case len(args) > 0:
				inc.unusable = fmt.Sprintf("names %s %s beside the requirement %s, which pip ignores; put the include on a line of its own",
					opt.long, value, strings.Join(args, " "))
			case inc.path != "":
				inc.unusable = fmt.Sprintf("names %s %s beside another include; put each on a line of its own",
					opt.long, value)
			}
			if inc.path == "" {
				inc.path, inc.constraint = value, opt.long == "--constraint"
			}
		case pypiOptionInert:
		}
	}
	if inc.path != "" && beside != "" && inc.unusable == "" {
		inc.unusable = fmt.Sprintf("names %s beside an include, which is dropped when the include is resolved; put each on a line of its own",
			beside)
	}
	return inc, nil
}

// breakPypiArgsOptions splits a logical line the way pip does: the tokens up to
// the first one starting with a dash are the requirement, the rest are the
// options string.
//
// The split is on a literal space rather than on whitespace, and the boundary
// is decided before any quote is removed, because that is what pip does. A
// leading `"-r"` is therefore part of the requirement to pip, not an include,
// and a tab never separates a requirement from an option.
func breakPypiArgsOptions(line string) (args []string, options string) {
	tokens := strings.Split(line, " ")
	for i, tok := range tokens {
		if strings.HasPrefix(tok, "-") {
			return tokens[:i], strings.Join(tokens[i:], " ")
		}
	}
	return tokens, ""
}

// pypiShlex splits an options string the way pip does, which is Python's
// shlex.split in POSIX mode: quotes are removed, a backslash escapes the next
// character, and inside double quotes it escapes only a quote or another
// backslash.
//
// Splitting on whitespace alone reads `--pre "--index-url" http://elsewhere/`
// as one inert option and two fragments that name no option at all, while pip
// reads an index option and downloads from it. Every concealment of that shape
// costs one quote or one backslash, so the tokenizer is the boundary, not the
// spellings it happens to produce.
//
// https://pip.pypa.io/en/stable/reference/requirements-file-format/
func pypiShlex(s string) ([]string, error) {
	const (
		whitespace = " \t\r\n"
		quotes     = `'"`
	)
	in := func(set string, c byte) bool { return strings.IndexByte(set, c) >= 0 }

	var (
		out     []string
		token   []byte
		quoted  bool
		state   byte = ' ' // ' ' or 'a' outside a quote, else the open quote or a backslash
		escaped byte = ' '
	)
	flush := func() {
		out = append(out, string(token))
		token, quoted = nil, false
	}

	for i := range len(s) {
		c := s[i]
		switch {
		case state == '\\':
			// Only a quote or the backslash itself is escapable inside a
			// quoted string; anything else keeps the backslash it followed.
			if in(quotes, escaped) && c != '\\' && c != escaped {
				token = append(token, '\\')
			}
			token = append(token, c)
			state = escaped
		case in(quotes, state):
			quoted = true
			switch {
			case c == state:
				state = 'a'
			case c == '\\' && state == '"':
				escaped, state = state, c
			default:
				token = append(token, c)
			}
		case in(whitespace, c):
			state = ' '
			if len(token) > 0 || quoted {
				flush()
			}
		case c == '\\':
			escaped, state = 'a', c
		case in(quotes, c):
			state = c
		default:
			token = append(token, c)
			state = 'a'
		}
	}

	switch {
	case in(quotes, state):
		return nil, fmt.Errorf("closes no %c quotation", state)
	case state == '\\':
		return nil, errors.New("ends on a backslash that escapes nothing")
	}
	if len(token) > 0 || quoted {
		flush()
	}
	return out, nil
}

// cutRequirementOption resolves one option token into the option pip reads and
// whatever value is attached to it.
//
// optparse accepts four spellings of the same option — `--index-url URL`,
// `--index-url=URL`, `-i URL` and `-iURL` — and any unambiguous prefix of a
// long name. Recognizing only the spaced spelling hands the other three to pip
// unread, and pip downloads from the index they name.
func cutRequirementOption(tok string) (opt pypiOption, value string, attached bool, err error) {
	if strings.HasPrefix(tok, "--") {
		name := tok
		if cut, inline, ok := strings.Cut(tok, "="); ok {
			name, value, attached = cut, inline, true
		}
		opt, err = matchPypiLongOption(name)
		if err != nil {
			return pypiOption{}, "", false, err
		}
		return opt, value, attached, nil
	}

	// Short options are never grouped here: every one pip reads from a
	// requirements file takes a value, so -iURL is a value, not two flags.
	name := tok
	if len(tok) > 2 {
		name, value, attached = tok[:2], tok[2:], true
	}
	for _, o := range pypiReqOptions {
		if o.short != "" && o.short == name {
			return o, value, attached, nil
		}
	}
	return pypiOption{}, "", false, unknownPypiOption(tok)
}

// matchPypiLongOption resolves a long option name, prefix included.
func matchPypiLongOption(name string) (pypiOption, error) {
	var hits []pypiOption
	for _, o := range pypiReqOptions {
		if o.long == name {
			return o, nil
		}
		if strings.HasPrefix(o.long, name) {
			hits = append(hits, o)
		}
	}
	switch len(hits) {
	case 0:
		return pypiOption{}, unknownPypiOption(name)
	case 1:
		return hits[0], nil
	}
	names := make([]string, 0, len(hits))
	for _, o := range hits {
		names = append(names, o.long)
	}
	return pypiOption{}, fmt.Errorf("%s abbreviates %s, and which one pip reads decides where it downloads from",
		name, strings.Join(names, " and "))
}

// unknownPypiOption reports an option this fetch cannot classify. Refusing
// rather than ignoring: an unread option is an option that may name an index,
// and the fetch cannot hold a pin it has already handed to pip.
func unknownPypiOption(tok string) error {
	return fmt.Errorf("names %s, which this fetch does not interpret; an option it cannot read may point pip at another origin", tok)
}

// pypiURLToken returns the URL a token names, if it names one. A requirement
// may carry its own download (`six @ https://host/six.whl`, a bare URL, a
// `git+ssh://` reference), which pip fetches without consulting any index.
func pypiURLToken(tok string) string {
	tok = strings.Trim(tok, `"'`)
	if strings.Contains(tok, "://") {
		return tok
	}
	return ""
}

// pypiValueSuffix renders an option's value for an error message, or nothing
// when the option takes none.
func pypiValueSuffix(value string) string {
	if value == "" {
		return ""
	}
	return " " + value
}

// sameIndexRoot reports whether a pip index option points at the index the
// manifest resolved against. The manifest records the root and pip is handed
// the PEP 503 path under it, so the two spellings have to compare equal.
func sameIndexRoot(value, root string) bool {
	norm := func(s string) string {
		s = strings.TrimRight(strings.TrimSpace(s), "/")
		return strings.TrimSuffix(s, "/simple")
	}
	return norm(value) == norm(root)
}

// pypiOffered renders an index's version list for an error message, newest last.
func pypiOffered(available []string) string {
	if len(available) == 0 {
		return "no versions at all"
	}
	if len(available) <= pypiOfferedMax {
		return strings.Join(available, ", ")
	}
	return fmt.Sprintf("%s (%d versions in all)",
		strings.Join(available[len(available)-pypiOfferedMax:], ", "), len(available))
}

// pypiRequirement renders one resolved entry as a pip requirement line.
//
// Arbitrary equality (===) rather than ==: PEP 440 version matching ignores a
// candidate's local label when the specifier carries none, so `six==1.16.0`
// against an index offering both 1.16.0 and 1.16.0+vendor.1 downloads the
// vendored build. Measured against pip 26.2.1. === compares the whole
// identity, so the version the resolver chose is the version pip stores.
//
// https://packaging.python.org/en/latest/specifications/version-specifiers/#version-matching
func pypiRequirement(name, resolved string) string {
	if resolved == "" {
		return name
	}
	if v, ok := ParsePyVersion(resolved); ok {
		return name + "===" + v.Canonical()
	}
	return name + "===" + resolved
}

// pypiPins reads back the exact pins a fetch wrote, keyed by normalized
// distribution name. Only the === lines are pins: the rest of the file is the
// applications' own requirements, whose closure is pip's to resolve.
func pypiPins(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	pins := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		name, version, ok := strings.Cut(line, "===")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		pins[manifest.CanonicalPypiName(strings.TrimSpace(name))] = strings.TrimSpace(version)
	}
	return pins, scanner.Err()
}

// parseWheelName splits a wheel filename into its distribution and version.
// The remaining tags decide which interpreter and platform the wheel is for,
// which is pip's business rather than the manifest's.
func parseWheelName(base string) (name, version string, ok bool) {
	// distribution-version(-build)?-python-abi-platform.whl, and neither the
	// distribution nor the version may carry a hyphen of its own.
	fields := strings.Split(strings.TrimSuffix(base, ".whl"), "-")
	if len(fields) < 5 {
		return "", "", false
	}
	return manifest.CanonicalPypiName(fields[0]), fields[1], true
}

// verifyPypiWheels fails when the wheels directory holds a pinned distribution
// at a version no pin names.
//
// A pin reaches pip as a specifier, and a specifier is a filter rather than a
// fact: an index that answers it with another build, a pip resolving it out of
// a cache, or a hand-edited requirements file all end with bytes on disk the
// manifest does not describe. The store is what gets published, so the store is
// what gets checked.
//
// A pin with no wheel at all passes here. pip exiting 0 having stored nothing
// for a requirement is a different defect, and failing it in this check would
// report it as a substituted version.
func verifyPypiWheels(reqPath, wheelsDir string) error {
	pins, err := pypiPins(reqPath)
	if err != nil {
		return fmt.Errorf("read the pins back from %s: %w", reqPath, err)
	}

	stored := make(map[string][]string)
	whlFiles, err := filepath.Glob(filepath.Join(wheelsDir, "*.whl"))
	if err != nil {
		return err
	}
	for _, whl := range whlFiles {
		if name, version, ok := parseWheelName(filepath.Base(whl)); ok {
			stored[name] = append(stored[name], version)
		}
	}

	for _, name := range sortedKeys(pins) {
		want := pins[name]
		have := stored[name]
		if len(have) == 0 || slices.ContainsFunc(have, func(got string) bool { return samePyVersion(got, want) }) {
			continue
		}
		return fmt.Errorf("pypi %s: the manifest names %s and the wheels directory holds %s — pip stored a version nobody approved",
			name, want, strings.Join(have, ", "))
	}
	return nil
}

// prunePypiWheels removes a pinned distribution's wheels at versions no pin
// names.
//
// pip writes into a flat --wheel-dir and removes nothing it did not just
// produce, so a re-pin from 1.17.0 to 1.16.0 leaves both wheels there:
// MANIFEST.sha256 attests both, the sync uploads both, and the simple index
// publishes both. verifyPypiWheels passes that directory, correctly — the
// pinned version is present — which is why this is a separate job rather than
// a stricter version of that check.
//
// An orphan already in object storage is not reached from here. Client.SyncDir
// is upload-only, so nothing a local prune does deletes the key a client
// resolves against.
func prunePypiWheels(out io.Writer, reqPath, wheelsDir string) error {
	pins, err := pypiPins(reqPath)
	if err != nil {
		return fmt.Errorf("read the pins back from %s: %w", reqPath, err)
	}
	if len(pins) == 0 {
		return nil
	}
	whlFiles, err := filepath.Glob(filepath.Join(wheelsDir, "*.whl"))
	if err != nil {
		return err
	}
	for _, whl := range whlFiles {
		name, version, ok := parseWheelName(filepath.Base(whl))
		if !ok {
			continue
		}
		want, pinned := pins[name]
		if !pinned || samePyVersion(version, want) {
			continue
		}
		if err := os.Remove(whl); err != nil {
			return fmt.Errorf("remove %s, which no manifest version names: %w", filepath.Base(whl), err)
		}
		_, _ = fmt.Fprintf(out, "    Removed %s: the manifest names %s at %s\n", filepath.Base(whl), name, want)
	}
	return nil
}

// reconcileWheelManifest reports whether MANIFEST.sha256 and the wheels on disk
// are the same set at the same digests.
//
// Bidirectional, on the same terms as verifyPypiClosure: a line naming a wheel
// that is gone attests bytes nobody holds, and a wheel with no line ships
// unattested. Either way the file is stale and the package stage has to write
// it again, which its existence cannot report.
func reconcileWheelManifest(wheelsDir, manifestPath string) error {
	recorded, err := readWheelManifest(manifestPath)
	if err != nil {
		return err
	}
	whlFiles, err := filepath.Glob(filepath.Join(wheelsDir, "*.whl"))
	if err != nil {
		return err
	}

	seen := make(map[string]bool, len(recorded))
	for _, whl := range whlFiles {
		base := filepath.Base(whl)
		want, ok := recorded[base]
		if !ok {
			return fmt.Errorf("pypi: %s holds %s, which %s attests nothing for",
				wheelsDir, base, filepath.Base(manifestPath))
		}
		got, err := computeFileSHA256(whl)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("pypi: %s no longer matches the digest in %s: recorded=%s on disk=%s",
				base, filepath.Base(manifestPath), want, got)
		}
		seen[base] = true
	}
	missing := make([]string, 0, len(recorded))
	for base := range recorded {
		if !seen[base] {
			missing = append(missing, base)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("pypi: %s attests %s and %s holds no such file",
			filepath.Base(manifestPath), strings.Join(missing, ", "), wheelsDir)
	}
	return nil
}

// readWheelManifest parses the "<sha256>  <filename>" lines generateWheelManifest
// writes, keyed by filename.
func readWheelManifest(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the build root's own
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	recorded := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		digest, name, ok := strings.Cut(line, "  ")
		if !ok {
			return nil, fmt.Errorf("%s: %q is not a checksum line", filepath.Base(path), line)
		}
		recorded[strings.TrimSpace(name)] = strings.TrimSpace(digest)
	}
	return recorded, scanner.Err()
}

// samePyVersion compares two version strings under PEP 440, falling back to
// string equality for the legacy versions no parser will read.
func samePyVersion(a, b string) bool {
	av, aOK := ParsePyVersion(a)
	bv, bOK := ParsePyVersion(b)
	if aOK && bOK {
		return av.Equal(bv)
	}
	return a == b
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isFile reports whether path exists and is a regular file.
func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// CheckPypiStage inspects the filesystem to determine which pipeline stages
// have completed for the pypi packages.
func CheckPypiStage(cfg *Config, store *manifest.Store) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypePypi))
	var s StageStatus

	// Fetched = the requirements and the closure they resolved to both exist.
	// The build reads the lock, so a run that wrote only the requirements has
	// nothing for the next stage and must not be reported as done.
	root := cfg.rootFor(manifest.TypePypi)
	s.Fetched = isFile(filepath.Join(root, "combined-requirements.txt")) && isFile(pypiLockPath(root))

	if s.Fetched {
		// Built = at least one .whl file in the wheels dir.
		wheelsDir := pypiWheelsDir(d)
		whlFiles, _ := filepath.Glob(filepath.Join(wheelsDir, "*.whl"))
		s.Built = len(whlFiles) > 0

		if s.Built {
			// Packaged = MANIFEST.sha256 reconciles with the wheels on disk.
			//
			// Its existence answers a different question. The build prunes a
			// wheel a re-pin orphaned and pip writes the replacement beside
			// it, so a file left by an earlier run attests a set that is no
			// longer there — and the run that changed the set would skip the
			// stage that would have corrected it. CheckGitStage opens its
			// bundle for the same reason.
			manifestFile := filepath.Join(wheelsDir, "MANIFEST.sha256")
			s.Packaged = reconcileWheelManifest(wheelsDir, manifestFile) == nil
		}
	}

	return s
}

// PypiArtifactDir returns the local wheels directory and S3 prefix for the
// pypi packages. Used by the upload and sync commands.
func PypiArtifactDir(cfg *Config, store *manifest.Store) (localDir, s3Prefix string) {
	return ArtifactDir(cfg, manifest.TypePypi), manifest.PypiWheelPrefix
}

// FetchPypi resolves requirements from previously-cloned git repos and from
// the extra packages listed in the pypi manifests, writes
// <build-root>/combined-requirements.txt, then downloads the closure that file
// resolves to into <build-root>/wheelhouse/ and records a SHA-256 per file in
// <build-root>/resolved-requirements.txt and the audit cache.
//
// The caller must ensure that any git repos referenced by base-requirement
// entries have been fetched before calling FetchPypi.
//
// Base requirements are tracked via RequiredBy on individual pypi VersionEntry
// records: when a VersionEntry has RequiredBy set, those git repos are treated
// as base apps and their requirements.txt files are included.
func FetchPypi(cfg *Config, store *manifest.Store) *Summary {
	summary := fetchPypi(cfg, store)
	if !summary.HasFailures() {
		return summary
	}

	// A fetch that failed must leave no resolved state behind. CheckPypiStage
	// reads the file's existence as "fetch is done" and the pipeline then skips
	// the retry, so a previous run's file outlives the pin it was resolved
	// from: edit a version, watch the re-fetch fail, and `build run pypi` still
	// stores the closure of the version nobody approved any more.
	root := cfg.rootFor(manifest.TypePypi)
	combinedReq := filepath.Join(root, "combined-requirements.txt")
	if err := os.Remove(combinedReq); err == nil {
		_, _ = fmt.Fprintf(cfg.stdout(), "    Discarded %s: it no longer describes the manifest\n", combinedReq)
	}
	_ = os.Remove(filepath.Join(root, "combined-constraints.txt"))
	// The lock and the wheelhouse go with it. Bytes left in the wheelhouse are
	// reachable from the build through --find-links, so a closure a fetch
	// refused must not survive the fetch that refused it.
	_ = os.Remove(pypiLockPath(root))
	_ = os.RemoveAll(pypiWheelhouseDir(root))
	return summary
}

func fetchPypi(cfg *Config, store *manifest.Store) *Summary {
	summary := resolvePypiRequirements(cfg, store)
	if summary.HasFailures() {
		return summary
	}
	return fetchPypiClosure(cfg, summary)
}

// resolvePypiRequirements writes combined-requirements.txt and, when the
// applications carry any, combined-constraints.txt. It reaches no index for
// bytes: it reads each entry's version off the index and each application's
// requirements off disk.
func resolvePypiRequirements(cfg *Config, store *manifest.Store) *Summary {
	ctx := context.Background()
	out := cfg.stdout()
	summary := &Summary{}
	dirs := buildDirs(cfg.rootFor(manifest.TypePypi))

	start := time.Now()
	result := Result{Type: manifest.TypePypi, Name: "requirements"}

	combinedReq := filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")
	_, _ = fmt.Fprintf(out, "\n>>> [pypi] fetch — resolving requirements\n")

	indexRoot, err := pypiIndexRoot(ctx, store)
	if err != nil {
		result.Err = err
		_, _ = fmt.Fprintf(out, "    FAILED: %v\n", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}

	reader := &pypiReader{indexRoot: indexRoot}
	reqLines := []string{"# Auto-generated by bodega from pypi manifests\n"}
	_, _ = fmt.Fprintf(out, "    Index: %s\n", indexRoot)
	reqLines = append(reqLines, pypiIndexLine(indexRoot))

	// Collect base requirements: git repos referenced via RequiredBy on any pypi entry.
	baseReqs := make(map[string]string) // repoName → ref
	for _, name := range store.ListPackages(manifest.TypePypi) {
		pm, err := store.GetPackage(ctx, manifest.TypePypi, name)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			for _, requiredBy := range ve.RequiredBy {
				// Look up the git ref for this repo.
				gitPM, err := store.GetPackage(ctx, manifest.TypeGit, requiredBy)
				if err != nil || gitPM == nil {
					continue
				}
				for _, gitVE := range gitPM.Versions {
					if gitVE.Ref != "" {
						baseReqs[requiredBy] = gitVE.Ref
						break
					}
				}
			}
		}
	}

	for repoName, ref := range baseReqs {
		worktree, err := GitWorktreePath(cfg.rootFor(manifest.TypeGit), repoName, ref)
		if err != nil {
			result.Err = fmt.Errorf("git worktree for %s@%s: %w", repoName, ref, err)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
		if worktree == "" {
			result.Err = fmt.Errorf(
				"git repo %q not found at %s — run 'fetch git' first",
				repoName, filepath.Join(dirs.repos, repoName+".git"),
			)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
		reqPath := filepath.Join(worktree, "requirements.txt")
		if _, err := os.Stat(reqPath); os.IsNotExist(err) {
			result.Err = fmt.Errorf("requirements.txt not found in %s", worktree)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
		if err := reader.read(reqPath, false, map[string]bool{}); err != nil {
			result.Err = fmt.Errorf("pypi base requirements for %s@%s: %w", repoName, ref, err)
			_, _ = fmt.Fprintf(out, "    FAILED: %v\n", result.Err)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
		_, _ = fmt.Fprintf(out, "    Base: %s @ %s (%s)\n", repoName, ref, reqPath)
	}

	combinedCon := filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-constraints.txt")
	if len(reader.constraints) > 0 {
		reqLines = append(reqLines, fmt.Sprintf("-c %s\n", combinedCon))
	}
	if len(reader.requirements) > 0 {
		reqLines = append(reqLines, "\n# Requirements read from the applications' own files\n")
		for _, line := range reader.requirements {
			reqLines = append(reqLines, line+"\n")
		}
	}

	// Collect extra packages from the pypi manifests.
	pkgNames := store.ListPackages(manifest.TypePypi)
	_, _ = fmt.Fprintf(out, "    Extra packages: %d\n", len(pkgNames))
	reqLines = append(reqLines, "\n# Extra packages from manifest\n")
	unresolved := false
	for _, name := range pkgNames {
		if err := cfg.EnforcePolicy(ctx, manifest.TypePypi, name, "", ""); err != nil {
			_, _ = fmt.Fprintf(out, "      %s — SKIPPED: %v\n", name, err)
			summary.Failures++
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypePypi, name)
		if err != nil {
			// The entry says which version was approved, so a fetch that cannot
			// read it has nothing to honor and must not fall back to a bare
			// requirement line.
			err = fmt.Errorf("pypi %s: read the manifest entry: %w", name, err)
			_, _ = fmt.Fprintf(out, "      %s — FAILED: %v\n", name, err)
			summary.Failures++
			summary.Total++
			summary.Results = append(summary.Results, Result{Type: manifest.TypePypi, Name: name, Err: err})
			unresolved = true
			continue
		}

		// A package with no version entries names no version, which is the
		// shape auto-imported dependencies arrive in.
		entries := []manifest.VersionEntry{{}}
		if pm != nil && len(pm.Versions) > 0 {
			entries = pm.Versions
		}
		for _, ve := range entries {
			resolved, err := resolvePypiVersion(indexRoot, name, ve)
			if err != nil {
				_, _ = fmt.Fprintf(out, "      %s — FAILED: %v\n", name, err)
				summary.Failures++
				summary.Total++
				summary.Results = append(summary.Results, Result{Type: manifest.TypePypi, Name: name, Err: err})
				unresolved = true
				continue
			}
			spec := pypiRequirement(name, resolved)
			_, _ = fmt.Fprintf(out, "      %s\n", spec)
			reqLines = append(reqLines, spec+"\n")
		}
	}

	// No requirements file at all rather than one missing the entry that failed:
	// a partial file builds cleanly and stores a closure nobody approved.
	if unresolved {
		return summary
	}

	// The constraint file lands first: the requirements file is what the next
	// stage reads as "fetch is done", so it must not exist while the `-c` in
	// it still points at nothing.
	if len(reader.constraints) > 0 {
		body := "# Auto-generated by bodega from the applications' own constraint files\n" +
			strings.Join(reader.constraints, "\n") + "\n"
		if err := os.WriteFile(combinedCon, []byte(body), 0o644); err != nil {
			result.Err = fmt.Errorf("write combined constraints: %w", err)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
		_, _ = fmt.Fprintf(out, "    Constraints written to: %s\n", combinedCon)
	} else {
		_ = os.Remove(combinedCon)
	}

	// Write combined requirements file.
	content := ""
	for _, line := range reqLines {
		content += line
	}
	if err := os.WriteFile(combinedReq, []byte(content), 0o644); err != nil {
		result.Err = fmt.Errorf("write combined requirements: %w", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}
	_, _ = fmt.Fprintf(out, "    Requirements written to: %s\n", combinedReq)

	result.Artifacts = []string{combinedReq}
	result.Elapsed = time.Since(start)
	summary.Results = append(summary.Results, result)
	summary.Total++

	return summary
}

// fetchPypiClosure downloads everything the resolved requirements imply, pins a
// digest per file, and writes the lock the build reads instead of an index.
func fetchPypiClosure(cfg *Config, summary *Summary) *Summary {
	ctx := context.Background()
	out := cfg.stdout()
	root := cfg.rootFor(manifest.TypePypi)
	combinedReq := filepath.Join(root, "combined-requirements.txt")
	house := pypiWheelhouseDir(root)

	start := time.Now()
	result := Result{Type: manifest.TypePypi, Name: "closure"}
	fail := func(err error) *Summary {
		result.Err = err
		_, _ = fmt.Fprintf(out, "    FAILED: %v\n", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		cfg.RecordAudit(audit.EventFetch, manifest.TypePypi, "requirements", "", "failure", time.Since(start), err)
		return summary
	}

	// An empty requirements file has no closure, and running pip over it builds
	// a resolver environment to resolve nothing. The lock still lands, because
	// the build reads it to decide the same thing.
	hasReqs, err := hasInstallableRequirements(combinedReq)
	if err != nil {
		return fail(fmt.Errorf("read %s: %w", combinedReq, err))
	}
	var arts []pypiArtifact
	if hasReqs {
		indexURL, err := pypiSelectedIndex(combinedReq)
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "\n>>> [pypi] fetch — resolving the closure from %s\n", indexURL)
		// Fresh: the fetch opens a pipeline run, and a venv left by an earlier
		// one carries whatever its python was.
		pipBin, err := ensurePypiVenv(out, root, true)
		if err != nil {
			return fail(err)
		}
		if arts, err = downloadPypiClosure(out, pipBin, indexURL, combinedReq, house); err != nil {
			return fail(err)
		}
	} else if err := os.RemoveAll(house); err != nil {
		return fail(fmt.Errorf("clear the wheelhouse at %s: %w", house, err))
	}

	if err := cfg.pinPypiClosure(ctx, arts, house); err != nil {
		return fail(err)
	}
	lock := pypiLockPath(root)
	if err := os.WriteFile(lock, []byte(pypiLockBody(arts)), 0o644); err != nil {
		return fail(fmt.Errorf("write the resolved closure: %w", err))
	}

	elapsed := time.Since(start)
	result.Artifacts = []string{lock}
	result.Elapsed = elapsed
	summary.Results = append(summary.Results, result)
	summary.Total++
	_, _ = fmt.Fprintf(out, "    Closure: %d artifacts pinned, recorded in %s\n", len(arts), lock)
	_, _ = fmt.Fprintf(out, "    Done (%s)\n", elapsed.Round(time.Millisecond))

	if cfg.Logger != nil {
		cfg.Logger.Audit("OK      pypi/requirements  (%s)", elapsed.Round(time.Millisecond))
	}
	cfg.RecordAudit(audit.EventFetch, manifest.TypePypi, "requirements", "", "success", elapsed, nil)

	return summary
}

// BuildPypi creates a build virtualenv and runs pip wheel to produce a
// directory of wheels under <build-root>/wheels[/<version>]/, from the closure
// the fetch downloaded and pinned. resolved-requirements.txt and the wheelhouse
// beside it must already exist (produced by FetchPypi).
//
// No index is reachable from here. The build resolves nothing and downloads
// nothing; it turns recorded bytes into wheels.
func BuildPypi(cfg *Config, store *manifest.Store) *Summary {
	out := cfg.stdout()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypePypi))

	start := time.Now()
	result := Result{Type: manifest.TypePypi, Name: "wheels"}

	root := cfg.rootFor(manifest.TypePypi)
	combinedReq := filepath.Join(root, "combined-requirements.txt")
	lock := pypiLockPath(root)
	house := pypiWheelhouseDir(root)
	if _, err := os.Stat(lock); os.IsNotExist(err) {
		result.Err = fmt.Errorf("resolved-requirements.txt not found at %s — run 'fetch pypi' first", lock)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}

	// Skip the whole venv + pip-wheel dance when the closure has no installable
	// lines. Saves ~8s per run when pypi entries resolve to nothing (e.g. a git
	// repo whose requirements.txt only references other git repos). PackagePypi
	// will see zero wheels and skip cleanly.
	hasReqs, err := hasInstallableRequirements(lock)
	if err != nil {
		result.Err = fmt.Errorf("read %s: %w", lock, err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}
	if !hasReqs {
		_, _ = fmt.Fprintf(out, "\n>>> [pypi] build — the resolved closure has no installable packages, skipping\n")
		return summary
	}

	// The bytes are checked before pip is pointed at them. pip would refuse the
	// same substitution under --require-hashes, but against whichever candidate
	// it happened to reach and only once it got there.
	if err := verifyPypiClosure(lock, house); err != nil {
		result.Err = err
		_, _ = fmt.Fprintf(out, "    FAILED: %v\n", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}
	pipEnv := pypiPipEnv()

	wheelsDir := pypiWheelsDir(d)
	if err := mkdirAll(wheelsDir); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	// The fetch built this venv to download the closure, so the same pip
	// consumes it. Rebuilt only when a build runs without one.
	_, _ = fmt.Fprintf(out, "\n>>> [pypi] build — build virtualenv\n")
	pipBin, err := ensurePypiVenv(out, root, false)
	if err != nil {
		result.Err = err
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}

	// Build wheels.
	//
	// --no-index and --find-links reach pip on the command line, and pip's own
	// precedence is what makes that hold: a requirements file's --index-url
	// replaces a command-line one outright, but every index option in
	// req_file.py is guarded by `and not no_index`, so no file at any include
	// depth can switch the index back on. --find-links appends unconditionally,
	// which is why --require-hashes is here too: a link pip was handed by some
	// other route still cannot produce bytes the fetch did not record.
	// Stale wheels go before pip writes beside them, never after: pruning the
	// output would delete a version pip substituted and leave verifyPypiWheels
	// with nothing to refuse.
	if err := prunePypiWheels(out, combinedReq, wheelsDir); err != nil {
		result.Err = err
		_, _ = fmt.Fprintf(out, "    FAILED: %v\n", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}

	_, _ = fmt.Fprintf(out, "\n>>> [pypi] build — building wheels from %s (C extensions will compile from source)\n", house)
	if err := runCmdEnv(out, "", pipEnv,
		pipBin, "wheel",
		"--isolated",
		"--no-index",
		"--find-links", house,
		"--require-hashes",
		"--wheel-dir", wheelsDir,
		"--progress-bar", "on",
		"-r", lock,
	); err != nil {
		result.Err = fmt.Errorf("pip wheel: %w", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}

	if err := verifyPypiWheels(combinedReq, wheelsDir); err != nil {
		result.Err = err
		_, _ = fmt.Fprintf(out, "    FAILED: %v\n", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}

	// Collect artifact paths.
	whlFiles, _ := filepath.Glob(filepath.Join(wheelsDir, "*.whl"))
	result.Artifacts = whlFiles
	result.Elapsed = time.Since(start)
	summary.Results = append(summary.Results, result)
	summary.Total++

	_, _ = fmt.Fprintf(out, "\n    Total wheels built: %d\n", len(whlFiles))
	_, _ = fmt.Fprintf(out, "    Done (%s)\n", result.Elapsed.Round(time.Millisecond))

	return summary
}

// PackagePypi generates MANIFEST.sha256 in the wheels directory. The wheels
// must already exist (produced by BuildPypi).
func PackagePypi(cfg *Config, store *manifest.Store) *Summary {
	out := cfg.stdout()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypePypi))

	start := time.Now()
	result := Result{Type: manifest.TypePypi, Name: "manifest"}

	wheelsDir := pypiWheelsDir(d)
	whlFiles, _ := filepath.Glob(filepath.Join(wheelsDir, "*.whl"))
	if len(whlFiles) == 0 {
		// Two distinct states: build hasn't run at all vs. build ran but
		// produced nothing. Only the former is an error — the latter happens
		// when combined-requirements.txt resolves to zero installable packages
		// (common with pypi entries auto-imported from a git repo that has no
		// direct requirements of its own). Treat it as a skip so the caller
		// doesn't abort the whole upload run.
		if _, err := os.Stat(wheelsDir); os.IsNotExist(err) {
			result.Err = fmt.Errorf("no wheels directory at %s — run 'build pypi' first", wheelsDir)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
		_, _ = fmt.Fprintf(out, "\n>>> [pypi] package — no wheels produced, skipping\n")
		return summary
	}

	_, _ = fmt.Fprintf(out, "\n>>> [pypi] package — generating checksums\n")

	manifestFile := filepath.Join(wheelsDir, "MANIFEST.sha256")
	if err := generateWheelManifest(wheelsDir, manifestFile); err != nil {
		result.Err = fmt.Errorf("generate MANIFEST.sha256: %w", err)
		_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
		summary.Failures++
	} else {
		_, _ = fmt.Fprintf(out, "    Written: %s\n", manifestFile)
		result.Artifacts = []string{manifestFile}

		// Scan wheel metadata and persist the dependency graph. This is a
		// best-effort operation: failures are logged but do not fail the build.
		depGraphPath := filepath.Join(wheelsDir, "dep-graph.json")
		if graph, err := ScanWheelMetadata(wheelsDir, store); err != nil {
			_, _ = fmt.Fprintf(out, "    WARNING: dep-graph scan failed: %v\n", err)
		} else if err := SaveDepGraph(depGraphPath, graph); err != nil {
			_, _ = fmt.Fprintf(out, "    WARNING: dep-graph save failed: %v\n", err)
		} else {
			_, _ = fmt.Fprintf(out, "    Dep graph: %s (%d packages)\n", depGraphPath, len(graph.Packages))
		}
	}

	result.Elapsed = time.Since(start)
	summary.Results = append(summary.Results, result)
	summary.Total++
	_, _ = fmt.Fprintf(out, "    Done (%s)\n", result.Elapsed.Round(time.Millisecond))

	if cfg.Logger != nil {
		if result.Err != nil {
			cfg.Logger.Audit("FAILED  pypi/manifest  (%s)  %v", result.Elapsed.Round(time.Millisecond), result.Err)
		} else {
			cfg.Logger.Audit("OK      pypi/manifest  (%s)", result.Elapsed.Round(time.Millisecond))
		}
	}
	pyStatus := "success"
	if result.Err != nil {
		pyStatus = "failure"
	}
	cfg.RecordAudit(audit.EventPackage, manifest.TypePypi, "manifest", "", pyStatus, result.Elapsed, result.Err)

	return summary
}

// RunPypi runs the full pypi pipeline (FetchPypi → BuildPypi → PackagePypi)
// for backward compatibility. New callers should invoke the stage functions
// individually.
func RunPypi(cfg *Config, store *manifest.Store) *Summary {
	fetchSummary := FetchPypi(cfg, store)
	if fetchSummary.HasFailures() {
		return fetchSummary
	}
	buildSummary := BuildPypi(cfg, store)
	if buildSummary.HasFailures() {
		return mergeSummaries(fetchSummary, buildSummary)
	}
	pkgSummary := PackagePypi(cfg, store)
	return mergeSummaries(mergeSummaries(fetchSummary, buildSummary), pkgSummary)
}

// generateWheelManifest writes a MANIFEST.sha256 file with checksums of every
// .whl file in wheelDir.
func generateWheelManifest(wheelDir, destPath string) error {
	matches, err := filepath.Glob(filepath.Join(wheelDir, "*.whl"))
	if err != nil {
		return err
	}

	var lines string
	for _, whl := range matches {
		sum, err := fileSHA256(whl)
		if err != nil {
			return err
		}
		lines += fmt.Sprintf("%s  %s\n", sum, filepath.Base(whl))
	}
	return os.WriteFile(destPath, []byte(lines), 0o644)
}
