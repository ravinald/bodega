package clientconf

import (
	"fmt"
	"math"
	"math/big"
	"strings"
)

// gitConv is how Git 2.54.0 converts one configuration variable when a
// callback reads it: the git_config_* helper in config.c the callback calls,
// or the checks it runs itself.
type gitConv uint8

const (
	// gitBool is git_config_bool: dies on a value that is neither a truth
	// word nor an integer.
	gitBool gitConv = iota + 1
	// gitInt, gitSsize and gitUlong are git_config_int, git_config_ssize_t
	// and git_config_ulong: die on a value that is no number of that width.
	gitInt
	gitSsize
	gitUlong
	// gitString needs a value: a name with no = is config_error_nonbool,
	// which fails the whole read.
	gitString
	// gitPath is git_config_pathname: a value, and a ~user it can expand.
	gitPath
	// gitLevel is the zlib level of core.compression, core.loosecompression
	// and pack.compression: an int that is -1 or 0 through 9.
	gitLevel
	// gitWordOrBool is a variable that takes its own words and otherwise
	// goes to git_config_bool.
	gitWordOrBool
	// gitWord needs a value, one of its words in the case the callback
	// compares them in, where any other is an error.
	gitWord
	// gitAbbrev is core.abbrev.
	gitAbbrev
	// gitComment is core.commentchar and core.commentstring.
	gitComment
	// gitColor is a color git parses with color_parse, and gitBackend
	// http.sslbackend, which git accepts only when the curl it was built
	// against carries that backend. This port holds neither, so a value for
	// one is refused as not interpreted.
	gitColor
	gitBackend
)

type gitVar struct {
	conv gitConv
	// words are the values gitWordOrBool and gitWord take, and fold whether
	// the callback compares them with strcasecmp.
	words []string
	fold  bool
}

// gitHTTPVars is http_options in http.c at Git 2.54.0 (lines 392-602), the
// callback git-remote-https converts every http variable with before its
// first request, keyed by the name after "http.". http.delegation is read as
// git built against curl 7.22.0 or later reads it. What http_init does with
// a converted value afterwards is not here: it parses http.proxy as a URL
// only once a request needs it.
var gitHTTPVars = map[string]gitVar{
	"version": {conv: gitString}, "sslverify": {conv: gitBool}, "sslcipherlist": {conv: gitString},
	"sslversion": {conv: gitString}, "sslcert": {conv: gitPath}, "sslcerttype": {conv: gitString},
	"sslkey": {conv: gitPath}, "sslkeytype": {conv: gitString}, "sslcapath": {conv: gitPath},
	"sslcainfo": {conv: gitPath}, "sslcertpasswordprotected": {conv: gitBool}, "ssltry": {conv: gitBool},
	"schannelcheckrevoke": {conv: gitBool}, "schannelusesslcainfo": {conv: gitBool},
	"minsessions": {conv: gitInt}, "maxrequests": {conv: gitInt}, "lowspeedlimit": {conv: gitInt},
	"lowspeedtime": {conv: gitInt}, "noepsv": {conv: gitBool}, "proxy": {conv: gitString},
	"proxyauthmethod": {conv: gitString}, "proxysslcert": {conv: gitString}, "proxysslkey": {conv: gitString},
	"proxysslcainfo": {conv: gitString}, "proxysslcertpasswordprotected": {conv: gitBool},
	"cookiefile": {conv: gitPath}, "savecookies": {conv: gitBool}, "postbuffer": {conv: gitSsize},
	"useragent": {conv: gitString}, "emptyauth": {conv: gitWordOrBool, words: []string{"auto"}},
	"delegation": {conv: gitString}, "pinnedpubkey": {conv: gitPath}, "extraheader": {conv: gitString},
	"curloptresolve": {conv: gitString}, "followredirects": {conv: gitWordOrBool, words: []string{"initial"}},
	// An unknown http.proactiveauth is a warning.
	"proactiveauth": {conv: gitString}, "keepaliveidle": {conv: gitInt}, "keepaliveinterval": {conv: gitInt},
	"keepalivecount": {conv: gitInt}, "retryafter": {conv: gitInt}, "maxretries": {conv: gitInt},
	"maxretrytime": {conv: gitInt}, "sslbackend": {conv: gitBackend},
}

// gitDefaultVars is git_default_config in environment.c at Git 2.54.0 (lines
// 665-712) with the callbacks it hands a variable to: git_default_core_config
// (301-524), git_ident_config and set_ident in ident.c, and the i18n, branch,
// push, attr and sparse callbacks beside it. http_options ends by calling it
// for every variable that is not its own, and nearly every git command reads
// its configuration through it too. core.eol, core.whitespace's rule words,
// core.fsync's component names and an unknown core.fsyncmethod fail nothing
// in git, and platform_core_config is Windows's alone.
var gitDefaultVars = map[string]gitVar{
	"core.filemode": {conv: gitBool}, "core.trustctime": {conv: gitBool},
	"core.checkstat": {conv: gitWord, words: []string{"default", "minimal"}, fold: true},
	"core.quotepath": {conv: gitBool}, "core.symlinks": {conv: gitBool}, "core.ignorecase": {conv: gitBool},
	"core.attributesfile": {conv: gitPath}, "core.bare": {conv: gitBool}, "core.ignorestat": {conv: gitBool},
	"core.abbrev":           {conv: gitAbbrev},
	"core.disambiguate":     {conv: gitWord, words: []string{"none", "commit", "committish", "tree", "treeish", "blob"}, fold: true},
	"core.loosecompression": {conv: gitLevel}, "core.compression": {conv: gitLevel},
	"core.autocrlf":               {conv: gitWordOrBool, words: []string{"input"}, fold: true},
	"core.safecrlf":               {conv: gitWordOrBool, words: []string{"warn"}, fold: true},
	"core.checkroundtripencoding": {conv: gitString}, "core.editor": {conv: gitString},
	"core.commentchar": {conv: gitComment}, "core.commentstring": {conv: gitComment},
	"core.askpass": {conv: gitString}, "core.excludesfile": {conv: gitPath},
	"core.whitespace": {conv: gitString}, "core.fsync": {conv: gitString}, "core.fsyncmethod": {conv: gitString},
	"core.fsyncobjectfiles": {conv: gitBool}, "core.lockfilepid": {conv: gitBool},
	"core.createobject":   {conv: gitWord, words: []string{"rename", "link"}},
	"core.sparsecheckout": {conv: gitBool}, "core.sparsecheckoutcone": {conv: gitBool},
	"core.precomposeunicode": {conv: gitBool}, "core.protecthfs": {conv: gitBool}, "core.protectntfs": {conv: gitBool},
	"user.useconfigonly": {conv: gitBool}, "user.name": {conv: gitString}, "user.email": {conv: gitString},
	"author.name": {conv: gitString}, "author.email": {conv: gitString},
	"committer.name": {conv: gitString}, "committer.email": {conv: gitString},
	"i18n.commitencoding": {conv: gitString}, "i18n.logoutputencoding": {conv: gitString},
	"branch.autosetupmerge":  {conv: gitWordOrBool, words: []string{"always", "inherit", "simple"}},
	"branch.autosetuprebase": {conv: gitWord, words: []string{"never", "local", "remote", "always"}},
	"push.default":           {conv: gitWord, words: []string{"nothing", "matching", "simple", "upstream", "tracking", "current"}},
	"attr.tree":              {conv: gitString},
	"color.advice":           {conv: gitWordOrBool, words: []string{"never", "always", "auto"}, fold: true},
	"color.advice.reset":     {conv: gitColor}, "color.advice.hint": {conv: gitColor},
	"pager.color": {conv: gitBool}, "color.pager": {conv: gitBool},
	"pack.packsizelimit": {conv: gitUlong}, "pack.compression": {conv: gitLevel},
	"sparse.expectfilesoutsideofpatterns": {conv: gitBool},
}

// gitAdvice is advice_setting in advice.c at Git 2.54.0, lowercased: the
// advice.* names git_default_advice_config converts with git_config_bool. Any
// other advice.* name is ignored.
var gitAdvice = strings.Fields(`addembeddedrepo addemptypathspec addignoredfile ambiguousfetchrefspec amworkdir
	checkoutambiguousremotebranchname commitbeforemerge defaultbranchname detachedhead diverging
	fetchremoteheadwarn fetchshowforcedupdates forcedeletebranch graftfiledeprecated ignoredhook
	implicitidentity mergeconflict nestedtag objectnamewarning pushalreadyexists pushfetchfirst
	pushneedsforce pushnonffcurrent pushnonffmatching pushrefneedsupdate pushunqualifiedrefname
	pushupdaterejected pushnonfastforward rebasetodoerror refsyntax resetnorefresh resolveconflict rmhints
	sequencerinuse setupstreamfailure skippedcherrypicks sparseindexexpanded statusaheadbehindwarning
	statushints statusuoption submodulesnotupdated submodulealternateerrorstrategydie
	submodulemergeconflict suggestdetachinghead updatesparsepath waitingforeditor worktreeaddorphan`)

// lookup is the conversion git-remote-https applies to e, as http_init's
// urlmatch_config_entry routes it: a variable of the http section goes to
// http_options under the name after its last dot, and any other to
// git_default_config under its whole name.
//
// git converts an [http "<url>"] variable only when the URL matches the
// remote and no closer match came before it. Which remote is not known here,
// so every http variable is converted: a value git would die on under a URL
// it never fetches from is refused all the same, which errs toward refusing.
func (e GitEntry) lookup() (name string, v gitVar, ok bool) {
	if e.Section == "http" {
		name = "http." + e.Name
		if v, ok = gitHTTPVars[e.Name]; ok {
			return name, v, true
		}
		if e.Subsection != "" {
			return name, v, false
		}
	}
	name = e.Key()
	if v, ok = gitDefaultVars[name]; ok {
		return name, v, true
	}
	if e.Section == "advice" && e.Subsection == "" {
		for _, k := range gitAdvice {
			if k == e.Name {
				return name, gitVar{conv: gitBool}, true
			}
		}
	}
	return name, v, false
}

// GitConvertError is the first variable of a git configuration file that git
// dies on while converting it, as the line it stands on and git's message, or
// 0 and "" for a file whose every variable converts. The file must already
// load: ParseGitConfig's BadLine comes first, as git's own parse does.
//
// It ports the conversion git-remote-https runs before it connects: http_init
// reads the configuration through urlmatch_config_entry with http_options as
// the callback and git_default_config behind it, and each calls
// git_config_bool, git_config_int and their kin, which die on a value of the
// wrong type, or returns an error, which git_config dies on. A variable
// neither callback names is not converted there and fails nothing.
func GitConvertError(cfg GitConfig) (line int, msg string) {
	for _, e := range cfg.Entries {
		name, v, ok := e.lookup()
		if !ok {
			continue
		}
		if msg := v.refuses(name, e.Value, e.HasValue); msg != "" {
			return e.Line, msg
		}
	}
	return 0, ""
}

func (v gitVar) refuses(name, value string, has bool) string {
	missing := fmt.Sprintf("missing value for '%s'", name)
	badBool := func() string {
		if has && !gitBoolish(value) {
			return fmt.Sprintf("bad boolean config value '%s' for '%s'", value, name)
		}
		return ""
	}
	word := func() bool {
		for _, w := range v.words {
			if has && (value == w || v.fold && strings.EqualFold(value, w)) {
				return true
			}
		}
		return false
	}
	number := func(min, max *big.Int) (*big.Int, string) {
		n, why := gitNumber(value, has, min, max)
		if why != "" {
			return nil, fmt.Sprintf("bad numeric config value '%s' for '%s': %s", value, name, why)
		}
		return n, ""
	}
	i32 := func() (*big.Int, string) { return number(big.NewInt(math.MinInt32), big.NewInt(math.MaxInt32)) }
	switch v.conv {
	case gitBool:
		return badBool()
	case gitInt:
		_, msg := i32()
		return msg
	case gitSsize:
		_, msg := number(big.NewInt(math.MinInt64), big.NewInt(math.MaxInt64))
		return msg
	case gitUlong:
		// git_parse_unsigned refuses a '-' anywhere before strtoumax can
		// wrap it.
		if strings.Contains(value, "-") {
			return fmt.Sprintf("bad numeric config value '%s' for '%s': invalid unit", value, name)
		}
		_, msg := number(new(big.Int), new(big.Int).SetUint64(math.MaxUint64))
		return msg
	case gitString:
		if !has {
			return missing
		}
	case gitPath:
		if !has {
			return missing
		}
		// interpolate_path asks the password database for ~user, which
		// doctor does not.
		path := strings.TrimPrefix(value, ":(optional)")
		if user, _, _ := strings.Cut(path, "/"); strings.HasPrefix(user, "~") && user != "~" {
			return fmt.Sprintf("'%s' for '%s' names the home directory of the account %s, which git dies on when no such account exists and doctor does not look up", value, name, user[1:])
		}
	case gitLevel:
		n, msg := i32()
		if msg != "" {
			return msg
		}
		if n.Int64() < -1 || n.Int64() > 9 {
			return fmt.Sprintf("bad zlib compression level %d for '%s'", n.Int64(), name)
		}
	case gitWordOrBool:
		if !word() {
			return badBool()
		}
	case gitWord:
		if !has {
			return missing
		}
		if !word() {
			return fmt.Sprintf("invalid value for '%s': '%s'", name, value)
		}
	case gitAbbrev:
		if !has {
			return missing
		}
		// "auto", or a word git_parse_maybe_bool_text reads as false.
		if strings.EqualFold(value, "auto") || value == "" || strings.EqualFold(value, "false") || strings.EqualFold(value, "no") || strings.EqualFold(value, "off") {
			return ""
		}
		n, msg := i32()
		if msg != "" {
			return msg
		}
		if n.Int64() < 4 {
			return fmt.Sprintf("abbrev length out of range: %d", n.Int64())
		}
	case gitComment:
		switch {
		case !has:
			return missing
		case value == "":
			return name + " must have at least one character"
		case !strings.EqualFold(value, "auto") && strings.Contains(value, "\n"):
			return name + " cannot contain newline"
		}
	case gitColor:
		if !has {
			return missing
		}
		return fmt.Sprintf("'%s' is a color git parses and dies on when it is malformed, which doctor does not interpret", name)
	case gitBackend:
		if has {
			return fmt.Sprintf("'%s' selects the TLS library git verifies with, and git dies on one its curl was not built with, which doctor does not interpret", name)
		}
	}
	return ""
}

// gitBoolish is git_parse_maybe_bool in parse.c for a variable with a value:
// "", a truth word in any case, or anything git_parse_int reads.
func gitBoolish(value string) bool {
	switch strings.ToLower(value) {
	case "", "true", "yes", "on", "false", "no", "off":
		return true
	}
	_, why := gitNumber(value, true, big.NewInt(math.MinInt32), big.NewInt(math.MaxInt32))
	return why == ""
}

// gitNumber is git_parse_signed and git_parse_unsigned in parse.c: strtoimax
// in base 0 (white space, a sign, then 0x hex, 0 octal or decimal digits),
// then nothing or one of k, m and g in either case as a power of 1024, the
// product held to [min, max]. why is the phrase die_bad_number ends on:
// "invalid unit" for a value that is no number or ends in anything else,
// "out of range" for one past the type. A variable with no value is the
// first.
func gitNumber(value string, has bool, min, max *big.Int) (n *big.Int, why string) {
	const unit, rng = "invalid unit", "out of range"
	if !has || value == "" {
		return nil, unit
	}
	s := strings.TrimLeft(value, " \t\n\v\f\r")
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg, s = s[0] == '-', s[1:]
	}
	hex := func(c byte) bool { return c >= '0' && c <= '9' || c|0x20 >= 'a' && c|0x20 <= 'f' }
	base := 10
	switch {
	case len(s) > 2 && s[0] == '0' && s[1]|0x20 == 'x' && hex(s[2]):
		base, s = 16, s[2:]
	case s != "" && s[0] == '0':
		base = 8
	}
	end := 0
	for end < len(s) {
		c := s[end]
		d := 99
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case hex(c):
			d = int(c|0x20-'a') + 10
		}
		if d >= base {
			break
		}
		end++
	}
	if end == 0 {
		return nil, unit
	}
	n, _ = new(big.Int).SetString(s[:end], base)
	if neg {
		n.Neg(n)
	}
	// strtoimax and strtoumax saturate with ERANGE before any unit is read.
	if n.Cmp(big.NewInt(math.MinInt64)) < 0 || n.Cmp(new(big.Int).SetUint64(math.MaxUint64)) > 0 || min.Sign() < 0 && n.Cmp(big.NewInt(math.MaxInt64)) > 0 {
		return nil, rng
	}
	factor := int64(0)
	switch strings.ToLower(s[end:]) {
	case "":
		factor = 1
	case "k":
		factor = 1 << 10
	case "m":
		factor = 1 << 20
	case "g":
		factor = 1 << 30
	default:
		return nil, unit
	}
	n.Mul(n, big.NewInt(factor))
	if n.Cmp(min) < 0 || n.Cmp(max) > 0 {
		return nil, rng
	}
	return n, ""
}
