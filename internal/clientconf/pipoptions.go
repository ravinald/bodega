package clientconf

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// pipKind is how pip 26.2.1's ConfigOptionParser._update_defaults
// (pip/_internal/cli/parser.py:259-314) converts a configured value for one
// option: the optparse action and type, or the callback, it is declared with.
type pipKind uint8

const (
	// pipText is a store or append of type string or path, and a callback
	// that refuses nothing. No value fails.
	pipText pipKind = iota
	// pipBool is store_true or store_false: pip's strtobool, else exit 2.
	pipBool
	// pipCount is strtobool or a non-negative int.
	pipCount
	// pipInt and pipFloat are optparse's check_builtin.
	pipInt
	pipFloat
	// pipChoice is optparse's check_choice, per word for an append option.
	pipChoice
	// The rest are callbacks in pip/_internal/cli/cmdoptions.py.
	pipNoCacheDir
	pipPythonVersion
	pipConfigSettings
	pipGroup
	// pipNoDash is the four handle_mutual_excludes callbacks and
	// _handle_refresh_package, which raise CommandError on a leading "-".
	pipNoDash
	pipUploadedPriorTo
)

// pipOpt is one long option of pip install's parser.
type pipOpt struct {
	name string
	kind pipKind
	// list is optparse's append action: the value is split on whitespace
	// and each word converted.
	list    bool
	choices []string
	// general options are also in pip's main parser, which converts them
	// before the command's parser converts anything.
	general bool
}

// pipInstallOpts is option_list_all of pip 26.2.1's install command, in its
// order: the command's own options, the index group, the general group.
// TestPipInstallOptionsMatchNativePip compares it with the pip installed.
var pipInstallOpts = func() []pipOpt {
	var out []pipOpt
	add := func(general bool, kind pipKind, names ...string) {
		for _, n := range names {
			out = append(out, pipOpt{name: n, kind: kind, general: general})
		}
	}
	list := func(general bool, kind pipKind, choices []string, names ...string) {
		for _, n := range names {
			out = append(out, pipOpt{name: n, kind: kind, list: true, choices: choices, general: general})
		}
	}
	choice := func(general bool, name string, choices ...string) {
		out = append(out, pipOpt{name: name, kind: pipChoice, choices: choices, general: general})
	}
	list(false, pipText, nil, "requirement", "constraint", "build-constraint", "requirements-from-script")
	add(false, pipBool, "no-deps", "no-dependencies", "only-deps", "only-dependencies")
	list(false, pipText, nil, "editable")
	add(false, pipBool, "dry-run")
	add(false, pipText, "target")
	list(false, pipText, nil, "platform")
	add(false, pipPythonVersion, "python-version")
	add(false, pipText, "implementation")
	list(false, pipText, nil, "abi")
	add(false, pipBool, "user", "no-user")
	add(false, pipText, "root", "prefix", "src", "source", "source-dir", "source-directory")
	add(false, pipBool, "upgrade")
	choice(false, "upgrade-strategy", "only-if-needed", "eager")
	add(false, pipBool, "force-reinstall", "ignore-installed", "ignore-requires-python", "no-build-isolation", "use-pep517", "check-build-dependencies", "break-system-packages")
	add(false, pipConfigSettings, "config-settings")
	add(false, pipBool, "compile", "no-compile", "no-warn-script-location", "no-warn-conflicts", "require-hashes", "no-require-hashes")
	choice(false, "progress-bar", "auto", "on", "off", "raw")
	choice(false, "root-user-action", "warn", "ignore")
	add(false, pipText, "report")
	add(false, pipGroup, "group")
	add(false, pipBool, "no-clean", "pre")
	add(false, pipNoDash, "all-releases", "only-final", "no-binary", "only-binary")
	add(false, pipBool, "prefer-binary")
	add(false, pipText, "index-url", "pypi-url")
	list(false, pipText, nil, "extra-index-url")
	add(false, pipBool, "no-index")
	add(false, pipNoDash, "refresh-package")
	list(false, pipText, nil, "find-links")
	add(false, pipUploadedPriorTo, "uploaded-prior-to")
	add(true, pipText, "help")
	add(true, pipBool, "debug", "isolated", "require-virtualenv", "require-venv")
	add(true, pipText, "python")
	add(true, pipCount, "verbose")
	add(true, pipBool, "version")
	add(true, pipCount, "quiet")
	add(true, pipText, "log", "log-file", "local-log")
	add(true, pipBool, "no-input")
	choice(true, "keyring-provider", "auto", "disabled", "import", "subprocess")
	add(true, pipText, "proxy")
	add(true, pipBool, "no-proxy-env")
	add(true, pipInt, "retries")
	add(true, pipFloat, "timeout", "default-timeout")
	list(true, pipChoice, []string{"s", "i", "w", "b", "a"}, "exists-action")
	list(true, pipText, nil, "trusted-host")
	add(true, pipText, "cert", "client-cert", "cache-dir")
	add(true, pipNoCacheDir, "no-cache-dir")
	add(true, pipBool, "disable-pip-version-check", "no-color", "no-python-version-warning")
	list(true, pipChoice, []string{"fast-deps", "inprocess-build-deps", "venv-isolation", "truststore", "no-binary-enable-wheel-cache", "build-constraint"}, "use-feature")
	list(true, pipChoice, []string{"legacy-resolver", "legacy-certs"}, "use-deprecated")
	add(true, pipInt, "resume-retries")
	return out
}()

// PipLayer is one configuration file pip loads, in load order.
type PipLayer struct {
	File string
	Data []byte
}

// pipSet is one option's final value in one of the three groups pip orders
// its configuration by, and where the value came from.
type pipSet struct {
	key, value, from string
}

// PipInstallError is why pip install exits before any request under the
// configuration in layers and the environment, or nil when it starts. Every
// layer must already load: PipLoadError's verdict comes first, as pip's does.
//
// It ports the initialization pip 26.2.1 runs between loading its files and
// running a command: ConfigOptionParser._get_ordered_configuration_items and
// _update_defaults (pip/_internal/cli/parser.py:225-314) with check_default
// (219-224), over optparse's check_builtin and check_choice and the callbacks
// in pip/_internal/cli/cmdoptions.py. A later file replaces an earlier one's
// value for one section and option, an empty final value is no setting, and
// what is left is converted group by group: [global], the command's section,
// then PIP_* from the environment. Each group is converted on its own, so a
// value [global] gets wrong ends pip even when [install] or the environment
// would have replaced it. pip's main parser runs that over the general options
// before the install parser runs it over all of them, which decides only
// which of two bad values is named. An option the parser does not declare is
// skipped, as pip skips it.
//
// The environment is read for the PIP_ name of each option the parser
// declares, in capitals: getenv answers for a name and cannot list the others
// pip would also fold to lower case.
//
// Two settings are refused as not interpreted rather than judged: python,
// which has pip run every command under another interpreter with its own
// configuration and bundle, and an uploaded-prior-to outside the forms every
// Python pip supports parses alike.
func PipInstallError(layers []PipLayer, getenv func(string) string) error {
	return pipInstallRefusal(pipGroups(layers, getenv))
}

// pipGroups is the configuration pip install converts, as the three groups
// _get_ordered_configuration_items orders it by: "global" and "install" from
// the files, a later file replacing an earlier one's value for one section and
// option, and ":env:" for the PIP_ name of each option the parser declares.
func pipGroups(layers []PipLayer, getenv func(string) string) map[string][]pipSet {
	groups := map[string][]pipSet{}
	put := func(group string, s pipSet) {
		if i := slices.IndexFunc(groups[group], func(o pipSet) bool { return o.key == s.key }); i >= 0 {
			groups[group][i].value, groups[group][i].from = s.value, s.from
			return
		}
		groups[group] = append(groups[group], s)
	}
	for _, l := range layers {
		f, err := readPipFile(l.Data)
		if err != nil {
			continue
		}
		for _, s := range f.settings() {
			if s.section == "global" || s.section == "install" {
				put(s.section, pipSet{key: s.option, value: s.value, from: fmt.Sprintf("%s under [%s], %s line %d", s.raw, s.section, l.File, s.line)})
			}
		}
	}
	if getenv != nil {
		for _, o := range pipInstallOpts {
			// ENV_NAMES_IGNORED: PIP_VERSION and PIP_HELP configure nothing.
			if o.name == "version" || o.name == "help" {
				continue
			}
			name := "PIP_" + strings.ToUpper(strings.ReplaceAll(o.name, "-", "_"))
			put(":env:", pipSet{key: o.name, value: getenv(name), from: "the environment's " + name})
		}
	}
	return groups
}

// pipInstallValue is the value pip install runs with for one option name, and
// where it came from: the last of [global], [install] and the environment to
// set it to anything but the empty string, which is the order _update_defaults
// assigns them in. "" when nothing sets it.
func pipInstallValue(groups map[string][]pipSet, name string) (value, from string) {
	for _, group := range []string{"global", "install", ":env:"} {
		for _, s := range groups[group] {
			if s.key == name && s.value != "" {
				value, from = s.value, s.from
			}
		}
	}
	return value, from
}

// PipNoIndex is where pip install is told to ask no index, or "" when it asks
// the ones configured. With no-index true, LinkCollector.create in pip 26.2.1
// (pip/_internal/index/collector.py:391-396) drops index-url and every
// extra-index-url before the first request, so an index naming bodega is one
// pip never contacts and no certificate is verified for it. The value is the
// one pip install runs with, [global] then [install] then PIP_NO_INDEX, read
// by pip's strtobool; PipInstallError has already refused one that is no
// truth value.
func PipNoIndex(layers []PipLayer, getenv func(string) string) string {
	value, from := pipInstallValue(pipGroups(layers, getenv), "no-index")
	switch strings.ToLower(value) {
	case "y", "yes", "t", "true", "on", "1":
		return from
	}
	return ""
}

// PipIndexAlias is where pip's configuration sets pypi-url, the second name
// pip install declares for index-url, or "" when nothing does. Both names
// assign one index, and which wins inside a file is the order pip walks that
// file's options in, so a configuration setting the alias is refused as not
// interpreted rather than read as naming no index.
func PipIndexAlias(layers []PipLayer, getenv func(string) string) string {
	_, from := pipInstallValue(pipGroups(layers, getenv), "pypi-url")
	return from
}

func pipInstallRefusal(groups map[string][]pipSet) error {
	pass := func(order []string, generalOnly bool) error {
		for _, group := range order {
			for _, s := range groups[group] {
				if s.value == "" {
					continue
				}
				i := slices.IndexFunc(pipInstallOpts, func(o pipOpt) bool { return o.name == s.key })
				if i < 0 || generalOnly && !pipInstallOpts[i].general {
					continue
				}
				if msg := pipInstallOpts[i].refuses(s.value); msg != "" {
					return fmt.Errorf("%s (%s)", msg, s.from)
				}
			}
		}
		return nil
	}
	if err := pass([]string{"global", ":env:"}, true); err != nil {
		return err
	}
	// main_parser.parse_command: a python setting re-runs pip under that
	// interpreter before the command's parser exists.
	for _, group := range []string{":env:", "global"} {
		for _, s := range groups[group] {
			if s.key == "python" && s.value != "" {
				return fmt.Errorf("the python option runs pip under the interpreter %s, whose configuration files and CA bundle doctor does not interpret (%s)", s.value, s.from)
			}
		}
	}
	return pass([]string{"global", "install", ":env:"}, false)
}

// refuses is the message pip exits with on val for this option, or "".
func (o pipOpt) refuses(val string) string {
	if o.list {
		if o.kind != pipChoice {
			return ""
		}
		for _, word := range pyFields(val) {
			if msg := o.choice(word); msg != "" {
				return msg
			}
		}
		return ""
	}
	switch o.kind {
	case pipBool:
		if !pipTruth(val) {
			return fmt.Sprintf("%s is not a valid value for %s option, please specify a boolean value like yes/no, true/false or 1/0 instead.", val, o.name)
		}
	case pipCount:
		if !pipTruth(val) && (!pyInt(val, 10) || strings.HasPrefix(pyNumeral(val), "-") && strings.Trim(pyNumeral(val), "-0_") != "") {
			return fmt.Sprintf("%s is not a valid value for %s option, please instead specify either a non-negative integer or a boolean value like yes/no or false/true which is equivalent to 1/0.", val, o.name)
		}
	case pipInt:
		// optparse._parse_num picks the radix from the value's opening.
		radix, num := 10, val
		switch low := strings.ToLower(val); {
		case strings.HasPrefix(low, "0x"):
			radix = 16
		case strings.HasPrefix(low, "0b"):
			if radix, num = 2, val[2:]; num == "" {
				num = "0"
			}
		case strings.HasPrefix(val, "0"):
			radix = 8
		}
		if !pyInt(num, radix) {
			return fmt.Sprintf("option %s: invalid integer value: %s", o.name, pyRepr(val))
		}
	case pipFloat:
		if !pyFloat(val) {
			return fmt.Sprintf("option %s: invalid floating-point value: %s", o.name, pyRepr(val))
		}
	case pipChoice:
		return o.choice(val)
	case pipNoCacheDir:
		if !pipTruth(val) {
			return fmt.Sprintf("--%s error: invalid truth value %s", o.name, pyRepr(strings.ToLower(val)))
		}
	case pipPythonVersion:
		parts := strings.Split(val, ".")
		if len(parts) > 3 {
			return fmt.Sprintf("--%s error: invalid --python-version value: %s: at most three version parts are allowed", o.name, pyRepr(val))
		}
		if r := []rune(val); len(parts) == 1 && len(r) > 1 {
			// "37" reads as 3.7.
			parts = []string{string(r[:1]), string(r[1:])}
		}
		for _, p := range parts {
			if !pyInt(p, 10) {
				return fmt.Sprintf("--%s error: invalid --python-version value: %s: each version part must be an integer", o.name, pyRepr(val))
			}
		}
	case pipConfigSettings:
		if !strings.Contains(val, "=") {
			return fmt.Sprintf("Arguments to --%s must be of the form KEY=VAL", o.name)
		}
	case pipGroup:
		if i := strings.LastIndex(val, ":"); i >= 0 && pyPathName(val[:i]) != "pyproject.toml" {
			return fmt.Sprintf("--%s error: group paths use 'pyproject.toml' filenames", o.name)
		}
	case pipNoDash:
		if strings.HasPrefix(val, "-") {
			return fmt.Sprintf("the --%s option requires 1 argument, and its configured value opens with -", o.name)
		}
	case pipUploadedPriorTo:
		if !pipUploadedPriorToKnown(val) {
			return fmt.Sprintf("--%s is set to a value outside the forms doctor interprets (a date as YYYY-MM-DD, a date and time as YYYY-MM-DDTHH:MM:SS with an optional Z or +HH:MM, or a count of days as PnD), and pip's own reading of any other depends on the Python it runs under", o.name)
		}
	}
	return ""
}

func (o pipOpt) choice(val string) string {
	if slices.Contains(o.choices, val) {
		return ""
	}
	quoted := make([]string, len(o.choices))
	for i, c := range o.choices {
		quoted[i] = pyRepr(c)
	}
	return fmt.Sprintf("option %s: invalid choice: %s (choose from %s)", o.name, pyRepr(val), strings.Join(quoted, ", "))
}

// pipTruth reports whether pip's strtobool (pip/_internal/utils/misc.py)
// converts val, to either truth value.
func pipTruth(val string) bool {
	switch strings.ToLower(val) {
	case "y", "yes", "t", "true", "on", "1", "n", "no", "f", "false", "off", "0":
		return true
	}
	return false
}

var pipDaysAgo = regexp.MustCompile(`^P([0-9]+)D\n?$`)

// pipUploadedPriorToKnown reports whether val is an uploaded-prior-to every
// Python that pip 26.2.1 runs on accepts: the PnD form of
// _handle_uploaded_prior_to, short enough that the date it counts back to
// exists, or one of the datetime.fromisoformat forms that do not vary between
// Python 3.9 and now, in years where converting to local time cannot overflow.
func pipUploadedPriorToKnown(val string) bool {
	if m := pipDaysAgo.FindStringSubmatch(val); m != nil {
		days := strings.TrimLeft(m[1], "0")
		return len(days) <= 5
	}
	for _, layout := range []string{"2006-01-02", "2006-01-02T15:04:05", "2006-01-02T15:04:05Z07:00"} {
		if at, err := time.Parse(layout, val); err == nil {
			return at.Year() > 1970 && at.Year() < 9999
		}
	}
	return false
}

// pyPathName is pathlib.PurePosixPath(p).name: the last component, with
// empty and "." components dropped.
func pyPathName(p string) string {
	name := ""
	for _, part := range strings.Split(p, "/") {
		if part != "" && part != "." {
			name = part
		}
	}
	return name
}

// pyRepr quotes s roughly as Python's repr does, for a message that reads
// like pip's own.
func pyRepr(s string) string {
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}

// pySpace is str.isspace for one character, which str.split and str.strip
// go by: Unicode white space and the four ASCII separators FS, GS, RS and US.
func pySpace(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f }

// pyFields is str.split with no argument.
func pyFields(s string) []string { return strings.FieldsFunc(s, pySpace) }

// pyNumeral is the ASCII text CPython's int and float constructors parse a
// str from (_PyUnicode_TransformDecimalAndSpaceToASCII, then the white space
// both constructors skip at either end): a decimal digit of any script is its
// ASCII digit, non-ASCII white space is a space, any other non-ASCII
// character is one no numeral holds.
func pyNumeral(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x7f:
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteByte(' ')
		case unicode.Is(unicode.Nd, r):
			// Every Nd range in Unicode is whole runs of ten, zero first.
			at := int64(r)
			for _, rng := range unicode.Nd.R16 {
				if lo := int64(rng.Lo); at >= lo && at <= int64(rng.Hi) {
					b.WriteString(strconv.FormatInt((at-lo)%10, 10))
				}
			}
			for _, rng := range unicode.Nd.R32 {
				if lo := int64(rng.Lo); at >= lo && at <= int64(rng.Hi) {
					b.WriteString(strconv.FormatInt((at-lo)%10, 10))
				}
			}
		default:
			b.WriteByte('?')
		}
	}
	return strings.Trim(b.String(), " \t\n\r\v\f")
}

// pyDigits reports whether s is one or more digits of base with single
// underscores between them only, CPython's digit grouping.
func pyDigits(s string, base int) bool {
	if s == "" || s[0] == '_' || s[len(s)-1] == '_' || strings.Contains(s, "__") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		d := 99
		switch {
		case c == '_':
			continue
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c|0x20 >= 'a' && c|0x20 <= 'z':
			d = int(c|0x20-'a') + 10
		}
		if d >= base {
			return false
		}
	}
	return true
}

// pyInt reports whether CPython's int(s, base) converts s (PyLong_FromString,
// Objects/longobject.c): an optional sign, the base's own 0x, 0o or 0b prefix
// with an underscore allowed after it, then digits. A decimal past
// sys.int_max_str_digits, 4300 by default, is refused as well.
func pyInt(s string, base int) bool {
	s = pyNumeral(s)
	if s != "" && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}
	prefix := map[int]string{16: "0x", 8: "0o", 2: "0b"}[base]
	if prefix != "" && len(s) >= 2 && strings.EqualFold(s[:2], prefix) {
		s = strings.TrimPrefix(s[2:], "_")
	}
	if !pyDigits(s, base) {
		return false
	}
	return base != 10 || len(strings.ReplaceAll(s, "_", "")) <= 4300
}

// pyFloat reports whether CPython's float(s) converts s (float_from_string
// in Objects/floatobject.c over PyOS_string_to_double): an optional sign,
// then inf, infinity or nan in any case, or a decimal with digits on at least
// one side of an optional point and an optional signed exponent, underscores
// between digits only. An overflowing value is inf, not an error.
func pyFloat(s string) bool {
	s = pyNumeral(s)
	if s != "" && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}
	switch strings.ToLower(s) {
	case "inf", "infinity", "nan":
		return true
	}
	for i := 0; i < len(s); i++ {
		digit := func(j int) bool { return j >= 0 && j < len(s) && s[j] >= '0' && s[j] <= '9' }
		if s[i] == '_' && !(digit(i-1) && digit(i+1)) {
			return false
		}
	}
	s = strings.ReplaceAll(s, "_", "")
	mantissa, exp := s, ""
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		mantissa, exp = s[:i], s[i+1:]
		if exp != "" && (exp[0] == '+' || exp[0] == '-') {
			exp = exp[1:]
		}
		if !pyDigits(exp, 10) {
			return false
		}
	}
	whole, frac, _ := strings.Cut(mantissa, ".")
	if whole == "" && frac == "" {
		return false
	}
	return (whole == "" || pyDigits(whole, 10)) && (frac == "" || pyDigits(frac, 10))
}
