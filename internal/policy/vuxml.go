package policy

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ulikunitz/xz"
)

// DefaultVuXMLURL is FreeBSD's advisory feed, the document `pkg audit` reads
// and the one a FreeBSD host names as VULNXML_SITE.
const DefaultVuXMLURL = "https://vuxml.freebsd.org/freebsd/vuln.xml.xz"

// VuXMLEcosystem is the advisory database a FreeBSD package is matched in. OSV
// publishes no FreeBSD ecosystem, so the name is bodega's own: it keys the
// archive `policy osv sync` writes, and no lookup sends it to api.osv.dev.
const VuXMLEcosystem = "FreeBSD"

// FreeBSDABIKey names, on a version entry the freebsd object gate builds, the
// ABI the package was served for. Its presence is what marks the entry as a
// package: a freebsd manifest entry is a repository at an ABI, whose version
// is the ABI string, and no advisory is written against that.
const FreeBSDABIKey = "freebsd_abi"

// vuxmlBound is one comparison of a VuXML <range>: lt, le, eq, ge or gt
// against a version in pkg's ordering.
type vuxmlBound struct {
	Op      string `json:"op"`
	Version string `json:"v"`
}

// vuxmlRange is one <range>, whose bounds all have to hold. A range with no
// bounds covers every version, which is what VuXML means by a <package> that
// names no range.
type vuxmlRange []vuxmlBound

func (r vuxmlRange) affects(order, version string) (matched bool, unorderable string) {
	for _, b := range r {
		c, ok := compareVersions(order, version, b.Version)
		if !ok {
			return false, b.Version
		}
		var hold bool
		switch b.Op {
		case "lt":
			hold = c < 0
		case "le":
			hold = c <= 0
		case "eq":
			hold = c == 0
		case "ge":
			hold = c >= 0
		case "gt":
			hold = c > 0
		default:
			return false, b.Op + " " + b.Version
		}
		if !hold {
			return false, ""
		}
	}
	return true, ""
}

// vuxmlVuln is the part of one <vuln> the gate reads. The description and
// references are prose for a person and are dropped, as distill drops OSV's.
type vuxmlVuln struct {
	VID       string    `xml:"vid,attr"`
	Topic     string    `xml:"topic"`
	Cancelled *struct{} `xml:"cancelled"`
	Packages  []struct {
		Names  []string `xml:"name"`
		Ranges []struct {
			Lt []string `xml:"lt"`
			Le []string `xml:"le"`
			Eq []string `xml:"eq"`
			Ge []string `xml:"ge"`
			Gt []string `xml:"gt"`
		} `xml:"range"`
	} `xml:"affects>package"`
}

// distillVuXML reads a VuXML document, xz-compressed or not, into the index
// the OSV gate matches against, keyed by package name. Base-system entries
// (<system>) are left out: they describe FreeBSD itself, which is not a
// package bodega serves. A cancelled entry is dropped for the reason a
// withdrawn OSV record is.
func distillVuXML(path string) (*osvIndex, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var in io.Reader = br
	if magic, _ := br.Peek(6); bytes.Equal(magic, []byte{0xfd, '7', 'z', 'X', 'Z', 0}) {
		xr, err := xz.NewReader(br)
		if err != nil {
			return nil, 0, fmt.Errorf("read %s: %w", path, err)
		}
		in = xr
	}

	idx := &osvIndex{Ecosystem: VuXMLEcosystem, Packages: map[string]osvRecordList{}}
	records := 0
	patterns := map[string]bool{}
	//nolint:gosec // G709: the feed decodes into vuxmlVuln's fixed fields and
	// nothing else; no type is chosen by the document, and every value it
	// yields is a string compared, never executed or used as a path.
	dec := xml.NewDecoder(in)
	// The descriptions are XHTML and carry its named entities; a strict
	// decoder stops at the first &nbsp; in a field the gate never reads.
	dec.Strict = false
	dec.Entity = xml.HTMLEntity
	sawVuln := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("parse %s: %w", path, err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "vuln" {
			continue
		}
		sawVuln = true
		var v vuxmlVuln
		if err := dec.DecodeElement(&v, &start); err != nil {
			return nil, 0, fmt.Errorf("parse %s: %w", path, err)
		}
		if v.VID == "" || v.Cancelled != nil {
			continue
		}
		topic := strings.Join(strings.Fields(v.Topic), " ")
		byKey := map[string]osvAffectedList{}
		for _, p := range v.Packages {
			var ranges []vuxmlRange
			for _, r := range p.Ranges {
				var rng vuxmlRange
				for _, op := range []struct {
					name string
					vs   []string
				}{{"lt", r.Lt}, {"le", r.Le}, {"eq", r.Eq}, {"ge", r.Ge}, {"gt", r.Gt}} {
					for _, ver := range op.vs {
						rng = append(rng, vuxmlBound{Op: op.name, Version: strings.TrimSpace(ver)})
					}
				}
				ranges = append(ranges, rng)
			}
			if len(ranges) == 0 {
				ranges = []vuxmlRange{{}}
			}
			for _, name := range p.Names {
				key := osvPackageKey(VuXMLEcosystem, strings.TrimSpace(name))
				if key == "" {
					continue
				}
				byKey[key] = append(byKey[key], osvAffected{VuXML: ranges})
				if isVuXMLPattern(key) && !patterns[key] {
					patterns[key] = true
					idx.Patterns = append(idx.Patterns, key)
				}
			}
		}
		if len(byKey) == 0 {
			continue
		}
		records++
		for key, affected := range byKey {
			idx.Packages[key] = append(idx.Packages[key], &osvRecord{ID: v.VID, Summary: topic, Affected: affected})
		}
	}
	if !sawVuln {
		return nil, 0, fmt.Errorf("%s holds no <vuln> entry, so it is not a VuXML document", path)
	}
	sort.Strings(idx.Patterns)
	return idx, records, nil
}

// isVuXMLPattern reports whether a VuXML <name> holds a character fnmatch(3)
// reads as a glob, the set pkg's pkg_audit_str_noglob_len stops at.
func isVuXMLPattern(name string) bool {
	return strings.ContainsAny(name, `*?[\`)
}

// vuxmlNameMatches is pkg audit's fnmatch(pattern, name, 0), ported from
// FreeBSD 15's lib/libc/gen/fnmatch.c in the C locale and used for every ABI,
// so sync, fetch checks and simulation agree on one dialect. It is a port
// rather than a translation into path.Match because the two disagree on
// bracket expressions fnmatch accepts and path.Match rejects as malformed
// ("[]a]", "[-ab]", "[ab-]"), and a rejected pattern would read as no
// advisory. With flags 0 the match is case-sensitive, '/' and a leading '.'
// are ordinary, a backslash escapes the byte after it, and a pattern ending in
// a lone backslash matches nothing. The C locale reads every byte as one
// character, so bytes above 0x7f compare as themselves and belong to no
// character class. FreeBSD 14 does not read
// "[:class:]", "[=c=]" or "[.c.]" inside a bracket expression, so a 14 host's
// pkg audit can disagree on a pattern that uses one.
func vuxmlNameMatches(pattern, name string) bool {
	pattern, name = cString(pattern), cString(name)
	p, s := 0, 0
	btP, btS := -1, 0
	for {
		pc := byteAt(pattern, p)
		if pc != 0 {
			p++
		}
		sc := byteAt(name, s)
		ok := false
		switch pc {
		case 0:
			if sc == 0 {
				return true
			}
		case '?':
			if sc == 0 {
				return false
			}
			s++
			continue
		case '*':
			for byteAt(pattern, p) == '*' {
				p++
			}
			if p == len(pattern) {
				return true
			}
			btP, btS = p, s
			continue
		case '[':
			if sc == 0 {
				return false
			}
			next, res := fnmatchBracket(pattern, p, sc)
			if res == bracketMatch {
				p, s = next, s+1
				continue
			}
			ok = res == bracketMalformed && sc == '['
		case '\\':
			pc = byteAt(pattern, p)
			if pc == 0 {
				return false
			}
			p++
			ok = sc != 0 && pc == sc
		default:
			ok = sc != 0 && pc == sc
		}
		if ok {
			s++
			continue
		}
		if btP < 0 || btS >= len(name) {
			return false
		}
		btS++
		p, s = btP, btS
	}
}

// cString cuts s at its first NUL, where C stops reading it.
func cString(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return s[:i]
	}
	return s
}

func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

type bracketResult int

const (
	bracketNoMatch bracketResult = iota
	bracketMatch
	// bracketMalformed is fnmatch.c's RANGE_ERROR, which fnmatch reads as a
	// literal '['.
	bracketMalformed
)

// fnmatchCClasses is wctype(3)'s class set in FreeBSD's C locale, each test
// measured against releng/15.0 libc for bytes 1-255. "ideogram", "special"
// and "phonogram" are valid names that select nothing there.
var fnmatchCClasses = map[string]func(byte) bool{
	"alnum":     func(b byte) bool { return isCAlpha(b) || isCDigit(b) },
	"alpha":     isCAlpha,
	"blank":     func(b byte) bool { return b == ' ' || b == '\t' },
	"cntrl":     func(b byte) bool { return b < 0x20 || b == 0x7f },
	"digit":     isCDigit,
	"graph":     func(b byte) bool { return b > ' ' && b < 0x7f },
	"lower":     func(b byte) bool { return b >= 'a' && b <= 'z' },
	"print":     func(b byte) bool { return b >= ' ' && b < 0x7f },
	"punct":     func(b byte) bool { return b > ' ' && b < 0x7f && !isCAlpha(b) && !isCDigit(b) },
	"space":     func(b byte) bool { return b == ' ' || (b >= '\t' && b <= '\r') },
	"upper":     func(b byte) bool { return b >= 'A' && b <= 'Z' },
	"xdigit":    func(b byte) bool { return isCDigit(b) || (b|0x20 >= 'a' && b|0x20 <= 'f') },
	"ideogram":  func(byte) bool { return false },
	"special":   func(byte) bool { return false },
	"phonogram": func(byte) bool { return false },
	"number":    isCDigit,
	"rune":      func(b byte) bool { return b < 0x80 },
}

func isCAlpha(b byte) bool { return b|0x20 >= 'a' && b|0x20 <= 'z' }
func isCDigit(b byte) bool { return b >= '0' && b <= '9' }

// fnmatchBracket is FreeBSD 15 fnmatch.c's rangematch in the C locale: it
// reads the bracket expression starting at pattern[p], just past the '[',
// against test and returns the index past its closing ']'. A leading '!' or
// '^' negates it; a ']' first in the list (after any negation) is a literal;
// a '-' first or last is a literal; a backslash escapes the byte after it.
// "[:name:]" is a character class, and "[.c.]" and "[=c=]" each name the one
// ASCII byte c. A class or "[=c=]" cannot bound a range, and because
// rangematch keeps the last such opener in one variable, every range after
// one in the same expression is malformed too ("[[:alpha:]a-z]"). After the
// first element that matches, the rest of the expression is skipped without
// honoring backslashes, as rangematch skips it. releng/15.0 leaves that
// variable uninitialized, so a range in an expression with no earlier '['
// element reads whatever the previous call left behind, and one pkg process
// can answer the same pattern differently over its life; this port takes the
// answer a fresh process gives, with nothing remembered.
func fnmatchBracket(pattern string, p int, test byte) (int, bracketResult) {
	at := func(i int) byte { return byteAt(pattern, i) }
	negate := at(p) == '!' || at(p) == '^'
	if negate {
		p++
	}
	matched := false
	first := p
	var special byte
scan:
	for {
		var c byte
		switch b := at(p); {
		case b == ']' && p > first:
			break scan
		case b == 0:
			return 0, bracketMalformed
		case b == '\\':
			p++
		case b == '[':
			special = at(p + 1)
			if special != '.' && special != '=' && special != ':' {
				break
			}
			p += 2
			cp := fnmatchSpecialEnd(pattern, p, special)
			if cp < 0 {
				return 0, bracketMalformed
			}
			if special == ':' {
				if at(cp+2) == '-' && at(cp+3) != 0 && at(cp+3) != ']' {
					return 0, bracketMalformed
				}
				class, known := fnmatchCClasses[pattern[p:cp]]
				if !known {
					return 0, bracketMalformed
				}
				p = cp + 2
				if class(test) {
					matched = true
					break scan
				}
				continue
			}
			if cp-p != 1 || pattern[p] >= 0x80 {
				return 0, bracketMalformed
			}
			c = pattern[p]
			p = cp + 2
		}
		if c == 0 {
			c = at(p)
			if c != 0 {
				p++
			}
		}
		if at(p) == '-' && at(p+1) != 0 && at(p+1) != ']' {
			p++
			if at(p) == '\\' {
				p++
			}
			c2 := at(p)
			if c2 == 0 {
				return 0, bracketMalformed
			}
			p++
			if c2 == '[' {
				special = at(p)
			}
			if (c2 == '[' && special == '.') || special == '=' || special == ':' {
				if special != '.' {
					return 0, bracketMalformed
				}
				p++
				cp := fnmatchSpecialEnd(pattern, p, '.')
				if cp < 0 || cp-p != 1 || pattern[p] >= 0x80 {
					return 0, bracketMalformed
				}
				c2 = pattern[p]
				p = cp + 2
			}
			if c <= test && test <= c2 {
				matched = true
				break
			}
		} else if c == test {
			matched = true
			break
		}
	}
	special = 0
	for at(p) != ']' {
		b := at(p)
		switch {
		case b == 0:
			return 0, bracketMalformed
		case b == special:
			p++
			if at(p) == ']' {
				special = 0
				p++
			}
		case special == 0 && b == '[':
			p++
			special = at(p)
			if special != '.' && special != '=' && special != ':' {
				special = 0
			} else {
				p++
			}
		default:
			p++
		}
	}
	if matched == negate {
		return p + 1, bracketNoMatch
	}
	return p + 1, bracketMatch
}

// fnmatchSpecialEnd returns the index of the first special byte at or after
// p that a ']' follows, searching to the end of the pattern as rangematch's
// strchr does, or -1.
func fnmatchSpecialEnd(pattern string, p int, special byte) int {
	for p < len(pattern) {
		i := strings.IndexByte(pattern[p:], special)
		if i < 0 {
			return -1
		}
		if byteAt(pattern, p+i+1) == ']' {
			return p + i
		}
		p += i + 1
	}
	return -1
}

// pkgVersion is a FreeBSD package version split as pkg-version(8) splits it:
// the port version, the port revision after the last underscore and the epoch
// after the comma that follows it.
type pkgVersion struct {
	version  string
	revision uint64
	epoch    uint64
}

// parsePkgVersion splits v, which may carry a package name ("openssl-3.0.15_1,1"):
// pkg reads the version from after the last hyphen, so the two spellings
// compare equal.
func parsePkgVersion(v string) pkgVersion {
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		v = v[i+1:]
	}
	out := pkgVersion{version: v}
	tail := v
	if i := strings.LastIndexByte(v, '_'); i >= 0 {
		out.version, tail = v[:i], v[i+1:]
		out.revision = leadingUint(tail)
	}
	if i := strings.LastIndexByte(tail, ','); i >= 0 {
		out.epoch = leadingUint(tail[i+1:])
		if tail == v {
			out.version = v[:i]
		}
	}
	return out
}

// leadingUint is strtoul's reading of s: the leading digits, or 0.
func leadingUint(s string) uint64 {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	n, _ := strconv.ParseUint(s[:end], 10, 64)
	return n
}

// comparePkgVersions orders two FreeBSD package versions the way
// pkg_version_cmp does: the epoch first, then the port version component by
// component, then the port revision. Every string has a place in that order,
// so the second return is always true.
//
// Checked against pkg 2.8.4's `pkg version -t` on FreeBSD 15.1, 2026-11-08:
// 3.0.15_1,1 > 3.0.15,1; 2.0 < 1.0,1; 1.0alpha1 < 1.0; 1.0a > 1.0;
// 1.0pl1 < 1.0; 1.0rc1 > 1.0beta2; 1.0.b < 1.0b; 1.0.0b > 1.0.0.b;
// 1.0.r = 1.0rc; 1.0+ = 1.0; 1.0 = 1.0.0; 5.36.0.1 > 5.36.0_1.
func comparePkgVersions(a, b string) (int, bool) {
	va, vb := parsePkgVersion(a), parsePkgVersion(b)
	if va.epoch != vb.epoch {
		return cmpUint(va.epoch, vb.epoch), true
	}
	if c := comparePkgPortVersion(va.version, vb.version); c != 0 {
		return c, true
	}
	return cmpUint(va.revision, vb.revision), true
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// pkgComponent is one component of a port version: a number, a letter or
// stage, and a trailing number. n is -1 for a component opening on a letter
// and -2 for '*'; pl is -1 for a letter with no number after it.
type pkgComponent struct {
	n, a, pl int64
}

// pkgStages are the words pkg reads as one letter: "pl" sorts below every
// letter and the rest as their initial's place in the alphabet, which puts
// alpha below beta below pre below rc below snap. Each still sorts below the
// release, because a stage opens a component whose number is -1.
var pkgStages = []struct {
	name  string
	value int64
}{
	{"pl", 0},
	{"snap", 's' - 'a' + 1},
	{"alpha", 1},
	{"beta", 'b' - 'a' + 1},
	{"pre", 'p' - 'a' + 1},
	{"rc", 'r' - 'a' + 1},
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

func isASCIIAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// nextPkgComponent is pkg's get_component: it reads one component from s and
// returns what is left. A stage word directly after a number ends the
// component there, as if a dot stood between them, which is why 1.0alpha1
// sorts below 1.0.
func nextPkgComponent(s string) (pkgComponent, string) {
	var c pkgComponent
	i := 0
	hasStage := false
	switch {
	case i < len(s) && isASCIIDigit(s[i]):
		j := i
		for j < len(s) && isASCIIDigit(s[j]) {
			j++
		}
		c.n, _ = strconv.ParseInt(s[i:j], 10, 64)
		i = j
	case i < len(s) && s[i] == '*':
		c.n = -2
		for i < len(s) && s[i] != '+' {
			i++
		}
	default:
		c.n = -1
		hasStage = true
	}

	hasPatchLevel := false
	if i < len(s) && isASCIIAlpha(s[i]) {
		hasPatchLevel = true
		matched := false
		for _, st := range pkgStages {
			end := i + len(st.name)
			if end <= len(s) && strings.EqualFold(s[i:end], st.name) && (end == len(s) || !isASCIIAlpha(s[end])) {
				matched = true
				if hasStage {
					c.a = st.value
					i = end
				} else {
					hasPatchLevel = false
				}
				break
			}
		}
		if !matched {
			c.a = int64(lowerASCII(s[i])-'a') + 1
			for i < len(s) && isASCIIAlpha(s[i]) {
				i++
			}
		}
	}

	if hasPatchLevel {
		if i < len(s) && isASCIIDigit(s[i]) {
			j := i
			for j < len(s) && isASCIIDigit(s[j]) {
				j++
			}
			c.pl, _ = strconv.ParseInt(s[i:j], 10, 64)
			i = j
		} else {
			c.pl = -1
		}
	}

	for i < len(s) && !isASCIIDigit(s[i]) && !isASCIIAlpha(s[i]) && s[i] != '+' && s[i] != '*' {
		i++
	}
	return c, s[i:]
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// comparePkgPortVersion compares two port versions component by component. A
// side that has run out, or reached a '+', compares as a zero component, and
// the '+' itself is skipped once both sides stand on one.
func comparePkgPortVersion(a, b string) int {
	if strings.EqualFold(a, b) {
		return 0
	}
	for a != "" || b != "" {
		var ca, cb pkgComponent
		blockA, blockB := a == "" || a[0] == '+', b == "" || b[0] == '+'
		if !blockA {
			ca, a = nextPkgComponent(a)
		}
		if !blockB {
			cb, b = nextPkgComponent(b)
		}
		switch {
		case blockA && blockB:
			if a != "" {
				a = a[1:]
			}
			if b != "" {
				b = b[1:]
			}
		case ca.n != cb.n:
			return cmpInt64(ca.n, cb.n)
		case ca.a != cb.a:
			return cmpInt64(ca.a, cb.a)
		case ca.pl != cb.pl:
			return cmpInt64(ca.pl, cb.pl)
		}
	}
	return 0
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
