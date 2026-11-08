package policy

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path"
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

// vuxmlNameMatches is pkg audit's fnmatch(pattern, name, 0): case-sensitive,
// and with no special meaning for '/', which no package name carries. A
// malformed pattern matches nothing, as fnmatch's refusal does in pkg.
func vuxmlNameMatches(pattern, name string) bool {
	ok, err := path.Match(fnmatchToGo(pattern), name)
	return err == nil && ok
}

// fnmatchToGo rewrites fnmatch's "[!" class negation as path.Match's "[^",
// which fnmatch also accepts; every other construct means the same in both.
func fnmatchToGo(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		b.WriteByte(c)
		switch {
		case c == '\\' && i+1 < len(pattern):
			i++
			b.WriteByte(pattern[i])
		case c == '[' && i+1 < len(pattern) && pattern[i+1] == '!':
			i++
			b.WriteByte('^')
		}
	}
	return b.String()
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
