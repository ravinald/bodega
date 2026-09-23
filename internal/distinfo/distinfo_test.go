package distinfo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	sumA = "3bc1906f8d4865bb02c59f2f752e79b08433bc1aa447d78ea3de1a0d02c45e64"
	sumB = "9b8d1ecedd5b5e81fbf1918e876752a7dd948e05c1a0dba10ab863842d45acd5"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func distinfoFor(name, sum string, size int) string {
	return "TIMESTAMP = 1739148475\nSHA256 (" + name + ") = " + sum + "\nSIZE (" + name + ") = " + strconv.Itoa(size) + "\n"
}

// The name inside the parentheses is the key, subdirectory and all. A parser
// that split DIST_SUBDIR off would key pcpustat's file as "1.6.tar.bz2", which
// no request carries, and the check would never fire for it.
func TestParseKeepsDistSubdirInTheName(t *testing.T) {
	got, unusable, err := Parse(strings.NewReader(distinfoFor("pcpustat/1.6.tar.bz2", sumA, 5135)))
	if err != nil || len(unusable) != 0 {
		t.Fatalf("Parse: %v, unusable %v", err, unusable)
	}
	e, ok := got["pcpustat/1.6.tar.bz2"]
	if !ok || e.SHA256 != sumA || e.Size != 5135 {
		t.Fatalf("got %+v, want pcpustat/1.6.tar.bz2 pinned to %s and 5135 bytes", got, sumA)
	}
}

// A filename may hold parentheses, so the split is at the last ") = ".
func TestParseTakesTheLastParenthesis(t *testing.T) {
	got, _, err := Parse(strings.NewReader(distinfoFor("foo (1).zip", sumA, 3)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["foo (1).zip"]; !ok {
		t.Fatalf("got %v, want the name with its parentheses", got)
	}
}

// graphics/epsonscan2-non-free-plugin ships a SIZE line with no "=". That line
// costs its own file and nothing else: the next file in the same distinfo
// still parses, and the broken one is refused as unusable rather than
// reported as unlisted, which would send an operator looking for a port.
func TestParseRefusesOnlyTheNameOnABrokenLine(t *testing.T) {
	body := "SHA256 (a.tar.gz) = " + sumA + "\nSIZE (a.tar.gz) 27507563\n" + distinfoFor("b.tar.gz", sumB, 9)
	got, unusable, err := Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["a.tar.gz"]; ok {
		t.Error("admitted a.tar.gz, whose SIZE line does not parse")
	}
	if _, ok := unusable["a.tar.gz"]; !ok {
		t.Errorf("a.tar.gz is not reported unusable: %v", unusable)
	}
	if _, ok := got["b.tar.gz"]; !ok {
		t.Error("b.tar.gz was lost to its neighbor's broken line")
	}
}

// A digest with no size, or a size with no digest, is half a pin.
func TestParseRefusesHalfAPin(t *testing.T) {
	got, unusable, err := Parse(strings.NewReader("SHA256 (a) = " + sumA + "\nSIZE (b) = 4\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || len(unusable) != 2 {
		t.Fatalf("got %v, unusable %v; want nothing admitted and both refused", got, unusable)
	}
}

// A name that would escape DISTDIR is never recorded, not even as unusable.
func TestParseDropsATraversal(t *testing.T) {
	got, unusable, err := Parse(strings.NewReader(distinfoFor("../../etc/passwd", sumA, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || len(unusable) != 0 {
		t.Fatalf("got %v, unusable %v; a traversal must reach neither", got, unusable)
	}
}

// portsTree builds a small tree carrying every spelling of "do not
// redistribute" a mirror has to read, beside one port that sets none.
func portsTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "Mk/bsd.licenses.db.mk", "_LICENSE_PERMS_DEFAULT=\tdist-mirror dist-sell pkg-mirror pkg-sell auto-accept\n"+
		"_LICENSE_PERMS_CC-BY-NC-4.0=\tdist-mirror pkg-mirror auto-accept\n"+
		"_LICENSE_PERMS_BSD2CLAUSE=\tdist-mirror dist-sell pkg-mirror pkg-sell auto-accept\n")

	write(t, root, "sysutils/pcpustat/Makefile", "PORTNAME=\tpcpustat\nDIST_SUBDIR=\tpcpustat\nLICENSE=\tBSD2CLAUSE\n")
	write(t, root, "sysutils/pcpustat/distinfo", distinfoFor("pcpustat/1.6.tar.bz2", sumA, 5135))

	write(t, root, "games/adom/Makefile", "PORTNAME=\tadom\n.if ${ARCH} == amd64\n\tRESTRICTED=\tno redistribution\n.endif\n")
	write(t, root, "games/adom/distinfo", distinfoFor("adom.tar.gz", sumA, 1))

	write(t, root, "fonts/cdrom/Makefile", "NO_CDROM=\tlicense forbids selling\n")
	write(t, root, "fonts/cdrom/distinfo", distinfoFor("cdrom.tar.gz", sumA, 2))

	// Line continuation: the permission list only withholds dist-sell once
	// the two halves are read as one value.
	write(t, root, "graphics/nosell/Makefile", "LICENSE_PERMS=\tdist-mirror pkg-mirror \\\n\t\tauto-accept\n")
	write(t, root, "graphics/nosell/distinfo", distinfoFor("nosell.tar.gz", sumA, 3))

	write(t, root, "graphics/allperms/Makefile", "LICENSE_PERMS=\tdist-mirror dist-sell pkg-mirror pkg-sell auto-accept\n")
	write(t, root, "graphics/allperms/distinfo", distinfoFor("allperms.tar.gz", sumA, 4))

	write(t, root, "graphics/nonfree/Makefile", "LICENSE_PERMS=\tno-dist-mirror no-dist-sell auto-accept dist-mirror dist-sell\n")
	write(t, root, "graphics/nonfree/distinfo", distinfoFor("nonfree.tar.gz", sumA, 5))

	write(t, root, "fonts/nc/Makefile", "LICENSE=\tCC-BY-NC-4.0\n")
	write(t, root, "fonts/nc/distinfo", distinfoFor("nc.zip", sumA, 6))

	// A slave that is restricted when its master is not: the names sit in
	// the master's distinfo, so the restriction has to travel there.
	write(t, root, "lang/master/Makefile", "PORTNAME=\tmaster\n")
	write(t, root, "lang/master/distinfo", distinfoFor("shared.tar.gz", sumA, 7))
	write(t, root, "lang/slave/Makefile", "MASTERDIR=\t${.CURDIR}/../master\nRESTRICTED=\tslave only\n.include \"${MASTERDIR}/Makefile\"\n")

	// Two ports pinning one name to different bytes.
	write(t, root, "misc/one/distinfo", distinfoFor("same.tar.gz", sumA, 8))
	write(t, root, "misc/two/distinfo", distinfoFor("same.tar.gz", sumB, 8))

	// Two ports agreeing on one name.
	write(t, root, "misc/three/distinfo", distinfoFor("agreed.tar.gz", sumA, 9))
	write(t, root, "misc/four/distinfo", distinfoFor("agreed.tar.gz", sumA, 9))
	return root
}

func TestLoadAdmitsAndRefuses(t *testing.T) {
	ix, err := Load(portsTree(t))
	if err != nil {
		t.Fatal(err)
	}

	e, err := ix.Lookup("pcpustat/1.6.tar.bz2")
	if err != nil || e.SHA256 != sumA || e.Size != 5135 || strings.Join(e.Ports, ",") != "sysutils/pcpustat" {
		t.Errorf("pcpustat: %+v, %v", e, err)
	}
	if e, err := ix.Lookup("agreed.tar.gz"); err != nil || strings.Join(e.Ports, ",") != "misc/four,misc/three" {
		t.Errorf("agreed.tar.gz: %+v, %v; two ports pinning the same bytes should both be named", e, err)
	}
	if _, err := ix.Lookup("allperms.tar.gz"); err != nil {
		t.Errorf("allperms.tar.gz grants dist-mirror and dist-sell and was refused: %v", err)
	}

	for name, want := range map[string]string{
		"adom.tar.gz":    "RESTRICTED",
		"cdrom.tar.gz":   "NO_CDROM",
		"nosell.tar.gz":  "LICENSE_PERMS",
		"nonfree.tar.gz": "LICENSE_PERMS",
		"nc.zip":         "CC-BY-NC-4.0",
		"shared.tar.gz":  "lang/slave",
	} {
		e, err := ix.Lookup(name)
		if !errors.Is(err, ErrRestricted) {
			t.Errorf("%s: %v, want ErrRestricted", name, err)
			continue
		}
		if !strings.Contains(e.Restricted, want) {
			t.Errorf("%s: reason %q does not name %s, so the operator cannot tell which port or variable refused it", name, e.Restricted, want)
		}
	}

	if _, err := ix.Lookup("same.tar.gz"); !errors.Is(err, ErrUnusable) {
		t.Errorf("same.tar.gz: %v, want ErrUnusable for two disagreeing pins", err)
	}
	if _, err := ix.Lookup("nowhere.tar.gz"); !errors.Is(err, ErrNotListed) {
		t.Errorf("nowhere.tar.gz: %v, want ErrNotListed", err)
	}
}

// A directory that is not a ports tree fails loudly, rather than loading as an
// empty index that answers every request "not listed".
func TestLoadRefusesSomethingThatIsNotAPortsTree(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Mk/bsd.licenses.db.mk", "")
	if _, err := Load(root); err == nil {
		t.Error("loaded a tree with no distinfo at all")
	}
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("loaded a tree with no Mk/bsd.licenses.db.mk")
	}
}

// The first read runs in the background; a lookup made during it waits for it
// rather than refusing, and a stale index re-reads without holding the lookup.
func TestTreeReadsInTheBackgroundAndRefreshes(t *testing.T) {
	root := portsTree(t)
	tr := NewTree(root, time.Millisecond, nil)
	if _, err := tr.Lookup("pcpustat/1.6.tar.bz2"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	write(t, root, "misc/new/distinfo", distinfoFor("new.tar.gz", sumB, 1))

	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := tr.Lookup("new.tar.gz")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a file added to the tree was never picked up: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A tree that cannot be read answers ErrNotReady, naming the failure.
func TestTreeReportsAFailedFirstRead(t *testing.T) {
	tr := NewTree(filepath.Join(t.TempDir(), "absent"), 0, nil)
	if err := tr.Wait(); err == nil {
		t.Fatal("Wait returned nil for a tree that does not exist")
	}
	if _, err := tr.Lookup("x"); !errors.Is(err, ErrNotReady) || !strings.Contains(err.Error(), "absent") {
		t.Errorf("Lookup: %v, want ErrNotReady naming the path", err)
	}
}

// Where the lexical read cannot establish what a port declares, it refuses:
// an unresolved LICENSE, a restriction in a file the Makefile includes, and an
// include it cannot follow all fail closed. What it can read still admits.
func TestRestrictionFailsClosedOnWhatItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		refused string // substring of the reason; "" means admitted
	}{
		{"variable license", map[string]string{"Makefile": "PORT_LICENSE=\tCC-BY-NC-4.0\nLICENSE=\t${PORT_LICENSE}\n"}, "cannot be evaluated"},
		{"variable perms name", map[string]string{"Makefile": "LICENSE=\tBSD2CLAUSE\nLICENSE_PERMS_${LICENSE}=\tdist-mirror pkg-mirror\n"}, "LICENSE_PERMS_${LICENSE}"},
		{"unknown license", map[string]string{"Makefile": "LICENSE=\tVENDOR\n"}, "does not define"},
		{"unknown license with full perms", map[string]string{"Makefile": "LICENSE=\tVENDOR\nLICENSE_PERMS_VENDOR=\tdist-mirror dist-sell pkg-mirror pkg-sell\n"}, ""},
		{"relative include", map[string]string{"Makefile": ".include \"redistribution.mk\"\n", "redistribution.mk": "NO_CDROM=\tNo resale\n"}, "NO_CDROM"},
		{"curdir include", map[string]string{"Makefile": ".include \"${.CURDIR}/files/extra.mk\"\n", "files/extra.mk": "RESTRICTED=\tno\n"}, "RESTRICTED"},
		{"sibling port include", map[string]string{"Makefile": ".include \"${.CURDIR:H:H}/lang/master/Makefile.common\"\n"}, "RESTRICTED"},
		{"unresolvable include", map[string]string{"Makefile": ".include \"${WHERE}/x.mk\"\n"}, "cannot be resolved"},
		{"missing include", map[string]string{"Makefile": ".include \"${.CURDIR}/absent.mk\"\n"}, "does not exist"},
		{"include leaving the tree", map[string]string{"Makefile": ".include \"${PORTSDIR}/../outside.mk\"\n"}, "leaves the ports tree"},
		{"optional missing include", map[string]string{"Makefile": "LICENSE=\tBSD2CLAUSE\n.sinclude \"${.CURDIR}/absent.mk\"\n.-include \"absent.mk\"\n"}, ""},
		{"framework include", map[string]string{"Makefile": "LICENSE=\tBSD2CLAUSE\n.include \"${PORTSDIR}/Mk/bsd.port.mk\"\n.include <bsd.port.mk>\n"}, ""},
		{"include cycle", map[string]string{"Makefile": "LICENSE=\tBSD2CLAUSE\n.include \"a.mk\"\n", "a.mk": ".include \"Makefile\"\n"}, "includes itself"},
		{"trailing comment", map[string]string{"Makefile": "LICENSE=\tBSD2CLAUSE # only\n"}, ""},
		{"commented-out restriction", map[string]string{"Makefile": "LICENSE=\tBSD2CLAUSE\n#RESTRICTED=\tonce\n"}, ""},
		{"either branch's master", map[string]string{"Makefile": ".if ${FLAVOR} == a\nMASTERDIR=\t${.CURDIR}/../../lang/master\n.else\nMASTERDIR=\t${.CURDIR}/../../lang/other\n.endif\n.include \"${MASTERDIR}/Makefile.common\"\n"}, "RESTRICTED"},
		{"master's ?= yields to the slave", map[string]string{"Makefile": "MASTERDIR=\t${.CURDIR}/../../lang/master\nMASTERDIR?=\t${.CURDIR}/../../lang/nowhere\n.include \"${MASTERDIR}/Makefile.common\"\n"}, "RESTRICTED"},
		{"reassigned between includes", map[string]string{"Makefile": "D=\t${.CURDIR}/../../lang/other\n.include \"${D}/Makefile.common\"\nD=\t${.CURDIR}/../../lang/master\n.include \"${D}/Makefile.common\"\n"}, "RESTRICTED"},
		{"guarded missing include", map[string]string{"Makefile": "LICENSE=\tBSD2CLAUSE\n.if exists(${.CURDIR}/opt.mk)\n.include \"${.CURDIR}/opt.mk\"\n.endif\n"}, ""},
		{"immediate assignment", map[string]string{"Makefile": "D=\tfiles/restricted.mk\nP:=\t${D}\nD=\tfiles/allowed.mk\n.include \"${P}\"\n", "files/restricted.mk": "NO_CDROM=\tNo resale\n", "files/allowed.mk": "LICENSE=\tBSD2CLAUSE\n"}, "NO_CDROM"},
		{"immediate assignment of an unknown", map[string]string{"Makefile": "P:=\t${WHERE}\n.include \"${.CURDIR}/${P}x.mk\"\n"}, "cannot be resolved"},
		{"repeated include", map[string]string{"Makefile": "D=\tfiles/allowed.mk\n.include \"files/dispatch.mk\"\nD=\tfiles/restricted.mk\n.include \"files/dispatch.mk\"\n", "files/dispatch.mk": ".include \"${.CURDIR}/${D}\"\n", "files/restricted.mk": "NO_CDROM=\tNo resale\n", "files/allowed.mk": "LICENSE=\tBSD2CLAUSE\n"}, "NO_CDROM"},
		{"assignment in a conditionally included file", map[string]string{"Makefile": "D=\tfiles/restricted.mk\n.if ${X} == y\n.include \"files/set.mk\"\n.endif\n.include \"${.CURDIR}/${D}\"\n", "files/set.mk": "D=\tfiles/allowed.mk\n", "files/restricted.mk": "NO_CDROM=\tNo resale\n", "files/allowed.mk": "LICENSE=\tBSD2CLAUSE\n"}, "NO_CDROM"},
		{"?= over a conditional value", map[string]string{"Makefile": ".if ${X} == y\nD=\tfiles/restricted.mk\n.endif\nD?=\tfiles/allowed.mk\n.include \"${.CURDIR}/${D}\"\n", "files/restricted.mk": "NO_CDROM=\tNo resale\n", "files/allowed.mk": "LICENSE=\tBSD2CLAUSE\n"}, "NO_CDROM"},
		{"append in a loop", map[string]string{"Makefile": ".for i in a b\nD+=\t${i}\n.endfor\n.include \"${.CURDIR}/${D}.mk\"\n"}, "cannot be resolved"},
		{"computed name", map[string]string{"Makefile": "D=\tfiles/allowed.mk\nN=\tD\n${N}=\tfiles/restricted.mk\n.include \"${.CURDIR}/${D}\"\n", "files/restricted.mk": "NO_CDROM=\tNo resale\n", "files/allowed.mk": "LICENSE=\tBSD2CLAUSE\n"}, "NO_CDROM"},
		{"computed name from a loop", map[string]string{"Makefile": "D=\tfiles/allowed.mk\n.for n in D\n${n}=\tfiles/restricted.mk\n.endfor\n.include \"${.CURDIR}/${D}\"\n", "files/restricted.mk": "NO_CDROM=\tNo resale\n", "files/allowed.mk": "LICENSE=\tBSD2CLAUSE\n"}, "NO_CDROM"},
		{"unresolvable computed name", map[string]string{"Makefile": "D=\tfiles/allowed.mk\n.for n in ${LIST:O}\n${n}=\tfiles/restricted.mk\n.endfor\n.include \"${.CURDIR}/${D}\"\n", "files/allowed.mk": "LICENSE=\tBSD2CLAUSE\n"}, "cannot be followed"},
		{"computed name elsewhere", map[string]string{"Makefile": "LICENSE=\tBSD2CLAUSE\n.for o in A B\n${o}_DESC=\tx\n.endfor\nD=\tfiles/allowed.mk\n.include \"${.CURDIR}/${D}\"\n", "files/allowed.mk": ""}, ""},
		{"modifier assignment", map[string]string{"Makefile": "D=\tfiles/allowed.mk\n.if ${D::=files/restricted.mk}\n.endif\n.include \"${.CURDIR}/${D}\"\n", "files/allowed.mk": "LICENSE=\tBSD2CLAUSE\n"}, "cannot be followed"},
		{"undef", map[string]string{"Makefile": "D=\tfiles/allowed.mk\n.undef D\n.include \"${.CURDIR}/${D}\"\n"}, "cannot be resolved"},
		{"slave with an if/else master", map[string]string{"Makefile": ".if defined(DEVEL)\nMASTERDIR=\t${.CURDIR}/../../lang/other\n.else\nMASTERDIR=\t${.CURDIR}/../../lang/other\n.endif\n.include \"${MASTERDIR}/Makefile.common\"\n"}, ""},
		{"slave with a ?= master", map[string]string{"Makefile": "MASTERDIR?=\t${.CURDIR}/../../lang/other\n.include \"${MASTERDIR}/Makefile.common\"\n"}, ""},
		{"framework default", map[string]string{"Makefile": "LICENSE=\tBSD2CLAUSE\n.include <bsd.port.options.mk>\n.include \"${FILESDIR}/extra.mk\"\n", "files/extra.mk": "RESTRICTED=\tno\n"}, "RESTRICTED"},
		{"include fan-out", fanOut(10), "more than"},
		{"shell-assigned path", map[string]string{"Makefile": "V!=\techo x\n.include \"${V}.mk\"\n"}, "cannot be resolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := portsTree(t)
			write(t, root, "lang/master/Makefile.common", "RESTRICTED=\tshared terms\n")
			write(t, root, "lang/other/Makefile.common", "LICENSE=\tBSD2CLAUSE\n")
			write(t, root, "Mk/bsd.port.mk", ".include \"${UNDEFINED}/whatever.mk\"\nRESTRICTED=\tframework text is not the port's\n")
			write(t, filepath.Dir(root), "outside.mk", "")
			for rel, body := range tc.files {
				write(t, root, "misc/probe/"+rel, body)
			}
			write(t, root, "misc/probe/distinfo", distinfoFor("probe.tar.gz", sumA, 10))
			ix, err := Load(root)
			if err != nil {
				t.Fatal(err)
			}
			e, err := ix.Lookup("probe.tar.gz")
			if tc.refused == "" {
				if err != nil {
					t.Fatalf("refused a port whose terms are readable: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrRestricted) || !strings.Contains(e.Restricted, tc.refused) {
				t.Fatalf("got %q, %v; want ErrRestricted naming %q", e.Restricted, err, tc.refused)
			}
		})
	}
}

// makeMeaning are Makefiles whose meaning base make on FreeBSD 15.1 settles:
// `make -V NO_CDROM` prints "No resale" for every case with want "NO_CDROM"
// and nothing for every case with want "". Each is a state the reader has to
// hold as make does, or refuse: definedness after an .undef that may not run,
// a .for variable shadowing an outer one only in the loop's own text, and an
// assignment whose name is computed reaching the restriction decision. The
// rest refuse because the reader cannot establish what make would do.
var makeMeaning = []struct {
	name, makefile, want string
}{
	{"conditional undef", "D=files/allowed.mk\n.if 1\n.undef D\n.endif\nD?=files/restricted.mk\n.include \"${D}\"\n", "NO_CDROM"},
	{"conditional undef in an included file", "D=files/allowed.mk\n.include \"files/drop.mk\"\nD?=files/restricted.mk\n.include \"${D}\"\n", "NO_CDROM"},
	{"undef in a loop", "D=files/allowed.mk\n.for i in 1\n.undef D\n.endfor\nD?=files/restricted.mk\n.include \"${D}\"\n", "NO_CDROM"},
	{"empty is still defined", "D=\nD?=files/restricted.mk\n.include \"files/allowed.mk\"\n", ""},
	{"loop shadow", "D=files/allowed.mk\n.for D in files/restricted.mk\n.include \"${D}\"\n.endfor\n", "NO_CDROM"},
	{"loop variable with a modifier", "D=files/allowed.mk\n.for D in files/x/restricted.mk\n.include \"${D:H:H}/restricted.mk\"\n.endfor\n", "NO_CDROM"},
	{"loop list from a variable", "L=files/allowed.mk files/restricted.mk\n.for D in ${L}\n.include \"${D}\"\n.endfor\n", "NO_CDROM"},
	{"loop variable kept past the loop", ".for D in files/restricted.mk\nX=${D}\n.endfor\n.include \"${X}\"\n", "NO_CDROM"},
	{"nested loop shadow", "D=files/allowed.mk\n.for D in files/restricted.mk\n.for D in files/allowed.mk\n.include \"${D}\"\n.endfor\n.endfor\n", "NO_CDROM"},
	{"nested loop shadowed by the outer", "D=files/restricted.mk\n.for D in files/allowed.mk\n.for D in files/restricted.mk\n.include \"${D}\"\n.endfor\n.endfor\n", ""},
	{"two loop variables", ".for A D in files/allowed.mk files/restricted.mk\n.include \"${D}\"\n.endfor\n", "NO_CDROM"},
	{"outer variable through another", "D=files/allowed.mk\nX=${D}\n.for D in files/missing.mk\n.include \"${X}\"\n.endfor\n", ""},
	{"computed restriction", "N=NO_CDROM\n${N}=No resale\n", "NO_CDROM"},
	{"computed restriction from a loop", ".for N in NO_CDROM\n${N}=No resale\n.endfor\n", "NO_CDROM"},
	{"computed name with a spaced modifier", "N=NO_X\n${N:S/X/CDROM/:S/ / /}=No resale\n", "may set"},
	{"computed name in an included file", ".include \"files/computed.mk\"\n", "NO_CDROM"},
	{"unresolvable computed prefix", "NO_${UNKNOWN}=No resale\n", "may set"},
	{"unresolvable computed name", "${UNKNOWN}=No resale\n", "may set"},
	{"unresolvable computed license permissions", "LICENSE_PERMS_${UNKNOWN}=dist-mirror dist-sell pkg-mirror pkg-sell\n", "may set"},
	{"unresolvable computed name set before the license it matches", "${UNKNOWN}_BSD2CLAUSE=dist-mirror\nLICENSE+=BSD2CLAUSE\n", "may set LICENSE_PERMS_BSD2CLAUSE"},
	{"unresolvable computed suffix elsewhere", "${UNKNOWN}_DESC=x\n", ""},
	{"nested computed suffix elsewhere", "CMAKE_${\"${FLAVOR:Mx}\":?ON:OFF}=\tX\n", ""},
	{"one-letter loop variable", ".for o in NO_CDROM\n$o=No resale\n.endfor\n", "NO_CDROM"},
	{"one-letter loop variable elsewhere", ".for o in A B\n$o_DESC=x\n.endfor\n", ""},
	{"escaped dollar is not a loop variable", "D=files/allowed.mk\n.for D in files/restricted.mk\nX=$$D\n.endfor\n.include \"${D}\"\n", ""},
	{"modifier assignment to a restriction", "X:=${NO_CDROM::=No resale}\n", "may set NO_CDROM"},
	{"underscore modifier", "D=files/allowed.mk\n.if ${:Ufiles/restricted.mk:_=D}\n.endif\n.include \"${D}\"\n", "cannot be followed"},
}

// A restriction make reaches is one the reader reaches, or the port refuses.
func TestRestrictionHoldsMakesMeaning(t *testing.T) {
	for _, tc := range makeMeaning {
		t.Run(tc.name, func(t *testing.T) {
			root := portsTree(t)
			write(t, root, "sysutils/pcpustat/Makefile", "LICENSE=\tBSD2CLAUSE\n"+tc.makefile)
			write(t, root, "sysutils/pcpustat/files/restricted.mk", "NO_CDROM=No resale\n")
			write(t, root, "sysutils/pcpustat/files/allowed.mk", "PORTNAME=pcpustat\n")
			write(t, root, "sysutils/pcpustat/files/drop.mk", ".if 1\n.undef D\n.endif\n")
			write(t, root, "sysutils/pcpustat/files/computed.mk", "N=NO_CDROM\n${N}=No resale\n")
			ix, err := Load(root)
			if err != nil {
				t.Fatal(err)
			}
			e, err := ix.Lookup("pcpustat/1.6.tar.bz2")
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused a port make does not restrict: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrRestricted) || !strings.Contains(e.Restricted, tc.want) {
				t.Fatalf("got %q, %v; want ErrRestricted naming %q", e.Restricted, err, tc.want)
			}
		})
	}
}

// fanOut is a port whose every file includes the next one twice, which make
// reads 2^depth times and the reader has to stop well before.
func fanOut(depth int) map[string]string {
	files := map[string]string{"Makefile": "LICENSE=\tBSD2CLAUSE\n.include \"f0.mk\"\n.include \"f0.mk\"\n"}
	for i := range depth {
		next := fmt.Sprintf("f%d.mk", i+1)
		files[fmt.Sprintf("f%d.mk", i)] = fmt.Sprintf(".include %q\n.include %q\n", next, next)
	}
	files[fmt.Sprintf("f%d.mk", depth)] = ""
	return files
}
