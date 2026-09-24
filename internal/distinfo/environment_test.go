package distinfo

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// aspellTree adds the shape of textproc/aspell/Makefile.inc at the stock 15.1
// tree: a dictionary port that includes the framework, then a file on the
// client host under ${LOCALBASE}, guarded by exists().
func aspellTree(t *testing.T) string {
	t.Helper()
	root := portsTree(t)
	write(t, root, "textproc/aspell/Makefile.inc", "LICENSE=\tBSD2CLAUSE\n.include <bsd.port.pre.mk>\n.if exists(${LOCALBASE}/etc/aspell.ver)\n. include \"${LOCALBASE}/etc/aspell.ver\"\n.endif\n")
	write(t, root, "arabic/aspell/Makefile", "PORTNAME=\taspell\n.include \"${.CURDIR}/../../textproc/aspell/Makefile.inc\"\n.include <bsd.port.post.mk>\n")
	write(t, root, "arabic/aspell/distinfo", distinfoFor("aspell6-ar-1.2-0.tar.bz2", sumA, 10))
	return root
}

func snapshot(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "aspell.ver")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func loadWith(t *testing.T, root string, spec EnvironmentSpec) *Index {
	t.Helper()
	env, err := spec.Load()
	if err != nil {
		t.Fatal(err)
	}
	ix, err := LoadIn(root, env)
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

// The F24 witness: base make on the stock arabic/aspell reads its own distinfo
// with no host file, and pcpustat's distinfo and NO_CDROM once
// ${LOCALBASE}/etc/aspell.ver holds two lines. The tree is the same in both.
// Only a declared environment may admit pcpustat, and a declaration carrying
// that file, alone or as one alternative, must restrict pcpustat's name.
func TestEnvironmentDecidesTheAspellWitness(t *testing.T) {
	root := aspellTree(t)
	hostile := func(distinfo string) string {
		return "DISTINFO_FILE=" + distinfo + "\nNO_CDROM=host file\n"
	}
	localbase := map[string][]string{"LOCALBASE": {"/usr/local"}}
	for name, tc := range map[string]struct {
		spec EnvironmentSpec
		want string // "" admits pcpustat
	}{
		"nothing declared":                 {EnvironmentSpec{}, "cannot be resolved"},
		"LOCALBASE declared, the file not": {EnvironmentSpec{Variables: localbase}, "does not declare it"},
		"file declared absent":             {EnvironmentSpec{Variables: localbase, Files: map[string][]string{"/usr/local/etc/aspell.ver": {Absent}}}, ""},
		"file declared as the witness": {EnvironmentSpec{Variables: localbase, Files: map[string][]string{
			"/usr/local/etc/aspell.ver": {snapshot(t, hostile("${PORTSDIR}/sysutils/pcpustat/distinfo"))},
		}}, "arabic/aspell sets NO_CDROM=host file"},
		"witness as one alternative": {EnvironmentSpec{Variables: localbase, Files: map[string][]string{
			"/usr/local/etc/aspell.ver": {Absent, snapshot(t, hostile("${PORTSDIR}/sysutils/pcpustat/distinfo"))},
		}}, "arabic/aspell sets NO_CDROM=host file"},
		"witness naming the tree by its absolute path": {EnvironmentSpec{Variables: localbase, Files: map[string][]string{
			"/usr/local/etc/aspell.ver": {snapshot(t, hostile(filepath.Join(root, "sysutils/pcpustat/distinfo")))},
		}}, "arabic/aspell sets NO_CDROM=host file"},
		// The client's tree is at /usr/ports and this one is not, so the
		// path names nothing Load indexes. It must not name nothing at all.
		"witness naming a tree bodega does not read": {EnvironmentSpec{Variables: localbase, Files: map[string][]string{
			"/usr/local/etc/aspell.ver": {snapshot(t, hostile("/nonexistent/ports/sysutils/pcpustat/distinfo"))},
		}}, "not a <category>/<port> directory"},
	} {
		t.Run(name, func(t *testing.T) {
			ix := loadWith(t, root, tc.spec)
			e, err := ix.Lookup("pcpustat/1.6.tar.bz2")
			if tc.want == "" {
				if err != nil {
					t.Fatalf("pcpustat: %v, want admitted", err)
				}
				if e.SHA256 != sumA || e.Size != 5135 {
					t.Fatalf("pcpustat = %+v, want its own pin", e)
				}
				if _, err := ix.Lookup("aspell6-ar-1.2-0.tar.bz2"); err != nil {
					t.Errorf("aspell's own distfile: %v, want admitted", err)
				}
				return
			}
			if !errors.Is(err, ErrRestricted) || !strings.Contains(err.Error()+" "+strings.Join(ix.Unowned(), " "), tc.want) {
				t.Fatalf("pcpustat: %v (unowned %q), want ErrRestricted naming %q", err, ix.Unowned(), tc.want)
			}
		})
	}
}

// The server's own filesystem is never the client's. A file at the path the
// port includes, present on the server, is not read in place of a declaration
// and does not stand in for one.
func TestEnvironmentNeverReadsTheServerHost(t *testing.T) {
	root := aspellTree(t)
	host := t.TempDir()
	write(t, host, "etc/aspell.ver", "NO_CDROM=server host file\n")
	vars := map[string][]string{"LOCALBASE": {host}}

	ix := loadWith(t, root, EnvironmentSpec{Variables: vars})
	if _, err := ix.Lookup("pcpustat/1.6.tar.bz2"); !errors.Is(err, ErrRestricted) || strings.Contains(err.Error(), "server host file") {
		t.Fatalf("undeclared: %v, want refused without reading the server's file", err)
	}

	ix = loadWith(t, root, EnvironmentSpec{Variables: vars, Files: map[string][]string{filepath.Join(host, "etc/aspell.ver"): {Absent}}})
	if _, err := ix.Lookup("aspell6-ar-1.2-0.tar.bz2"); err != nil {
		t.Fatalf("declared absent: %v, want admitted: the declaration, not the server's file, decides", err)
	}
}

// The audit11 witness: a literal client-host path, missing on the server,
// under .sinclude and under exists(). Server-side absence was read as
// harmless; only a declaration may say it is.
func TestEnvironmentLiteralHostInclude(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "client-input", "terms.mk")
	for name, makefile := range map[string]string{
		"sinclude":       ".sinclude \"" + outside + "\"\n",
		"exists guarded": ".if exists(" + outside + ")\n.include \"" + outside + "\"\n.endif\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := portsTree(t)
			write(t, root, "lang/probe/Makefile", "LICENSE=\tBSD2CLAUSE\n"+makefile+"DISTINFO_FILE=\t${.CURDIR}/../../sysutils/pcpustat/distinfo\n.include <bsd.port.mk>\n")
			ix := loadWith(t, root, EnvironmentSpec{})
			if _, err := ix.Lookup("pcpustat/1.6.tar.bz2"); !errors.Is(err, ErrRestricted) {
				t.Fatalf("undeclared: %v, want refused", err)
			}
			ix = loadWith(t, root, EnvironmentSpec{Files: map[string][]string{outside: {Absent}}})
			if _, err := ix.Lookup("pcpustat/1.6.tar.bz2"); err != nil {
				t.Fatalf("declared absent: %v, want admitted", err)
			}
			ix = loadWith(t, root, EnvironmentSpec{Files: map[string][]string{outside: {Absent, snapshot(t, "NO_CDROM=client host terms\n")}}})
			if _, err := ix.Lookup("pcpustat/1.6.tar.bz2"); !errors.Is(err, ErrRestricted) || !strings.Contains(err.Error(), "client host terms") {
				t.Fatalf("declared as a restriction: %v, want refused naming it", err)
			}
		})
	}
}

// A variable declared undefined expands to nothing, as make expands it, and
// one the environment does not mention still refuses.
func TestEnvironmentVariables(t *testing.T) {
	for name, tc := range map[string]struct {
		vars map[string][]string
		want string
	}{
		"undeclared":         {nil, "cannot be resolved"},
		"declared undefined": {map[string][]string{"SUFFIX": {}}, ""},
		"declared values":    {map[string][]string{"SUFFIX": {"", "-restricted"}}, "RESTRICTED"},
	} {
		t.Run(name, func(t *testing.T) {
			root := portsTree(t)
			write(t, root, "lang/restricted/Makefile.common", "RESTRICTED=\tshared terms\n")
			write(t, root, "lang/probe/Makefile", "LICENSE=\tBSD2CLAUSE\n.sinclude \"${.CURDIR}/../${SUFFIX:C/-//}/Makefile.common\"\n")
			write(t, root, "lang/probe/distinfo", distinfoFor("probe.tar.gz", sumA, 11))
			ix := loadWith(t, root, EnvironmentSpec{Variables: tc.vars})
			_, err := ix.Lookup("probe.tar.gz")
			if tc.want == "" {
				if err != nil {
					t.Fatalf("%v, want admitted", err)
				}
				return
			}
			if !errors.Is(err, ErrRestricted) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v, want refused naming %q", err, tc.want)
			}
		})
	}
}

func TestEnvironmentSpecRefusesWhatItCannotModel(t *testing.T) {
	for name, spec := range map[string]EnvironmentSpec{
		"reserved variable":        {Variables: map[string][]string{"DISTINFO_FILE": {"/x"}}},
		"a restriction everywhere": {Variables: map[string][]string{"NO_CDROM": {"yes"}}},
		"per-license permissions":  {Variables: map[string][]string{"LICENSE_PERMS_GPLv2": {"dist-mirror"}}},
		"not a variable name":      {Variables: map[string][]string{"A B": {"x"}}},
		"relative file":            {Files: map[string][]string{"etc/aspell.ver": {Absent}}},
		"unclean file":             {Files: map[string][]string{"/usr/local/../etc/x": {Absent}}},
		"no alternative":           {Files: map[string][]string{"/etc/x": {}}},
		"relative snapshot":        {Files: map[string][]string{"/etc/x": {"snap"}}},
		// What the client check cannot write back into make.conf unquoted.
		"path with a space":       {Files: map[string][]string{"/etc/a b": {Absent}}},
		"path with a colon":       {Files: map[string][]string{"/etc/a:b": {Absent}}},
		"path with a reference":   {Files: map[string][]string{"/etc/${X}": {Absent}}},
		"value with a comment":    {Variables: map[string][]string{"LOCALBASE": {"/usr/local#x"}}},
		"value with a backslash":  {Variables: map[string][]string{"LOCALBASE": {`/usr\local`}}},
		"value with space around": {Variables: map[string][]string{"LOCALBASE": {" /usr/local"}}},
		"the check's own name":    {Variables: map[string][]string{"BODEGA_DISTFILES_ENV": {"x"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := spec.Validate(); err == nil {
				t.Fatal("Validate accepted it")
			}
		})
	}
	missing := EnvironmentSpec{Files: map[string][]string{"/etc/x": {filepath.Join(t.TempDir(), "gone")}}}
	if err := missing.Validate(); err != nil {
		t.Fatalf("Validate reads no snapshot, so a missing one is Load's to refuse: %v", err)
	}
	if _, err := missing.Load(); err == nil {
		t.Fatal("Load admitted against a snapshot it could not read")
	}
}

// A snapshot that changes or disappears after the first read drops the index:
// the index was admitted against the old bytes, which are no longer the
// declared environment. The tree failing to read keeps it; that is the other
// case, covered by TestTreeReadsInTheBackgroundAndRefreshes.
func TestTreeRefusesAChangedEnvironment(t *testing.T) {
	root := aspellTree(t)
	snap := snapshot(t, "ASPELL_VER=0.60\n")
	spec := EnvironmentSpec{
		Variables: map[string][]string{"LOCALBASE": {"/usr/local"}},
		Files:     map[string][]string{"/usr/local/etc/aspell.ver": {snap}},
	}
	for name, change := range map[string]func(){
		"changed": func() {
			if err := os.WriteFile(snap, []byte("NO_CDROM=later\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"removed": func() {
			if err := os.Remove(snap); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(snap, []byte("ASPELL_VER=0.60\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			tr := NewTreeIn(root, spec, time.Nanosecond, nil)
			if err := tr.Wait(); err != nil {
				t.Fatal(err)
			}
			if _, err := tr.Lookup("pcpustat/1.6.tar.bz2"); err != nil {
				t.Fatalf("before: %v", err)
			}
			change()
			deadline := time.Now().Add(10 * time.Second)
			for {
				_, err := tr.Lookup("pcpustat/1.6.tar.bz2")
				if errors.Is(err, ErrNotReady) {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("after the snapshot %s: %v, want ErrNotReady", name, err)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// An empty snapshot is a declared empty file, not a missing one: the path it
// stands for is on the client and is never opened on the server, even when
// the server has a file there.
func TestEnvironmentEmptySnapshotIsNotTheServerFile(t *testing.T) {
	root := aspellTree(t)
	host := t.TempDir()
	write(t, host, "etc/aspell.ver", "NO_CDROM=server host file\n")
	ix := loadWith(t, root, EnvironmentSpec{
		Variables: map[string][]string{"LOCALBASE": {host}},
		Files:     map[string][]string{filepath.Join(host, "etc/aspell.ver"): {snapshot(t, "")}},
	})
	if _, err := ix.Lookup("aspell6-ar-1.2-0.tar.bz2"); err != nil {
		t.Fatalf("%v, want admitted against the empty snapshot", err)
	}
}

// A declared variable is what make.conf, the environment or the command line
// hold, and a stock client holds LOCALBASE in none of them: above
// bsd.port.pre.mk base make expands it to nothing. Below it the framework's
// default applies, and a default the declaration does not list reaches no
// client the check admits, unless the port assigns the variable after it.
func TestDeclaredVariablesAroundTheFramework(t *testing.T) {
	localbase := map[string][]string{"LOCALBASE": {"/opt/local"}}
	for name, tc := range map[string]struct {
		makefile string
		files    map[string][]string
		want     string // "" admits pcpustat
	}{
		"above the framework, unset":         {".include \"${LOCALBASE}/etc/x.mk\"\n.include <bsd.port.pre.mk>\n", map[string][]string{"/opt/local/etc/x.mk": {snapshot(t, "")}}, "/etc/x.mk leaves the ports tree"},
		"above the framework, both declared": {".include \"${LOCALBASE}/etc/x.mk\"\n.include <bsd.port.pre.mk>\n", map[string][]string{"/opt/local/etc/x.mk": {snapshot(t, "")}, "/etc/x.mk": {Absent}}, ""},
		"below the framework":                {".include <bsd.port.pre.mk>\n.include \"${LOCALBASE}/etc/x.mk\"\n", map[string][]string{"/opt/local/etc/x.mk": {snapshot(t, "")}}, ""},
		// java/bootstrap-openjdk8/Makefile.update.
		"defaulted again below the framework": {".include <bsd.port.pre.mk>\n.include \"${LOCALBASE}/etc/x.mk\"\nLOCALBASE?=\t/usr/local\n", map[string][]string{"/opt/local/etc/x.mk": {snapshot(t, "")}}, ""},
		"assigned below the framework":        {".include <bsd.port.pre.mk>\n.include \"${LOCALBASE}/etc/x.mk\"\nLOCALBASE=\t/opt/local\n", map[string][]string{"/opt/local/etc/x.mk": {snapshot(t, "")}}, "assigns LOCALBASE below a framework include"},
		// The command line wins over the port's own assignment.
		"assigned by the port":                      {"LOCALBASE=\t${.CURDIR}\n.include \"${LOCALBASE}/etc/x.mk\"\n", map[string][]string{"/opt/local/etc/x.mk": {Absent}}, ""},
		"assigned by the port, command line unread": {"LOCALBASE=\t${.CURDIR}\n.include \"${LOCALBASE}/etc/x.mk\"\n", nil, "/opt/local/etc/x.mk leaves the ports tree"},
	} {
		t.Run(name, func(t *testing.T) {
			root := portsTree(t)
			write(t, root, "sysutils/pcpustat/Makefile", "LICENSE=\tBSD2CLAUSE\n"+tc.makefile)
			write(t, root, "sysutils/pcpustat/etc/x.mk", "")
			ix := loadWith(t, root, EnvironmentSpec{Variables: localbase, Files: tc.files})
			e, err := ix.Lookup("pcpustat/1.6.tar.bz2")
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("pcpustat: %v, want admitted", err)
			case tc.want != "" && (!errors.Is(err, ErrRestricted) || !strings.Contains(e.Restricted, tc.want)):
				t.Fatalf("pcpustat: %v (reason %q), want refused naming %q", err, e.Restricted, tc.want)
			}
		})
	}
}

// The client check names every input admission assumed, so a client that
// holds anything else names "unsupported". TestClientCheckUnderBaseMake runs
// it; this pins what it is written to test on any host.
func TestClientCheckNamesEveryDeclaredInput(t *testing.T) {
	snap := snapshot(t, "PERL5_DEFAULT=5.42\n")
	env, err := EnvironmentSpec{
		Variables: map[string][]string{"LOCALBASE": {"/usr/local"}, "USESDIR": {"${PORTSDIR}/Mk/Uses"}, "PKGNAMESUFFIX": {}},
		Files:     map[string][]string{"/usr/local/etc/aspell.ver": {Absent}, "/tmp/PERL5_DEFAULT": {Absent, snap}, "/etc/present.mk": {snap}},
	}.Load()
	if err != nil {
		t.Fatal(err)
	}
	check := string(env.ClientCheck())
	for _, want := range []string{
		"for environment " + env.Digest(),
		// Reserved and declared-undefined names, set anywhere outside the tree.
		".for _bodega_v in DISTINFO_FILE FILESDIR LICENSE LICENSE_PERMS MASTERDIR NO_CDROM PKGDIR PKGNAMESUFFIX RESTRICTED\n",
		"!empty(_BODEGA_DISTFILES_ENVIRON:MLICENSE_PERMS_*=*)",
		// A command-line variable is declared or one the framework passes on.
		"${.MAKEOVERRIDES:O:u:NLOCALBASE:NUSESDIR:NARCH:",
		"/usr/bin/grep -lE '" + confPattern + "' ${.MAKE.MAKEFILES:N/usr/share/mk/*:N${.PARSEDIR}/${.PARSEFILE}}",
		// Declared values, where make.conf sets them and where the fetch reads them.
		"_BODEGA_DISTFILES_V0_0=\t/usr/local\n.if defined(LOCALBASE) && !(\"${LOCALBASE}\" == \"${_BODEGA_DISTFILES_V0_0}\")",
		"_BODEGA_DISTFILES_V1_0=\t${PORTSDIR}/Mk/Uses\n",
		// A file declared absent alone may not exist; one with a snapshot
		// alone must exist, be a regular file and match it.
		".if !(\"${_BODEGA_DISTFILES_F2}\" == \"absent\")\nBODEGA_DISTFILES_DRIFT+=\t/usr/local/etc/aspell.ver\n.endif\n",
		"if [ -f /tmp/PERL5_DEFAULT ]; then /usr/bin/timeout 10 /sbin/sha256 -q /tmp/PERL5_DEFAULT 2>/dev/null || echo unreadable; elif [ -e /tmp/PERL5_DEFAULT ]; then echo irregular; else echo absent; fi",
		".if !(\"${_BODEGA_DISTFILES_F0}\" == \"348d182711a2886bc0a8eb38c2df85032e593d133971389f2563befc7cbbcb1c\")\nBODEGA_DISTFILES_DRIFT+=\t/etc/present.mk\n",
		// Measured again where the fetch expands the digest.
		"${(!defined(LOCALBASE) || \"${LOCALBASE}\" == \"${_BODEGA_DISTFILES_V0_0}\"):?:LOCALBASE}",
		"${(\"${_BODEGA_DISTFILES_L1}\" == \"348d182711a2886bc0a8eb38c2df85032e593d133971389f2563befc7cbbcb1c\" || \"${_BODEGA_DISTFILES_L1}\" == \"absent\"):?:/tmp/PERL5_DEFAULT}",
		"_BODEGA_DISTFILES_FLAGS:=\t${.MAKEFLAGS:M-[eI]*}\n",
		":N/etc/present.mk:N/tmp/PERL5_DEFAULT:N/usr/local/etc/aspell.ver:${_BODEGA_DISTFILES_READ}}",
		":?" + env.Digest() + ":unsupported}\n",
	} {
		if !strings.Contains(check, want) {
			t.Errorf("the check does not carry %q:\n%s", want, check)
		}
	}
	if strings.Contains(check, "PKGNAMESUFFIX}\" ==") {
		t.Error("a variable declared undefined is compared at fetch time, where the port may set it itself")
	}
}

// TestClientCheckUnderBaseMake installs the check at the end of a make.conf and
// asks base FreeBSD make, in one port, which environment it names. Every case
// but the first changes one input the reader's decision rests on, without
// touching the port or the declaration, and must name "unsupported".
func TestClientCheckUnderBaseMake(t *testing.T) {
	if runtime.GOOS != "freebsd" {
		t.Skip("the check is written for base FreeBSD make")
	}
	scratch := t.TempDir()
	client := filepath.Join(scratch, "client")
	tree := filepath.Join(scratch, "ports")
	snap := snapshot(t, "OK=snapshot\n")
	declared := filepath.Join(client, "snap.mk")
	absent := filepath.Join(client, "aspell.ver")
	write(t, scratch, "client/snap.mk", "OK=snapshot\n")
	write(t, scratch, "ports/misc/probe/Makefile", "P=\t${.CURDIR}/allowed.mk\n.include \"${P}\"\n.if exists("+absent+")\n.include \""+absent+"\"\n.endif\nall:\n")
	write(t, scratch, "ports/misc/probe/allowed.mk", "OK=yes\n")
	write(t, scratch, "ports/misc/probe/restricted.mk", "NO_CDROM=command line terms\n")
	env, err := EnvironmentSpec{
		Variables: map[string][]string{"LOCALBASE": {"/usr/local"}},
		Files:     map[string][]string{declared: {snap}, absent: {Absent}},
	}.Load()
	if err != nil {
		t.Fatal(err)
	}
	checkPath := filepath.Join(scratch, "environment.mk")
	if err := os.WriteFile(checkPath, env.ClientCheck(), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := func(extra string) string {
		p := filepath.Join(t.TempDir(), "make.conf")
		if err := os.WriteFile(p, []byte(extra+"PORTSDIR=\t"+tree+"\n.include \""+checkPath+"\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	extra := filepath.Join(scratch, "extra.mk")
	write(t, scratch, "extra.mk", "P=\t"+tree+"/misc/probe/restricted.mk\n")
	port := filepath.Join(tree, "misc/probe")
	for _, tc := range []struct {
		name  string
		conf  string
		env   []string
		args  []string
		setup func()
		want  string // the digest, or "unsupported"
	}{
		{name: "stock", want: env.Digest()},
		// -V keeps its argument unexpanded in .MAKEFLAGS, where a check that
		// read .MAKEFLAGS while expanding the digest would recurse.
		{name: "-V naming the digest as an expression", args: []string{"-V", "${BODEGA_DISTFILES_ENV}"}, want: env.Digest()},
		{name: "a declared variable at a declared value", args: []string{"LOCALBASE=/usr/local"}, want: env.Digest()},
		{name: "a variable the framework passes on", args: []string{"OSVERSION=1501000"}, want: env.Digest()},
		{name: "a declared variable at another value", args: []string{"LOCALBASE=/opt"}},
		{name: "an undeclared command-line variable", args: []string{"P=" + port + "/restricted.mk"}},
		{name: "an undeclared variable through MAKEFLAGS", env: []string{"MAKEFLAGS=P=" + port + "/restricted.mk"}},
		{name: "-e", args: []string{"-e"}},
		{name: "-I", args: []string{"-I", scratch}},
		{name: "-m", args: []string{"-m", scratch, "-m", "/usr/share/mk"}},
		{name: ".MAKEFLAGS in make.conf", conf: ".MAKEFLAGS: P=" + port + "/restricted.mk\n"},
		{name: ".READONLY in make.conf", conf: "P=\t" + port + "/restricted.mk\n.READONLY: P\n"},
		{name: "a makefile read after make.conf", args: []string{"-f", extra, "-f", "Makefile"}},
		{name: "a declared snapshot changed", setup: func() { write(t, scratch, "client/snap.mk", "NO_CDROM=changed\n") }},
		{name: "a file declared absent, present before make", setup: func() { write(t, scratch, "client/aspell.ver", "NO_CDROM=host\n") }},
		// The port writes the file itself once make.conf has been read, as a
		// concurrent writer would: only the second measurement can see it.
		{name: "a file declared absent, written while make reads the port", setup: func() {
			write(t, scratch, "ports/misc/probe/Makefile", "_W!=\tprintf 'NO_CDROM=host\\n' > "+absent+"\n.if exists("+absent+")\n.include \""+absent+"\"\n.endif\nall:\n")
		}},
		// A FIFO no writer holds open: reading it would block make forever.
		{name: "a FIFO where a snapshot is declared", setup: func() {
			if err := os.Remove(declared); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(declared, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "an obj directory", setup: func() {
			if err := os.MkdirAll(filepath.Join(port, "obj"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.RemoveAll(filepath.Join(port, "obj"))
			_ = os.Remove(absent)
			_ = os.Remove(declared)
			write(t, scratch, "client/snap.mk", "OK=snapshot\n")
			write(t, scratch, "ports/misc/probe/Makefile", "P=\t${.CURDIR}/allowed.mk\n.include \"${P}\"\n.if exists("+absent+")\n.include \""+absent+"\"\n.endif\nall:\n")
			if tc.setup != nil {
				tc.setup()
			}
			want := tc.want
			if want == "" {
				want = ClientUnsupported
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "make", append(append([]string{"-C", port}, tc.args...), "-V", "BODEGA_DISTFILES_ENV", "-V", "BODEGA_DISTFILES_DRIFT")...)
			cmd.WaitDelay = time.Second
			cmd.Env = append(append(os.Environ(), "__MAKE_CONF="+conf(tc.conf)), tc.env...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("make: %v\n%s", err, out)
			}
			lines := strings.SplitN(string(out), "\n", 2)
			t.Logf("%s", strings.TrimSpace(string(out)))
			if lines[0] != want {
				t.Errorf("the check names %q, want %q", lines[0], want)
			}
		})
	}
}

// LookupIn answers only a client whose check named the digest the index was
// admitted against. A drifted client, one checking another declaration, and
// one with no check are refused, whatever the name.
func TestTreeLookupInBindsTheClient(t *testing.T) {
	root := aspellTree(t)
	spec := EnvironmentSpec{Variables: map[string][]string{"LOCALBASE": {"/usr/local"}}, Files: map[string][]string{"/usr/local/etc/aspell.ver": {Absent}}}
	env, err := spec.Load()
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTreeIn(root, spec, 0, nil)
	if err := tr.Wait(); err != nil {
		t.Fatal(err)
	}
	other, _ := EnvironmentSpec{}.Load()
	for _, digest := range []string{"", ClientUnsupported, other.Digest(), strings.ToUpper(env.Digest())} {
		if _, err := tr.LookupIn(digest, "pcpustat/1.6.tar.bz2"); !errors.Is(err, ErrEnvironment) {
			t.Errorf("LookupIn(%q): %v, want ErrEnvironment", digest, err)
		}
	}
	if e, err := tr.LookupIn(env.Digest(), "pcpustat/1.6.tar.bz2"); err != nil || e.SHA256 != sumA {
		t.Errorf("LookupIn(the admitted digest): %+v, %v", e, err)
	}
	check, err := tr.ClientCheck()
	if err != nil || !strings.Contains(string(check), ":?"+env.Digest()+":") {
		t.Errorf("ClientCheck names another environment than LookupIn admits: %v\n%s", err, check)
	}
}
