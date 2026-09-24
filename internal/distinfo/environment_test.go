package distinfo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
