package host

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/distinfo"
)

// stockFreeBSD15 is /etc/pkg/FreeBSD.conf as 15.1-RELEASE ships it.
const stockFreeBSD15 = `# To disable a repository, create /usr/local/etc/pkg/repos/FreeBSD.conf
FreeBSD-ports: {
  url: "pkg+https://pkg.FreeBSD.org/${ABI}/quarterly",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
FreeBSD-ports-kmods: {
  url: "pkg+https://pkg.FreeBSD.org/${ABI}/kmods_quarterly_${VERSION_MINOR}",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
FreeBSD-base: {
  url: "pkg+https://pkg.FreeBSD.org/${ABI}/base_release_${VERSION_MINOR}",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkgbase-${VERSION_MAJOR}",
  enabled: no
}
`

const bodegaRepos15 = `/* written by bodega doctor --write-pkg-repo */
FreeBSD-ports: { enabled: no }
FreeBSD-ports-kmods: { enabled: no }
FreeBSD-base: { enabled: no }

bodega-latest: {
  url: "https://bodega.internal/freebsd/${ABI}/latest",
  mirror_type: "none",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
`

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func assertFinding(t *testing.T, got Finding, want Status, detail ...string) {
	t.Helper()
	if got.Status != want {
		t.Fatalf("status = %s, want %s (detail: %s)", got.Status, want, got.Detail)
	}
	for _, d := range detail {
		if !strings.Contains(got.Detail, d) {
			t.Errorf("detail %q does not mention %q", got.Detail, d)
		}
	}
}

func TestCheckPkgRepos(t *testing.T) {
	tests := []struct {
		name   string
		goos   string
		files  map[string]string
		want   Status
		detail []string
	}{
		{
			name:   "stock 15.1 host",
			goos:   "freebsd",
			files:  map[string]string{"/etc/pkg/FreeBSD.conf": stockFreeBSD15},
			want:   StatusWarn,
			detail: []string{"FreeBSD-ports (", "FreeBSD-ports-kmods (", "no enabled repository points at a bodega"},
		},
		{
			name: "what --write-pkg-repo installs",
			goos: "freebsd",
			files: map[string]string{
				"/etc/pkg/FreeBSD.conf":                stockFreeBSD15,
				"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15,
			},
			want:   StatusOK,
			detail: []string{"bodega-latest"},
		},
		{
			// FreeBSD-base is off in the stock file and turned on here, in
			// a local file sorting after bodega's, which is the precedence
			// pkg.conf(5) gives it.
			name: "a later local file re-enables a base repository",
			goos: "freebsd",
			files: map[string]string{
				"/etc/pkg/FreeBSD.conf":                stockFreeBSD15,
				"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15,
				"/usr/local/etc/pkg/repos/zz.conf":     "FreeBSD-base { enabled = true; }\n",
			},
			want:   StatusWarn,
			detail: []string{"FreeBSD-base (", "set in /usr/local/etc/pkg/repos/zz.conf"},
		},
		{
			name: "a 14 host disables FreeBSD but not FreeBSD-kmods",
			goos: "freebsd",
			files: map[string]string{
				"/etc/pkg/FreeBSD.conf": "FreeBSD: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/quarterly\", enabled: yes }\n" +
					"FreeBSD-kmods: { url: \"pkg+https://pkg.FreeBSD.org/${ABI}/kmods_quarterly_${VERSION_MINOR}\", enabled: yes }\n",
				"/usr/local/etc/pkg/repos/bodega.conf": "FreeBSD: { enabled: no }\nbodega-latest: { url: \"https://b/freebsd/${ABI}/latest\" }\n",
			},
			want:   StatusWarn,
			detail: []string{"FreeBSD-kmods ("},
		},
		{
			name: "upstream disabled and nothing in its place",
			goos: "freebsd",
			files: map[string]string{
				"/etc/pkg/FreeBSD.conf":                 stockFreeBSD15,
				"/usr/local/etc/pkg/repos/FreeBSD.conf": "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n",
			},
			want:   StatusWarn,
			detail: []string{"no enabled repository points at a bodega"},
		},
		{
			name: "a base tag pointed at bodega counts as bodega",
			goos: "freebsd",
			files: map[string]string{
				"/etc/pkg/FreeBSD.conf": stockFreeBSD15,
				"/usr/local/etc/pkg/repos/FreeBSD.conf": "FreeBSD-ports: { url: \"https://b/freebsd-profile/dev/${ABI}/latest\", mirror_type: none }\n" +
					"FreeBSD-ports-kmods: { enabled: NO }\n",
			},
			want: StatusOK,
		},
		{
			name: "an unknown tag at pkg.FreeBSD.org is upstream",
			goos: "freebsd",
			files: map[string]string{
				"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15,
				"/usr/local/etc/pkg/repos/mine.conf":   "mine: { url: \"https://PKG.freebsd.org/${ABI}/latest\" }\n",
			},
			want:   StatusWarn,
			detail: []string{"mine ("},
		},
		{
			name: "an unparseable file is not read as clean",
			goos: "freebsd",
			files: map[string]string{
				"/usr/local/etc/pkg/repos/bodega.conf": "bodega-latest: { url: \"https://b/freebsd/x/latest\"\n",
			},
			want:   StatusSkip,
			detail: []string{"/usr/local/etc/pkg/repos/bodega.conf", "not closed"},
		},
		{
			name: "an include enables an upstream repository",
			goos: "freebsd",
			files: map[string]string{
				"/usr/local/etc/pkg/repos/bodega.conf": "bodega: { url: \"https://b/freebsd/FreeBSD:15:aarch64/latest\", enabled: yes }\n.include \"/tmp/upstream.inc\"\n",
				"/tmp/upstream.inc":                    "FreeBSD: { url: \"https://pkg.FreeBSD.org/FreeBSD:15:aarch64/quarterly\", enabled: yes }\n",
			},
			want:   StatusWarn,
			detail: []string{"FreeBSD (", "set in /tmp/upstream.inc"},
		},
		{
			// libucl keeps the first object of a name within one file and
			// its includes, so the outer disable after the include is dropped.
			name: "an included definition comes first and wins",
			goos: "freebsd",
			files: map[string]string{
				"/usr/local/etc/pkg/repos/bodega.conf": ".include \"/tmp/upstream.inc\"\nFreeBSD: { enabled: no }\nbodega: { url: \"https://b/freebsd/x/latest\" }\n",
				"/tmp/upstream.inc":                    "FreeBSD: { url: \"https://pkg.FreeBSD.org/x\", enabled: yes }\n",
			},
			want:   StatusWarn,
			detail: []string{"FreeBSD ("},
		},
		{
			name: "an include that only disables upstream",
			goos: "freebsd",
			files: map[string]string{
				"/etc/pkg/FreeBSD.conf":                stockFreeBSD15,
				"/usr/local/etc/pkg/repos/bodega.conf": "bodega: { url: \"https://b/freebsd/x/latest\" }\n.include \"/usr/local/etc/pkg/off.inc\"\n",
				"/usr/local/etc/pkg/off.inc":           "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n",
			},
			want: StatusOK,
		},
		{
			name:   "an include of a missing file",
			goos:   "freebsd",
			files:  map[string]string{"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15 + ".include \"/tmp/gone.inc\"\n"},
			want:   StatusWarn,
			detail: []string{"/tmp/gone.inc, which does not exist", "cannot establish"},
		},
		{
			name:   "a directive doctor does not evaluate",
			goos:   "freebsd",
			files:  map[string]string{"/usr/local/etc/pkg/repos/bodega.conf": ".priority 5\n" + bodegaRepos15},
			want:   StatusWarn,
			detail: []string{".priority is a UCL directive doctor does not evaluate"},
		},
		{
			name:   "an include with parameters",
			goos:   "freebsd",
			files:  map[string]string{"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15 + ".include(try=true) \"/tmp/x.inc\"\n"},
			want:   StatusWarn,
			detail: []string{"doctor does not evaluate"},
		},
		{
			name: "try_include, which pkg 2.8 fails on",
			goos: "freebsd",
			files: map[string]string{
				"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15 + ".try_include \"/tmp/x.inc\"\n",
				"/tmp/x.inc":                           "\n",
			},
			want:   StatusWarn,
			detail: []string{".try_include is a UCL directive"},
		},
		{
			name:   "a relative include",
			goos:   "freebsd",
			files:  map[string]string{"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15 + ".include \"up.inc\"\n"},
			want:   StatusWarn,
			detail: []string{"is relative"},
		},
		{
			name:   "an include path with a variable",
			goos:   "freebsd",
			files:  map[string]string{"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15 + ".include \"/tmp/${ABI}.inc\"\n"},
			want:   StatusWarn,
			detail: []string{"holds a variable"},
		},
		{
			name:   "an include inside an object",
			goos:   "freebsd",
			files:  map[string]string{"/usr/local/etc/pkg/repos/bodega.conf": "bodega: { url: \"https://b/freebsd/x/latest\"\n.include \"/tmp/e.inc\"\n}\n"},
			want:   StatusWarn,
			detail: []string{"inside object \"bodega\""},
		},
		{
			name: "a file that includes itself",
			goos: "freebsd",
			files: map[string]string{
				"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15 + ".include \"/usr/local/etc/pkg/repos/bodega.conf\"\n",
			},
			want:   StatusWarn,
			detail: []string{"levels of nesting"},
		},
		{
			name:   "enabled: 0 disables the only bodega repository",
			goos:   "freebsd",
			files:  map[string]string{"/usr/local/etc/pkg/repos/bodega.conf": "bodega: { url: \"https://b/freebsd/FreeBSD:15:aarch64/latest\", enabled: 0 }\n"},
			want:   StatusWarn,
			detail: []string{"no enabled repository points at a bodega"},
		},
		{
			// pkg keeps the first value of a repeated key, but applies
			// differently cased spellings in order, so the later one wins.
			name: "repeated and recased keys",
			goos: "freebsd",
			files: map[string]string{
				"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15,
				"/usr/local/etc/pkg/repos/up.conf":     "up: { url: \"https://pkg.FreeBSD.org/x\", url: \"https://b/freebsd/y\", Enabled: no, enabled: yes }\n",
			},
			want:   StatusWarn,
			detail: []string{"up (https://pkg.FreeBSD.org/x"},
		},
		{
			name: "repository names are case-sensitive",
			goos: "freebsd",
			files: map[string]string{
				"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15,
				"/usr/local/etc/pkg/repos/up.conf":     "FreeBSD: { url: \"https://pkg.FreeBSD.org/x\" }\n",
				"/usr/local/etc/pkg/repos/zz.conf":     "freebsd: { enabled: no }\n",
			},
			want:   StatusWarn,
			detail: []string{"FreeBSD (https://pkg.FreeBSD.org/x"},
		},
		{
			name:  "linux",
			goos:  "linux",
			files: map[string]string{"/etc/pkg/FreeBSD.conf": stockFreeBSD15},
			want:  StatusNA,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkPkgRepos(writeTree(t, tt.files), tt.goos)
			assertFinding(t, got, tt.want, tt.detail...)
			if got.Status == StatusWarn && !strings.Contains(got.Remediation, "bodega doctor --write-pkg-repo") {
				t.Errorf("remediation %q does not name --write-pkg-repo", got.Remediation)
			}
		})
	}
}

func TestCheckMakeConf(t *testing.T) {
	rendered := clientconf.MakeConf("https://bodega.internal").Content
	check := "BODEGA_DISTFILES_DRIFT=\nBODEGA_DISTFILES_ENV=\t${\"${BODEGA_DISTFILES_DRIFT:M*}\" == \"\":?abc:unsupported}\n"
	site := "https://bodega.internal/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/"

	tests := []struct {
		name   string
		goos   string
		env    map[string]string
		files  map[string]string
		want   Status
		detail []string
	}{
		{
			name:   "no make.conf",
			goos:   "freebsd",
			want:   StatusWarn,
			detail: []string{"/etc/make.conf does not exist"},
		},
		{
			name: "what clientconf renders, check copied",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              "WITHOUT_X11=yes\n" + rendered,
				clientconf.DistfilesCheckPath: check,
			},
			want: StatusOK,
		},
		{
			// docs/usage.md's second delivery: the check read off a mount.
			name: "check included from a distfiles mount",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf": "MASTER_SITE_OVERRIDE?=\t" + site + "\nMASTER_SITE_BACKUP=" + site + " \\\n  \n" +
					"DISTDIR=\t/net/b/distfiles/@${BODEGA_DISTFILES_ENV}\n.include \"/net/b/distfiles/@environment.mk\" # last\n",
				"/net/b/distfiles/@environment.mk": check,
			},
			want: StatusOK,
		},
		{
			name: "backup left at the FreeBSD distcache",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf": "MASTER_SITE_OVERRIDE?= " + site + "\nMASTER_SITE_BACKUP?= " + site + " https://distcache.FreeBSD.org/${DIST_SUBDIR}/\n" +
					".include \"" + clientconf.DistfilesCheckPath + "\"\n",
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"MASTER_SITE_BACKUP=", "does not end every site"},
		},
		{
			// A later ?= does not replace an earlier =, as in make.
			name: "a ?= after an = changes nothing",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              "MASTER_SITE_OVERRIDE= https://mirror.example/\n" + rendered,
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"MASTER_SITE_OVERRIDE=https://mirror.example/"},
		},
		{
			name: "sites set, include not last",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              rendered + "WITH_DEBUG=yes\n",
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"the last line is WITH_DEBUG=yes"},
		},
		{
			name: "include of a file that is not the check",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              rendered,
				clientconf.DistfilesCheckPath: "# empty\n",
			},
			want:   StatusWarn,
			detail: []string{"does not define BODEGA_DISTFILES_ENV"},
		},
		{
			name:   "include of a file that is missing, and no sites",
			goos:   "freebsd",
			files:  map[string]string{"/etc/make.conf": ".include \"" + clientconf.DistfilesCheckPath + "\"\n"},
			want:   StatusWarn,
			detail: []string{"MASTER_SITE_OVERRIDE is not set", "MASTER_SITE_BACKUP is not set", "which does not exist"},
		},
		{
			name: "__MAKE_CONF replaces /etc/make.conf",
			goos: "freebsd",
			env:  map[string]string{"__MAKE_CONF": "/usr/local/etc/make.conf"},
			files: map[string]string{
				"/etc/make.conf":              rendered,
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"/usr/local/etc/make.conf does not exist"},
		},
		{
			name: "sites assigned under .if 0",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf": "MASTER_SITE_OVERRIDE=https://mirror.example/\nMASTER_SITE_BACKUP=https://mirror.example/\n.if 0\n" +
					"MASTER_SITE_OVERRIDE=" + site + "\nMASTER_SITE_BACKUP=" + site + "\n.endif\n.include \"/check.mk\"\n",
				"/check.mk": check,
			},
			want:   StatusWarn,
			detail: []string{"MASTER_SITE_OVERRIDE=https://mirror.example/", "MASTER_SITE_BACKUP=https://mirror.example/"},
		},
		{
			name: "sites assigned under .if 1",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf": "MASTER_SITE_OVERRIDE=https://mirror.example/\nMASTER_SITE_BACKUP=https://mirror.example/\n.if 1\n" +
					"MASTER_SITE_OVERRIDE=" + site + "\nMASTER_SITE_BACKUP=" + site + "\n.else\nMASTER_SITE_BACKUP=https://mirror.example/\n.endif\n.include \"/check.mk\"\n",
				"/check.mk": check,
			},
			want: StatusOK,
		},
		{
			name: "a site assigned under a condition doctor does not evaluate",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              ".if defined(MIRROR)\nMASTER_SITE_OVERRIDE=https://mirror.example/\n.endif\n" + rendered,
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"MASTER_SITE_OVERRIDE cannot be established: assigned under a conditional"},
		},
		{
			// The plain = after the conditional replaces whatever it did.
			name: "an unconditional assignment after an unknown branch",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf": ".if defined(MIRROR)\nMASTER_SITE_OVERRIDE=https://mirror.example/\n.endif\n" +
					"MASTER_SITE_OVERRIDE=" + site + "\nMASTER_SITE_BACKUP=" + site + "\n.include \"" + clientconf.DistfilesCheckPath + "\"\n",
				clientconf.DistfilesCheckPath: check,
			},
			want: StatusOK,
		},
		{
			name: "a site assigned in a .for loop",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              ".for s in https://mirror.example/\nMASTER_SITE_BACKUP+=${s}\n.endfor\n" + rendered,
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"MASTER_SITE_BACKUP cannot be established"},
		},
		{
			name: "a site set from a shell command",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              "MASTER_SITE_OVERRIDE!=echo " + site + "\nMASTER_SITE_BACKUP=" + site + "\n.include \"" + clientconf.DistfilesCheckPath + "\"\n",
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"MASTER_SITE_OVERRIDE cannot be established", "shell command doctor does not run"},
		},
		{
			name: "a site pinned by .READONLY before bodega's assignment",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              "MASTER_SITE_OVERRIDE=https://mirror.example/\n.READONLY: MASTER_SITE_OVERRIDE\n" + strings.ReplaceAll(rendered, "?=", "="),
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"MASTER_SITE_OVERRIDE=https://mirror.example/ (set in /etc/make.conf) does not end every site"},
		},
		{
			name: "the final include overrides a site",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              rendered,
				clientconf.DistfilesCheckPath: "BODEGA_DISTFILES_ENV=abc\nMASTER_SITE_OVERRIDE=https://mirror.example/\n",
			},
			want:   StatusWarn,
			detail: []string{"MASTER_SITE_OVERRIDE=https://mirror.example/ (set in " + clientconf.DistfilesCheckPath + ")"},
		},
		{
			name: "an earlier include overrides a site",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              "MASTER_SITE_OVERRIDE=" + site + "\nMASTER_SITE_BACKUP=" + site + "\n.include \"local.mk\"\n.include \"" + clientconf.DistfilesCheckPath + "\"\n",
				"/etc/local.mk":               "MASTER_SITE_BACKUP+=https://mirror.example/\n",
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"(set in /etc/local.mk) does not end every site"},
		},
		{
			name: "an earlier include that sets the sites",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              ".include \"/usr/local/etc/sites.mk\"\n.include \"" + clientconf.DistfilesCheckPath + "\"\n",
				"/usr/local/etc/sites.mk":     "MASTER_SITE_OVERRIDE?=" + site + "\nMASTER_SITE_BACKUP?=" + site + "\n",
				clientconf.DistfilesCheckPath: check,
			},
			want: StatusOK,
		},
		{
			name: "an earlier include that is missing",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              ".include \"/usr/local/etc/gone.mk\"\n" + rendered,
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"/usr/local/etc/gone.mk, which does not exist"},
		},
		{
			name: "an earlier include doctor cannot resolve",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              ".include \"${LOCALBASE}/etc/sites.mk\"\n" + rendered,
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"MASTER_SITE_OVERRIDE cannot be established", "whose variables doctor does not expand"},
		},
		{
			name: "an unclosed conditional",
			goos: "freebsd",
			files: map[string]string{
				"/etc/make.conf":              ".if 1\n" + rendered,
				clientconf.DistfilesCheckPath: check,
			},
			want:   StatusWarn,
			detail: []string{"conditional or loop still open"},
		},
		{
			name:  "linux",
			goos:  "linux",
			files: map[string]string{"/etc/make.conf": ""},
			want:  StatusNA,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(k string) string { return tt.env[k] }
			got := checkMakeConf(writeTree(t, tt.files), tt.goos, getenv)
			assertFinding(t, got, tt.want, tt.detail...)
		})
	}
}

// Each check that reads a system path, against one fixture root per
// operating system: the Linux paths, and FreeBSD's /usr/local/etc ones.
func TestChecksAgainstFixtureRootPerOS(t *testing.T) {
	tree := map[string]string{
		"/etc/apt/sources.list.d/ubuntu.sources": "URIs: http://archive.ubuntu.com/ubuntu\n",
		"/usr/local/etc/pip.conf":                "[global]\nindex-url = https://pypi.org/simple\n",
		"/usr/local/etc/npmrc":                   "registry=https://registry.npmjs.org/\n",
		"/etc/pkg/FreeBSD.conf":                  stockFreeBSD15,
	}
	home := "/home/op"
	type row struct {
		check string
		run   func(root, goos string) Finding
		linux Status
		bsd   Status
	}
	rows := []row{
		{"apt-sources", checkAptSources, StatusWarn, StatusNA},
		{"pkg-repos", checkPkgRepos, StatusNA, StatusWarn},
		{"make-conf", func(root, goos string) Finding { return checkMakeConf(root, goos, func(string) string { return "" }) }, StatusNA, StatusWarn},
		{"pip-config", func(root, goos string) Finding { return checkPipConfig(root, goos, home) }, StatusOK, StatusWarn},
		{"npm-config", func(root, goos string) Finding { return checkNpmConfig(root, goos, home) }, StatusOK, StatusWarn},
	}
	root := writeTree(t, tree)
	for _, r := range rows {
		for goos, want := range map[string]Status{"linux": r.linux, "freebsd": r.bsd} {
			t.Run(r.check+"/"+goos, func(t *testing.T) {
				got := r.run(root, goos)
				if got.Check != r.check {
					t.Errorf("check = %q, want %q", got.Check, r.check)
				}
				assertFinding(t, got, want)
			})
		}
	}

	// The paths the FreeBSD rows read on their own, with nothing else in
	// the tree that could produce the same answer.
	pip := writeTree(t, map[string]string{"/usr/local/pip.conf": "index-url = https://pypi.org/simple\n"})
	assertFinding(t, checkPipConfig(pip, "freebsd", ""), StatusWarn, "/usr/local/pip.conf")
	npm := writeTree(t, map[string]string{"/home/op/.npmrc": "registry=https://registry.npmjs.org/\n"})
	assertFinding(t, checkNpmConfig(npm, "freebsd", home), StatusWarn, ".npmrc")
}

// The fragment bodega serves at /distfiles/@environment.mk uses .for, .if,
// != and :=, none of them on a site variable, so walking it must certify.
func TestCheckMakeConfWalksTheServedClientCheck(t *testing.T) {
	env, err := distinfo.EnvironmentSpec{Variables: map[string][]string{"WITH_DEBUG": {"yes"}}}.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{clientconf.DistfilesCheckPath, "/net/b/distfiles/@environment.mk"} {
		conf := strings.ReplaceAll(clientconf.MakeConf("https://b").Content, clientconf.DistfilesCheckPath, path)
		root := writeTree(t, map[string]string{"/etc/make.conf": conf, path: string(env.ClientCheck())})
		assertFinding(t, checkMakeConf(root, "freebsd", func(string) string { return "" }), StatusOK)
	}
}

func TestMakeConfSitesComeFromTheRenderer(t *testing.T) {
	names, route := makeConfSites()
	if strings.Join(names, ",") != "MASTER_SITE_OVERRIDE,MASTER_SITE_BACKUP" {
		t.Errorf("names = %v", names)
	}
	if route != "/distfiles/@${"+distfilesEnvVar+"}/${DIST_SUBDIR}/" {
		t.Errorf("route = %q", route)
	}
}

// Every form of enabled pkg 2.8.4 was asked about on 15.1, with what
// pkg -vv reported for a bodega repository carrying it.
func TestPkgEnabledMatchesPkg(t *testing.T) {
	enabled := map[string]bool{
		"yes": true, "YES": true, "true": true, "TRUE": true, "on": true, "ON": true,
		"no": false, "No": false, "false": false, "off": false,
		"0": false, "1": false, "2": false, "-1": false, "0.0": false, "1.5": false,
		"0x1": false, "1k": false, "nope": false, "null": false,
		`"yes"`: false, `"no"`: false, `'yes'`: false, `""`: false,
	}
	for v, want := range enabled {
		t.Run(v, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"/usr/local/etc/pkg/repos/bodega.conf": "bodega: { url: \"https://b/freebsd/x/latest\", enabled: " + v + " }\n",
			})
			got := checkPkgRepos(root, "freebsd")
			if (got.Status == StatusOK) != want {
				t.Fatalf("enabled: %s gave %s (%s), want enabled=%v", v, got.Status, got.Detail, want)
			}
		})
	}
}

func TestPkgUnreadableInclude(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 000 file")
	}
	root := writeTree(t, map[string]string{
		"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15 + ".include \"/tmp/closed.inc\"\n",
		"/tmp/closed.inc":                      "FreeBSD: { url: \"https://pkg.FreeBSD.org/x\" }\n",
	})
	if err := os.Chmod(filepath.Join(root, "/tmp/closed.inc"), 0); err != nil {
		t.Fatal(err)
	}
	assertFinding(t, checkPkgRepos(root, "freebsd"), StatusSkip, "read /tmp/closed.inc, which /usr/local/etc/pkg/repos/bodega.conf includes")
}

func TestMakeConfUnreadableInclude(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 000 file")
	}
	root := writeTree(t, map[string]string{
		"/etc/make.conf":              ".include \"/etc/local.mk\"\n" + clientconf.MakeConf("https://b").Content,
		"/etc/local.mk":               "MASTER_SITE_OVERRIDE=https://mirror.example/\n",
		clientconf.DistfilesCheckPath: "BODEGA_DISTFILES_ENV=abc\n",
	})
	if err := os.Chmod(filepath.Join(root, "/etc/local.mk"), 0); err != nil {
		t.Fatal(err)
	}
	assertFinding(t, checkMakeConf(root, "freebsd", func(string) string { return "" }), StatusSkip, "read /etc/local.mk, which /etc/make.conf includes")
}

// Repository files pkg 2.8.4 was given on 15.1 with pkg -o REPOS_DIR=<dir>
// -vv, each named for the repositories pkg -vv then listed as enabled.
// Every object sorts into a.conf, b.conf, and so on, in the order listed.
func TestPkgAcceptMatchesPkg(t *testing.T) {
	const bodegaRepo = "bodega: { url: \"https://b/freebsd/x/latest\" }\n"
	const upstream = "FreeBSD: { url: \"https://pkg.FreeBSD.org/x\" }\n"
	tests := []struct {
		name  string
		files []string
		want  Status
		// detail is what the finding names; for WARN, why.
		detail []string
	}{
		{"an override with a mistyped priority is rejected whole", []string{upstream, "FreeBSD: { enabled: no, priority: \"bad\" }\n" + bodegaRepo}, StatusWarn,
			[]string{"FreeBSD (", "pkg rejects and ignores FreeBSD in /usr/local/etc/pkg/repos/b.conf (priority must be an integer, not a string)"}},
		{"a rejected sole bodega object creates nothing", []string{"bodega: { url: \"https://b/freebsd/x/latest\", priority: \"bad\" }\n"}, StatusWarn,
			[]string{"no enabled repository points at a bodega", "pkg rejects and ignores bodega"}},
		{"a url that is a number is rejected", []string{upstream, "FreeBSD: { enabled: no, url: 5 }\n" + bodegaRepo}, StatusWarn, []string{"url must be a string, not an integer"}},
		{"a quoted rwhich_database is rejected", []string{upstream, "FreeBSD: { enabled: no, rwhich_database: \"yes\" }\n" + bodegaRepo}, StatusWarn, []string{"rwhich_database must be a boolean"}},
		{"an env that is not an object is rejected", []string{upstream, "FreeBSD: { enabled: no, env: \"x\" }\n" + bodegaRepo}, StatusWarn, []string{"env must be an object"}},
		{"an unknown signature_type is rejected", []string{upstream, "FreeBSD: { enabled: no, signature_type: \"bogus\" }\n" + bodegaRepo}, StatusWarn, []string{`signature_type "bogus" is not`}},
		{"an empty signature_type is rejected, not read as absent", []string{upstream, "FreeBSD: { enabled: no, signature_type: \"\" }\n" + bodegaRepo}, StatusWarn, []string{"FreeBSD (", `signature_type "" is not`}},
		{"a signature_type with a leading space is rejected", []string{upstream, "FreeBSD: { enabled: no, signature_type: \" none\" }\n" + bodegaRepo}, StatusWarn, []string{"FreeBSD ("}},
		{"a sole bodega object with an empty signature_type creates nothing", []string{"bodega: { url: \"https://b/freebsd/x/latest\", signature_type: \"\" }\n"}, StatusWarn, []string{"no enabled repository points at a bodega", "pkg rejects and ignores bodega"}},
		{"an absent signature_type applies the override", []string{upstream, "FreeBSD: { enabled: no }\n" + bodegaRepo}, StatusOK, nil},
		{"signature_type none applies the override", []string{upstream, "FreeBSD: { enabled: no, signature_type: \"none\" }\n" + bodegaRepo}, StatusOK, nil},
		{"signature_type NONE applies the override", []string{upstream, "FreeBSD: { enabled: no, signature_type: \"NONE\" }\n" + bodegaRepo}, StatusOK, nil},
		{"a disable with no url on a new name creates nothing", []string{"FreeBSD: { enabled: no }\n", upstream + bodegaRepo}, StatusWarn, []string{"FreeBSD ("}},
		{"enabled carries over to a later object that leaves it unset", []string{"FreeBSD: { url: \"https://pkg.FreeBSD.org/x\", enabled: no }\n", "FreeBSD: { url: \"https://pkg.FreeBSD.org/y\" }\n" + bodegaRepo}, StatusOK, nil},
		{"the first object of a name in one file wins", []string{bodegaRepo + "bodega: { enabled: no }\n"}, StatusOK, nil},
		{"the first url in one object wins", []string{"bodega: { url: \"https://b/freebsd/x/latest\", url: \"https://pkg.FreeBSD.org/x\" }\n"}, StatusOK, nil},
		{"a bare url is a string", []string{"bodega: { url: https://b/freebsd/x/latest }\n"}, StatusOK, nil},
		{"Enabled matches without regard to case", []string{"FreeBSD: { url: \"https://pkg.FreeBSD.org/x\", Enabled: no }\n" + bodegaRepo}, StatusOK, nil},
		{"a host pkg fills in from a variable", []string{"x: { url: \"https://pkg.${OSNAME}.org/x\" }\n" + bodegaRepo}, StatusWarn, []string{"host doctor cannot resolve: x ("}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{}
			for i, body := range tt.files {
				files[fmt.Sprintf("/usr/local/etc/pkg/repos/%c.conf", 'a'+i)] = body
			}
			assertFinding(t, checkPkgRepos(writeTree(t, files), "freebsd"), tt.want, tt.detail...)
		})
	}
}

// Every key add_repo type-checks, given a value of the right type and one of
// the wrong type in the override that disables upstream. The right type
// applies the disable; the wrong one rejects the object and leaves upstream
// enabled.
func TestPkgRepoKeyKinds(t *testing.T) {
	good := map[uclKind]string{uclString: `"none"`, uclInt: "4", uclBool: "yes", uclObjectKind: "{ A: b }"}
	bad := map[uclKind]string{uclString: "5", uclInt: `"4"`, uclBool: `"yes"`, uclObjectKind: `"A=b"`}
	for key, kind := range pkgRepoKeyKinds {
		for _, tc := range []struct {
			val  string
			want Status
		}{{good[kind], StatusOK}, {bad[kind], StatusWarn}} {
			val := tc.val
			if key == "signature_type" && tc.want == StatusOK {
				val = `"fingerprints"`
			}
			if key == "url" && tc.want == StatusOK {
				val = `"https://b/freebsd/y/latest"`
			}
			t.Run(key+"="+val, func(t *testing.T) {
				root := writeTree(t, map[string]string{
					"/etc/pkg/FreeBSD.conf":                "FreeBSD: { url: \"https://pkg.FreeBSD.org/x\", enabled: yes }\n",
					"/usr/local/etc/pkg/repos/bodega.conf": "FreeBSD: { enabled: no, " + key + ": " + val + " }\nbodega: { url: \"https://b/freebsd/x/latest\" }\n",
				})
				assertFinding(t, checkPkgRepos(root, "freebsd"), tc.want)
			})
		}
	}
	for _, v := range []string{"10k", "0x4", "1.5", "+4", "NULL"} {
		t.Run("priority="+v, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"/usr/local/etc/pkg/repos/bodega.conf": "bodega: { url: \"https://b/freebsd/x/latest\", priority: " + v + " }\n",
			})
			assertFinding(t, checkPkgRepos(root, "freebsd"), StatusWarn, "cannot establish")
		})
	}
}

// pkg's configfile() skips a name starting with a dot, but an .include
// naming one reads it.
func TestPkgHiddenFiles(t *testing.T) {
	assertFinding(t, checkPkgRepos(writeTree(t, map[string]string{
		"/usr/local/etc/pkg/repos/.bodega.conf": "bodega: { url: \"https://b/freebsd/x/latest\" }\n",
	}), "freebsd"), StatusWarn, "no enabled repository points at a bodega")
	assertFinding(t, checkPkgRepos(writeTree(t, map[string]string{
		"/etc/pkg/FreeBSD.conf":                 stockFreeBSD15,
		"/usr/local/etc/pkg/repos/.off.conf":    "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n",
		"/usr/local/etc/pkg/repos/bodega.conf":  "bodega: { url: \"https://b/freebsd/x/latest\" }\n",
		"/usr/local/etc/pkg/repos/.conf":        "FreeBSD-ports: { enabled: no }\n",
		"/usr/local/etc/pkg/repos/off.conf.bak": "FreeBSD-ports: { enabled: no }\n",
	}), "freebsd"), StatusWarn, "FreeBSD-ports (", "FreeBSD-ports-kmods (")
	assertFinding(t, checkPkgRepos(writeTree(t, map[string]string{
		"/usr/local/etc/pkg/repos/bodega.conf":  ".include \"/usr/local/etc/pkg/repos/.bodega.conf\"\n",
		"/usr/local/etc/pkg/repos/.bodega.conf": "bodega: { url: \"https://b/freebsd/x/latest\" }\n",
	}), "freebsd"), StatusOK)
}

func TestPkgReposState(t *testing.T) {
	base := map[string]string{
		"/etc/pkg/FreeBSD.conf":                stockFreeBSD15,
		"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15,
	}
	with := func(extra ...string) map[string]string {
		m := maps.Clone(base)
		for _, p := range extra {
			m[p] = ""
		}
		return m
	}
	assertFinding(t, checkPkgRepos(writeTree(t, with()), "freebsd"), StatusOK)
	assertFinding(t, checkPkgRepos(writeTree(t, with("/var/db/pkg/repos_state/enable/FreeBSD-ports")), "freebsd"),
		StatusWarn, "FreeBSD-ports (pkg+https://pkg.FreeBSD.org/${ABI}/quarterly, set in /var/db/pkg/repos_state/enable/FreeBSD-ports)")
	assertFinding(t, checkPkgRepos(writeTree(t, with("/var/db/pkg/repos_state/disable/bodega-latest")), "freebsd"),
		StatusWarn, "no enabled repository points at a bodega")
	// enable/ wins over disable/, as pkg tests it first.
	assertFinding(t, checkPkgRepos(writeTree(t, with("/var/db/pkg/repos_state/disable/FreeBSD-base", "/var/db/pkg/repos_state/enable/FreeBSD-base")), "freebsd"),
		StatusWarn, "FreeBSD-base (")
}

func TestPkgConfOverrides(t *testing.T) {
	good := map[string]string{"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15}
	conf := func(body string) map[string]string {
		m := maps.Clone(good)
		m["/usr/local/etc/pkg.conf"] = body
		return m
	}
	assertFinding(t, checkPkgRepos(writeTree(t, conf("# REPOS_DIR: [\"/x\"]\nASSUME_ALWAYS_YES: no\nALIAS: { ls: \"query %n\" }\n")), "freebsd"), StatusOK)
	for _, body := range []string{"repos_dir: [\"/etc/pkg/\"]\n", "REPOSITORIES: { FreeBSD: { url: \"https://pkg.FreeBSD.org/x\" } }\n", "PKG_DBDIR = /tmp/db\n"} {
		assertFinding(t, checkPkgRepos(writeTree(t, conf(body)), "freebsd"), StatusWarn, "/usr/local/etc/pkg.conf sets", "cannot establish")
	}
	for _, k := range pkgConfOverrides {
		env := func(n string) string { return map[string]string{k: "/elsewhere"}[n] }
		assertFinding(t, checkPkgReposEnv(writeTree(t, good), "freebsd", env), StatusWarn, "the environment sets "+k)
	}
}

// What make on 15.1 expands each site to decides; the words doctor reads
// before expansion do not.
func TestMakeConfExpandedSites(t *testing.T) {
	check := map[string]string{clientconf.DistfilesCheckPath: "BODEGA_DISTFILES_ENV=abc\n"}
	for name, conf := range map[string]string{
		"a variable holding a second site": "MIRRORS=https://mirror.example/ https://b\n" + clientconf.MakeConf("${MIRRORS}").Content,
		"a parenthesized reference":        clientconf.MakeConf("$(MIRRORS)").Content,
		"a single-letter reference":        clientconf.MakeConf("https://b$M").Content,
	} {
		t.Run(name, func(t *testing.T) {
			files := maps.Clone(check)
			files["/etc/make.conf"] = conf
			assertFinding(t, checkMakeConf(writeTree(t, files), "freebsd", func(string) string { return "" }),
				StatusWarn, "MASTER_SITE_OVERRIDE=", "MASTER_SITE_BACKUP=", "which doctor does not expand")
		})
	}
}

func TestMakeConfEnvDefinition(t *testing.T) {
	conf := clientconf.MakeConf("https://b").Content
	for _, tc := range []struct {
		name, check, conf string
		want              Status
		detail            []string
	}{
		{"only under .if 0", ".if 0\nBODEGA_DISTFILES_ENV=abc\n.endif\n", conf, StatusWarn, []string{"does not define BODEGA_DISTFILES_ENV on any line make reads"}},
		{"under .if 1", ".if 1\nBODEGA_DISTFILES_ENV=abc\n.endif\n", conf, StatusOK, nil},
		{"under a condition doctor does not evaluate", ".if defined(X)\nBODEGA_DISTFILES_ENV=abc\n.endif\n", conf, StatusWarn, []string{"cannot establish defines BODEGA_DISTFILES_ENV"}},
		{"removed by .undef", "BODEGA_DISTFILES_ENV=abc\n.undef BODEGA_DISTFILES_ENV\n", conf, StatusWarn, []string{"does not define BODEGA_DISTFILES_ENV"}},
		{"kept by .READONLY through .undef", "BODEGA_DISTFILES_ENV=abc\n.READONLY: BODEGA_DISTFILES_ENV\n.undef BODEGA_DISTFILES_ENV\n", conf, StatusOK, nil},
		{"set in make.conf, not in the include", "X=1\n", "BODEGA_DISTFILES_ENV=abc\n" + conf, StatusWarn, []string{"its value comes from /etc/make.conf"}},
		{"to more than one word", "BODEGA_DISTFILES_ENV=abc https://mirror.example/\n", conf, StatusWarn, []string{"expands to one word"}},
		{"to a variable", "BODEGA_DISTFILES_ENV=${X}\n", conf, StatusWarn, []string{"expands to one word"}},
		{"empty", "BODEGA_DISTFILES_ENV=\n", conf, StatusWarn, []string{"expands to one word"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{"/etc/make.conf": tc.conf, clientconf.DistfilesCheckPath: tc.check})
			assertFinding(t, checkMakeConf(root, "freebsd", func(string) string { return "" }), tc.want, tc.detail...)
		})
	}
}

// make reads the environment below a makefile's own assignments: ?= keeps
// an environment value and = replaces it, measured with bmake on 15.1.
func TestMakeConfEnvironment(t *testing.T) {
	check := "BODEGA_DISTFILES_ENV=abc\n"
	rendered := clientconf.MakeConf("https://b").Content
	for _, tc := range []struct {
		name, conf string
		env        map[string]string
		want       Status
		detail     []string
	}{
		{"?= keeps the environment's site", rendered, map[string]string{"MASTER_SITE_OVERRIDE": "https://env.example/"}, StatusWarn, []string{"MASTER_SITE_OVERRIDE=https://env.example/ (set in the environment)"}},
		{"= replaces it", strings.ReplaceAll(rendered, "?=", "="), map[string]string{"MASTER_SITE_OVERRIDE": "https://env.example/"}, StatusOK, nil},
		{"+= onto it", strings.ReplaceAll(rendered, "?=", "+="), map[string]string{"MASTER_SITE_BACKUP": "https://env.example/"}, StatusWarn, []string{"appends to a value from the environment"}},
		{"MAKEFLAGS names a site", rendered, map[string]string{"MAKEFLAGS": "MASTER_SITE_BACKUP=https://env.example/"}, StatusWarn, []string{"MASTER_SITE_BACKUP cannot be established: the environment's MAKEFLAGS"}},
		{"DIST_SUBDIR from the environment", rendered, map[string]string{"DIST_SUBDIR": "x https://env.example"}, StatusWarn, []string{"DIST_SUBDIR=x https://env.example is set in the environment"}},
		{"DIST_SUBDIR in make.conf", "DIST_SUBDIR=x\n" + rendered, nil, StatusWarn, []string{"DIST_SUBDIR=x is set in /etc/make.conf"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{"/etc/make.conf": tc.conf, clientconf.DistfilesCheckPath: check})
			assertFinding(t, checkMakeConf(root, "freebsd", func(k string) string { return tc.env[k] }), tc.want, tc.detail...)
		})
	}
}

func TestPkgScalarAndObjectOfOneName(t *testing.T) {
	root := writeTree(t, map[string]string{
		"/usr/local/etc/pkg/repos/bodega.conf": "FreeBSD = \"x\";\nFreeBSD: { url: \"https://pkg.FreeBSD.org/x\" }\nbodega: { url: \"https://b/freebsd/x/latest\" }\n",
	})
	assertFinding(t, checkPkgRepos(root, "freebsd"), StatusWarn, "both a scalar and an object", "cannot establish")
}

// pkg tests each override variable for presence, so one set and empty
// replaces the default like any other value: with REPOS_DIR empty, pkg 2.8.4
// on 15.1 lists no repositories at all.
func TestPkgConfOverrideSetEmpty(t *testing.T) {
	root := writeTree(t, map[string]string{"/usr/local/etc/pkg/repos/bodega.conf": bodegaRepos15})
	lookup := func(k string) (string, bool) { return "", k == "REPOS_DIR" }
	assertFinding(t, checkPkgReposLookup(root, "freebsd", lookup), StatusWarn, `the environment sets REPOS_DIR=""`, "cannot establish")
}

// Where make on 15.1 takes each value from when flags, the environment and
// inputs doctor does not read decide precedence rather than the value
// written. Every expectation was measured with a recipe that echoes the
// expanded site, which is what fetch uses: make -V prints the makefile's
// value even under -e.
func TestMakeConfPrecedence(t *testing.T) {
	check := "BODEGA_DISTFILES_ENV=abc\n"
	rendered := clientconf.MakeConf("https://b").Content
	assigned := strings.ReplaceAll(rendered, "?=", "=")
	site := "https://b/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/"
	mirrors := map[string]string{"MASTER_SITE_OVERRIDE": "https://mirror.example/", "MASTER_SITE_BACKUP": "https://mirror.example/"}
	with := func(m map[string]string, kv ...string) map[string]string {
		out := maps.Clone(m)
		if out == nil {
			out = map[string]string{}
		}
		for i := 0; i < len(kv); i += 2 {
			out[kv[i]] = kv[i+1]
		}
		return out
	}
	for _, tc := range []struct {
		name, conf string
		files      map[string]string
		env        map[string]string
		want       Status
		detail     []string
	}{
		// -e from the environment, in each form bmake reads it.
		{"MAKEFLAGS=-e puts the environment's sites above =", assigned, nil, with(mirrors, "MAKEFLAGS", "-e"), StatusWarn,
			[]string{"MASTER_SITE_OVERRIDE=https://mirror.example/ (set in the environment, above make.conf because the environment's MAKEFLAGS passes -e)", "MASTER_SITE_BACKUP=https://mirror.example/"}},
		{"a bare first word in MAKEFLAGS is flags", assigned, nil, with(mirrors, "MAKEFLAGS", "e"), StatusWarn, []string{"passes -e"}},
		{"-e inside a cluster", assigned, nil, with(mirrors, "MAKEFLAGS", "-j 4 -ke"), StatusWarn, []string{"passes -e"}},
		{"MAKEFLAGS without -e leaves = above the environment", assigned, nil, with(mirrors, "MAKEFLAGS", "-j 4 -k"), StatusOK, nil},
		{"-e with no site in the environment", assigned, nil, map[string]string{"MAKEFLAGS": "-e"}, StatusOK, nil},
		{"-e with bodega's sites in the environment", assigned, nil, with(nil, "MAKEFLAGS", "-e", "MASTER_SITE_OVERRIDE", site, "MASTER_SITE_BACKUP", site), StatusOK, nil},
		{"-e takes BODEGA_DISTFILES_ENV from the environment", assigned, nil, with(nil, "MAKEFLAGS", "-e", distfilesEnvVar, "abc"), StatusWarn, []string{"its value comes from the environment"}},
		// -e from make.conf, which applies to every recipe however late it
		// is read.
		{".MAKEFLAGS: -e in make.conf", ".MAKEFLAGS: -e\n" + assigned, nil, mirrors, StatusWarn, []string{"above make.conf because .MAKEFLAGS in /etc/make.conf passes -e"}},
		{".MFLAGS: -e in the final include", assigned, map[string]string{clientconf.DistfilesCheckPath: check + ".MFLAGS: -e\n"}, mirrors, StatusWarn, []string{"passes -e"}},
		{".MAKEFLAGS: -e under a condition doctor does not evaluate", ".if defined(X)\n.MAKEFLAGS: -e\n.endif\n" + assigned, nil, mirrors, StatusWarn,
			[]string{"MASTER_SITE_OVERRIDE cannot be established: the environment sets it, and .MAKEFLAGS in /etc/make.conf may pass -e"}},
		{".MAKEFLAGS: -e under .if 0", ".if 0\n.MAKEFLAGS: -e\n.endif\n" + assigned, nil, mirrors, StatusOK, nil},
		// Other flags and words.
		{"a flag doctor does not model", assigned, nil, map[string]string{"MAKEFLAGS": "-I /tmp/mk"}, StatusWarn, []string{"the environment's MAKEFLAGS passes -I, which doctor does not model"}},
		{"a target in .MAKEFLAGS", ".MAKEFLAGS: all\n" + assigned, nil, nil, StatusWarn, []string{"passes all, which doctor does not model"}},
		{".MAKEFLAGS alongside another target", ".MAKEFLAGS .PHONY: -e\n" + assigned, nil, nil, StatusWarn, []string{"passes make flags on .MAKEFLAGS .PHONY: -e"}},
		{"-D is a global ?= keeps", rendered, nil, map[string]string{"MAKEFLAGS": "-D MASTER_SITE_OVERRIDE"}, StatusWarn, []string{"MASTER_SITE_OVERRIDE=1 (set in -D in the environment's MAKEFLAGS)"}},
		{"-D is a global = replaces", assigned, nil, map[string]string{"MAKEFLAGS": "-DMASTER_SITE_OVERRIDE"}, StatusOK, nil},
		{"-D beats the environment", rendered, nil, with(nil, "MAKEFLAGS", "-DDIST_SUBDIR", "DIST_SUBDIR", ""), StatusWarn, []string{"DIST_SUBDIR=1 is set in -D in the environment's MAKEFLAGS"}},
		{"a command-line assignment in .MAKEFLAGS", ".MAKEFLAGS: MASTER_SITE_BACKUP=https://mirror.example/\n" + assigned, nil, nil, StatusWarn,
			[]string{"MASTER_SITE_BACKUP cannot be established: .MAKEFLAGS in /etc/make.conf names it"}},
		{"a command-line assignment after --", assigned, nil, map[string]string{"MAKEFLAGS": "-- MASTER_SITE_BACKUP=https://mirror.example/"}, StatusWarn, []string{"MASTER_SITE_BACKUP cannot be established"}},
		{"MAKEFLAGS assigns __MAKE_CONF", rendered, nil, map[string]string{"MAKEFLAGS": "__MAKE_CONF=/tmp/other.conf"}, StatusWarn, []string{"cannot establish which make.conf"}},
		// Absent and empty are different to make.
		{"?= keeps an empty site from the environment", rendered, nil, map[string]string{"MASTER_SITE_OVERRIDE": ""}, StatusWarn, []string{"MASTER_SITE_OVERRIDE= (set in the environment)"}},
		{"= replaces an empty site from the environment", assigned, nil, map[string]string{"MASTER_SITE_OVERRIDE": ""}, StatusOK, nil},
		{"__MAKE_CONF set and empty", rendered, nil, map[string]string{"__MAKE_CONF": ""}, StatusWarn, []string{"__MAKE_CONF is set and empty"}},
		{"__MAKE_CONF relative", rendered, nil, map[string]string{"__MAKE_CONF": "make.conf"}, StatusWarn, []string{"is relative"}},
		// .undef removes a makefile value, not the environment's.
		{".undef leaves the environment's value", ".undef DIST_SUBDIR\n" + rendered, nil, map[string]string{"DIST_SUBDIR": "x"}, StatusWarn, []string{"DIST_SUBDIR=x is set in the environment"}},
		{".undef of a name doctor does not expand", assigned + "", map[string]string{clientconf.DistfilesCheckPath: check + ".undef ${X}\n"}, nil, StatusWarn, []string{"MASTER_SITE_OVERRIDE cannot be established: .undef ${X}"}},
		{"a later = after an unexpanded .undef", ".undef ${X}\n" + assigned, nil, nil, StatusOK, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := with(tc.files, "/etc/make.conf", tc.conf)
			if _, ok := files[clientconf.DistfilesCheckPath]; !ok {
				files[clientconf.DistfilesCheckPath] = check
			}
			lookup := func(k string) (string, bool) { v, ok := tc.env[k]; return v, ok }
			assertFinding(t, checkMakeConfLookup(writeTree(t, files), "freebsd", lookup), tc.want, tc.detail...)
		})
	}
}

// An input doctor did not read may have made a site read-only or a
// command-line variable, so no assignment or .undef after it proves the
// value make uses. An unknown branch holding only an ordinary assignment is
// different: a later unconditional one replaces it.
func TestMakeConfUnreadInputsPinSites(t *testing.T) {
	check := map[string]string{clientconf.DistfilesCheckPath: "BODEGA_DISTFILES_ENV=abc\n"}
	assigned := strings.ReplaceAll(clientconf.MakeConf("https://b").Content, "?=", "=")
	for _, tc := range []struct {
		name, conf string
		files      map[string]string
		want       Status
		detail     []string
	}{
		{"an unresolved include, then safe assignments", "LOCALBASE=/usr/local\n.include \"${LOCALBASE}/etc/sites.mk\"\n" + assigned, nil, StatusWarn,
			[]string{"MASTER_SITE_OVERRIDE cannot be established: /etc/make.conf includes ${LOCALBASE}/etc/sites.mk", "MASTER_SITE_BACKUP cannot be established"}},
		{"an unresolved include, then .undef", ".include \"${LOCALBASE}/etc/sites.mk\"\n.undef MASTER_SITE_OVERRIDE MASTER_SITE_BACKUP DIST_SUBDIR\n" + assigned, nil, StatusWarn,
			[]string{"MASTER_SITE_OVERRIDE cannot be established", "MASTER_SITE_BACKUP cannot be established"}},
		{"a self-include, then safe assignments", ".include \"/etc/make.conf\"\n" + assigned, nil, StatusWarn, []string{"MASTER_SITE_OVERRIDE cannot be established: /etc/make.conf includes /etc/make.conf, which is already being read"}},
		{".READONLY of a name doctor does not expand", "MASTER_SITE_OVERRIDE=https://mirror.example/\n.READONLY: ${X}\n" + assigned, nil, StatusWarn, []string{".READONLY in /etc/make.conf names variables doctor does not expand"}},
		{".READONLY under an unknown branch, then =", "MASTER_SITE_OVERRIDE=https://mirror.example/\n.if defined(X)\n.READONLY: MASTER_SITE_OVERRIDE\n.endif\n" + assigned, nil, StatusWarn, []string{"MASTER_SITE_OVERRIDE cannot be established"}},
		{".NOREADONLY under an unknown branch, then =", strings.Replace(clientconf.MakeConf("https://b").Content, ".include", ".READONLY: MASTER_SITE_OVERRIDE\n.if defined(X)\n.NOREADONLY:\n.endif\nMASTER_SITE_OVERRIDE=https://mirror.example/\n.include", 1), nil, StatusWarn,
			[]string{"MASTER_SITE_OVERRIDE cannot be established: .NOREADONLY under a conditional"}},
		{"a known .NOREADONLY, then =", "MASTER_SITE_OVERRIDE=https://mirror.example/\n.READONLY: MASTER_SITE_OVERRIDE\n.NOREADONLY: MASTER_SITE_OVERRIDE\n" + assigned, nil, StatusOK, nil},
		{"an unknown branch with an ordinary assignment, then =", ".if defined(X)\nMASTER_SITE_OVERRIDE=https://mirror.example/\n.endif\n" + assigned, nil, StatusOK, nil},
		{"an include doctor reads, then =", ".include \"/etc/sites.mk\"\n" + assigned, map[string]string{"/etc/sites.mk": "MASTER_SITE_OVERRIDE=https://mirror.example/\n"}, StatusOK, nil},
		{"an include doctor reads that pins, then =", ".include \"/etc/sites.mk\"\n" + assigned, map[string]string{"/etc/sites.mk": "MASTER_SITE_OVERRIDE=https://mirror.example/\n.READONLY: MASTER_SITE_OVERRIDE\n"}, StatusWarn,
			[]string{"MASTER_SITE_OVERRIDE=https://mirror.example/ (set in /etc/sites.mk) does not end every site"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := maps.Clone(check)
			maps.Copy(files, tc.files)
			files["/etc/make.conf"] = tc.conf
			assertFinding(t, checkMakeConf(writeTree(t, files), "freebsd", func(string) string { return "" }), tc.want, tc.detail...)
		})
	}
}

// Whether BODEGA_DISTFILES_ENV came from the client check is a property of
// the whole subtree the last include of make.conf reads, and returning from
// a child include inside it leaves the check's own later lines final.
func TestMakeConfFinalIncludeProvenance(t *testing.T) {
	conf := clientconf.MakeConf("https://b").Content
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  Status
		// detail is what the finding names; for WARN, why.
		detail []string
	}{
		{"defined by a child of the check", map[string]string{clientconf.DistfilesCheckPath: ".include \"/usr/local/etc/env.mk\"\n", "/usr/local/etc/env.mk": "BODEGA_DISTFILES_ENV=abc\n"}, StatusOK, nil},
		{"defined after an unrelated child", map[string]string{clientconf.DistfilesCheckPath: ".include \"/usr/local/etc/helper.mk\"\nBODEGA_DISTFILES_ENV=abc\n", "/usr/local/etc/helper.mk": "HELPER=1\n"}, StatusOK, nil},
		{"defined between two unrelated children", map[string]string{clientconf.DistfilesCheckPath: ".include \"/usr/local/etc/helper.mk\"\nBODEGA_DISTFILES_ENV=abc\n.include \"/usr/local/etc/helper.mk\"\n", "/usr/local/etc/helper.mk": "HELPER=1\n"}, StatusOK, nil},
		{"a child definition under .if 0", map[string]string{clientconf.DistfilesCheckPath: ".include \"/usr/local/etc/env.mk\"\n", "/usr/local/etc/env.mk": ".if 0\nBODEGA_DISTFILES_ENV=abc\n.endif\n"}, StatusWarn, []string{"does not define BODEGA_DISTFILES_ENV on any line make reads"}},
		{"a child definition the check then removes", map[string]string{clientconf.DistfilesCheckPath: ".include \"/usr/local/etc/env.mk\"\n.undef BODEGA_DISTFILES_ENV\n", "/usr/local/etc/env.mk": "BODEGA_DISTFILES_ENV=abc\n"}, StatusWarn, []string{"does not define BODEGA_DISTFILES_ENV"}},
		{"defined by an earlier include of make.conf", map[string]string{
			"/etc/make.conf":              ".include \"/usr/local/etc/env.mk\"\n" + conf,
			"/usr/local/etc/env.mk":       "BODEGA_DISTFILES_ENV=abc\n",
			clientconf.DistfilesCheckPath: "HELPER=1\n",
		}, StatusWarn, []string{"its value comes from /usr/local/etc/env.mk"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := maps.Clone(tc.files)
			if _, ok := files["/etc/make.conf"]; !ok {
				files["/etc/make.conf"] = conf
			}
			assertFinding(t, checkMakeConf(writeTree(t, files), "freebsd", func(string) string { return "" }), tc.want, tc.detail...)
		})
	}
}

// Each file follows an enabled upstream in a.conf as z.conf, and was given
// to pkg 2.8.4 on 15.1 with pkg -o REPOS_DIR=<dir> -vv. pkg discards a file
// it cannot lex whole, objects before the error included, so the upstream
// stays enabled. OK means pkg applied the file and doctor certifies it; a
// file pkg accepts but doctor does not lex the way libucl does is declined.
func TestPkgLexicalMatchesPkg(t *testing.T) {
	const b = `bodega: { url: "https://b/freebsd/x/latest" }`
	for _, tc := range []struct {
		name, body string
		want       Status
	}{
		{"a closed comment", `FreeBSD: { enabled: no } ` + b + ` /* closed */`, StatusOK},
		{"an unfinished comment after the disabling object", `FreeBSD: { enabled: no } ` + b + ` /* unclosed`, StatusSkip},
		{"a nested comment, which pkg accepts", `FreeBSD: { enabled: no } /* a /* b */ c */ ` + b, StatusWarn},
		{"a quote inside a comment, which pkg rejects", `FreeBSD: { enabled: no } /* " */ ` + b, StatusWarn},
		{"a newline in a double-quoted string", "FreeBSD: { enabled: no, pubkey: \"a\nb\" }\n" + b, StatusSkip},
		{"a tab in a double-quoted string", "FreeBSD: { enabled: no, pubkey: \"a\tb\" } " + b, StatusSkip},
		{"an unclosed string", `FreeBSD: { enabled: no } bodega: { url: "https://b/freebsd/x/latest }`, StatusSkip},
		{"a closing brace with nothing open", `FreeBSD: { enabled: no } ` + b + ` }`, StatusSkip},
		{"an empty bare value", `FreeBSD: { enabled: no, pubkey: , } ` + b, StatusSkip},
		{"an escape in a key doctor ignores", `FreeBSD: { enabled: no, pubkey: "a\qb" } ` + b, StatusOK},
		{"a newline in a single-quoted string", "FreeBSD: { enabled: no, pubkey: 'a\nb' } " + b, StatusOK},
		{"an escape in a url", `FreeBSD: { enabled: no } bodega: { url: "https:\/\/b/freebsd/x/latest" }`, StatusWarn},
		{"an escape in a repository name", `"Free\BSD": { enabled: no } ` + b, StatusWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"/usr/local/etc/pkg/repos/a.conf": `FreeBSD: { url: "https://pkg.FreeBSD.org/x", enabled: yes }` + "\n",
				"/usr/local/etc/pkg/repos/z.conf": tc.body + "\n",
			})
			assertFinding(t, checkPkgRepos(root, "freebsd"), tc.want)
		})
	}
	t.Run("an unfinished comment in an included file", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"/etc/pkg/FreeBSD.conf":                `FreeBSD: { url: "https://pkg.FreeBSD.org/x", enabled: yes }` + "\n",
			"/usr/local/etc/pkg/repos/bodega.conf": "FreeBSD: { enabled: no }\n" + b + "\n.include \"/tmp/tail.inc\"\n",
			"/tmp/tail.inc":                        "x: { enabled: no } /* unclosed\n",
		})
		assertFinding(t, checkPkgRepos(root, "freebsd"), StatusSkip, "unfinished multiline comment")
	})
}

// pkg 2.8.4 on 15.1 given each url on the FreeBSD override that disables
// upstream, with bodega's repository beside it. pkg validates every url
// after merging, disabled repositories included, and exits 1 on the first it
// refuses.
func TestPkgURLValidationMatchesPkg(t *testing.T) {
	const b = `bodega: { url: "https://b/freebsd/x/latest" }`
	for _, tc := range []struct {
		name, body string
		want       Status
		detail     []string
	}{
		{"absent keeps the earlier url", `FreeBSD: { enabled: no } ` + b, StatusOK, nil},
		{"empty", `FreeBSD: { enabled: no, url: "" } ` + b, StatusWarn, []string{"pkg refuses to start", "invalid url"}},
		{"https", `FreeBSD: { enabled: no, url: "https://c/freebsd/x" } ` + b, StatusOK, nil},
		{"pkg+https", `FreeBSD: { enabled: no, url: "pkg+https://c/freebsd/x" } ` + b, StatusOK, nil},
		{"file", `FreeBSD: { enabled: no, url: "file:///srv/x" } ` + b, StatusOK, nil},
		{"an unsupported scheme", `FreeBSD: { enabled: no, url: "gopher://c/x" } ` + b, StatusWarn, []string{"invalid scheme gopher"}},
		{"an upper-case scheme", `FreeBSD: { enabled: no, url: "HTTPS://c/x" } ` + b, StatusWarn, []string{"invalid scheme HTTPS"}},
		{"no scheme", `FreeBSD: { enabled: no, url: "c/x" } ` + b, StatusWarn, []string{"invalid url"}},
		{"a scheme a valid one begins with", `FreeBSD: { enabled: no, url: "htt://c/x" } ` + b, StatusOK, nil},
		{"an empty scheme", `FreeBSD: { enabled: no, url: ":/c/x" } ` + b, StatusOK, nil},
		{"an empty url on a new disabled repository", `FreeBSD: { enabled: no } ` + b + ` z: { url: "", enabled: no }`, StatusWarn, []string{"repository z", "invalid url"}},
		{"a variable in the scheme", `FreeBSD: { enabled: no, url: "${S}://c/x" } ` + b, StatusWarn, []string{"cannot establish that pkg starts"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"/usr/local/etc/pkg/repos/a.conf": `FreeBSD: { url: "https://pkg.FreeBSD.org/x", enabled: yes }` + "\n",
				"/usr/local/etc/pkg/repos/z.conf": tc.body + "\n",
			})
			assertFinding(t, checkPkgRepos(root, "freebsd"), tc.want, tc.detail...)
		})
	}
}

// Export directives change the environment while make reads makefiles, so
// the one doctor started with no longer says what a recipe under -e reads,
// or what .undef falls back to. Measured with bmake on 15.1: .unexport-env
// and .export-literal of make.conf's mirror sites leave a recipe under -e
// fetching from the mirror, though the environment named bodega.
func TestMakeConfExportDirectives(t *testing.T) {
	site := "https://b/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/"
	mirror := strings.ReplaceAll(strings.ReplaceAll(clientconf.MakeConf("https://b").Content, "?=", "="), site, "https://mirror.example/")
	assigned := strings.ReplaceAll(clientconf.MakeConf("https://b").Content, "?=", "=")
	eSafe := map[string]string{"MAKEFLAGS": "-e", "MASTER_SITE_OVERRIDE": site, "MASTER_SITE_BACKUP": site}
	before := func(conf, lines string) string { return strings.Replace(conf, ".include", lines+".include", 1) }
	for _, tc := range []struct {
		name, conf string
		inc        string
		env        map[string]string
		want       Status
		detail     []string
	}{
		{"-e with no directive takes the environment's sites", mirror, "", eSafe, StatusOK, nil},
		{".unexport-env under -e", before(mirror, ".unexport-env\n"), "", eSafe, StatusWarn, []string{"MASTER_SITE_OVERRIDE cannot be established: .unexport-env in /etc/make.conf changes the environment"}},
		{".export-literal under -e", before(mirror, ".export-literal MASTER_SITE_OVERRIDE MASTER_SITE_BACKUP\n"), "", eSafe, StatusWarn, []string{"MASTER_SITE_BACKUP cannot be established: .export-literal"}},
		{".export-env under -e", before(mirror, ".export-env MASTER_SITE_OVERRIDE\n"), "", eSafe, StatusWarn, []string{"MASTER_SITE_OVERRIDE cannot be established"}},
		{".export with no names under -e", before(mirror, ".export\n"), "", eSafe, StatusWarn, []string{"MASTER_SITE_BACKUP cannot be established"}},
		{".unexport of a name doctor does not expand under -e", before(mirror, ".unexport ${X}\n"), "", eSafe, StatusWarn, []string{"cannot be established"}},
		{".unexport-env under .if 0", before(mirror, ".if 0\n.unexport-env\n.endif\n"), "", eSafe, StatusOK, nil},
		{".unexport-env under a condition doctor does not evaluate", before(mirror, ".if defined(X)\n.unexport-env\n.endif\n"), "", eSafe, StatusWarn, []string{"cannot be established"}},
		{".unexport-env in an earlier include", ".include \"/etc/local.mk\"\n" + mirror, "", eSafe, StatusWarn, []string{".unexport-env in /etc/local.mk"}},
		{".unexport-env in the final include", mirror, ".unexport-env\n", eSafe, StatusWarn, []string{"cannot be established"}},
		{"an export naming another variable", before(mirror, ".export-literal OTHER\n"), "", eSafe, StatusOK, nil},
		// Without -e a makefile assignment still shadows the environment.
		{".unexport-env without -e, sites assigned after", ".unexport-env\n" + assigned, "", nil, StatusOK, nil},
		{".undef back to a changed environment", ".unexport-env\n" + assigned + ".undef MASTER_SITE_OVERRIDE\n", "", map[string]string{"MASTER_SITE_OVERRIDE": site}, StatusWarn, []string{"MASTER_SITE_OVERRIDE cannot be established: .unexport-env"}},
		{".export-env of DIST_SUBDIR from the environment", ".export-env DIST_SUBDIR\n" + assigned, "", map[string]string{"DIST_SUBDIR": ""}, StatusWarn, []string{"DIST_SUBDIR, which the route expands, may be set"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"/etc/make.conf":              tc.conf,
				"/etc/local.mk":               ".unexport-env\n",
				clientconf.DistfilesCheckPath: "BODEGA_DISTFILES_ENV=abc\n" + tc.inc,
			}
			lookup := func(k string) (string, bool) { v, ok := tc.env[k]; return v, ok }
			assertFinding(t, checkMakeConfLookup(writeTree(t, files), "freebsd", lookup), tc.want, tc.detail...)
		})
	}
}

// -D __MAKE_CONF in MAKEFLAGS sets a global of 1 that sys.mk's ?= keeps, so
// bmake on 15.1 reads no make.conf at all, or under -e the environment's.
// Either way doctor has not established the file it would be certifying.
func TestMakeConfDefineSelectsFile(t *testing.T) {
	assigned := strings.ReplaceAll(clientconf.MakeConf("https://b").Content, "?=", "=")
	for _, mf := range []string{"-D__MAKE_CONF", "-D __MAKE_CONF", "-e -D__MAKE_CONF", "-kD __MAKE_CONF"} {
		for _, envConf := range []string{"", "/etc/make.conf"} {
			t.Run(mf+" __MAKE_CONF="+envConf, func(t *testing.T) {
				env := map[string]string{"MAKEFLAGS": mf}
				if envConf != "" {
					env["__MAKE_CONF"] = envConf
				}
				root := writeTree(t, map[string]string{"/etc/make.conf": assigned, clientconf.DistfilesCheckPath: "BODEGA_DISTFILES_ENV=abc\n"})
				lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
				assertFinding(t, checkMakeConfLookup(root, "freebsd", lookup), StatusWarn, "defines __MAKE_CONF with -D", "cannot establish which make.conf")
			})
		}
	}
	t.Run("-D of another variable leaves the selection alone", func(t *testing.T) {
		root := writeTree(t, map[string]string{"/etc/make.conf": assigned, clientconf.DistfilesCheckPath: "BODEGA_DISTFILES_ENV=abc\n"})
		lookup := func(k string) (string, bool) {
			v, ok := map[string]string{"MAKEFLAGS": "-D__MAKE_CONFX"}[k]
			return v, ok
		}
		assertFinding(t, checkMakeConfLookup(root, "freebsd", lookup), StatusOK)
	})
}

// Nested values pkg 2.8.4 was given on 15.1 under a key add_repo ignores,
// in a file that also disables FreeBSD, with what pkg -vv reported: pkg
// discards the whole file over a malformed nested value, leaving FreeBSD
// enabled. doctor may decline a form pkg accepts, but never certify one pkg
// rejects.
func TestPkgNestedValuesMatchPkg(t *testing.T) {
	for value, pkgAccepts := range map[string]bool{
		`{ a: "x" }`: true, `{ a = x; b = y }`: true, `{ a x }`: true, `{ a: x, }`: true,
		`{}`: true, "{ a: x\nb: y }": true, `{ a: x b: y }`: true, `[a, b]`: true, `[a b]`: true,
		"[a\nb]": true, `[a, b,]`: true, `[a; b]`: true, `[]`: true, `{ a: [ { b: c } ] }`: true,
		"{ a: b # c\n}": true, `{ a: /* c */ b }`: true, `{ a: { } }`: true, `[ { } ]`: true,
		`{ "a": "b" }`: true, `{ a: "" }`: true, `[ "" ]`: true, `{ a { b: c } }`: true,
		`[ , ]`: false, `{ a: b ]`: false, `[ a }`: false, `{ bad: }`: false, `{ garbage }`: false,
		`{ bad: , }`: false, `{ bad: [ }`: false, `[ }`: false, `{ a: { b: } }`: false, `[ [ ] ]]`: false,
	} {
		for _, key := range []string{"ignored", "env"} {
			t.Run(key+" "+value, func(t *testing.T) {
				root := writeTree(t, map[string]string{
					"/etc/pkg/FreeBSD.conf":                `FreeBSD: { url: "https://pkg.FreeBSD.org/x", enabled: yes }`,
					"/usr/local/etc/pkg/repos/bodega.conf": "FreeBSD: { enabled: no, " + key + ": " + value + " }\nbodega: { url: \"https://b/freebsd/x/latest\" }\n",
				})
				got := checkPkgRepos(root, "freebsd")
				// env must be an object, or add_repo refuses the override.
				certify := pkgAccepts && (key != "env" || strings.HasPrefix(value, "{"))
				switch {
				case !certify && got.Status == StatusOK:
					t.Fatalf("status = OK (%s); pkg leaves FreeBSD enabled", got.Detail)
				case certify && got.Status != StatusOK:
					t.Fatalf("status = %s (%s); pkg reads the disabling override", got.Status, got.Detail)
				}
			})
		}
	}
	t.Run("malformed nested value in an included file", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"/etc/pkg/FreeBSD.conf":                `FreeBSD: { url: "https://pkg.FreeBSD.org/x", enabled: yes }`,
			"/usr/local/etc/pkg/repos/bodega.conf": "bodega: { url: \"https://b/freebsd/x/latest\" }\n.include \"/usr/local/etc/pkg/off.inc\"\n",
			"/usr/local/etc/pkg/off.inc":           "FreeBSD: { enabled: no, env: { bad: } }\n",
		})
		if got := checkPkgRepos(root, "freebsd"); got.Status == StatusOK {
			t.Fatalf("status = OK (%s); pkg rejects bodega.conf with its include", got.Detail)
		}
	})
	t.Run("forms doctor declines", func(t *testing.T) {
		for _, value := range []string{`[a,,b]`, `{ a: b"c }`, `{ a: <<EOD` + "\nx\nEOD\n}", `{ .include "/x" }`} {
			root := writeTree(t, map[string]string{
				"/usr/local/etc/pkg/repos/bodega.conf": "bodega: { url: \"https://b/freebsd/x/latest\", other: " + value + " }\n",
			})
			assertFinding(t, checkPkgRepos(root, "freebsd"), StatusWarn, "doctor cannot establish which repositories pkg reads")
		}
	})
}

// Operations that write the environment without naming a site variable,
// each measured with bmake on 15.1 or documented in its make(1): under -e a
// recipe expands the environment, so a site exported from make.conf is what
// fetch uses. The environment starts at bodega's route and make.conf sets
// the mirror; doctor may certify only where nothing exported the mirror.
func TestMakeConfEnvironmentControls(t *testing.T) {
	site := "https://b/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/"
	mirror := "MASTER_SITE_OVERRIDE=https://mirror.example/\nMASTER_SITE_BACKUP=https://mirror.example/\n"
	for _, tc := range []struct {
		name, conf, local, flags string
		want                     Status
	}{
		{name: "no export", conf: mirror, flags: "-e", want: StatusOK},
		{name: ".export-all", conf: mirror + ".export-all\n", flags: "-e", want: StatusWarn},
		{name: ".MAKE.EXPORTED=", conf: mirror + ".MAKE.EXPORTED=MASTER_SITE_OVERRIDE MASTER_SITE_BACKUP\n", flags: "-e", want: StatusWarn},
		{name: ".MAKE.EXPORTED+=", conf: mirror + ".MAKE.EXPORTED+=MASTER_SITE_OVERRIDE MASTER_SITE_BACKUP\n", flags: "-e", want: StatusWarn},
		{name: ".MAKE.EXPORTED:=", conf: mirror + ".MAKE.EXPORTED:=MASTER_SITE_OVERRIDE MASTER_SITE_BACKUP\n", flags: "-e", want: StatusWarn},
		{name: "computed export list", conf: "SITES=MASTER_SITE_OVERRIDE MASTER_SITE_BACKUP\n" + mirror + ".MAKE.EXPORTED=${SITES}\n", flags: "-e", want: StatusWarn},
		{name: "computed variable name", conf: "L=.MAKE.EXPORTED\n" + mirror + "${L}=MASTER_SITE_OVERRIDE MASTER_SITE_BACKUP\n", flags: "-e", want: StatusWarn},
		{name: "export name=value", conf: "export MASTER_SITE_OVERRIDE=https://mirror.example/\nexport MASTER_SITE_BACKUP=https://mirror.example/\n", flags: "-e", want: StatusWarn},
		{name: ".export-all under an unknown conditional", conf: mirror + ".if defined(X)\n.export-all\n.endif\n", flags: "-e", want: StatusWarn},
		{name: ".export-all under a skipped conditional", conf: mirror + ".if 0\n.export-all\n.endif\n", flags: "-e", want: StatusOK},
		{name: ".export-all in an included file", conf: mirror + ".include \"/etc/local.mk\"\n", local: ".export-all\n", flags: "-e", want: StatusWarn},
		{name: ".MAKE.EXPORTED in MAKEFLAGS", conf: mirror, flags: "-e .MAKE.EXPORTED=MASTER_SITE_OVERRIDE", want: StatusWarn},
		{name: "another control variable", conf: mirror + ".MAKE.SAVE_DOLLARS=no\n", flags: "-e", want: StatusWarn},
		{name: "a special target doctor does not model", conf: mirror + ".SHELL: name=sh\n", flags: "-e", want: StatusWarn},
		{name: "a computed target", conf: "T=.MAKEFLAGS\n" + mirror + "${T}: -X\n", flags: "-e", want: StatusWarn},
		{name: "an attribute target", conf: mirror + ".PHONY: fetch\n", flags: "-e", want: StatusOK},
		{name: ".export-all without -e", conf: "MASTER_SITE_OVERRIDE=" + site + "\nMASTER_SITE_BACKUP=" + site + "\n.export-all\n", want: StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"/etc/make.conf":              tc.conf + ".include \"" + clientconf.DistfilesCheckPath + "\"\n",
				"/etc/local.mk":               tc.local,
				clientconf.DistfilesCheckPath: "BODEGA_DISTFILES_ENV=abc\n",
			})
			env := map[string]string{"MAKEFLAGS": tc.flags, "MASTER_SITE_OVERRIDE": site, "MASTER_SITE_BACKUP": site}
			lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
			assertFinding(t, checkMakeConfLookup(root, "freebsd", lookup), tc.want)
		})
	}
}

// A tab-led line is a shell command of the open dependency group, whatever
// it looks like, and bmake on 15.1 refuses one when no group is open. Only
// an assignment closes a group; a leading space, even before a tab, makes an
// ordinary line.
func TestMakeConfRecipeLines(t *testing.T) {
	site := "https://b/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/"
	mirror := "MASTER_SITE_OVERRIDE=https://mirror.example/\nMASTER_SITE_BACKUP=https://mirror.example/\n"
	safe := "MASTER_SITE_OVERRIDE=" + site + "\nMASTER_SITE_BACKUP=" + site + "\n"
	indent := func(prefix, s string) string {
		return prefix + strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\n"+prefix) + "\n"
	}
	check := "BODEGA_DISTFILES_ENV=abc\n"
	for _, tc := range []struct {
		name, conf, local, check string
		want                     Status
		detail                   string
	}{
		{name: "global assignments", conf: safe, want: StatusOK},
		{name: "recipe assignments in make.conf", conf: mirror + "unused:\n" + indent("\t", safe), want: StatusWarn, detail: "mirror.example"},
		{name: "recipe assignments in an included file", conf: mirror + "unused:\n.include \"/etc/local.mk\"\n", local: indent("\t", safe), want: StatusWarn, detail: "mirror.example"},
		{name: "recipe assignments across an include's return", conf: mirror + ".include \"/etc/local.mk\"\n" + indent("\t", safe), local: "unused:\n", want: StatusWarn, detail: "mirror.example"},
		{name: "recipe assignments under a conditional", conf: mirror + "unused:\n.if 1\n" + indent("\t", safe) + ".endif\n", want: StatusWarn, detail: "mirror.example"},
		{name: "tab-led line with no target", conf: indent("\t", safe), want: StatusWarn, detail: "unassociated shell command"},
		{name: "tab-led line after an assignment closed the group", conf: "unused:\nX=1\n" + indent("\t", safe), want: StatusWarn, detail: "unassociated shell command"},
		{name: "tab-led line after a target make may skip", conf: ".if defined(X)\nunused:\n.endif\n" + indent("\t", safe), want: StatusWarn, detail: "cannot establish follows a target"},
		{name: "space-led assignments after a target", conf: mirror + "unused:\n" + indent("  ", safe), want: StatusOK},
		{name: "space then tab after a target", conf: mirror + "unused:\n" + indent(" \t", safe), want: StatusOK},
		{name: "recipe-only client check definition", conf: safe, check: "unused:\n\tBODEGA_DISTFILES_ENV=abc\n", want: StatusWarn, detail: "does not define BODEGA_DISTFILES_ENV"},
		{name: "a line with no operator", conf: safe + "foo bar\n", want: StatusWarn, detail: "refuses as invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := check
			if tc.check != "" {
				c = tc.check
			}
			root := writeTree(t, map[string]string{
				"/etc/make.conf":              tc.conf + ".include \"" + clientconf.DistfilesCheckPath + "\"\n",
				"/etc/local.mk":               tc.local,
				clientconf.DistfilesCheckPath: c,
			})
			var detail []string
			if tc.detail != "" {
				detail = append(detail, tc.detail)
			}
			assertFinding(t, checkMakeConf(root, "freebsd", func(string) string { return "" }), tc.want, detail...)
		})
	}
	t.Run("tab-led final include", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"/etc/make.conf":              safe + "unused:\n\t.include \"" + clientconf.DistfilesCheckPath + "\"\n",
			clientconf.DistfilesCheckPath: check,
		})
		assertFinding(t, checkMakeConf(root, "freebsd", func(string) string { return "" }), StatusWarn, "shell command rather than an .include")
	})
}

// A byte libucl may read as structure is refused in every unquoted token,
// whatever depth or file it sits in; the same bytes quoted are text.
func TestPkgBareTokensHoldNoStructure(t *testing.T) {
	upstream := `FreeBSD: { url: "https://pkg.FreeBSD.org/x", enabled: yes }`
	bodega := ` bodega: { url: "https://b/freebsd/x/latest" }`
	for _, tok := range []string{`abc{`, `abc[`, `a"b"`, `a'b'`, `a\b`, `a/*b*/`} {
		for name, body := range map[string]string{
			"field":  `FreeBSD: { enabled: no, ignored: ` + tok + ` }` + bodega,
			"nested": `FreeBSD: { enabled: no, ignored: { deeper: [ ` + tok + ` ] } }` + bodega,
			"key":    `FreeBSD: { enabled: no, ` + tok + `: x }` + bodega,
			"scalar": `stray ` + tok + "\n" + `FreeBSD: { enabled: no }` + bodega,
		} {
			t.Run(name+"/"+tok, func(t *testing.T) {
				root := writeTree(t, map[string]string{
					"/etc/pkg/FreeBSD.conf":                upstream,
					"/usr/local/etc/pkg/repos/bodega.conf": body,
				})
				if got := checkPkgRepos(root, "freebsd"); got.Status == StatusOK {
					t.Fatalf("OK over %q: %s", body, got.Detail)
				}
			})
		}
		t.Run("included/"+tok, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"/etc/pkg/FreeBSD.conf":                upstream,
				"/usr/local/etc/pkg/repos/bodega.conf": ".include \"/usr/local/etc/pkg/off.inc\"\n" + bodega,
				"/usr/local/etc/pkg/off.inc":           `FreeBSD: { enabled: no, ignored: ` + tok + ` }`,
			})
			if got := checkPkgRepos(root, "freebsd"); got.Status == StatusOK {
				t.Fatalf("OK: %s", got.Detail)
			}
		})
	}
	for _, tok := range []string{`"abc{"`, `'a[b'`, `abc`, `"a/*b"`} {
		t.Run("quoted/"+tok, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"/etc/pkg/FreeBSD.conf":                upstream,
				"/usr/local/etc/pkg/repos/bodega.conf": `FreeBSD: { enabled: no, ignored: ` + tok + ` }` + bodega,
			})
			assertFinding(t, checkPkgRepos(root, "freebsd"), StatusOK)
		})
	}
}

// An expression make evaluates may assign, whatever line carries it and
// however indirectly it is reached. Each case is make.conf's bodega sites
// followed by the lines given, then the client check.
func TestMakeConfExpressionEffects(t *testing.T) {
	site := "https://b/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/"
	safe := "MASTER_SITE_OVERRIDE=" + site + "\nMASTER_SITE_BACKUP=" + site + "\nMIRROR=https://mirror.example/\n"
	effects := map[string]string{
		"assign":            "${MASTER_SITE_OVERRIDE::=${MIRROR}}",
		"assign-if-unset":   "${MASTER_SITE_OVERRIDE::?=${MIRROR}}",
		"append":            "${MASTER_SITE_OVERRIDE::+=${MIRROR}}",
		"assign-shell":      "${MASTER_SITE_OVERRIDE::!=echo x}",
		"underscore":        "${MIRROR:_=MASTER_SITE_OVERRIDE}",
		"loop-deletes-site": "${MIRROR:@MASTER_SITE_OVERRIDE@x@}",
		"loop-control":      "${MIRROR:@.MAKEFLAGS@x@}",
		"indirect-modifier": "${MIRROR:${MODS}}",
		"computed-name":     "${${NAME}}",
		"paren-form":        "$(MASTER_SITE_OVERRIDE::=${MIRROR})",
	}
	sites := map[string]func(expr string) string{
		"immediate":      func(e string) string { return "UNRELATED:= " + e + "\n" },
		"indirect":       func(e string) string { return "EFFECT=" + e + "\nUNRELATED:= ${EFFECT}\n" },
		"two-hops":       func(e string) string { return "E1=" + e + "\nE2=${E1}\nUNRELATED:= ${E2}\n" },
		"defined-later":  func(e string) string { return "E2=${E1}\nE1=" + e + "\nUNRELATED:= ${E2}\n" },
		"info":           func(e string) string { return "EFFECT=" + e + "\n.info ${EFFECT}\n" },
		"warning":        func(e string) string { return ".warning " + e + "\n" },
		"condition":      func(e string) string { return "EFFECT=" + e + "\n.if \"${EFFECT}\" == \" \"\n.endif\n" },
		"empty-function": func(e string) string { return "EFFECT=" + e + "\n.if empty(EFFECT)\n.endif\n" },
		"elif":           func(e string) string { return ".if 0\n.elif \"" + e + "\" == \"\"\n.endif\n" },
		"for-list":       func(e string) string { return ".for _x in " + e + "\n.endfor\n" },
		"shell-command":  func(e string) string { return "UNRELATED!= echo " + e + "\n" },
		"dependency":     func(e string) string { return "foo: " + e + "\n" },
		"recipe":         func(e string) string { return ".BEGIN:\n\t@: " + e + "\n" },
		"undef":          func(e string) string { return ".undef " + e + "\n" },
		"deferred-only":  func(e string) string { return "FETCH_ENV=" + e + "\n" },
		"unknown-branch": func(e string) string { return ".if ${OPSYS} == FreeBSD\nUNRELATED:= " + e + "\n.endif\n" },
	}
	for sname, wrap := range sites {
		for ename, expr := range effects {
			t.Run(sname+"/"+ename, func(t *testing.T) {
				root := writeTree(t, map[string]string{
					"/etc/make.conf":                     safe + wrap(expr) + ".include \"/usr/local/etc/bodega-distfiles.mk\"\n",
					"/usr/local/etc/bodega-distfiles.mk": "BODEGA_DISTFILES_ENV=abc\n",
				})
				if got := checkMakeConf(root, "freebsd", func(string) string { return "" }); got.Status == StatusOK {
					t.Fatalf("OK: %s", got.Detail)
				}
			})
		}
	}

	// Text that reaches make again after one expansion is syntax there.
	for name, lines := range map[string]string{
		"dollars-through-:=":     "HIDDEN:= $${MASTER_SITE_OVERRIDE::=x}\nUNRELATED:= ${HIDDEN}\n",
		"shell-output-expanded":  "HIDDEN!= echo x\n.if !empty(HIDDEN:M*)\n.endif\n",
		"for-substitutes-dollar": "LIST=$$x\n.for _x in ${LIST}\n.endfor\n",
		"loop-over-dollars":      "HIDDEN!= echo x\nUNRELATED:= ${HIDDEN:@w@${w}@}\n",
		"in-included-file":       ".include \"/etc/more.mk\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"/etc/make.conf":                     safe + lines + ".include \"/usr/local/etc/bodega-distfiles.mk\"\n",
				"/etc/more.mk":                       "UNRELATED:= ${MASTER_SITE_BACKUP::=${MIRROR}}\n",
				"/usr/local/etc/bodega-distfiles.mk": "BODEGA_DISTFILES_ENV=abc\n",
			})
			if got := checkMakeConf(root, "freebsd", func(string) string { return "" }); got.Status == StatusOK {
				t.Fatalf("OK: %s", got.Detail)
			}
		})
	}

	// An effect in the client check itself counts as one in make.conf.
	t.Run("in-client-check", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"/etc/make.conf":                     safe + ".include \"/usr/local/etc/bodega-distfiles.mk\"\n",
			"/usr/local/etc/bodega-distfiles.mk": "BODEGA_DISTFILES_ENV=abc\n.info ${MASTER_SITE_OVERRIDE::=x}\n",
		})
		if got := checkMakeConf(root, "freebsd", func(string) string { return "" }); got.Status == StatusOK {
			t.Fatalf("OK: %s", got.Detail)
		}
	})

	// The environment's values are make syntax wherever make expands them.
	t.Run("environment-value", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"/etc/make.conf":                     safe + "UNRELATED:= ${FROM_ENV}\n.include \"/usr/local/etc/bodega-distfiles.mk\"\n",
			"/usr/local/etc/bodega-distfiles.mk": "BODEGA_DISTFILES_ENV=abc\n",
		})
		env := map[string]string{"FROM_ENV": "${MASTER_SITE_OVERRIDE::=x}"}
		lookup := func(n string) (string, bool) { v, ok := env[n]; return v, ok }
		if got := checkMakeConfEnviron(root, "freebsd", lookup, []string{"FROM_ENV=" + env["FROM_ENV"]}); got.Status == StatusOK {
			t.Fatalf("OK: %s", got.Detail)
		}
	})

	// Pure expressions stay certifiable.
	for name, lines := range map[string]string{
		"filters":        "UNRELATED:= ${MIRROR:M*:N*.org:S/a/b/:tu}\n",
		"condition-form": "UNRELATED:= ${\"${MIRROR}\" == \"\":?yes:no}\n",
		"info":           ".info ${MIRROR:Q}\n",
		"condition":      ".if !empty(MIRROR:M*) && defined(MIRROR)\n.endif\n",
		"safe-loop":      "UNRELATED:= ${MIRROR:@w@<${w}>@}\n",
		"shell-compared": ".if \"${:!echo hi!}\" == \"hi\"\n.endif\n",
	} {
		t.Run("pure/"+name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"/etc/make.conf":                     safe + lines + ".include \"/usr/local/etc/bodega-distfiles.mk\"\n",
				"/usr/local/etc/bodega-distfiles.mk": "BODEGA_DISTFILES_ENV=abc\n",
			})
			assertFinding(t, checkMakeConf(root, "freebsd", func(string) string { return "" }), StatusOK)
		})
	}
}

// The served client check runs commands whose output make expands again;
// doctor models what each one prints, for every environment bodega can
// declare, and certifies it only while those inputs hold no effect.
func TestCheckMakeConfServedCheckCommands(t *testing.T) {
	snap := filepath.Join(t.TempDir(), "snap")
	if err := os.WriteFile(snap, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := distinfo.EnvironmentSpec{
		Variables: map[string][]string{"WITH_DEBUG": {"yes"}, "NO_X11": {}},
		Files:     map[string][]string{"/etc/src.conf": {distinfo.Absent}, "/usr/local/etc/declared.conf": {snap, distinfo.Absent}},
	}
	env, err := spec.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{clientconf.DistfilesCheckPath, "/net/b/distfiles/@environment.mk"} {
		conf := strings.ReplaceAll(clientconf.MakeConf("https://b").Content, clientconf.DistfilesCheckPath, path)
		files := map[string]string{"/etc/make.conf": conf, path: string(env.ClientCheck())}
		t.Run(path, func(t *testing.T) {
			lookup := func(string) (string, bool) { return "", false }
			assertFinding(t, checkMakeConfEnviron(writeTree(t, files), "freebsd", lookup, []string{"PS1=\\u@\\h\\$ ", "HOME=/root"}), StatusOK)
		})
		t.Run(path+"/environment-effect", func(t *testing.T) {
			lookup := func(string) (string, bool) { return "", false }
			got := checkMakeConfEnviron(writeTree(t, files), "freebsd", lookup, []string{"LC_X=${MASTER_SITE_OVERRIDE::=https://mirror.example/}"})
			assertFinding(t, got, StatusWarn, "may assign a variable")
		})
		t.Run(path+"/ports-tree-dollar", func(t *testing.T) {
			lookup := func(n string) (string, bool) {
				if n == "PORTSDIR" {
					return "/usr/ports$${X}", true
				}
				return "", false
			}
			assertFinding(t, checkMakeConfLookup(writeTree(t, files), "freebsd", lookup), StatusWarn, "may assign a variable")
		})
	}
}

// A missing first candidate proves an include absent only where make looks
// nowhere else.
func TestMakeConfIncludeSearch(t *testing.T) {
	site := "https://b/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/"
	safe := "MASTER_SITE_OVERRIDE=" + site + "\nMASTER_SITE_BACKUP=" + site + "\n"
	check := ".include \"/usr/local/etc/bodega-distfiles.mk\"\n"
	for _, tc := range []struct {
		name, line string
		extra      map[string]string
		env        map[string]string
		want       Status
	}{
		{"relative soft, missing beside", ".sinclude \"other.mk\"\n", nil, nil, StatusWarn},
		{"relative -include, missing beside", ".-include \"other.mk\"\n", nil, nil, StatusWarn},
		{"relative dinclude, missing beside", ".dinclude \"other.mk\"\n", nil, nil, StatusWarn},
		{"relative hard, missing beside", ".include \"other.mk\"\n", nil, nil, StatusWarn},
		{"relative, found beside", ".sinclude \"other.mk\"\n", map[string]string{"/etc/other.mk": "UNRELATED=1\n"}, nil, StatusOK},
		{"relative, found beside with an override", ".sinclude \"other.mk\"\n", map[string]string{"/etc/other.mk": "MASTER_SITE_OVERRIDE=https://mirror.example/\n"}, nil, StatusWarn},
		{"absolute soft, absent", ".sinclude \"/nonexistent/other.mk\"\n", nil, nil, StatusOK},
		{"system soft, absent", ".sinclude <nonexistent.mk>\n", nil, nil, StatusOK},
		{"system soft, MAKESYSPATH set", ".sinclude <nonexistent.mk>\n", nil, map[string]string{"MAKESYSPATH": "/elsewhere"}, StatusWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"/etc/make.conf":                     safe + tc.line + check,
				"/usr/local/etc/bodega-distfiles.mk": "BODEGA_DISTFILES_ENV=abc\n",
			}
			for p, b := range tc.extra {
				files[p] = b
			}
			lookup := func(n string) (string, bool) { v, ok := tc.env[n]; return v, ok }
			assertFinding(t, checkMakeConfLookup(writeTree(t, files), "freebsd", lookup), tc.want)
		})
	}
}

func TestMakeConfLoopDoctorCannotParse(t *testing.T) {
	site := "https://b/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/"
	root := writeTree(t, map[string]string{
		"/etc/make.conf":                     "MASTER_SITE_OVERRIDE=" + site + "\nMASTER_SITE_BACKUP=" + site + "\nUNRELATED:= ${A:@v@${B:@MASTER_SITE_OVERRIDE@x@}@}\n.include \"/usr/local/etc/bodega-distfiles.mk\"\n",
		"/usr/local/etc/bodega-distfiles.mk": "BODEGA_DISTFILES_ENV=abc\n",
	})
	if got := checkMakeConf(root, "freebsd", func(string) string { return "" }); got.Status == StatusOK {
		t.Fatalf("OK: %s", got.Detail)
	}
}
