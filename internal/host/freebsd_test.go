package host

import (
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
	check := "_BODEGA_DISTFILES_DRIFT=\nBODEGA_DISTFILES_ENV=\t${\"${_BODEGA_DISTFILES_DRIFT:M*}\" == \"\":?abc:unsupported}\n"
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
			detail: []string{"MASTER_SITE_OVERRIDE cannot be established", ".READONLY"},
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
