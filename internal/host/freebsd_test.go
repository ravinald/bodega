package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
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

func TestMakeConfSitesComeFromTheRenderer(t *testing.T) {
	names, route := makeConfSites()
	if strings.Join(names, ",") != "MASTER_SITE_OVERRIDE,MASTER_SITE_BACKUP" {
		t.Errorf("names = %v", names)
	}
	if route != "/distfiles/@${"+distfilesEnvVar+"}/${DIST_SUBDIR}/" {
		t.Errorf("route = %q", route)
	}
}
