package clientconf

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

const testBase = "https://bodega.example.com"

// TestRenderers pins every renderer's output for one base URL, character for
// character. Each client parses its file strictly and reports a bad one
// against the file rather than against whatever produced it.
func TestRenderers(t *testing.T) {
	aptSrc := aptsources.Render(aptsources.State{PublicURL: testBase, Suites: []string{"jammy"}, Signed: true})
	repo, err := pkgrepos.Render(pkgrepos.State{
		PublicURL: testBase, Repo: "latest", ABI: "FreeBSD:15:amd64",
		Upstream: "https://pkg.freebsd.org/FreeBSD:15:amd64/latest",
	})
	if err != nil {
		t.Fatalf("pkgrepos.Render: %v", err)
	}

	for _, tc := range []struct {
		name    string
		got     File
		content string
		paths   map[string]string
	}{
		{
			name:    "pip",
			got:     Pip(testBase + "/"),
			content: "[global]\nindex-url = https://bodega.example.com/pypi/simple/\n",
			paths: map[string]string{
				OSLinux:   "/etc/pip.conf",
				OSFreeBSD: "/etc/pip.conf",
				OSDarwin:  "/Library/Application Support/pip/pip.conf",
			},
		},
		{
			name:    "npm",
			got:     Npm(testBase),
			content: "registry=https://bodega.example.com/npm/\n",
			paths:   everywhere("~/.npmrc"),
		},
		{
			name: "cargo",
			got:  Cargo(testBase),
			content: "[source.crates-io]\nreplace-with = \"bodega\"\n\n" +
				"[source.bodega]\nregistry = \"sparse+https://bodega.example.com/cargo/\"\n",
			paths: everywhere("~/.cargo/config.toml"),
		},
		{
			name:    "gomod",
			got:     Gomod(testBase),
			content: "GOPROXY=https://bodega.example.com/go\n",
			paths: map[string]string{
				OSLinux:   "~/.config/go/env",
				OSFreeBSD: "~/.config/go/env",
				OSDarwin:  "~/Library/Application Support/go/env",
			},
		},
		{
			name: "helm",
			got:  Helm(testBase),
			content: "apiVersion: \"\"\ngenerated: \"0001-01-01T00:00:00Z\"\nrepositories:\n" +
				"- name: bodega\n  url: https://bodega.example.com/helm\n",
			paths: map[string]string{
				OSLinux:   "~/.config/helm/repositories.yaml",
				OSFreeBSD: "~/.config/helm/repositories.yaml",
				OSDarwin:  "~/Library/Preferences/helm/repositories.yaml",
			},
		},
		{
			name: "git",
			got: Git(testBase, map[string]config.GitUpstream{
				"gitlab": {URL: "https://gitlab.example.com/"},
				"github": {URL: "https://github.com/"},
			}),
			content: "[url \"https://bodega.example.com/git/github/\"]\n\tinsteadOf = https://github.com/\n" +
				"[url \"https://bodega.example.com/git/gitlab/\"]\n\tinsteadOf = https://gitlab.example.com/\n",
			paths: everywhere("~/.gitconfig"),
		},
		{
			name: "make.conf",
			got:  MakeConf(testBase),
			content: "MASTER_SITE_OVERRIDE?= https://bodega.example.com/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/\n" +
				"MASTER_SITE_BACKUP?= https://bodega.example.com/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/\n" +
				".include \"/usr/local/etc/bodega-distfiles.mk\"\n",
			paths: map[string]string{OSFreeBSD: "/etc/make.conf"},
		},
		{
			name:    "apt",
			got:     Apt(aptSrc),
			content: aptSrc.Deb822 + "\n",
			paths:   map[string]string{OSLinux: "/etc/apt/sources.list.d/bodega.sources"},
		},
		{
			name:    "freebsd",
			got:     FreeBSD(repo),
			content: repo.Conf,
			paths:   map[string]string{OSFreeBSD: "/usr/local/etc/pkg/repos/bodega.conf"},
		},
		{
			name:    "binary",
			got:     Binary(testBase, BinaryLink{Filename: "tool", Path: "tool/1.0/tool"}),
			content: "https://bodega.example.com/binaries/tool/1.0/tool",
		},
		{
			name:    "git bundle",
			got:     GitBundleURL(testBase, GitBundle{Name: "org/repo", Ref: "v1.0.0"}),
			content: "https://bodega.example.com/git/org--repo/org--repo-v1.0.0.bundle",
		},
		{
			name:    "git release",
			got:     GitBundleURL(testBase, GitBundle{Name: "org/repo", Ref: "v1.0.0", Release: true}),
			content: "https://bodega.example.com/git/org--repo/org--repo-v1.0.0.tar.gz",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got.Content != tc.content {
				t.Errorf("content:\n got %q\nwant %q", tc.got.Content, tc.content)
			}
			if len(tc.got.Paths) != len(tc.paths) {
				t.Errorf("paths: got %v, want %v", tc.got.Paths, tc.paths)
			}
			for goos, want := range tc.paths {
				if got := tc.got.Path(goos); got != want {
					t.Errorf("path on %s: got %q, want %q", goos, got, want)
				}
			}
			if tc.got.Label == "" {
				t.Error("no label; a pane would render the row with an empty key")
			}
		})
	}
}

// The apt stanza's notes travel on the file, because the web page and the TUI
// read them off it and the [trusted=yes] consequence must reach both.
func TestAptCarriesNotes(t *testing.T) {
	f := Apt(aptsources.Render(aptsources.State{PublicURL: testBase, Suites: []string{"jammy"}}))
	if len(f.Notes) == 0 || !strings.Contains(strings.Join(f.Notes, " "), "trusted=yes") {
		t.Errorf("unsigned stanza carries no note on its trust option: %q", f.Notes)
	}
}

// helmRepoFile mirrors helm's repo.File, the struct helm unmarshals
// repositories.yaml into, with the entry fields bodega writes.
type helmRepoFile struct {
	APIVersion   string    `yaml:"apiVersion"`
	Generated    time.Time `yaml:"generated"`
	Repositories []struct {
		Name                  string `yaml:"name"`
		URL                   string `yaml:"url"`
		Username              string `yaml:"username"`
		Password              string `yaml:"password"`
		InsecureSkipTLSverify bool   `yaml:"insecure_skip_tls_verify"`
	} `yaml:"repositories"`
}

// parseHelmFile decodes a rendered repositories.yaml the way helm does,
// strict about keys.
func parseHelmFile(t *testing.T, doc string) helmRepoFile {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(doc))
	dec.KnownFields(true)
	var f helmRepoFile
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("helm could not read this repositories.yaml: %v\n%s", err, doc)
	}
	return f
}

// TestHelmIsARepositoryFile parses what Helm renders as the file helm reads,
// rather than comparing bytes: the bare list item this renderer used to
// return passed a byte comparison and `helm repo list` read no repository
// from it. The credential-bearing entry goes through the same parse, because
// it is the same document with keys added to the one item.
func TestHelmIsARepositoryFile(t *testing.T) {
	for name, doc := range map[string]string{
		"public":     Helm(testBase + "/").Content,
		"credential": HelmDocument(HelmRepository(testBase, "username: bodega", "password: tok")),
	} {
		t.Run(name, func(t *testing.T) {
			f := parseHelmFile(t, doc)
			if len(f.Repositories) != 1 || f.Repositories[0].Name != "bodega" || f.Repositories[0].URL != testBase+"/helm" {
				t.Fatalf("no bodega repository at %s/helm in:\n%s", testBase, doc)
			}
		})
	}
}

// TestNoDirectFallback holds the GOPROXY value to what doctor accepts. Both
// earlier copies appended a direct fallback, which doctor's goproxy-env check
// reports as a bypass of the server that handed the value out.
func TestNoDirectFallback(t *testing.T) {
	if got := GoProxy(testBase + "/"); got != testBase+"/go" {
		t.Errorf("GoProxy = %q, want %q", got, testBase+"/go")
	}
}

// TestForTypeCoversEveryKnownType asserts every manifest type renders
// something through the one dispatcher, given the inputs its caller supplies.
// A type with no arm falls through to nothing, and both panes drop the row.
func TestForTypeCoversEveryKnownType(t *testing.T) {
	in := Inputs{
		Base:         testBase,
		GitUpstreams: map[string]config.GitUpstream{"github": {URL: "https://github.com/"}},
		Apt:          []aptsources.Sources{aptsources.Render(aptsources.State{PublicURL: testBase})},
		FreeBSD:      []pkgrepos.Repo{{Repo: "latest", ABI: "FreeBSD:15:amd64", Conf: "bodega-latest: {}\n"}},
		Binary:       []BinaryLink{{Filename: "tool", Path: "tool/1.0/tool"}},
	}
	for _, typ := range manifest.AllTypes {
		if got := ForType(typ, in); len(got) == 0 {
			t.Errorf("ForType(%q) rendered nothing", typ)
		}
	}
	if got := ForType(manifest.TypeGit, Inputs{Base: testBase}); len(got) != 0 {
		t.Errorf("git with no upstreams and no bundle rendered %d files; an empty insteadOf is not configuration", len(got))
	}
}

// clientLineMarkers are fragments of client configuration syntax. One inside
// a string literal in the TUI or the server, or in the page's script, means
// that surface is composing a client line itself instead of taking it from
// this package, which is how the two earlier copies drifted.
var clientLineMarkers = []string{
	"index-url",
	"registry=",
	"--registry",
	"replace-with",
	"sparse+",
	"[registries.",
	"[source.",
	"GOPROXY=",
	"insteadOf",
	"MASTER_SITE_OVERRIDE",
	"MASTER_SITE_BACKUP",
	"helm repo add",
	"name: bodega",
}

// tuiRouteMarkers are the served routes a client line is built on. The TUI
// serves none of them, so one in a TUI literal is a URL composed for a client
// there; the server names them in its own routing and is held to the syntax
// markers alone.
var tuiRouteMarkers = []string{
	"/apt/", "/binaries/", "/cargo/", "/distfiles/", "/git/", "/go", "/helm", "/npm/", "/pypi/",
}

// TestNoSurfaceComposesAClientLine fails when the TUI or the server renders a
// client line without this package. Comments are exempt: they name the syntax
// to explain it. Route patterns are string literals too, so the check reads
// the literal's value against the markers rather than the file's text.
func TestNoSurfaceComposesAClientLine(t *testing.T) {
	for dir, markers := range map[string][]string{
		"../tui":    append(append([]string(nil), clientLineMarkers...), tuiRouteMarkers...),
		"../server": clientLineMarkers,
	} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no Go files under %s; the guard is reading the wrong tree", dir)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				for _, m := range markers {
					if strings.Contains(val, m) && !routePattern(val) {
						t.Errorf("%s: literal %q holds %q; render it through internal/clientconf", fset.Position(lit.Pos()), val, m)
					}
				}
				return true
			})
		}
	}

	page, err := os.ReadFile("../server/web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script := regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(string(page), "")
	for _, m := range append([]string{"getClientUrl", "/pypi/simple", "/go,"}, clientLineMarkers...) {
		if strings.Contains(script, m) {
			t.Errorf("web/index.html holds %q outside a comment; the page reads client_config off GET /api/v1/packages/{type}/{name}", m)
		}
	}
}

// routePattern reports a net/http mux pattern, which names a route rather
// than handing a client a line.
func routePattern(s string) bool {
	return strings.HasPrefix(s, "GET /") || strings.HasPrefix(s, "POST /") || strings.HasPrefix(s, "HEAD /")
}

// A namespaced binary is served at /binaries/<its name>; anything else keeps
// the storage-key link BinaryLinkName composes.
func TestNamespacedBinaryPath(t *testing.T) {
	upstreams := map[string]config.BinaryUpstream{"github": {URL: "https://github.com/"}}
	for _, tc := range []struct {
		name, want string
		ok         bool
	}{
		{"github/ravinald/wifimgr/releases/download/v0.1.1/wifimgr.tar.gz", "github/ravinald/wifimgr/releases/download/v0.1.1/wifimgr.tar.gz", true},
		{"wifimgr", "", false},
		{"github", "", false},
		{"github/", "", false},
		{"githbu/ravinald/wifimgr.tar.gz", "", false},
	} {
		got, ok := NamespacedBinaryPath(tc.name, upstreams)
		if got != tc.want || ok != tc.ok {
			t.Errorf("NamespacedBinaryPath(%q) = %q, %v, want %q, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
	if _, ok := NamespacedBinaryPath("github/ravinald/wifimgr.tar.gz", nil); ok {
		t.Error("a name is namespaced with no binary_upstreams configured")
	}
	f := Binary(testBase, BinaryLink{Filename: "wifimgr.tar.gz", Path: "github/ravinald/wifimgr.tar.gz"})
	if want := testBase + "/binaries/github/ravinald/wifimgr.tar.gz"; f.Content != want {
		t.Errorf("Binary content = %q, want %q", f.Content, want)
	}
}
