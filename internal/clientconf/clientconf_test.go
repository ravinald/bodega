package clientconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
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
			got:     Npm(testBase, nil),
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
		RpmRepos:     []string{"rocky-baseos"},
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

// TestPipTrustedHost pins the trusted-host pip needs before it reads a
// plaintext index. The IPv6 form was measured against pip 26.2.1: with no
// trusted-host it ignores http://[2001:db8::5]:8080/ and suggests
// `--trusted-host 2001:db8::5`, and with that bracketless line it does not.
func TestPipTrustedHost(t *testing.T) {
	for _, tc := range []struct {
		base, want string
	}{
		{"http://10.0.0.5:8080", "[global]\nindex-url = http://10.0.0.5:8080/pypi/simple/\ntrusted-host = 10.0.0.5\n"},
		{"http://bodega.internal/", "[global]\nindex-url = http://bodega.internal/pypi/simple/\ntrusted-host = bodega.internal\n"},
		{"http://[2001:db8::5]:8080", "[global]\nindex-url = http://[2001:db8::5]:8080/pypi/simple/\ntrusted-host = 2001:db8::5\n"},
		{"https://bodega.internal", "[global]\nindex-url = https://bodega.internal/pypi/simple/\n"},
	} {
		if got := Pip(tc.base).Content; got != tc.want {
			t.Errorf("Pip(%q).Content = %q, want %q", tc.base, got, tc.want)
		}
	}
}

// .npmrc is the registry line alone whatever binary_upstreams holds: npm
// warns on a disturl line and its next major stops forwarding it. node-gyp's
// mirror is NodeMirror's file, rendered only for an open nodejs.org
// namespace, under whatever key it has. A catalog namespace leaves a note on
// .npmrc instead, because it would 404 every header no manifest names.
func TestNpmPointsNodeGypThroughNodeMirror(t *testing.T) {
	registry := "registry=https://bodega.example.com/npm/\n"
	cases := []struct {
		name      string
		upstreams map[string]config.BinaryUpstream
		mirror    string
		note      string
	}{
		{"no binary namespace", nil, "", ""},
		{"open nodejs namespace", map[string]config.BinaryUpstream{
			"nodejs": {URL: "https://nodejs.org/", Mode: config.UpstreamModeOpen},
		}, "https://bodega.example.com/binaries/nodejs/dist", ""},
		{"other key", map[string]config.BinaryUpstream{
			"rustup": {URL: "https://static.rust-lang.org/", Mode: config.UpstreamModeOpen},
			"node":   {URL: "https://nodejs.org/", Mode: config.UpstreamModeOpen},
		}, "https://bodega.example.com/binaries/node/dist", ""},
		{"catalog nodejs namespace", map[string]config.BinaryUpstream{
			"nodejs": {URL: "https://nodejs.org/", Mode: config.UpstreamModeCatalog},
		}, "", `binary_upstreams["nodejs"] is in catalog mode`},
		{"other host only", map[string]config.BinaryUpstream{
			"nodejs": {URL: "https://nodejs.example.com/", Mode: config.UpstreamModeOpen},
			"dist":   {URL: "https://nodejs.org/dist/", Mode: config.UpstreamModeOpen},
		}, "", ""},
		{"two nodejs namespaces pick the first sorted", map[string]config.BinaryUpstream{
			"zeta":  {URL: "https://nodejs.org/", Mode: config.UpstreamModeOpen},
			"alpha": {URL: "https://NodeJS.org/", Mode: config.UpstreamModeOpen},
		}, "https://bodega.example.com/binaries/alpha/dist", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			npmrc := Npm(testBase+"/", tc.upstreams)
			if npmrc.Content != registry {
				t.Errorf("Npm content = %q, want %q", npmrc.Content, registry)
			}
			if got := strings.Join(npmrc.Notes, "\n"); (tc.note == "") != (got == "") || !strings.Contains(got, tc.note) {
				t.Errorf("Npm notes = %q, want one holding %q", got, tc.note)
			}
			wantSystem, wantUser := "", ""
			if tc.mirror != "" {
				wantSystem = "export NODEJS_ORG_MIRROR='" + tc.mirror + "'\n"
				wantUser = "NODEJS_ORG_MIRROR=" + tc.mirror + "\n"
			}
			sys := NodeMirror(testBase, tc.upstreams, true)
			if sys.Content != wantSystem || sys.Path(OSLinux) != NodeMirrorSystemPath || sys.Path(OSFreeBSD) != NodeMirrorSystemPath {
				t.Errorf("NodeMirror(system) = %+v, want %q at %s", sys, wantSystem, NodeMirrorSystemPath)
			}
			user := NodeMirror(testBase, tc.upstreams, false)
			if user.Content != wantUser || user.Path(OSLinux) != NodeMirrorUserPath || user.Path(OSFreeBSD) != "" {
				t.Errorf("NodeMirror(user) = %+v, want %q at %s on linux alone", user, wantUser, NodeMirrorUserPath)
			}
			got := ForType(manifest.TypeNpm, Inputs{Base: testBase, BinaryUpstreams: tc.upstreams})
			want := 1
			if tc.mirror != "" {
				want = 2
			}
			if len(got) != want || got[0].Content != registry || (want == 2 && got[1].Content != wantSystem) {
				t.Errorf("ForType(npm) = %+v, want .npmrc and %d mirror file(s)", got, want-1)
			}
			for _, f := range got {
				if strings.Contains(f.Content, "disturl") {
					t.Errorf("ForType(npm) still renders disturl: %q", f.Content)
				}
			}
		})
	}
}

// The profile script is sourced by every login shell, so a quote in the URL
// stays inside the value rather than ending it.
func TestNodeMirrorQuotesTheProfileValue(t *testing.T) {
	up := map[string]config.BinaryUpstream{"nodejs": {URL: "https://nodejs.org/", Mode: config.UpstreamModeOpen}}
	got := NodeMirror("https://h/it's", up, true).Content
	if want := `export NODEJS_ORG_MIRROR='https://h/it'\''s/binaries/nodejs/dist'` + "\n"; got != want {
		t.Errorf("NodeMirror content = %q, want %q", got, want)
	}
}

func TestRubygemsRendersGemrcAndBundlerMirror(t *testing.T) {
	files := Rubygems(testBase + "/")
	if len(files) != 2 {
		t.Fatalf("Rubygems rendered %d files, want ~/.gemrc and ~/.bundle/config", len(files))
	}
	for i, want := range []struct{ path, content string }{
		{"~/.gemrc", "---\n:sources:\n- https://bodega.example.com/rubygems/\n"},
		{"~/.bundle/config", "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"https://bodega.example.com/rubygems/\"\n"},
	} {
		f := files[i]
		if f.System != manifest.TypeRubygems || f.Content != want.content {
			t.Errorf("file %d: system %q content %q, want rubygems and %q", i, f.System, f.Content, want.content)
		}
		for _, os := range []string{OSLinux, OSFreeBSD, OSDarwin} {
			if got := f.Path(os); got != want.path {
				t.Errorf("file %d on %s at %q, want %q", i, os, got, want.path)
			}
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(f.Content), &doc); err != nil {
			t.Errorf("%s is not YAML: %v", want.path, err)
		}
	}
}

func TestComposerRendersAGlobalConfigWithPackagistOff(t *testing.T) {
	f := Composer(testBase + "/")
	if f.System != manifest.TypeComposer {
		t.Errorf("system %q, want composer", f.System)
	}
	var doc struct {
		Repositories map[string]any `json:"repositories"`
	}
	if err := json.Unmarshal([]byte(f.Content), &doc); err != nil {
		t.Fatalf("config.json is not JSON: %v\n%s", err, f.Content)
	}
	bodega, _ := doc.Repositories["bodega"].(map[string]any)
	if bodega["type"] != "composer" || bodega["url"] != "https://bodega.example.com/composer" {
		t.Errorf("repositories.bodega = %v, want a composer repository at https://bodega.example.com/composer", bodega)
	}
	if v, ok := doc.Repositories["packagist.org"]; !ok || v != false {
		t.Errorf("repositories[\"packagist.org\"] = %v, want false so Packagist is not read around bodega", v)
	}
	for os, want := range map[string]string{OSLinux: "~/.config/composer/config.json", OSDarwin: "~/.composer/config.json", OSFreeBSD: "~/.composer/config.json"} {
		if got := f.Path(os); got != want {
			t.Errorf("path on %s = %q, want %q", os, got, want)
		}
	}
}

// testCA mints a CA and a certificate it issues for dnsName, both as PEM.
func testCA(t *testing.T, dnsName string) (caPEM, leafPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bodega test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// caPlan builds the changes a plan carries for files, each a system and its
// rendered file, at the file's Linux path rooted under home.
func caPlan(t *testing.T, home string, files ...File) []Change {
	t.Helper()
	var out []Change
	for _, f := range files {
		p := f.Path(OSLinux)
		if !strings.HasPrefix(p, "~/") {
			p = "~" + p
		}
		sum := sha256.Sum256([]byte(f.Content))
		c, err := NewChange(PlanRecord{System: f.System, Action: PlanInstall, Path: p, SHA256: hex.EncodeToString(sum[:])}, []byte(f.Content), home)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func changeAt(t *testing.T, changes []Change, target string) Change {
	t.Helper()
	for _, c := range changes {
		if c.Target == target {
			return c
		}
	}
	var have []string
	for _, c := range changes {
		have = append(have, c.Target)
	}
	t.Fatalf("no change writes %s; the plan writes:\n  %s", target, strings.Join(have, "\n  "))
	return Change{}
}

// F116 R1, R3: the CA lands where each client reads it, every other setting
// in an edited file is kept, and a second plan over the applied host changes
// nothing and runs no trust store step.
func TestAddCALandsWhereEachClientReadsIt(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	home, root := t.TempDir(), t.TempDir()
	h := CAHost{Base: testBase, Home: home, Root: root, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\nID_LIKE=debian\n")}
	plan := func() []Change {
		oci := OCIClient(testBase, map[string]string{"docker.io": "https://registry-1.docker.io"})
		files := []File{
			Npm(testBase, nil), Pip(testBase),
			Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}}),
			Gomod(testBase), Cargo(testBase),
		}
		for _, f := range oci {
			files = append(files, f.File)
		}
		return caPlan(t, home, files...)
	}
	userCA := filepath.Join(home, ".config/bodega/ca.pem")

	in, err := AddCA(plan(), ca, h)
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{
		filepath.Join(home, ".npmrc"):       "registry=https://bodega.example.com/npm/\ncafile=" + userCA + "\n",
		filepath.Join(home, "etc/pip.conf"): "[global]\ncert = " + userCA + "\nindex-url = https://bodega.example.com/pypi/simple/\n",
		filepath.Join(home, ".gitconfig"):   "[url \"https://bodega.example.com/git/gh/\"]\n\tinsteadOf = https://github.com/\n[http \"https://bodega.example.com/\"]\n\tsslCAInfo = " + userCA + "\n",
		userCA:                              string(caPEM),
		filepath.Join(home, "etc/docker/certs.d/bodega.example.com/ca.crt"):     string(caPEM),
		filepath.Join(home, "etc/containers/certs.d/bodega.example.com/ca.crt"): string(caPEM),
		filepath.Join(root, "usr/local/share/ca-certificates/bodega-ca.crt"):    string(caPEM),
	} {
		if got := string(changeAt(t, in.Changes, target).New); got != want {
			t.Errorf("%s =\n%s\nwant\n%s", target, got, want)
		}
	}
	var hosts struct {
		Server string `toml:"server"`
		Host   map[string]struct {
			CA           string   `toml:"ca"`
			Capabilities []string `toml:"capabilities"`
		} `toml:"host"`
	}
	hostsToml := changeAt(t, in.Changes, filepath.Join(home, "etc/containerd/certs.d/docker.io/hosts.toml"))
	if _, err := toml.Decode(string(hostsToml.New), &hosts); err != nil {
		t.Fatalf("hosts.toml does not parse: %v\n%s", err, hostsToml.New)
	}
	if got := hosts.Host[testBase]; got.CA != userCA || len(got.Capabilities) != 2 || hosts.Server == "" {
		t.Errorf("hosts.toml host table = %+v, server %q; want ca %s beside the capabilities\n%s", got, hosts.Server, userCA, hostsToml.New)
	}
	if !slices.Equal(in.Step, []string{"update-ca-certificates"}) {
		t.Errorf("step = %v, want update-ca-certificates for the anchor go and cargo read through", in.Step)
	}
	// daemon.json takes no CA setting: Docker reads certs.d beside it.
	if got := changeAt(t, in.Changes, filepath.Join(home, "etc/docker/daemon.json")); strings.Contains(string(got.New), "ca") {
		t.Errorf("daemon.json gained a CA key: %s", got.New)
	}

	if _, err := Apply(in.Changes, ".bak"); err != nil {
		t.Fatal(err)
	}
	again, err := AddCA(plan(), ca, h)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range again.Changes {
		if !c.Unchanged() {
			t.Errorf("a second plan still changes %s:\n%s\nto\n%s", c.Target, c.Old, c.New)
		}
	}
	if again.Step != nil {
		t.Errorf("a second plan runs %v with no anchor changed", again.Step)
	}
}

// F116 R1: a file under /etc names the shared copy rather than one in a home
// directory, and each family's anchor and command are its own.
func TestAddCAFollowsTheHost(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(append(caPEM, caPEM...))
	if err != nil {
		t.Fatal(err)
	}
	apt := Change{Record: PlanRecord{System: manifest.TypeApt, Path: AptSourcesPath}, Target: AptSourcesPath}
	for _, tc := range []struct {
		name, goos, osRelease string
		anchors               []string
		step                  []string
	}{
		{"ubuntu", OSLinux, "ID=ubuntu\nID_LIKE=debian\n",
			[]string{"usr/local/share/ca-certificates/bodega-ca.crt", "usr/local/share/ca-certificates/bodega-ca-2.crt"}, []string{"update-ca-certificates"}},
		{"rocky", OSLinux, "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n",
			[]string{"etc/pki/ca-trust/source/anchors/bodega-ca.pem", "etc/pki/ca-trust/source/anchors/bodega-ca-2.pem"}, []string{"update-ca-trust", "extract"}},
		{"freebsd", OSFreeBSD, "",
			[]string{"usr/local/share/certs/bodega-ca.pem", "usr/local/share/certs/bodega-ca-2.pem"}, []string{"certctl", "rehash"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			pip := Change{Record: PlanRecord{System: manifest.TypePypi, Path: "/etc/pip.conf"}, Target: "/etc/pip.conf", New: []byte(Pip(testBase).Content)}
			in, err := AddCA([]Change{apt, pip}, ca, CAHost{Base: testBase, Home: t.TempDir(), Root: root, GOOS: tc.goos, OSRelease: []byte(tc.osRelease)})
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range tc.anchors {
				// One certificate to a file: c_rehash and certctl link a
				// file by the first certificate in it.
				if got := changeAt(t, in.Changes, filepath.Join(root, a)); string(got.New) != string(caPEM) {
					t.Errorf("%s = %s, want one certificate", a, got.New)
				}
			}
			if !slices.Equal(in.Step, tc.step) {
				t.Errorf("step = %v, want %v", in.Step, tc.step)
			}
			shared := filepath.Join(root, CASharedPath)
			if got := string(in.Changes[1].New); !strings.Contains(got, "cert = "+shared+"\n") {
				t.Errorf("/etc/pip.conf names no shared copy at %s:\n%s", shared, got)
			}
			changeAt(t, in.Changes, shared)
		})
	}

	_, err = AddCA([]Change{apt}, ca, CAHost{Base: testBase, GOOS: OSDarwin})
	if err == nil || !strings.Contains(err.Error(), "apt verify through the system trust store") {
		t.Errorf("a system-store client on macOS = %v, want a refusal naming it", err)
	}
	if _, err := AddCA([]Change{apt}, ca, CAHost{Base: "http://bodega.example.com", GOOS: OSLinux}); err == nil {
		t.Error("a plaintext base took a CA")
	}
	mvn := Change{Record: PlanRecord{System: manifest.TypeMaven, Path: MavenSettingsPath}}
	in, err := AddCA([]Change{mvn}, ca, CAHost{Base: testBase, GOOS: OSDarwin})
	if err != nil || !strings.Contains(in.Notes[manifest.TypeMaven], "keytool") || len(in.Changes) != 1 {
		t.Errorf("maven = %v, notes %v, %d changes; want the keytool note and no file", err, in.Notes, len(in.Changes))
	}
}

// F116 R1: a file that is no CA bundle is refused, naming why.
func TestParseCARefusesWhatIsNotACA(t *testing.T) {
	caPEM, leafPEM, keyPEM := testCA(t, "bodega.example.com")
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"no certificate", []byte("not a pem file\n"), "holds no PEM certificate"},
		{"empty", nil, "holds no PEM certificate"},
		{"a leaf", leafPEM, "is not a CA"},
		{"a CA then a leaf", append(slices.Clone(caPEM), leafPEM...), "certificate 2 (CN=bodega.example.com) is not a CA"},
		{"a key beside the CA", append(slices.Clone(caPEM), keyPEM...), `"EC PRIVATE KEY" block`},
	} {
		if _, err := ParseCA(tc.data); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ParseCA = %v, want an error naming %q", tc.name, err, tc.want)
		}
	}
	ca, err := ParseCA(append([]byte("subject=CN=bodega test CA\n"), caPEM...))
	if err != nil || len(ca.Certs) != 1 || string(ca.PEM) != string(caPEM) {
		t.Errorf("a CA under a text header = %v, %d certs; want it accepted and re-encoded alone", err, len(ca.Certs))
	}
}
