package clientconf

import (
	"bytes"
	"context"
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
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/oracletest"
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
			Gomod(testBase), Helm(testBase),
		}
		// podman's registries.conf is refused under a CA plan, as
		// TestAddCARefusesEveryOtherClient holds it to.
		for _, f := range oci {
			if OCIRuntimeOf(f.Path(OSLinux)) != RuntimePodman {
				files = append(files, f.File)
			}
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
		filepath.Join(home, "etc/docker/certs.d/bodega.example.com/ca.crt"):  string(caPEM),
		filepath.Join(root, "usr/local/share/ca-certificates/bodega-ca.crt"): string(caPEM),
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
		t.Errorf("step = %v, want update-ca-certificates for the anchor go and helm read through", in.Step)
	}
	// daemon.json takes no CA setting: Docker reads certs.d beside it.
	if got := changeAt(t, in.Changes, filepath.Join(home, "etc/docker/daemon.json")); strings.Contains(string(got.New), "ca") {
		t.Errorf("daemon.json gained a CA key: %s", got.New)
	}

	if _, err := Apply(in.Changes, ".bak"); err != nil {
		t.Fatal(err)
	}
	// The anchor is written and the store the clients read is not rebuilt
	// yet, which is where a failed update-ca-certificates leaves a host: the
	// step is still owed.
	owed, err := AddCA(plan(), ca, h)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(owed.Step, []string{"update-ca-certificates"}) {
		t.Errorf("step with the anchor written and the store not rebuilt = %v, want update-ca-certificates again", owed.Step)
	}
	bundle := filepath.Join(root, "etc/ssl/certs/ca-certificates.crt")
	if err := os.MkdirAll(filepath.Dir(bundle), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, caPEM, 0o644); err != nil {
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
		t.Errorf("a second plan runs %v with the store holding the anchor", again.Step)
	}
}

// F116 R1: a CA plan holding a record for any client other than apt, go,
// helm, pip, npm, git, Docker Engine and containerd is refused whole, naming
// the client, with no edit planned for the clients beside it.
func TestAddCARefusesEveryOtherClient(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	other := func(system string) File {
		return File{System: system, Paths: map[string]string{OSLinux: "/etc/bodega-" + system + ".conf"}, Content: "x\n"}
	}
	for name, tc := range map[string]struct {
		file File
		want string
	}{
		"maven":     {Maven(testBase, nil)[0], "maven: private-CA installation for maven is not supported"},
		"rpm":       {Rpm(testBase, []string{"baseos"}), "rpm: private-CA installation for rpm is not supported"},
		"cargo":     {Cargo(testBase), "cargo: private-CA installation for cargo is not supported"},
		"rubygems":  {Rubygems(testBase)[0], "rubygems: private-CA installation for rubygems is not supported"},
		"composer":  {Composer(testBase), "composer: private-CA installation for composer is not supported"},
		"freebsd":   {other(manifest.TypeFreeBSD), "freebsd: private-CA installation for freebsd is not supported"},
		"distfiles": {other(manifest.TypeDistfiles), "distfiles: private-CA installation for distfiles is not supported"},
		"binary":    {other(manifest.TypeBinary), "binary: private-CA installation for binary is not supported"},
		"podman":    {RegistriesConf(testBase, []string{"docker.io"}), "oci: private-CA installation for podman, buildah and CRI-O is not supported"},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			h := CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")}
			for _, files := range [][]File{{tc.file}, {Pip(testBase), tc.file}, {tc.file, Gomod(testBase)}} {
				in, err := AddCA(caPlan(t, home, files...), ca, h)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("AddCA over %d file(s) = %v, want a refusal holding %q", len(files), err, tc.want)
				}
				if len(in.Changes) != 0 || in.Step != nil {
					t.Errorf("a refused plan still carries %d change(s) and the step %v", len(in.Changes), in.Step)
				}
			}
		})
	}
	if err := CAUnsupported(PlanRecord{System: manifest.TypeOCI}); err != nil {
		t.Errorf("oci named alone = %v, want it left to the plan's records", err)
	}
	for _, f := range OCIClient(testBase, map[string]string{"docker.io": "https://registry-1.docker.io"}) {
		rec := PlanRecord{System: f.System, Path: f.Path(OSLinux)}
		if err := CAUnsupported(rec); (err != nil) != (OCIRuntimeOf(rec.Path) == RuntimePodman) {
			t.Errorf("CAUnsupported(%s) = %v, want a refusal for podman's file alone", rec.Path, err)
		}
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
}

// F116 R1: merging into an existing file replaces a repeated key as a group,
// drops the lines continuing a replaced value, and refuses a hosts.toml the
// line merge would corrupt rather than writing it.
func TestAddCAMergesWithoutCorrupting(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	write := func(home string, f File, content string) string {
		target := filepath.Join(home, strings.TrimPrefix(f.Path(OSLinux), "~"))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return target
	}
	home := t.TempDir()
	h := CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux}
	userCA := filepath.Join(home, ".config/bodega/ca.pem")

	pip := Pip(testBase)
	target := write(home, pip, "# site policy\n[global]\nINDEX-URL =\n    https://pypi.org/simple/\ntimeout = 5\ncert = /old/ca.pem\n")
	in, err := AddCA(caPlan(t, home, pip), ca, h)
	if err != nil {
		t.Fatal(err)
	}
	want := "# site policy\n[global]\nindex-url = https://bodega.example.com/pypi/simple/\ntimeout = 5\ncert = " + userCA + "\n"
	if got := string(changeAt(t, in.Changes, target).New); got != want {
		t.Errorf("pip.conf =\n%s\nwant\n%s", got, want)
	}

	git := Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}, "gl": {URL: "https://gitlab.com/"}})
	target = write(home, git, "[core]\n\teditor = vi\n"+git.Content+"[http \"https://bodega.example.com/\"]\n\tsslCAInfo = /old/ca.pem\n\tproxy = http://p\n")
	in, err = AddCA(caPlan(t, home, git), ca, h)
	if err != nil {
		t.Fatal(err)
	}
	want = "[core]\n\teditor = vi\n" + git.Content + "[http \"https://bodega.example.com/\"]\n\tsslCAInfo = " + userCA + "\n\tproxy = http://p\n"
	if got := string(changeAt(t, in.Changes, target).New); got != want {
		t.Errorf(".gitconfig =\n%s\nwant\n%s", got, want)
	}

	hosts := ContainerdHosts(testBase, "docker.io", "https://registry-1.docker.io")
	write(home, hosts, "server = \"https://registry-1.docker.io\"\n[host.\""+testBase+"\"]\n  capabilities = [\n    \"pull\",\n  ]\n")
	if _, err := AddCA(caPlan(t, home, hosts), ca, h); err == nil || !strings.Contains(err.Error(), "move the file aside") {
		t.Errorf("a hosts.toml with a value over several lines = %v, want a refusal naming the next step", err)
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

func TestReviewCAKeepsExistingSettings(t *testing.T) {
	pem, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(pem)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		file File
		keep string
	}{
		{"npm", Npm(testBase, nil), "save-exact=true\n"},
		{"pip", Pip(testBase), "[install]\nno-compile = true\n"},
		{"git", Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}}), "[user]\n\tname = Existing User\n"},
		{"containerd", ContainerdHosts(testBase, "docker.io", "https://registry-1.docker.io"), "[host.\"" + testBase + "\".header]\n  X-Existing = [\"kept\"]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := tc.file.Path(OSLinux)
			path = strings.TrimPrefix(path, "~")
			target := filepath.Join(home, path)
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(tc.file.Content+tc.keep), 0644); err != nil {
				t.Fatal(err)
			}
			in, err := AddCA(caPlan(t, home, tc.file), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Apply(in.Changes, ".review-backup"); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), tc.keep) {
				t.Errorf("CA install discarded %q; wrote:\n%s", tc.keep, got)
			}
		})
	}
}

func TestAuditCAPreservesExistingSettings(t *testing.T) {
	pem, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(pem)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		file         File
		before, keep string
	}{
		{"pip-indented", Pip(testBase), "[global]\n  index-url = https://pypi.org/simple/\n  timeout = 120\n", "timeout = 120"},
		{"go", Gomod(testBase), "GOPROXY=https://proxy.golang.org\nGOPRIVATE=corp.example/*\n", "GOPRIVATE=corp.example/*"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, strings.TrimPrefix(tc.file.Path(OSLinux), "~"))
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(tc.before), 0644); err != nil {
				t.Fatal(err)
			}
			in, err := AddCA(caPlan(t, home, tc.file), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Apply(in.Changes, ".audit-backup"); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), tc.keep) {
				t.Fatalf("CA install discarded %q; wrote:\n%s", tc.keep, got)
			}
		})
	}
}

func TestAuditFreeBSDHashCollisionsRemainIdempotent(t *testing.T) {
	first, _, _ := testCA(t, "bodega.example.com")
	second, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(append(slices.Clone(first), second...))
	if err != nil {
		t.Fatal(err)
	}
	home, root := t.TempDir(), t.TempDir()
	h := CAHost{Base: testBase, Home: home, Root: root, GOOS: OSFreeBSD}
	plan := func() []Change { return caPlan(t, home, Gomod(testBase)) }
	in, err := AddCA(plan(), ca, h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(in.Changes, ".audit-backup"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "etc/ssl/certs")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"12345678.0": first, "12345678.1": second} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	again, err := AddCA(plan(), ca, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Step) != 0 {
		t.Fatalf("both CAs are in FreeBSD's hashed store, but second apply runs %v", again.Step)
	}
}

// F116 R1: under a CA plan every existing file keeps what the plan does not
// set, in each format a plan edits, takes what the plan does set, and reads
// the same after a second plan over the applied host.
func TestAddCAMergesEveryFormatItEdits(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	at := func(f File, path string) File {
		f.Paths = map[string]string{OSLinux: path}
		return f
	}
	git := Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}})
	for _, tc := range []struct {
		name   string
		file   File
		before string
		// keep stays, want arrives and gone leaves.
		keep, want, gone []string
	}{
		{"helm", Helm(testBase), "apiVersion: \"\"\ngenerated: \"0001-01-01T00:00:00Z\"\nrepositories:\n  - name: corp\n    url: https://charts.corp.example\n  - name: bodega\n    url: https://old.example/helm\n",
			[]string{"name: corp", "url: https://charts.corp.example"}, []string{testBase + "/helm"}, []string{"old.example"}},
		{"apt", AptArchive(testBase, "noble", nil), "Types: deb\nURIs: https://corp.example/apt\nSuites: stable\nComponents: main\n\n# ours\nTypes: deb\nURIs: " + testBase + "/apt/\nSuites: noble\nComponents: main\nTrusted: yes\n",
			[]string{"URIs: https://corp.example/apt", "Suites: stable"}, []string{"Suites: noble", "Signed-By: "}, []string{"Components: main\nTrusted", "Trusted: yes"}},
		{"node mirror", at(File{System: manifest.TypeNpm, Content: "NODEJS_ORG_MIRROR=" + testBase + "/binaries/node/dist\n"}, NodeMirrorUserPath),
			"EDITOR=vi\nNODEJS_ORG_MIRROR=https://nodejs.org/dist\n", []string{"EDITOR=vi"}, []string{testBase + "/binaries/node/dist"}, []string{"nodejs.org"}},
		{"pip", Pip(testBase), "[global]\n  index_url: https://pypi.org/simple/\n  find-links =\n    cert = not-a-setting\n    /srv/wheels\n[install]\ncert = /old/ca.pem\nno-compile = true\n[download]\ncert:/old/ca.pem\n",
			[]string{"  find-links =\n    cert = not-a-setting\n    /srv/wheels\n", "no-compile = true"},
			[]string{"  index-url = " + testBase + "/pypi/simple/", "[install]\ncert = ", "[download]\ncert = "}, []string{"pypi.org", "/old/ca.pem"}},
		{"git", git, "[url \"https://old.example/git/gh/\"]\n\tinsteadOf = https://github.com/\n[alias]\n\tlg = log \\\n\t\t--oneline = x\n",
			[]string{"[alias]\n\tlg = log \\\n\t\t--oneline = x\n", "[url \"https://old.example/git/gh/\"]"}, []string{strings.TrimSpace(git.Content), "sslCAInfo = "}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			h := CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")}
			target := filepath.Join(home, strings.TrimPrefix(tc.file.Path(OSLinux), "~"))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(tc.before), 0o644); err != nil {
				t.Fatal(err)
			}
			in, err := AddCA(caPlan(t, home, tc.file), ca, h)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Apply(in.Changes, ".merge-backup"); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			got := string(raw)
			for _, s := range append(slices.Clone(tc.keep), tc.want...) {
				if !strings.Contains(got, s) {
					t.Errorf("merged file lacks %q:\n%s", s, got)
				}
			}
			for _, s := range tc.gone {
				if strings.Contains(got, s) {
					t.Errorf("merged file still holds %q:\n%s", s, got)
				}
			}
			again, err := AddCA(caPlan(t, home, tc.file), ca, h)
			if err != nil {
				t.Fatal(err)
			}
			if c := changeAt(t, again.Changes, target); !c.Unchanged() {
				t.Errorf("a second plan rewrites the file:\n%s\nfrom\n%s", c.New, c.Old)
			}
		})
	}
}

func TestIndependentCANamedEntryPreservation(t *testing.T) {
	raw, leaf, key := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	// A client pair helm can load: it reads both files beside the caFile the
	// install adds, and an entry naming a pair it cannot read is refused.
	pair := t.TempDir()
	certFile, keyFile := filepath.Join(pair, "client.crt"), filepath.Join(pair, "client.key")
	for path, data := range map[string][]byte{certFile: leaf, keyFile: key} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name         string
		file         File
		before, keep string
	}{
		{"apt", AptArchive(testBase, "noble", nil), "Types: deb\nURIs: " + testBase + "/apt/\nSuites: noble\nComponents: main\nArchitectures: amd64\n", "Architectures: amd64"},
		{"helm", Helm(testBase), HelmDocument(HelmRepository(testBase, "certFile: "+certFile, "keyFile: "+keyFile)), "certFile: " + certFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, strings.TrimPrefix(tc.file.Path(OSLinux), "~"))
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(tc.before), 0644); err != nil {
				t.Fatal(err)
			}
			in, err := AddCA(caPlan(t, home, tc.file), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Apply(in.Changes, ".independent-backup"); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), tc.keep) {
				t.Fatalf("CA install discarded %q; wrote:\n%s", tc.keep, got)
			}
		})
	}
}

// TestEntryMergeIsFieldLevel pins what a named entry keeps when a plan joins
// it: every field the plan does not set, in the layout the host wrote, less
// the fields named as unable to stand beside the plan's. A second merge
// changes nothing, and an entry the merge cannot follow is refused.
func TestEntryMergeIsFieldLevel(t *testing.T) {
	helm := fileKind{blocks: func(o, p []string) []string { return mergeYAML(o, p, "repositories") }, holds: yamlHolds("repositories")}
	for _, tc := range []struct {
		name         string
		kind         fileKind
		old, planned string
		want         string
	}{
		{"helm entry keeps client auth, loses caFile and its duplicate", helm,
			"repositories:\n  - caFile: /old/ca.pem\n    name: bodega\n    url: https://old/helm\n    certFile: /c.crt\n  # corp\n  - name: corp\n    url: https://corp\n  - name: bodega\n    url: https://dup\n", "repositories:\n" + HelmRepository("https://b"),
			"repositories:\n  - name: bodega\n    url: https://b/helm\n    certFile: /c.crt\n  # corp\n  - name: corp\n    url: https://corp\n"},
		{"helm empty flow sequence", helm, "repositories: []\n", "repositories:\n" + HelmRepository("https://b"), "repositories:\n- name: bodega\n  url: https://b/helm\n"},
		{"apt stanza", fileKind{blocks: mergeDeb822}, "# ours\nTypes: deb\nURIs: https://b/apt/\nSuites: noble\nEnabled: no\nArchitectures: amd64\n arm64\nTrusted: yes\n",
			"Types: deb\nURIs: https://b/apt/\nSuites: noble\nSigned-By: /k.asc\n",
			"# ours\nTypes: deb\nURIs: https://b/apt/\nSuites: noble\nArchitectures: amd64\n arm64\nSigned-By: /k.asc\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.kind.merge([]byte(tc.old), []byte(tc.planned))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("merged:\n%s\nwant:\n%s", got, tc.want)
			}
			again, err := tc.kind.merge(got, []byte(tc.planned))
			if err != nil || string(again) != tc.want {
				t.Fatalf("a second merge changed the file (%v):\n%s", err, again)
			}
		})
	}
}

// TestPipOptionsReadsPipsGrammar pins the reader the trust probe shares with
// the merge: a colon delimits, a deeper line continues the option above it
// across a comment and a blank line, a line indented under a header is an
// option, and a file pip refuses to load gives no option.
func TestPipOptionsReadsPipsGrammar(t *testing.T) {
	got := PipOptions([]byte("[global]\nIndex_URL: https://b/simple\nfind-links =\n  cert=/not.pem\n  # note\n\n  /srv/wheels\ncert=/b.pem\n[install]\n  no-compile = true\n"))
	want := map[string]string{"global.index-url": "https://b/simple", "global.cert": "/b.pem", "global.find-links": "\ncert=/not.pem\n\n/srv/wheels", "install.no-compile": "true"}
	if !maps.Equal(got, want) {
		t.Fatalf("PipOptions = %q, want %q", got, want)
	}
	for _, refused := range []string{
		"[global]\ncert = /a.pem\ncert = /b.pem\n",
		"[global]\nindex-url = https://b/simple\nnot-an-assignment\n",
		"[global]\nindex-url = https://b/simple\n= nameless\n",
		"[global\nindex-url = https://b/simple\n",
	} {
		if got := PipOptions([]byte(refused)); len(got) != 0 {
			t.Errorf("PipOptions(%q) = %q, want none from a file pip refuses to load", refused, got)
		}
	}
}

func TestStaffCAKeepsRepositoryPolicy(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		file         File
		before, keep string
	}{
		{"apt-distinct-stanza", AptArchive(testBase, "noble", nil), "Types: deb\nURIs: " + testBase + "/apt/\nSuites: noble\nComponents: main\nArchitectures: amd64\n\nTypes: deb-src\nURIs: " + testBase + "/apt/\nSuites: jammy\nComponents: main\nArchitectures: arm64\n", "Types: deb-src\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, strings.TrimPrefix(tc.file.Path(OSLinux), "~"))
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(tc.before), 0644); err != nil {
				t.Fatal(err)
			}
			in, err := AddCA(caPlan(t, home, tc.file), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Apply(in.Changes, ".staff-backup"); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), tc.keep) {
				t.Fatalf("CA apply removed unrelated policy %q:\n%s", tc.keep, got)
			}
		})
	}
}

func TestStaffGitCAReachesEffectiveURL(t *testing.T) {
	git := oracletest.Git(t)
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	target := filepath.Join(home, ".gitconfig")
	old := "[http \"" + testBase + "/git/gh/\"]\n\tsslCAInfo = /missing/old-git-ca.pem\n\textraHeader = X-Corp: keep\n"
	if err := os.WriteFile(target, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	file := Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}})
	in, err := AddCA(caPlan(t, home, file), ca, CAHost{Base: testBase, Home: home, GOOS: OSLinux})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(in.Changes, ".staff-backup"); err != nil {
		t.Fatal(err)
	}
	got, err := exec.Command(git, "config", "--file", target, "--get-urlmatch", "http.sslCAInfo", testBase+"/git/gh/repo").CombinedOutput()
	if err != nil {
		t.Fatalf("git config: %v: %s", err, got)
	}
	want := filepath.Join(home, ".config/bodega/ca.pem")
	if strings.TrimSpace(string(got)) != want {
		t.Fatalf("git reads %q after successful CA apply; want %q", strings.TrimSpace(string(got)), want)
	}
}

// F116 R1: the files a CA plan reaches through a client's own selection rules
// are idle on a second plan, and the selection follows each client's order.
func TestCASelectionSecondPlanIsIdle(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	home, root := t.TempDir(), t.TempDir()
	venv := filepath.Join(root, "venv")
	// The copy a setting names sits beside the file naming it: git's is per
	// user, pip's is under /etc.
	caPath, pipCA := filepath.Join(home, ".config/bodega/ca.pem"), filepath.Join(root, "usr/local/share/bodega/ca.pem")
	// git: a longer section in another file git reads, and a wildcard host
	// that never outranks the plan's. pip: a file loaded before the plan's
	// whose command section sets cert, and the virtualenv's, loaded after.
	xdgGit := filepath.Join(home, ".config/git/config")
	write(xdgGit, "[http \""+testBase+"/git/gh/corp/\"]\n\tsslCAInfo = /old/corp.pem\n\tproxy = http://p\n[http \"https://*.example.com/\"]\n\tsslCAInfo = /old/wild.pem\n")
	write(filepath.Join(home, ".gitconfig"), "[http \""+testBase+"\"]\n\tsslCAInfo = /old/base.pem\n[user]\n\tname = x\n")
	early := filepath.Join(root, "etc/xdg/pip/pip.conf")
	write(early, "[global]\ncert = /old/global.pem\n[install]\ncert = /old/install.pem\ntimeout = 9\n")
	write(filepath.Join(venv, "pip.conf"), "[global]\ncert = /old/venv.pem\nretries = 2\n")
	h := CAHost{Base: testBase, Home: home, Root: root, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n"), Getenv: func(k string) string {
		if k == "VIRTUAL_ENV" {
			return venv
		}
		return ""
	}}
	pip := Pip(testBase)
	pip.Paths = everywhere(filepath.Join(root, "etc/pip.conf"))
	plan := func() CAInstall {
		t.Helper()
		var changes []Change
		for _, f := range []File{Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}}), pip} {
			sum := sha256.Sum256([]byte(f.Content))
			c, err := NewChange(PlanRecord{System: f.System, Action: PlanInstall, Path: f.Path(OSLinux), SHA256: hex.EncodeToString(sum[:])}, []byte(f.Content), home)
			if err != nil {
				t.Fatal(err)
			}
			changes = append(changes, c)
		}
		in, err := AddCA(changes, ca, h)
		if err != nil {
			t.Fatal(err)
		}
		return in
	}
	if _, err := Apply(plan().Changes, ".bak"); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]string{
		xdgGit:                            {"sslCAInfo = " + caPath + "\n\tproxy = http://p", "sslCAInfo = /old/wild.pem"},
		filepath.Join(home, ".gitconfig"): {"[http \"" + testBase + "\"]\n\tsslCAInfo = " + caPath, "name = x"},
		early:                             {"[global]\ncert = /old/global.pem", "[install]\ncert = " + pipCA + "\ntimeout = 9"},
		filepath.Join(venv, "pip.conf"):   {"cert = " + pipCA, "retries = 2", "index-url = " + testBase},
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range want {
			if !strings.Contains(string(got), w) {
				t.Errorf("%s does not hold %q:\n%s", path, w, got)
			}
		}
	}
	own, narrower := GitCAInfo(GitConfigFiles(h.Getenv, home, root), testBase+"/git/gh/", home)
	if own == nil || own.Value != caPath || len(narrower) != 1 || narrower[0].Value != caPath {
		t.Errorf("git resolves %+v and %+v after the apply; want %s for the prefix and for the one section below it", own, narrower, caPath)
	}
	for _, c := range plan().Changes {
		if !c.Unchanged() {
			d, _ := c.Diff()
			t.Errorf("a second plan still changes %s:\n%s", c.Target, d)
		}
	}
}

// F116 R1, R2: pip loads its files in one order, with PIP_CONFIG_FILE
// displacing the per-user ones.
func TestTrustSourceSelection(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	env := map[string]string{"VIRTUAL_ENV": "/venv"}
	h := PipHost{GOOS: OSLinux, Root: root, Home: home, Getenv: func(k string) string { return env[k] }}
	rel := func(files []string) string {
		return strings.NewReplacer(root, "R", home, "H").Replace(strings.Join(files, " "))
	}
	files, global := PipConfigFiles(h)
	if got, want := rel(files), "R/etc/xdg/pip/pip.conf R/etc/pip.conf H/.pip/pip.conf H/.config/pip/pip.conf /venv/pip.conf"; got != want || global != 2 {
		t.Errorf("pip on Linux loads %s (%d global); want %s", got, global, want)
	}
	explicit := filepath.Join(root, "explicit.conf")
	if err := os.WriteFile(explicit, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	env["PIP_CONFIG_FILE"] = explicit
	if files, _ = PipConfigFiles(h); rel(files) != "R/etc/xdg/pip/pip.conf R/etc/pip.conf /venv/pip.conf R/explicit.conf" {
		t.Errorf("with PIP_CONFIG_FILE pip loads %s; want no per-user file and the named one last", rel(files))
	}
	env["PIP_CONFIG_FILE"] = os.DevNull
	if files, _ = PipConfigFiles(h); len(files) != 0 {
		t.Errorf("with PIP_CONFIG_FILE the null device pip loads %v; want none", files)
	}
	delete(env, "PIP_CONFIG_FILE")
	delete(env, "VIRTUAL_ENV")
	h.GOOS, h.Prefix = OSDarwin, "/opt/py"
	if files, _ = PipConfigFiles(h); rel(files) != "R/Library/Application Support/pip/pip.conf H/.pip/pip.conf H/.config/pip/pip.conf /opt/py/pip.conf" {
		t.Errorf("pip on macOS loads %s", rel(files))
	}
}

func TestFinalCAPreservesAlternateSyntax(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		file         File
		before, keep string
	}{
		{"helm-dash", Helm(testBase), "repositories:\n  -\n    name: bodega\n    url: https://old.example/helm\n    certFile: /corp/client.pem\n    keyFile: /corp/client.key\n", "certFile: /corp/client.pem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, strings.TrimPrefix(tc.file.Path(OSLinux), "~"))
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(tc.before), 0600); err != nil {
				t.Fatal(err)
			}
			in, err := AddCA(caPlan(t, home, tc.file), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")})
			if err != nil {
				return
			} // Refusing an unsupported form before writing preserves the file.
			if _, err := Apply(in.Changes, ".audit"); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), tc.keep) {
				t.Fatalf("successful apply discarded %q:\n%s", tc.keep, got)
			}
		})
	}
}

func TestFinalGitCAAcceptsNativeSectionSyntax(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{" # corporate roots", "; corporate roots"} {
		t.Run(suffix, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, ".gitconfig")
			old := "[http \"" + testBase + "/git/gh/\"]" + suffix + "\n\tsslCAInfo = /missing/corporate.pem\n\textraHeader = X-Corp: keep\n"
			if err := os.WriteFile(target, []byte(old), 0600); err != nil {
				t.Fatal(err)
			}
			native := func() string {
				t.Helper()
				out, err := exec.Command("git", "config", "--file", target, "--get-urlmatch", "http.sslCAInfo", testBase+"/git/gh/repo").CombinedOutput()
				if err != nil {
					t.Fatalf("native git: %v: %s", err, out)
				}
				return strings.TrimSpace(string(out))
			}
			if got := native(); got != "/missing/corporate.pem" {
				t.Fatalf("fixture: git reads %q", got)
			}
			in, err := AddCA(caPlan(t, home, Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}})), ca, CAHost{Base: testBase, Home: home, GOOS: OSLinux})
			if err != nil {
				return
			}
			if _, err := Apply(in.Changes, ".audit"); err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(home, ".config/bodega/ca.pem")
			if got := native(); got != want {
				t.Fatalf("git still reads %q after successful CA apply; want %q", got, want)
			}
		})
	}
}

// F116 R1: a file the plan cannot be placed in field by field is refused
// before anything is written, naming the file and what stands in the way, and
// so is a plan file the environment tells its client not to load. None of
// them is replaced, and none is reported installed.
func TestCARefusesWhatItCannotEditExactly(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	git := Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}})
	for name, tc := range map[string]struct {
		file   File
		before string
		env    map[string]string
		want   string
	}{
		"pip header with a comment":     {Pip(testBase), "[global] ; site policy\nindex-url = https://corp.example/simple\n", nil, "[global] ; site policy"},
		"git setting on a header line":  {git, "[http \"" + testBase + "/\"] sslCAInfo = /corp.pem\n", nil, "opens a section"},
		"git value continued":           {git, "[http \"" + testBase + "/git/\"]\n\tsslCAInfo = /corp\\\n.pem\n", nil, "opens a section"},
		"helm flow sequence of entries": {Helm(testBase), "repositories: [{name: corp, url: \"https://corp.example\", certFile: /c.pem}]\n", nil, "move the file aside"},
		"pip told to load no file":      {Pip(testBase), "", map[string]string{"PIP_CONFIG_FILE": os.DevNull}, "PIP_CONFIG_FILE"},
		"git told to load no file":      {git, "", map[string]string{"GIT_CONFIG_GLOBAL": os.DevNull}, "GIT_CONFIG_GLOBAL"},
		"git configured by environment": {git, "", map[string]string{"GIT_CONFIG_COUNT": "1"}, "GIT_CONFIG_COUNT"},
		"npm pointed at a missing file": {Npm(testBase, nil), "", map[string]string{"NPM_CONFIG_USERCONFIG": "/missing/work.npmrc"}, "NPM_CONFIG_USERCONFIG"},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(tc.file.Path(OSLinux), "~"), "/"))
			if tc.before != "" {
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte(tc.before), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			_, err := AddCA(caPlan(t, home, tc.file), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n"),
				Getenv: func(k string) string { return tc.env[k] }})
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), target) {
				t.Fatalf("AddCA = %v; want a refusal naming %s and %q", err, target, tc.want)
			}
		})
	}
}

// F116 R1, R2: a git value is read and written by git's own grammar, so a
// path holding # or ; is not cut short at it, and the reader agrees with the
// writer.
func TestGitValueGrammar(t *testing.T) {
	for raw, want := range map[string]string{
		" /etc/ca.pem":           "/etc/ca.pem",
		" /etc/ca.pem # roots":   "/etc/ca.pem",
		" /etc/ca#1.pem":         "/etc/ca",
		" \"/etc/ca#1.pem\" ; x": "/etc/ca#1.pem",
		" /a\\\\b \"c d\"  ":     "/a\\b c d",
		" \"say \\\"hi\\\"\"":    "say \"hi\"",
	} {
		if got, whole := gitValue(raw); got != want || !whole {
			t.Errorf("gitValue(%q) = %q, %v; want %q", raw, got, whole, want)
		}
	}
	for _, raw := range []string{" /etc/ca\\", " \"/etc/ca"} {
		if got, whole := gitValue(raw); whole {
			t.Errorf("gitValue(%q) = %q, read as a whole value", raw, got)
		}
	}
	for _, v := range []string{"/etc/ca.pem", "/tmp/a_#_b/ca.pem", "/tmp/a;b", `C:\certs\ca.pem`, `/q"uote`, " lead"} {
		if got, whole := gitValue(" " + gitQuote(v)); got != v || !whole {
			t.Errorf("gitQuote(%q) = %s, which reads back as %q", v, gitQuote(v), got)
		}
	}
}

func TestAudit6CAHandlesGitIncludes(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	target, included := filepath.Join(home, ".gitconfig"), filepath.Join(home, "corporate.gitconfig")
	if err := os.WriteFile(included, []byte("[http \""+testBase+"/git/gh/\"]\n\tsslCAInfo = /missing/corporate.pem\n\textraHeader = X-Corp: keep\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("[include]\n\tpath = "+included+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	native := func() string {
		t.Helper()
		out, err := exec.Command("git", "config", "--includes", "--file", target, "--get-urlmatch", "http.sslCAInfo", testBase+"/git/gh/repo").CombinedOutput()
		if err != nil {
			t.Fatalf("native git: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if got := native(); got != "/missing/corporate.pem" {
		t.Fatalf("fixture: git reads %q", got)
	}
	in, err := AddCA(caPlan(t, home, Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}})), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux})
	if err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "include") {
			t.Fatalf("refusal must identify the unread include: %v", err)
		}
		return
	}
	if _, err := Apply(in.Changes, ".audit"); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".config/bodega/ca.pem")
	if got := native(); got != want {
		t.Fatalf("successful CA apply leaves native git reading %q; want %q or a pre-write refusal of the include", got, want)
	}
}

func TestAudit6NpmInlineCAAfterCAFile(t *testing.T) {
	nativeNpm(t)
	raw, leaf, _ := testCA(t, "bodega.example.com")
	other, _, _ := testCA(t, "other.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	target := filepath.Join(home, ".npmrc")
	old := "registry=" + testBase + "/npm/\ncafile=/missing/previous.pem\nca[]=\"" + strings.ReplaceAll(strings.TrimSpace(string(other)), "\n", `\n`) + "\"\nsave-exact=true\n"
	if err := os.WriteFile(target, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	in, err := AddCA(caPlan(t, home, Npm(testBase, nil)), ca, CAHost{Base: testBase, Home: home, GOOS: OSLinux})
	if err != nil {
		return
	}
	if _, err := Apply(in.Changes, ".audit"); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("npm", "config", "get", "ca", "--json", "--userconfig", target, "--globalconfig", filepath.Join(home, "global.npmrc"))
	cmd.Dir = home
	for _, entry := range os.Environ() {
		k, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(strings.ToLower(k), "npm_config_") && k != "HOME" && k != "NODE_OPTIONS" {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "HOME="+home)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("native npm: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(out) {
		t.Fatalf("native npm returned no CA: %s", out)
	}
	block, _ := pem.Decode(leaf)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "bodega.example.com"}); err != nil {
		t.Fatalf("successful apply leaves npm's effective inline CA without bodega's issuer: %v", err)
	}
}

// F116 R1: what AddCA detects in a client's configuration and does not
// interpret is refused while the plan is built, naming it, so nothing is
// written; an environment cafile naming the installed copy is not one.
func TestCARefusesWhatItDoesNotInterpret(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	git := Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}})
	for _, tc := range []struct {
		name  string
		file  File
		files map[string]string
		env   map[string]string
		want  []string
	}{
		{"git includeIf in the per-user file", git, map[string]string{"~/.gitconfig": "[user]\n\tname = kept\n[includeIf \"gitdir:~/work/\"]\n\tpath = ~/work.gitconfig\n"}, nil, []string{"includeIf", ".gitconfig"}},
		{"git include in the system file", git, map[string]string{"/etc/gitconfig": "[Include]\n\tpath = /etc/corp.gitconfig\n"}, nil, []string{"[Include]", "etc/gitconfig"}},
		{"npm inline ca ahead of cafile", Npm(testBase, nil), map[string]string{"~/.npmrc": "ca=\ncafile=/old.pem\n"}, nil, []string{"sets ca,", ".npmrc"}},
		{"npm ca[] in the file the environment selects", Npm(testBase, nil), map[string]string{"~/corp.npmrc": "ca[]=\"x\"\n"}, map[string]string{"NPM_CONFIG_USERCONFIG": "~/corp.npmrc"}, []string{"ca[]", "corp.npmrc"}},
		{"npm inline ca from the environment", Npm(testBase, nil), nil, map[string]string{"npm_config_ca": "x"}, []string{"npm_config_ca"}},
		{"git header carrying a setting in a file the plan does not edit", git, map[string]string{"~/.config/git/config": "[http] sslCAInfo = /corp.pem\n"}, nil, []string{"[http] sslCAInfo", ".config/git/config"}},
		{"npm ca[] beside cafile in the global file", Npm(testBase, nil), map[string]string{"/etc/npmrc": "cafile=/corp.pem\nca[]=\"x\"\n"}, nil, []string{"ca[] beside cafile", "etc/npmrc"}},
		{"npm cafile with a comment in the global file", Npm(testBase, nil), map[string]string{"/etc/npmrc": "cafile=/corp.pem # corporate\n"}, nil, nil},
		{"npm cafile from a reference in the global file", Npm(testBase, nil), map[string]string{"/etc/npmrc": "save=true\ncafile=${CORP_CA}\n"}, nil, []string{"sets cafile", "line 2 of", "etc/npmrc"}},
		{"npm quoted ca[] beside quoted cafile in the global file", Npm(testBase, nil), map[string]string{"/etc/npmrc": "'cafile'=/corp.pem\n\"ca[]\"=x\n"}, nil, []string{"ca[] beside cafile", "etc/npmrc"}},
		{"npm plain cafile in the global file", Npm(testBase, nil), map[string]string{"/etc/npmrc": "cafile=/corp.pem\n"}, nil, nil},
		{"npm cafile from the environment", Npm(testBase, nil), nil, map[string]string{"NPM_CONFIG_CAFILE": "/etc/ssl/corp.pem"}, []string{"NPM_CONFIG_CAFILE", "/etc/ssl/corp.pem"}},
		{"npm cafile from the environment naming the installed copy", Npm(testBase, nil), nil, map[string]string{"NPM_CONFIG_CAFILE": "~/.config/bodega/ca.pem"}, nil},
	} {
		home, root := t.TempDir(), t.TempDir()
		at := func(p string) string {
			if rest, ok := strings.CutPrefix(p, "~/"); ok {
				return filepath.Join(home, rest)
			}
			return filepath.Join(root, p)
		}
		for p, content := range tc.files {
			if err := os.MkdirAll(filepath.Dir(at(p)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(at(p), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		getenv := func(key string) string {
			if v, ok := tc.env[key]; ok && strings.HasPrefix(v, "~/") {
				return at(v)
			}
			return tc.env[key]
		}
		_, err := AddCA(caPlan(t, home, tc.file), ca, CAHost{Base: testBase, Home: home, Root: root, GOOS: OSLinux, Getenv: getenv})
		if tc.want == nil {
			if err != nil {
				t.Errorf("%s: %v; want a plan", tc.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: planned an install", tc.name)
			continue
		}
		for _, want := range append(tc.want, "Nothing was written") {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: refusal does not name %q: %v", tc.name, want, err)
			}
		}
		for p, content := range tc.files {
			if got, _ := os.ReadFile(at(p)); string(got) != content {
				t.Errorf("%s: the refusal changed %s", tc.name, p)
			}
		}
		if _, err := os.Stat(filepath.Join(home, ".config/bodega/ca.pem")); !os.IsNotExist(err) {
			t.Errorf("%s: the refusal left a CA copy behind: %v", tc.name, err)
		}
	}
}

func TestAudit7GitInlineIncludeInSelectedFileRefusesBeforeWrite(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	xdg := filepath.Join(home, ".config/git/config")
	included := filepath.Join(home, "corporate.gitconfig")
	if err := os.MkdirAll(filepath.Dir(xdg), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(included, []byte("[http \""+testBase+"/git/gh/\"]\nsslCAInfo = /missing/corporate.pem\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := "[include] path = " + included + "\n"
	if err := os.WriteFile(xdg, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "config", "--includes", "--file", xdg, "--get-urlmatch", "http.sslCAInfo", testBase+"/git/gh/repo").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "/missing/corporate.pem" {
		t.Fatalf("native git fixture: %q, %v", out, err)
	}
	_, err = AddCA(caPlan(t, home, Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}})), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "include") || !strings.Contains(err.Error(), xdg) {
		t.Fatalf("selected %s imports native Git CA policy through %q; want a pre-write refusal naming it, got %v", xdg, strings.TrimSpace(old), err)
	}
	if got, _ := os.ReadFile(xdg); string(got) != old {
		t.Fatal("refusal changed the selected file")
	}
	if _, err := os.Stat(filepath.Join(home, ".config/bodega/ca.pem")); !os.IsNotExist(err) {
		t.Fatalf("refusal wrote a CA: %v", err)
	}
}

func TestAudit8NpmQuotedCARefusesBeforeWrite(t *testing.T) {
	nativeNpm(t)
	raw, _, _ := testCA(t, "bodega.example.com")
	other, _, _ := testCA(t, "other.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	target := filepath.Join(home, ".npmrc")
	old := "registry=" + testBase + "/npm/\ncafile=/missing/previous.pem\n\"ca\"=\"" + strings.ReplaceAll(strings.TrimSpace(string(other)), "\n", `\n`) + "\"\nsave-exact=true\n"
	if err := os.WriteFile(target, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("npm", "config", "get", "ca", "--userconfig", target, "--globalconfig", filepath.Join(home, "global.npmrc"))
	cmd.Dir = home
	for _, entry := range os.Environ() {
		k, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(strings.ToLower(k), "npm_config_") && k != "HOME" && k != "NODE_OPTIONS" {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "HOME="+home)
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != strings.TrimSpace(string(other)) {
		t.Fatalf("native npm did not select the quoted ca: %q, %v", out, err)
	}
	_, err = AddCA(caPlan(t, home, Npm(testBase, nil)), ca, CAHost{Base: testBase, Home: home, GOOS: OSLinux, Root: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), target) || !strings.Contains(err.Error(), "ca") {
		t.Fatalf("native npm selects the quoted ca beside cafile; want pre-write refusal naming %s and ca, got %v", target, err)
	}
	if got, _ := os.ReadFile(target); string(got) != old {
		t.Fatal("refusal changed .npmrc")
	}
	if _, err := os.Stat(filepath.Join(home, ".config/bodega/ca.pem")); !os.IsNotExist(err) {
		t.Fatalf("refusal wrote a CA: %v", err)
	}
}

// TestNpmOptionsDecodeAsNpmDoes holds the npmrc decoder to native npm's own
// reading of the same file: every name and value NpmOptions is sure of is
// the one `npm config list --json` reports.
func TestNpmOptionsDecodeAsNpmDoes(t *testing.T) {
	nativeNpm(t)
	rc := strings.Join([]string{
		`"tag"=a1`,
		`'otp'="q # x"`,
		`scope = @x ; trailing`,
		`heading=a\#b\;c\qd`,
		` "init-author-url" = y `,
		`omit[]=dev`,
		`"omit[]"="peer"`,
		`ca # named before the comment = dropped`,
		`init-author-name="unterminated`,
		`init-author-email='single'`,
		`init-license = "a\nb"`,
		`"init-version"[]=z`,
		`=skipped`,
		`; cafile=/comment`,
		`[section]`,
		`registry=https://under.section.example/`,
	}, "\n") + "\n"
	dir := t.TempDir()
	file := filepath.Join(dir, "rc")
	if err := os.WriteFile(file, []byte(rc), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("npm", "config", "list", "--json", "--userconfig", file, "--globalconfig", filepath.Join(dir, "global"))
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("npm config list: %v", err)
	}
	var native map[string]any
	if err := json.Unmarshal(out, &native); err != nil {
		t.Fatalf("npm config list printed %q: %v", out, err)
	}
	opts := NpmOptions([]byte(rc))
	if len(opts) != 12 {
		t.Fatalf("decoded %d options, want the 12 above the section: %+v", len(opts), opts)
	}
	for _, o := range opts {
		if o.Unsure != "" || o.ValueUnsure != "" {
			t.Errorf("line %d: unsure of a line npm reads plainly: %+v", o.Line, o)
			continue
		}
		switch got := native[o.Key].(type) {
		case string:
			if o.Array || got != o.Value {
				t.Errorf("line %d: decoded %q = %q, npm reads %q", o.Line, o.Key, o.Value, got)
			}
		case []any:
			if !slices.Contains(got, any(o.Value)) {
				t.Errorf("line %d: decoded %q[] = %q, npm reads %v", o.Line, o.Key, o.Value, got)
			}
		case bool:
			if !o.Bare || !got {
				t.Errorf("line %d: decoded %q = %q, npm reads %v", o.Line, o.Key, o.Value, got)
			}
		default:
			t.Errorf("line %d: npm reports no option named %q (%v)", o.Line, o.Key, got)
		}
	}
	if native["registry"] != "https://registry.npmjs.org/" {
		t.Errorf("npm read the registry under a section: %v", native["registry"])
	}
}

// TestNpmUnclassifiedLinesRefuseAndStayUnchecked walks the forms the decoder
// is not sure of, and the registry forms the readers do not take: each names
// its file and line, and none echoes a value.
func TestNpmUnclassifiedLinesRefuseAndStayUnchecked(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, line := range map[string]string{
		"quoted number name":  `'8443'=hunter2`,
		"env in name":         `//${HOST}/:_authToken=hunter2`,
		"indented bracket":    ` [scope]`,
		"header with comment": `[scope] ; hunter2`,
		"carriage return":     "save=hunter2\rregistry=https://elsewhere.example/",
		"registry list":       `registry[]=https://elsewhere.example/hunter2`,
		"bare registry":       `@corp:registry`,
		"quoted list value":   `registry='["hunter2"]'`,
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, ".npmrc")
			old := "save-exact=true\n" + line + "\n"
			if err := os.WriteFile(target, []byte(old), 0600); err != nil {
				t.Fatal(err)
			}
			got := NpmUnclassified(target)
			if !strings.Contains(got, "line 2 of "+target) || strings.Contains(got, "hunter2") {
				t.Fatalf("NpmUnclassified = %q, want line 2 of %s named and no value", got, target)
			}
			_, err := AddCA(caPlan(t, home, Npm(testBase, nil)), ca, CAHost{Base: testBase, Home: home, GOOS: OSLinux, Root: t.TempDir()})
			if err == nil || !strings.Contains(err.Error(), "line 2 of "+target) || strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("AddCA = %v, want a refusal naming line 2 of %s and no value", err, target)
			}
			if now, _ := os.ReadFile(target); string(now) != old {
				t.Fatal("refusal changed .npmrc")
			}
		})
	}
	// A token whose value npm fills from the environment is the common
	// credential line, and names nothing this install reads.
	home := t.TempDir()
	target := filepath.Join(home, ".npmrc")
	if err := os.WriteFile(target, []byte("//registry.example/:_authToken=${NPM_TOKEN}\n\"registry\"=https://old.example/\n'cafile' = /old.example.pem ; before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	in, err := AddCA(caPlan(t, home, Npm(testBase, nil)), ca, CAHost{Base: testBase, Home: home, GOOS: OSLinux, Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	merged := string(in.Changes[0].New)
	if !strings.Contains(merged, "//registry.example/:_authToken=${NPM_TOKEN}\n") || strings.Contains(merged, "old.example") || !strings.Contains(merged, "registry="+testBase+"/npm/\n") || strings.Count(merged, "cafile") != 1 {
		t.Fatalf("merge did not replace the quoted registry and cafile and keep the token line:\n%s", merged)
	}
}

// nativeNpm gates a test that holds doctor's reading of an npmrc against
// npm's own. A developer's machine without npm skips it. CI does not: its
// test job installs a pinned Node, so a missing npm there is a broken job
// that would otherwise pass every oracle test unrun.
func nativeNpm(t *testing.T) {
	t.Helper()
	oracletest.Npm(t)
}

func TestAudit9NativeOraclesCannotSkipInCI(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.v", "-test.run=^(TestAudit8NpmQuotedCARefusesBeforeWrite|TestNpmOptionsDecodeAsNpmDoes)$")
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		if k != "CI" && k != "PATH" {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "CI=true", "PATH="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("CI=true with no npm passed its oracle tests:\n%s", out)
	}
}

func TestAudit9CIInstallsPinnedNativeOracle(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string            `yaml:"uses"`
				Run  string            `yaml:"run"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	pinned := false
	for _, step := range workflow.Jobs["test"].Steps {
		if strings.HasPrefix(step.Uses, "actions/setup-node@") {
			pinned = regexp.MustCompile(`^actions/setup-node@[0-9a-f]{40}$`).MatchString(step.Uses) && regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(step.With["node-version"])
		}
		if strings.Contains(step.Run, "make test") && !pinned {
			t.Fatal("CI's Go test job runs before any full-SHA setup-node with an exact node-version; native npm oracle is not pinned and required")
		}
	}
	if !pinned {
		t.Fatal("CI's test job installs no pinned Node/npm release")
	}
}

// F116 R2: an absent ca, a null one and an empty one are three states to
// npm, and NpmCAOf folds a file's lines to the one native npm reports. The
// global file gives ca a value, so a per-user file that does not set it
// shows as that value and a null shows as null.
func TestNpmCAStatesAsNpmDoes(t *testing.T) {
	nativeNpm(t)
	dir := t.TempDir()
	global, user := filepath.Join(dir, "global"), filepath.Join(dir, "rc")
	if err := os.WriteFile(global, []byte("ca=GLOBAL\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		"", "ca=", `ca=""`, "ca= ; comment", "ca=null", `ca="null"`, "ca=true", "ca=false", "ca",
		"ca[]=", "ca[]=null", "ca=x\nca=", "ca=x\nca=null", "ca[]=x\nca=", "ca[]=x\nca=null",
		"ca=null\nca[]=x", "ca=x\nca[]=y", "ca=null\nca=x", "cafile=/corp.pem",
	} {
		if err := os.WriteFile(user, []byte(body+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("npm", "config", "list", "--json", "--userconfig", user, "--globalconfig", global)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%q: npm config list: %v", body, err)
		}
		var native struct {
			CA any `json:"ca"`
		}
		if err := json.Unmarshal(out, &native); err != nil {
			t.Fatalf("%q: npm config list printed %q: %v", body, out, err)
		}
		// want is the state native npm reports: absent, null, unread for a
		// value holding anything but strings, or the list itself.
		want := "unread"
		switch v := native.CA.(type) {
		case nil:
			want = "null"
		case string:
			want = "list " + strconv.Quote(v)
		case []any:
			var list []string
			for _, e := range v {
				if s, ok := e.(string); ok {
					list = append(list, strconv.Quote(s))
				}
			}
			if len(list) == len(v) {
				want = "list " + strings.Join(list, ",")
			}
		}
		if want == `list "GLOBAL"` {
			want = "absent"
		}
		ca := NpmCAOf(NpmOptions([]byte(body + "\n")))
		got := "absent"
		switch {
		case ca.Why != "":
			got = "unread"
		case ca.Set && ca.List == nil:
			got = "null"
		case ca.Set:
			var list []string
			for _, s := range ca.List {
				list = append(list, strconv.Quote(s))
			}
			got = "list " + strings.Join(list, ",")
		}
		if got != want {
			t.Errorf("%q: NpmCAOf = %s, native npm reports %s (%v)", body, got, want, native.CA)
		}
		if unread := NpmUnread(user); (unread != "") != (want == "unread") {
			t.Errorf("%q: NpmUnread = %q, and native npm reports %s", body, unread, want)
		}
	}
}

// F116 R1: a record no editor reads is written whole only over nothing. Over
// an existing file it keeps the file when the rendering is intact inside it,
// and is refused, naming the file, when the two differ any other way.
func TestCAPlanNeverOverwritesAWholeFileItCannotAccountFor(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	const rendered = "# bodega apt settings\nAcquire::Retries \"3\";\n"
	for name, tc := range map[string]struct {
		old     string
		want    string
		refused bool
	}{
		"blank":                {" \n", rendered, false},
		"same":                 {rendered, rendered, false},
		"lines around":         {"# mine\n" + rendered + "APT::Color \"0\";\n", "# mine\n" + rendered + "APT::Color \"0\";\n", false},
		"an older rendering":   {"# bodega apt settings\nAcquire::Retries \"1\";\n", "", true},
		"edited inside":        {"# bodega apt settings\nAPT::Color \"0\";\nAcquire::Retries \"3\";\n", "", true},
		"another file's lines": {"APT::Color \"0\";\n", "", true},
	} {
		home := t.TempDir()
		// A record beside the system's first one, in a format no editor here
		// reads.
		const companionPath = "/etc/apt/apt.conf.d/90bodega"
		main := AptArchive(testBase, "noble", nil)
		companion := File{System: main.System, Paths: map[string]string{OSLinux: companionPath}, Content: rendered}
		target := filepath.Join(home, companionPath)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(tc.old), 0600); err != nil {
			t.Fatal(err)
		}
		in, err := AddCA(caPlan(t, home, main, companion), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")})
		if tc.refused {
			if err == nil || !strings.Contains(err.Error(), target) || !strings.Contains(err.Error(), "Move the file aside") {
				t.Errorf("%s: AddCA = %v, want a refusal naming %s and the next step", name, err, target)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: AddCA = %v", name, err)
			continue
		}
		if _, err := Apply(in.Changes, ".f116"); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(target); string(got) != tc.want {
			t.Errorf("%s: wrote %q, want %q", name, got, tc.want)
		}
		again, err := AddCA(caPlan(t, home, main, companion), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")})
		if err != nil {
			t.Errorf("%s: second AddCA = %v", name, err)
			continue
		}
		for _, c := range again.Changes {
			if c.Target == target && !c.Unchanged() {
				t.Errorf("%s: a second apply would rewrite %s", name, target)
			}
		}
	}
}

func TestAudit10GitCommentCannotHideTrustOverride(t *testing.T) {
	oracletest.Git(t)
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	target := filepath.Join(home, ".gitconfig")
	old := "[http \"https://bodega.example.com/git/\"]\n# company policy \\\nsslCAInfo = /missing/company-ca.pem\n"
	if err := os.WriteFile(target, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	remote := "https://bodega.example.com/git/gh/repo"
	native := func() string {
		cmd := exec.Command("git", "config", "--file", target, "--get-urlmatch", "http.sslCAInfo", remote)
		cmd.Dir = home
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1"}
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	if got := native(); got != "/missing/company-ca.pem" {
		t.Fatalf("native control = %q", got)
	}
	file := Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}})
	in, err := AddCA(caPlan(t, home, file), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux})
	if err != nil {
		if !strings.Contains(err.Error(), target) {
			t.Fatalf("refusal omits target: %v", err)
		}
		return
	}
	if _, err := Apply(in.Changes, ".audit10"); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".config/bodega/ca.pem")
	if got := native(); got != want {
		t.Fatalf("CA apply succeeded but native git still selects %q; want %q", got, want)
	}
}

func TestAudit10NpmUncheckedInputRefusesInPrimaryFile(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, option := range []string{"cafile=", "cafile[]=/missing/company.pem", "cafile=${CORP_CA}"} {
		t.Run(option, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, ".npmrc")
			old := "registry=" + testBase + "/npm/\n" + option + "\n"
			if err := os.WriteFile(target, []byte(old), 0600); err != nil {
				t.Fatal(err)
			}
			if why := NpmUnread(target); why == "" {
				t.Fatal("control: probe classifier did not mark the input unchecked")
			}
			_, err := AddCA(caPlan(t, home, Npm(testBase, nil)), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux})
			if err == nil || !strings.Contains(err.Error(), target) {
				t.Fatalf("primary file has a documented unchecked construct %q, but AddCA = %v; want refusal naming %s", option, err, target)
			}
			if got, _ := os.ReadFile(target); string(got) != old {
				t.Fatal("refusal changed the primary file")
			}
		})
	}
}

// TestGitContinuationFollowsGitsLexer holds the one continuation decision the
// editor, the classifier and the probe share to native git's, on the lines
// that tell a value running on from a backslash that continues nothing.
func TestGitContinuationFollowsGitsLexer(t *testing.T) {
	oracletest.Git(t)
	const base = "https://bodega.example.com/"
	for name, body := range map[string]string{
		"a # comment ending in a backslash":          "[http]\n# note \\\nsslCAInfo = /ca.pem\n",
		"a ; comment ending in a backslash":          "[http]\n; note \\\nsslCAInfo = /ca.pem\n",
		"a header comment ending in a backslash":     "[http] # note \\\nsslCAInfo = /ca.pem\n",
		"a value comment ending in a backslash":      "[http]\nproxy = x # note \\\nsslCAInfo = /ca.pem\n",
		"an escaped backslash ending a value":        "[http]\nproxy = \"x\\\\\"\nsslCAInfo = /ca.pem\n",
		"a value running on":                         "[http]\nproxy = x \\\nsslCAInfo = /ca.pem\n",
		"a quoted ; before the backslash":            "[http]\nproxy = \"x ; y\" \\\nsslCAInfo = /ca.pem\n",
		"a quoted value running on past a ;":         "[http]\nproxy = \"x ; \\\nsslCAInfo = /ca.pem\"\n",
		"a ] inside the subsection before a comment": "[http \"https://bodega.example.com/a]b/\"] # note \\\nsslCAInfo = /deep.pem\n[http]\nsslCAInfo = /ca.pem\n",
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config")
			if err := os.WriteFile(file, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("git", "config", "--file", file, "--get-urlmatch", "http.sslCAInfo", base)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1"}
			out, _ := cmd.Output()
			want := strings.TrimSpace(string(out))
			got := ""
			if own, _ := GitCAInfo([]string{file}, base, ""); own != nil {
				got = own.Value
			}
			if got != want {
				t.Errorf("git reads http.sslCAInfo = %q, this package %q, from:\n%s", want, got, body)
			}
		})
	}
}

// TestContinuationIsEachFormatsOwn holds each line format to its own reader:
// sh ends a comment at the newline, where systemd's environment.d joins
// lines before it looks for one.
func TestContinuationIsEachFormatsOwn(t *testing.T) {
	for _, c := range []struct {
		name  string
		rules lineRules
		lines []string
		want  []bool
	}{
		{"sh comment", shRules, []string{`# note \`, `export A=b`}, []bool{false, false}},
		{"sh trailing comment", shRules, []string{`export A=b # note \`, `export C=d`}, []bool{false, false}},
		{"sh value", shRules, []string{`export A=b\`, `c`, `export C=d`}, []bool{false, true, false}},
		{"sh # inside a word", shRules, []string{`export A=b#c\`, `d`}, []bool{false, true}},
		{"sh single quotes keep a backslash", shRules, []string{`export A='b\'`, `export C=d`}, []bool{false, false}},
		{"sh open quote", shRules, []string{`export A="b`, `# c"`, `export C=d`}, []bool{false, true, false}},
		{"environment.d comment", envdRules, []string{`# note \`, `A=b`, `C=d`}, []bool{false, true, false}},
	} {
		t.Run(c.name, func(t *testing.T) {
			scan := lineScan{rules: c.rules, keyIndent: -1}
			for i, l := range c.lines {
				if got := scan.continues(l); got != c.want[i] {
					t.Errorf("line %d %q: continues = %v, want %v", i+1, l, got, c.want[i])
				}
			}
		})
	}
}

func TestAudit11CAPlanEditsSelectedHelmConfig(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	home, root := t.TempDir(), t.TempDir()
	target := filepath.Join(t.TempDir(), "repositories.yaml")
	old := HelmDocument(HelmRepository(testBase, "caFile: /missing/company-ca.pem", "username: company-user", "password: company-password"))
	if err := os.WriteFile(target, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	h := CAHost{Base: testBase, Home: home, Root: root, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n"), Getenv: func(k string) string {
		if k == "HELM_REPOSITORY_CONFIG" {
			return target
		}
		return ""
	}}
	in, err := AddCA(caPlan(t, home, Helm(testBase)), ca, h)
	if err != nil {
		t.Fatal(err)
	}
	change := changeAt(t, in.Changes, target)
	if strings.Contains(string(change.New), "/missing/company-ca.pem") {
		t.Fatal("selected Helm file still replaces system roots with the missing CA")
	}
	for _, keep := range []string{"company-user", "company-password"} {
		if !strings.Contains(string(change.New), keep) {
			t.Fatalf("selected Helm file lost %s", keep)
		}
	}
	if _, err := Apply(in.Changes, ".audit11"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, change.New) {
		t.Fatalf("selected Helm file was not applied: %s, %v", got, err)
	}
	again, err := AddCA(caPlan(t, home, Helm(testBase)), ca, h)
	if err != nil {
		t.Fatal(err)
	}
	if !changeAt(t, again.Changes, target).Unchanged() {
		t.Fatal("selected Helm file changes again")
	}
}

// A system-store client whose configuration the environment relocates gets
// the plan's merge in the file it reads, with that file's other settings
// kept, and a second plan leaves it alone.
func TestCAPlanEditsEnvSelectedSystemStoreFiles(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		file File
		env  func(target string) map[string]string
		path string
		old  string
		want string
	}{
		{"GOENV", Gomod(testBase), func(f string) map[string]string { return map[string]string{"GOENV": f} }, "goenv",
			"GOFLAGS=-mod=mod\nGOPROXY=https://proxy.golang.org,direct\n", "GOPROXY=" + GoProxy(testBase)},
		{"XDG_CONFIG_HOME for go", Gomod(testBase), func(f string) map[string]string {
			return map[string]string{"XDG_CONFIG_HOME": filepath.Dir(filepath.Dir(f))}
		}, "go/env", "GOFLAGS=-mod=mod\n", "GOPROXY=" + GoProxy(testBase)},
		{"HELM_CONFIG_HOME", Helm(testBase), func(f string) map[string]string { return map[string]string{"HELM_CONFIG_HOME": filepath.Dir(f)} }, "repositories.yaml",
			HelmDocument("- name: company\n  url: https://charts.example/\n"), testBase + "/helm"},
	} {
		t.Run(c.name, func(t *testing.T) {
			home, root := t.TempDir(), t.TempDir()
			target := filepath.Join(t.TempDir(), c.path)
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(c.old), 0600); err != nil {
				t.Fatal(err)
			}
			env := c.env(target)
			h := CAHost{Base: testBase, Home: home, Root: root, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n"), Getenv: func(k string) string { return env[k] }}
			in, err := AddCA(caPlan(t, home, c.file), ca, h)
			if err != nil {
				t.Fatal(err)
			}
			change := changeAt(t, in.Changes, target)
			if !strings.Contains(string(change.New), c.want) {
				t.Fatalf("%s does not hold %s:\n%s", target, c.want, change.New)
			}
			for _, line := range strings.Split(strings.TrimSpace(c.old), "\n") {
				if !strings.HasPrefix(line, "GOPROXY=") && !strings.Contains(string(change.New), line) {
					t.Errorf("%s lost the line %q:\n%s", target, line, change.New)
				}
			}
			if _, err := Apply(in.Changes, ".selected"); err != nil {
				t.Fatal(err)
			}
			again, err := AddCA(caPlan(t, home, c.file), ca, h)
			if err != nil {
				t.Fatal(err)
			}
			if !changeAt(t, again.Changes, target).Unchanged() {
				t.Fatal("the selected file changes again on a second plan")
			}
		})
	}
}

// TestPipOptionsMatchesNativePip compares PipOptions with pip config list
// across the spellings pip's loader folds together: a -- prefix, _ for -,
// case, a colon delimiter, and [DEFAULT] inheritance in either direction.
func TestPipOptionsMatchesNativePip(t *testing.T) {
	python := oracletest.Pip(t)
	cases := []string{
		"[global]\n--cert = /a.pem\nindex-url = https://x/simple/\n",
		"[global]\ncert = /a.pem\n--cert = /b.pem\n",
		"[global]\n--Index_URL: https://x/simple/\n",
		"[DEFAULT]\ncert = /d.pem\n[global]\nindex-url = https://x/simple/\n[install]\n",
		"[DEFAULT]\n--cert = /d.pem\n[global]\ncert = /g.pem\n",
		"[DEFAULT]\ncert = /d.pem\n[global]\n--cert = /g.pem\n",
		"[DEFAULT]\nindex-url = https://d/simple/\n[install]\nextra_index_url = https://e/simple/\n  https://f/simple/\n",
		"[global]\n  index-url = https://x/simple/\n  cert = /a.pem\n",
		"[global]\nfind-links = /a\n  # note\n\n  /b\n  [install]\n  cert = /not.pem\ncert = /a.pem\n",
		"[global] trailing\ncert = /a.pem # kept\n",
		"[global]\nfind-links =\n  /a\n\n  /b\n",
		"[global]\r\ncert = /a.pem\r\n[install]\r\ntimeout: 5\r\n",
	}
	line := regexp.MustCompile(`^([^=]+)='(.*)'$`)
	for _, body := range cases {
		file := filepath.Join(t.TempDir(), "pip.conf")
		if err := os.WriteFile(file, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(python, "-m", "pip", "config", "list")
		cmd.Dir = t.TempDir()
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "PIP_CONFIG_FILE=" + file}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("native pip on %q: %v: %s", body, err, out)
		}
		native := map[string]string{}
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if m := line.FindStringSubmatch(l); m != nil && !strings.HasPrefix(m[1], ":env:.") {
				native[m[1]] = strings.ReplaceAll(m[2], `\n`, "\n")
			}
		}
		if got := PipOptions([]byte(body)); !maps.Equal(got, native) {
			t.Errorf("PipOptions(%q)\n got %v\nnative pip %v", body, got, native)
		}
	}
}

// TestPipLoadErrorMatchesNativePip compares PipLoadError with whether pip
// config list loads the file at all.
func TestPipLoadErrorMatchesNativePip(t *testing.T) {
	python := oracletest.Pip(t)
	cases := []string{
		"[global]\ntimeout = 1\ntimeout = 2\n",
		"[global]\ntimeout = 1\n[global]\nretries = 2\n",
		"[global]\nTimeout = 1\ntimeout = 2\n",
		"[global]\ncert = /a.pem\n--cert = /b.pem\n",
		"[global]\nindex_url = https://a/\nindex-url = https://b/\n",
		"[DEFAULT]\ntimeout = 1\n[DEFAULT]\nretries = 2\n",
		"[DEFAULT]\ntimeout = 1\n[DEFAULT]\ntimeout = 2\n",
		"timeout = 1\n[global]\n",
		"[global]\nindex-url = https://a/\n  https://b/\n[install]\nindex-url = https://c/\n",
		"# comment\n\n[global]\ntimeout: 1\n",
		// The rest of configparser's line grammar: every line that is not
		// blank or a comment is a header, an option or a continuation.
		"[global]\ntimeout = 1\nnot-an-assignment\n",
		"[global]\ntimeout = 1\n= nameless\n",
		"[global]\ntimeout = 1\n: nameless\n",
		"[global\ntimeout = 1\n",
		"[global]\ntimeout = 1\n[install\nretries = 2\n",
		"[global]\ntimeout = 1\n[]\n",
		"[global]\n  not-an-assignment\n",
		"[global]\n  timeout = 1\n",
		"[global]\n  timeout = 1\nretries = 2\n",
		"[global]\nfind-links = /a\n  not-an-assignment\n",
		"[global]\nfind-links = /a\n\n  not-an-assignment\n",
		"[global]\nfind-links = /a\n# note\n  not-an-assignment\n",
		"[global]\nfind-links = /a\n  [install]\n  retries = 2\n",
		"[global]\nfind-links = /a\n  /b\nnot-an-assignment\n",
		"[global]\n= nameless\n  not-an-assignment\n",
		"[global] trailing\ntimeout = 1\n",
		"[global]\n  # indented comment\n; another\ntimeout = 1\n",
		"[global]\nfind-links = /a # not a comment\n",
		"[global]\r\ntimeout = 1\r\nnot-an-assignment\r\n",
		"not-an-assignment\n[global]\n",
		"[global]\ntimeout\n",
	}
	accepted, refused := 0, 0
	for _, body := range cases {
		file := filepath.Join(t.TempDir(), "pip.conf")
		if err := os.WriteFile(file, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(python, "-m", "pip", "config", "list")
		cmd.Dir = t.TempDir()
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "PIP_CONFIG_FILE=" + file}
		out, nativeErr := cmd.CombinedOutput()
		if nativeErr == nil {
			accepted++
		} else {
			refused++
		}
		if got := PipLoadError([]byte(body)); (got == nil) != (nativeErr == nil) {
			t.Errorf("PipLoadError(%q) = %v, native pip: %v: %s", body, got, nativeErr, out)
		}
	}
	// A pip that refuses or accepts everything would agree with nothing
	// these cases are here to tell apart.
	if accepted == 0 || refused == 0 {
		t.Fatalf("native pip accepted %d and refused %d of the cases; the oracle is not telling them apart", accepted, refused)
	}
}

// F116 R1, R2: ParseGitConfig loads a file as git itself does. Native git is
// the oracle: for each body the variables it lists, or the line it refuses
// the file at, are the ones the port gives, for a line in any section.
func TestGitConfigMatchesNativeGit(t *testing.T) {
	git := oracletest.Git(t)
	dir := t.TempDir()
	for i, body := range []string{
		"",
		"top = level\n",
		"[user]\n\tname = \"bad\\q\"\n",
		"[user]\n\tname = \"A \\\"B\\\" \\\\ C\\tD\\n\\b\"\n",
		"[a]\n\tb\n\tc =\n\td = \n",
		"[a] b = c\n[d.E]\nf=g\n[H \"I.j\"] k = l\n",
		"[a \"b\\c\\\"d\"]\n e = f\n",
		"[a]\n b = c \\\n d ; x\n e = \"f \\\n g\" h # i\n",
		"\xef\xbb\xbf[a]\nb=c\n",
		"\xef\xbb[a]\nb=c\n",
		"[a]\n b = \"open\n c = d\n",
		"[a]\n 1b = c\n",
		"[a]\n b c\n",
		"[a]\n b ; c\n",
		"[a]\r\n b = c\r\n d = e\\\r\n f\r\n",
		"[a]\n b = c\\",
		"[a]\n b = c \\\n",
		"[]\n",
		"[a\n b = c\n",
		"[a \"b\n\"]\n",
		"[a \"b\" ]\n",
		"[ a]\n",
		"[a b]\n",
		"[a_b]\n",
		"# c\n; d\n[a] # e\n b = c#d\n f = \"g#h\" ; i\n",
		"[a]\n b = c ; \\\n d = e\n",
		"[http]\n sslCAInfo = /a\\\n/b\n[http \"https://h/\"]\n\tsslCAInfo = ~/x.pem  \n",
		"[url \"https://h/git/\"]\n insteadOf = https://github.com/\n insteadOf = gh:\n",
		"[a]\n b = x\ty  z \n",
		"[a]\n\x0cb = c\n",
		"[a]\n b = c\n=d\n",
	} {
		file := filepath.Join(dir, strconv.Itoa(i)+".cfg")
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(git, "config", "--file", file, "--list", "-z")
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1"}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		native, nativeErr := cmd.Output()
		got := ParseGitConfig([]byte(body))
		if nativeErr != nil {
			want := 0
			if m := regexp.MustCompile(`^fatal: bad config line (\d+) `).FindStringSubmatch(stderr.String()); m != nil {
				want, _ = strconv.Atoi(m[1])
			} else {
				t.Fatalf("%q: native git failed another way: %s", body, stderr.String())
			}
			if got.BadLine != want {
				t.Errorf("%q: BadLine = %d; native git stops at line %d", body, got.BadLine, want)
			}
			continue
		}
		var ours []string
		for _, e := range got.Entries {
			one := e.Key()
			if e.HasValue {
				one += "\n" + e.Value
			}
			ours = append(ours, one)
		}
		var theirs []string
		if len(native) > 0 {
			theirs = strings.Split(strings.TrimSuffix(string(native), "\x00"), "\x00")
		}
		if got.BadLine != 0 || !slices.Equal(ours, theirs) {
			t.Errorf("%q: BadLine = %d and variables %q; native git loads it as %q", body, got.BadLine, ours, theirs)
		}
	}
}

// F116 R1, R2: the two spellings of one npm option in the environment are
// one option. Agreeing or alone they give its value; disagreeing they give
// none and name the pair, since the order npm takes them in is not readable.
func TestNpmEnvResolvesOneOption(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, tc := range []struct {
		env      map[string]string
		value    string
		conflict bool
	}{
		{env: nil},
		{env: map[string]string{"npm_config_registry": "https://a/"}, value: "https://a/"},
		{env: map[string]string{"NPM_CONFIG_REGISTRY": "https://b/"}, value: "https://b/"},
		{env: map[string]string{"npm_config_registry": "https://a/", "NPM_CONFIG_REGISTRY": "https://a/"}, value: "https://a/"},
		{env: map[string]string{"npm_config_registry": "https://a/", "NPM_CONFIG_REGISTRY": "https://b/"}, conflict: true},
	} {
		value, conflict := NpmEnv(env(tc.env), "registry")
		if value != tc.value || (conflict != "") != tc.conflict || NpmEnvConflict(env(tc.env)) != conflict {
			t.Errorf("NpmEnv(%v) = %q, %q; want %q, conflict %v", tc.env, value, conflict, tc.value, tc.conflict)
		}
	}
	if c := NpmEnvConflict(env(map[string]string{"npm_config_userconfig": "/a", "NPM_CONFIG_USERCONFIG": "/b"})); !strings.Contains(c, "npm_config_userconfig") {
		t.Errorf("NpmEnvConflict over userconfig = %q; want the pair named", c)
	}
}

// F116 R1, R2: repositories.yaml loads the way helm v4.3.0 loads it. A wrong
// type in any field of File or Entry is a load error, whichever field it is,
// and where helm is installed it gives the same verdict on the same bytes.
func TestHelmFileLoadsAsHelmLoadsIt(t *testing.T) {
	entry := "repositories:\n  - name: bodega\n    url: https://b/helm\n"
	for name, tc := range map[string]struct {
		body string
		bad  string
	}{
		"plan's own document":   {body: HelmDocument(HelmRepository("https://b"))},
		"empty file":            {body: ""},
		"emptied list":          {body: "repositories: []\n"},
		"null entry":            {body: "repositories:\n  -\n", bad: "is null"},
		"unknown keys":          {body: entry + "    extra: [1]\nother: {a: 1}\n"},
		"bool spelled as YAML":  {body: entry + "    insecure_skip_tls_verify: yes\n"},
		"syntax":                {body: entry + "broken: [\n", bad: "did not find expected"},
		"pass_credentials_all":  {body: entry + "    pass_credentials_all: [wrong-type]\n", bad: "cannot unmarshal"},
		"insecure as a string":  {body: entry + "    insecure_skip_tls_verify: \"maybe\"\n", bad: "cannot unmarshal"},
		"name as a list":        {body: "repositories:\n  - name: [a]\n    url: https://b/helm\n", bad: "cannot unmarshal"},
		"caFile as a mapping":   {body: entry + "    caFile: {a: b}\n", bad: "cannot unmarshal"},
		"password as a list":    {body: entry + "    password: [x]\n", bad: "cannot unmarshal"},
		"generated not a time":  {body: "generated: yesterday\n" + entry, bad: "parsing time"},
		"apiVersion as a list":  {body: "apiVersion: [v1]\n" + entry, bad: "cannot unmarshal"},
		"repositories a string": {body: "repositories: none\n", bad: "cannot unmarshal"},
		"entry a string":        {body: "repositories:\n  - bodega\n", bad: "cannot unmarshal"},
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "repositories.yaml")
			if err := os.WriteFile(file, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			doc, err := LoadHelmFile(file)
			switch {
			case tc.bad == "" && (err != nil || doc == nil):
				t.Fatalf("LoadHelmFile = %v, %v; helm loads this file", doc, err)
			case tc.bad != "" && (err == nil || !strings.Contains(err.Error(), tc.bad) || !strings.Contains(err.Error(), file)):
				t.Fatalf("LoadHelmFile error = %v; want one naming %s and %q", err, file, tc.bad)
			}
			helm := oracletest.Helm(t)
			cmd := exec.Command(helm, "repo", "update", "audit-nonexistent", "--repository-config", file)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
			out, _ := cmd.CombinedOutput()
			// helm prints a load error and panics on a null entry; either way it
			// has stopped before any request.
			if refused := strings.Contains(string(out), "failed loading file") || strings.Contains(string(out), "nil pointer dereference"); refused != (tc.bad != "") {
				t.Errorf("native helm refused the file: %v (%s); LoadHelmFile error = %v", refused, out, err)
			}
		})
	}
	if doc, err := LoadHelmFile(filepath.Join(t.TempDir(), "absent.yaml")); doc != nil || err != nil {
		t.Errorf("a path holding no file = %v, %v; want a helm with no repositories", doc, err)
	}
}

// F116 R1, R2: one resolver names the repositories.yaml helm reads, in
// helm's own order on every platform, and native helm names the same file.
func TestHelmRepositoryFileFollowsHelmpath(t *testing.T) {
	cases := []struct {
		goos string
		env  map[string]string
		want string
	}{
		{OSLinux, nil, "/h/.config/helm/repositories.yaml"},
		{OSDarwin, nil, "/h/Library/Preferences/helm/repositories.yaml"},
		{OSLinux, map[string]string{"XDG_CONFIG_HOME": "/x"}, "/x/helm/repositories.yaml"},
		{OSDarwin, map[string]string{"XDG_CONFIG_HOME": "/x"}, "/x/helm/repositories.yaml"},
		{OSDarwin, map[string]string{"XDG_CONFIG_HOME": "/x", "HELM_CONFIG_HOME": "/c"}, "/c/repositories.yaml"},
		{OSLinux, map[string]string{"XDG_CONFIG_HOME": "/x", "HELM_CONFIG_HOME": "/c", "HELM_REPOSITORY_CONFIG": "/r.yaml"}, "/r.yaml"},
	}
	for _, tc := range cases {
		got := HelmRepositoryFile(func(k string) string { return tc.env[k] }, tc.goos, "/h")
		if got != tc.want {
			t.Errorf("%s %v = %s; want %s", tc.goos, tc.env, got, tc.want)
		}
	}
	if got := HelmRepositoryFile(nil, OSLinux, ""); got != "" {
		t.Errorf("no home and no environment = %q; want none", got)
	}
	helm := oracletest.Helm(t)
	for _, tc := range cases {
		if tc.goos != runtime.GOOS {
			continue
		}
		cmd := exec.Command(helm, "env", "HELM_REPOSITORY_CONFIG")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=/h"}
		for k, v := range tc.env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		out, err := cmd.Output()
		if err != nil || strings.TrimSpace(string(out)) != tc.want {
			t.Errorf("%s %v: native helm reads %s (%v); want %s", tc.goos, tc.env, out, err, tc.want)
		}
	}
}

// F116 R1: a repositories.yaml helm cannot load is refused before any edit
// is built, on the file the plan writes and on the one the environment
// selects, and on a second run as on the first.
func TestCAPlanRefusesUnloadableHelmFile(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	broken := HelmDocument(HelmRepository(testBase, "pass_credentials_all: [wrong-type]"))
	for name, selected := range map[string]bool{"plan's own file": false, "file the environment selects": true} {
		t.Run(name, func(t *testing.T) {
			home, root := t.TempDir(), t.TempDir()
			target := filepath.Join(home, ".config/helm/repositories.yaml")
			env := map[string]string{}
			if selected {
				target = filepath.Join(t.TempDir(), "repositories.yaml")
				env["HELM_REPOSITORY_CONFIG"] = target
			}
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(broken), 0600); err != nil {
				t.Fatal(err)
			}
			h := CAHost{Base: testBase, Home: home, Root: root, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n"), Getenv: func(k string) string { return env[k] }}
			for range 2 {
				_, err := AddCA(caPlan(t, home, Helm(testBase)), ca, h)
				if err == nil || !strings.Contains(err.Error(), target) || !strings.Contains(err.Error(), "pass_credentials_all") {
					t.Fatalf("AddCA error = %v; want a refusal naming %s and the field", err, target)
				}
			}
		})
	}
}

func TestAudit21AptLoadErrorsRefuseCAPlan(t *testing.T) {
	for _, location := range []string{"APT_CONFIG", "etc/apt/apt.conf", "etc/apt/apt.conf.d/99local"} {
		for _, body := range []string{"Acquire::https::CAInfo \"/unused.pem\"\n", "Acquire::Retries \"3\" extra;\n"} {
			t.Run(location+"/"+strings.TrimSpace(body), func(t *testing.T) {
				home := t.TempDir()
				file := filepath.Join(home, location)
				if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				caPEM, _, _ := testCA(t, "bodega.example.com")
				ca, err := ParseCA(caPEM)
				if err != nil {
					t.Fatal(err)
				}
				getenv := func(key string) string {
					if location == "APT_CONFIG" && key == "APT_CONFIG" {
						return file
					}
					return ""
				}
				f := File{System: manifest.TypeApt, Paths: map[string]string{OSLinux: AptSourcesPath}, Content: "Types: deb\nURIs: " + testBase + "/apt\nSuites: stable\nComponents: main\n"}
				in, err := AddCA(caPlan(t, home, f), ca, CAHost{Base: testBase, Home: home, Root: home, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n"), Getenv: getenv})
				if err == nil || !strings.Contains(err.Error(), file) || len(in.Changes) != 0 {
					t.Errorf("CA plan accepted apt's unloadable file %s: err=%v changes=%d step=%v", file, err, len(in.Changes), in.Step)
				}
			})
		}
	}
}

func TestAudit22GomodInvalidProxyRefusesCAPlan(t *testing.T) {
	for _, tail := range []string{"broken", "ftp://mirror.invalid", "file://mirror.invalid/cache"} {
		t.Run(tail, func(t *testing.T) {
			home, root := t.TempDir(), t.TempDir()
			caPEM, _, _ := testCA(t, "bodega.example.com")
			ca, err := ParseCA(caPEM)
			if err != nil {
				t.Fatal(err)
			}
			in, err := AddCA(caPlan(t, home, Gomod(testBase)), ca, CAHost{
				Base: testBase, Home: home, Root: root, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n"),
				Getenv: func(key string) string {
					if key == "GOPROXY" {
						return testBase + "/go," + tail
					}
					return ""
				},
			})
			if err == nil || !strings.Contains(err.Error(), "GOPROXY") || len(in.Changes) != 0 || len(in.Step) != 0 {
				t.Errorf("invalid GOPROXY accepted: err=%v changes=%d step=%v", err, len(in.Changes), in.Step)
			}
		})
	}
}

// F116 R1: a value the client refuses when it comes to use it, or sends
// somewhere this package does not work out, refuses the CA plan before any
// change is built, in whichever documented input holds it. Each client's
// plan is accepted on the same host without that value.
func TestAudit23EndpointValuesRefuseCAPlan(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	apt := File{System: manifest.TypeApt, Paths: map[string]string{OSLinux: AptSourcesPath}, Content: "Types: deb\nURIs: " + testBase + "/apt\nSuites: stable\nComponents: main\n"}
	for _, tc := range []struct {
		name  string
		plan  File
		files map[string]string
		env   map[string]string
		names string
	}{
		{name: "apt, an entry with no suite in another list", plan: apt,
			files: map[string]string{"etc/apt/sources.list.d/extra.list": "deb https://mirror.example/ubuntu\n"}, names: "(Suite)"},
		{name: "apt, an unknown type in sources.list", plan: apt,
			files: map[string]string{"etc/apt/sources.list": "rpm https://mirror.example/ubuntu stable main\n"}, names: "Type 'rpm' is not known"},
		{name: "npm, a registry with no scheme in the environment", plan: Npm(testBase, nil),
			env: map[string]string{"npm_config_registry": "//bodega.example.com/npm/"}, names: "npm_config_registry"},
		{name: "npm, a scoped registry in another scheme", plan: Npm(testBase, nil),
			files: map[string]string{".npmrc": "@corp:registry=ftp://corp.example/npm/\n"}, names: "@corp:registry=ftp://corp.example/npm/"},
		{name: "npm, a registry Node's URL parser reads and net/url does not", plan: Npm(testBase, nil),
			files: map[string]string{".npmrc": "@corp:registry=https:bodega.example.com/npm/\n"}, names: "@corp:registry"},
		{name: "git, a rewrite to a URL git does not normalize", plan: Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}}),
			files: map[string]string{".gitconfig": "[url \"https://bodega.example.com/git/%zz/\"]\n\tinsteadOf = https://example.org/\n"}, names: "invalid %XX escape sequence"},
		{name: "helm, a repository in a scheme with no getter", plan: Helm(testBase),
			files: map[string]string{".config/helm/repositories.yaml": "apiVersion: \"\"\nrepositories:\n- name: other\n  url: ftp://charts.example/\n"}, names: "could not find protocol handler for: ftp"},
		{name: "docker, a client certificate with no key", plan: DockerDaemon(testBase, nil),
			files: map[string]string{"etc/docker/certs.d/bodega.example.com/client.cert": string(caPEM)}, names: "missing key client.key"},
		{name: "containerd, a ca another host of the file names and nothing holds", plan: ContainerdHosts(testBase, "docker.io", "https://registry-1.docker.io"),
			files: map[string]string{"etc/containerd/certs.d/docker.io/hosts.toml": "server = \"https://registry-1.docker.io\"\n\n[host.\"https://mirror.example\"]\n  ca = \"/missing/mirror-ca.pem\"\n"}, names: "unable to read CA cert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			h := CAHost{Base: testBase, Home: home, Root: home, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n"),
				Getenv: func(key string) string { return tc.env[key] }}
			clean := h
			clean.Getenv = func(string) string { return "" }
			if _, err := AddCA(caPlan(t, home, tc.plan), ca, clean); err != nil {
				t.Fatalf("the plan is refused on a clean host: %v", err)
			}
			for name, body := range tc.files {
				path := filepath.Join(home, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			in, err := AddCA(caPlan(t, home, tc.plan), ca, h)
			if err == nil || !strings.Contains(err.Error(), tc.names) || len(in.Changes) != 0 || len(in.Step) != 0 {
				t.Errorf("CA plan accepted: err=%v changes=%d step=%v; want a refusal naming %q", err, len(in.Changes), in.Step, tc.names)
			}
		})
	}
}

// F116 R1, R2: the one-line sources format as APT 3.0.3's ParseFileOldStyle
// and Type::ParseLine read it, each refusal in apt's words.
func TestAudit23AptSourcesListReadsAsApt(t *testing.T) {
	for _, tc := range []struct {
		line, refused string
		uri           string
	}{
		{line: "deb https://a.example/ubuntu stable main", uri: "https://a.example/ubuntu"},
		{line: "deb-src https://a.example/ubuntu stable main contrib # trailing", uri: "https://a.example/ubuntu"},
		{line: "deb [arch=amd64 signed-by=/k.gpg] https://a.example/ubuntu stable main", uri: "https://a.example/ubuntu"},
		{line: "deb [ arch=amd64 ] https://a.example/ubuntu stable main", uri: "https://a.example/ubuntu"},
		{line: "deb [arch=amd64] \"https://a.example/ubuntu\" stable/", uri: "https://a.example/ubuntu"},
		{line: "deb https://a.example/%75buntu stable main", uri: "https://a.example/ubuntu"},
		{line: "  # deb https://a.example/ubuntu stable main"},
		{line: "deb", refused: "Malformed line 1 in source list"},
		{line: "rpm https://a.example/ubuntu stable main", refused: "Type 'rpm' is not known on line 1"},
		{line: "deb [arch=amd64", refused: "([option] unparsable)"},
		{line: "deb [arch=\"amd64 https://a.example/ubuntu stable main", refused: "([option] unparsable)"},
		{line: "deb [arch=amd64 https://a.example/ubuntu stable main", refused: "([option] not assignment)"},
		{line: "deb [a] https://a.example/ubuntu stable main", refused: "([option] too short)"},
		{line: "deb [abc] https://a.example/ubuntu stable main", refused: "([option] not assignment)"},
		{line: "deb [=amd64] https://a.example/ubuntu stable main", refused: "([option] no key)"},
		{line: "deb [arch=] https://a.example/ubuntu stable main", refused: "([option] no value)"},
		{line: "deb [arch=amd64]", refused: "(URI)"},
		{line: "deb https://a.example/ubuntu", refused: "(Suite)"},
		{line: "deb a.example/ubuntu stable main", refused: "(URI parse)"},
		{line: "deb https://a.example/ubuntu stable", refused: "(Component)"},
		{line: "deb https://a.example/ubuntu stable/ main", refused: "(absolute Suite Component)"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, AptSourcesList)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			entries, err := LoadAptSources(root)
			switch {
			case tc.refused != "":
				if err == nil || !strings.Contains(err.Error(), tc.refused) {
					t.Errorf("LoadAptSources = %+v, %v; apt refuses this line with %q", entries, err, tc.refused)
				}
			case err != nil:
				t.Errorf("LoadAptSources refuses a line apt loads: %v", err)
			case tc.uri == "" && len(entries) != 0, tc.uri != "" && (len(entries) != 1 || entries[0].URIs[0] != tc.uri):
				t.Errorf("LoadAptSources = %+v; want the URI %q", entries, tc.uri)
			}
		})
	}
	for uri, want := range map[string][3]string{
		"https://bodega.example.com:8443/apt":        {"https", "bodega.example.com", "8443"},
		"https://user:pw@bodega.example.com/apt":     {"https", "bodega.example.com", "0"},
		"mirror+https://bodega.example.com/list.txt": {"https", "bodega.example.com", "0"},
		"http://[fd00::1]:8080/apt":                  {"http", "fd00::1", "8080"},
		"file:/srv/mirror":                           {"file", "", "0"},
		"cdrom:[Ubuntu 26.04]/":                      {"cdrom", "", "0"},
	} {
		access, host, port := AptURIHost(uri)
		if got := [3]string{access, host, strconv.Itoa(port)}; got != want {
			t.Errorf("AptURIHost(%q) = %v, want %v", uri, got, want)
		}
	}
}

// F116: the trust-store diagnostics for a refused endpoint never carry a URL
// password, whether the client's own parser accepted the URL or not.
func TestAudit23EndpointRefusalsRedactPasswords(t *testing.T) {
	const secret = "hunter2"
	for _, list := range []string{
		"https://bodega.example.com/go,ftp://ci:" + secret + "@mirror.example/go",
		"https://bodega.example.com/go,file://ci:" + secret + "@mirror.example/cache",
		"https://bodega.example.com/go,https://ci:" + secret + "@mirror.example:port/go",
	} {
		if _, err := GoProxyList(list); err == nil || strings.Contains(err.Error(), secret) {
			t.Errorf("GoProxyList(%q) = %v; want a refusal without the password", list, err)
		}
	}
	if list, err := GoProxyList("https://bodega.example.com/go,off,ftp://never.example"); err != nil || len(list) != 2 {
		t.Errorf("an entry past off is never checked: %v, %v", list, err)
	}
	regs := []NpmRegistry{{Option: "registry", Value: "ftp://ci:" + secret + "@mirror.example/npm/", From: "the test"}}
	if unread := NpmRegistryUnread(regs); unread == "" || strings.Contains(unread, secret) {
		t.Errorf("NpmRegistryUnread = %q; want the registry named without the password", unread)
	}
	for value, read := range map[string]bool{
		"https://bodega.example.com/npm/":            true,
		" HTTPS://ci:pw@Bodega.Example.com:8443/n ":  true,
		"https://127.0.0.1:8443/npm/":                true,
		"https://[fd00::1]:8443/npm/":                true,
		"https://0x7f.1/npm/":                        false,
		"https://bodega.example.com:99999/npm/":      false,
		"https://bodega.example.com\\@evil.example/": false,
		"https://bodega.example.com:08443/npm/":      false,
		"https:///bodega.example.com/npm/":           false,
	} {
		if _, err := NpmRegistryURL(value); (err == nil) != read {
			t.Errorf("NpmRegistryURL(%q) = %v; read should be %v", value, err, read)
		}
	}
}

func TestAudit24PipOptionTypeRefusesCAPlan(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	target := filepath.Join(home, "etc/pip.conf")
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("[global]\nindex-url = https://pypi.org/simple/\ntimeout = abc\n"), 0600); err != nil {
		t.Fatal(err)
	}
	in, err := AddCA(caPlan(t, home, Pip(testBase)), ca, CAHost{Base: testBase, Home: home, Root: home, GOOS: OSLinux})
	if err == nil || !strings.Contains(err.Error(), "timeout") || len(in.Changes) != 0 || len(in.Step) != 0 {
		t.Errorf("CA plan accepted pip's invalid timeout: err=%v changes=%d step=%v", err, len(in.Changes), in.Step)
	}
}

func TestAudit24GomodEmptyProxyListRefusesCAPlan(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	in, err := AddCA(caPlan(t, home, Gomod(testBase)), ca, CAHost{
		Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n"),
		Getenv: func(key string) string {
			if key == "GOPROXY" {
				return ",|"
			}
			return ""
		},
	})
	if err == nil || !strings.Contains(err.Error(), "GOPROXY") || len(in.Changes) != 0 || len(in.Step) != 0 {
		t.Errorf("empty proxy list accepted: err=%v changes=%d step=%v", err, len(in.Changes), in.Step)
	}
}

// nativePip261 finds a python3 whose pip is the 26.2.1 PipInstallError
// ports: another pip declares other options.
func nativePip261(t *testing.T) string {
	t.Helper()
	return oracletest.Pip(t)
}

// nativeGit254 finds the git whose 2.54 the configuration port is of: another
// release converts other variables.
func nativeGit254(t *testing.T) string {
	t.Helper()
	return oracletest.Git(t)
}

// TestPipInstallOptionsMatchNativePip compares the option table
// PipInstallError converts by with the parser pip install builds.
func TestPipInstallOptionsMatchNativePip(t *testing.T) {
	python := nativePip261(t)
	const dump = `
from pip._internal.commands import create_command
from pip._internal.cli.main_parser import create_main_parser
general = {l for o in create_main_parser().option_list_all for l in o._long_opts}
for o in create_command("install").parser.option_list_all:
    for l in o._long_opts:
        print(l[2:], o.action, o.type or "-", o.callback.__name__ if o.callback else "-", ",".join(o.choices or ()) or "-", int(l in general))
`
	cmd := exec.Command(python, "-I", "-c", dump)
	cmd.Dir = t.TempDir()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("native pip: %v", err)
	}
	kind := func(action, typ, callback string) (pipKind, bool) {
		switch {
		case action == "store_true" || action == "store_false":
			return pipBool, true
		case action == "count":
			return pipCount, true
		case action == "callback":
			k, ok := map[string]pipKind{
				"_handle_no_cache_dir": pipNoCacheDir, "_handle_python_version": pipPythonVersion, "_handle_src": pipText,
				"_handle_config_settings": pipConfigSettings, "_handle_dependency_group": pipGroup,
				"_handle_all_releases": pipNoDash, "_handle_only_final": pipNoDash, "_handle_no_binary": pipNoDash,
				"_handle_only_binary": pipNoDash, "_handle_refresh_package": pipNoDash, "_handle_uploaded_prior_to": pipUploadedPriorTo,
			}[callback]
			return k, ok && (typ == "string" || typ == "path" || typ == "-")
		case action != "store" && action != "append" && action != "help":
			return 0, false
		}
		k, ok := map[string]pipKind{"string": pipText, "path": pipText, "-": pipText, "int": pipInt, "float": pipFloat, "choice": pipChoice}[typ]
		return k, ok
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != len(pipInstallOpts) {
		t.Fatalf("native pip install declares %d long options, the table %d", len(lines), len(pipInstallOpts))
	}
	for i, l := range lines {
		f := strings.Fields(l)
		k, ok := kind(f[1], f[2], f[3])
		if !ok {
			t.Errorf("native option %q converts in a way the port does not model", l)
			continue
		}
		want := pipOpt{name: f[0], kind: k, list: f[1] == "append", general: f[5] == "1"}
		if f[4] != "-" {
			want.choices = strings.Split(f[4], ",")
		}
		if got := pipInstallOpts[i]; got.name != want.name || got.kind != want.kind || got.list != want.list || got.general != want.general || !slices.Equal(got.choices, want.choices) {
			t.Errorf("option %d: table has %+v, native pip %+v", i, got, want)
		}
	}
}

// TestPipInstallErrorMatchesNativePip compares PipInstallError with whether
// pip install gets past its option conversion: an offline install of a
// package that does not exist reaches "No matching distribution" only when
// the configuration converts. The cases cover each conversion, the order of
// the three groups, a later file replacing an earlier one's value, and the
// empty value that is no setting.
func TestPipInstallErrorMatchesNativePip(t *testing.T) {
	python := nativePip261(t)
	type tc struct {
		legacy, user string
		env          []string
	}
	global := func(lines ...string) tc { return tc{user: "[global]\n" + strings.Join(lines, "\n") + "\n"} }
	cases := []tc{
		global("timeout = abc"),
		global("timeout = 5"),
		global("timeout = 1_0.5e1_0"),
		global("timeout = 1__0"),
		global("timeout = 1_"),
		global("timeout = 1e"),
		global("timeout = .5"),
		global("timeout = 5."),
		global("timeout = ."),
		global("timeout = +inf"),
		global("timeout = -NaN"),
		global("timeout = Infinity"),
		global("timeout = 0x10"),
		global("timeout = 1e999"),
		global("timeout = ٣٫٥"),
		global("timeout = ٣"),
		global("default_timeout = abc"),
		global("--Timeout: abc"),
		global("retries = 5"),
		global("retries = 08"),
		global("retries = 017"),
		global("retries = 0o17"),
		global("retries = 0x1F"),
		global("retries = 0x_1f"),
		global("retries = 0x"),
		global("retries = 0b"),
		global("retries = 0b101"),
		global("retries = 0b2"),
		global("retries = 0B-1"),
		global("retries = 1_000"),
		global("retries = 1__0"),
		global("retries = -3"),
		global("retries = +3"),
		global("retries = 3.0"),
		global("retries = ٣"),
		global("retries = 0٣"),
		global("retries = 0٩"),
		global("retries = " + strings.Repeat("9", 4300)),
		global("retries = " + strings.Repeat("9", 4301)),
		global("resume-retries = x"),
		global("no-input = maybe"),
		global("no-input = ON"),
		global("no-input = t"),
		global("version = abc"),
		global("help = abc"),
		global("verbose = 2"),
		global("verbose = yes"),
		global("verbose = -1"),
		global("verbose = -0"),
		global("verbose = 1.5"),
		global("quiet = 0x1"),
		global("keyring-provider = nope"),
		global("keyring-provider = disabled"),
		global("exists-action = s w"),
		global("exists-action = s\n  w"),
		global("exists-action = s q"),
		global("use-feature = truststore fast-deps"),
		global("use-feature = truststore nope"),
		global("use-deprecated = legacy-certs"),
		global("no-cache-dir = false"),
		global("no-cache-dir = perhaps"),
		global("progress-bar = loud"),
		global("progress-bar = raw"),
		global("upgrade-strategy = sometimes"),
		global("root-user-action = shrug"),
		global("python-version = 3.12"),
		global("python-version = 312"),
		global("python-version = 3.12.1.0"),
		global("python-version = 3.x"),
		global("python-version = 3."),
		global("python-version = 3. 1_2"),
		global("config-settings = novalue"),
		global("config-settings = key=value"),
		global("group = dev"),
		global("group = other.toml:dev"),
		global("group = sub/pyproject.toml/.:dev"),
		global("no-binary = -x"),
		global("no-binary = :all:"),
		global("only-binary = -x"),
		global("all-releases = -x"),
		global("only-final = -x"),
		global("refresh-package = -x"),
		global("uploaded-prior-to = P3D"),
		global("uploaded-prior-to = 2026-01-01"),
		global("uploaded-prior-to = 2026-01-01T00:00:00Z"),
		global("uploaded-prior-to = 2026-01-01T00:00:00+02:00"),
		global("no-such-option = abc", "timeout_ = abc"),
		global("upgrade = maybe"),
		global("upgrade = yes", "pre = n", "compile = 0", "no-compile = F"),
		global("cert = /nowhere.pem", "index-url = not a url", "proxy = ::", "trusted-host = a b", "find-links = /a\n  /b", "target = x", "src = y"),
		{user: "[global]\ntimeout = abc\n[install]\ntimeout = 5\n"},
		{user: "[global]\ntimeout = 5\n[install]\ntimeout = abc\n"},
		{user: "[install]\nupgrade = maybe\n"},
		{user: "[download]\ntimeout = abc\n[freeze]\nupgrade = maybe\n"},
		{user: "[DEFAULT]\ntimeout = abc\n[global]\nretries = 1\n"},
		{user: "[DEFAULT]\ntimeout = abc\n[global]\ntimeout = 1\n"},
		{user: "[DEFAULT]\ntimeout = abc\n[download]\nretries = 1\n"},
		{user: "[global]\ntimeout = abc\n--timeout = 1\n"},
		{user: "[global]\n--timeout = 1\ntimeout = abc\n"},
		{user: "[global.x]\ntimeout = abc\n"},
		{user: "[global]\ntimeout =\n"},
		{legacy: "[global]\ntimeout = abc\n", user: "[global]\ntimeout = 5\n"},
		{legacy: "[global]\ntimeout = 5\n", user: "[global]\ntimeout = abc\n"},
		{legacy: "[global]\ntimeout = abc\n", user: "[global]\ntimeout =\n"},
		{legacy: "[global]\ntimeout = abc\n", user: "[install]\ntimeout = 5\n"},
		{legacy: "[global]\ntimeout = abc\n", user: "[global]\nretries = 2\n"},
		{env: []string{"PIP_TIMEOUT=abc"}},
		{env: []string{"PIP_TIMEOUT=5"}},
		{env: []string{"PIP_TIMEOUT= 5 "}},
		{env: []string{"PIP_DEFAULT_TIMEOUT=abc"}},
		{env: []string{"PIP_RETRIES= 0x10"}},
		{env: []string{"PIP_NO_CACHE_DIR=perhaps"}},
		{env: []string{"PIP_NO_INPUT=maybe"}},
		{env: []string{"PIP_VERSION=abc", "PIP_HELP=abc"}},
		{env: []string{"PIP_UPGRADE_STRATEGY=sometimes"}},
		{user: "[global]\ntimeout = abc\n", env: []string{"PIP_TIMEOUT=5"}},
		{user: "[global]\ntimeout = 5\n", env: []string{"PIP_TIMEOUT=abc"}},
	}
	// pip is started once per case, several at a time.
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	for _, c := range cases {
		home, cwd := t.TempDir(), t.TempDir()
		var layers []PipLayer
		for _, f := range []struct{ rel, body string }{{".pip/pip.conf", c.legacy}, {".config/pip/pip.conf", c.user}} {
			if f.body == "" {
				continue
			}
			path := filepath.Join(home, f.rel)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(f.body), 0600); err != nil {
				t.Fatal(err)
			}
			if err := PipLoadError([]byte(f.body)); err != nil {
				t.Fatalf("case %+v does not load: %v", c, err)
			}
			layers = append(layers, PipLayer{File: path, Data: []byte(f.body)})
		}
		if err := os.WriteFile(filepath.Join(cwd, "pyproject.toml"), []byte("[dependency-groups]\ndev = []\n"), 0600); err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			// --no-deps and --target satisfy the checks pip install runs on
			// its merged options after converting them, which argv can
			// always complete and the configuration alone does not fail.
			cmd := exec.Command(python, "-m", "pip", "install", "--dry-run", "--no-index", "--no-deps", "--target", filepath.Join(home, "target"), "bodega-audit-does-not-exist")
			cmd.Dir = cwd
			cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"), "XDG_CONFIG_DIRS=" + filepath.Join(home, "none"), "PIP_DISABLE_PIP_VERSION_CHECK=1"}, c.env...)
			out, _ := cmd.CombinedOutput()
			// A group path that passes its conversion is opened afterwards.
			native := strings.Contains(string(out), "No matching distribution found") || strings.Contains(string(out), "Cannot resolve '--group' option")
			env := map[string]string{}
			for _, kv := range c.env {
				k, v, _ := strings.Cut(kv, "=")
				env[k] = v
			}
			err := PipInstallError(layers, func(k string) string { return env[k] })
			if (err == nil) != native {
				t.Errorf("%+v\n PipInstallError = %v\n native pip starts = %v: %s", c, err, native, strings.TrimSpace(string(out)))
			}
		}()
	}
	wg.Wait()
}

// TestPipInstallErrorRefusesWhatItDoesNotInterpret covers the two settings
// PipInstallError refuses without judging, and that an error names its
// source.
func TestPipInstallErrorRefusesWhatItDoesNotInterpret(t *testing.T) {
	for body, want := range map[string]string{
		"[global]\npython = /opt/other/bin/python\n":                "python",
		"[global]\nuploaded-prior-to = 2026-W01\n":                  "uploaded-prior-to",
		"[global]\nuploaded-prior-to = P999999999D\n":               "uploaded-prior-to",
		"[global]\nretries = 2\n\n[install]\nDefault_Timeout = x\n": "default_timeout under [install], pip.conf line 5",
	} {
		if err := PipInstallError([]PipLayer{{File: "pip.conf", Data: []byte(body)}}, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("PipInstallError(%q) = %v; want a refusal naming %s", body, err, want)
		}
	}
	env := func(k string) string { return map[string]string{"PIP_PYTHON": "/opt/other/bin/python"}[k] }
	if err := PipInstallError(nil, env); err == nil || !strings.Contains(err.Error(), "PIP_PYTHON") {
		t.Errorf("PIP_PYTHON = %v; want a refusal naming it", err)
	}
	if err := PipInstallError([]PipLayer{{File: "pip.conf", Data: []byte("[global]\nindex-url = https://x/simple/\ncert = /a.pem\ntimeout = 15\n")}}, nil); err != nil {
		t.Errorf("valid configuration refused: %v", err)
	}
}

// TestGitConvertErrorMatchesNativeGit compares GitConvertError with whether
// git-remote-https, the process that reads http.sslCAInfo and connects, gets
// past its configuration: started on a URL nothing listens at with no
// command on stdin, it exits 128 with "fatal:" when a variable does not
// convert and 1 when all of them do. Every variable of http_options and
// git_default_config is given every value below, alone and under an
// [http "<url>"] section matching the remote, beside names the port leaves
// alone. TestGitOperationVarsMatchNativeGit holds the variables git fetch and
// git clone convert themselves against those commands.
func TestGitConvertErrorMatchesNativeGit(t *testing.T) {
	git := nativeGit254(t)
	const remote = "https://127.0.0.1:1/"
	const novalue = "\x00"
	common := []string{"maybe", "true", "ON", "1", "abc", "auto", "", novalue}
	numbers := []string{"-1", "-2", "3", "9", "10", "1k", "2G", "4g", "0x10", "08", " 7", "99999999999",
		"9223372036854775807", "9223372036854775808", "18446744073709551615", "18446744073709551616", "8589934591g"}
	words := []string{"AUTO", "input", "warn", "initial", "always", "never", "simple", "inherit", "none", "default", "Minimal",
		"rename", "link", "nothing", "tracking", "local", "commit", "a\\nb", "~/x", ":(optional)~/x", "10"}
	type entry struct {
		section, name string
		conv          gitConv
	}
	var entries []entry
	for name, v := range gitHTTPVars {
		// The backend is refused as not interpreted, which is no claim
		// about git.
		if v.conv != gitBackend {
			entries = append(entries, entry{"[http]", name, v.conv}, entry{`[http "` + remote + `"]`, name, v.conv})
		}
	}
	for key, v := range gitDefaultVars {
		if v.conv != gitColor {
			section, name, _ := strings.Cut(key, ".")
			entries = append(entries, entry{"[" + section + "]", name, v.conv})
		}
	}
	entries = append(entries, []entry{
		{section: "[advice]", name: "detachedHead"}, {section: "[advice]", name: "statushints"}, {section: "[advice]", name: "noSuchAdvice"},
		{section: `[advice "x"]`, name: "detachedhead"}, {section: "[http]", name: "nosuchkey"}, {section: `[http "` + remote + `"]`, name: "nosuchkey"},
		{section: "[core]", name: "eol"}, {section: "[color]", name: "ui"}, {section: "[alias]", name: "co"}, {section: "[CORE]", name: "FileMode"},
	}...)
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	home := t.TempDir()
	for i, e := range entries {
		values := slices.Clone(common)
		switch e.conv {
		case gitInt, gitSsize, gitUlong, gitLevel, gitAbbrev, gitBool:
			values = append(values, numbers...)
		default:
			values = append(values, words...)
		}
		for j, v := range values {
			// git converts these two and then acts on them: it parses a
			// proxy as a URL once a request needs one, and asks for a
			// username under proactive authentication.
			if e.name == "proxy" && strings.ContainsAny(v, `/\`) || e.name == "proactiveauth" && v == "auto" {
				continue
			}
			body := e.section + "\n\t" + e.name + " = \"" + v + "\"\n"
			if v == novalue {
				body = e.section + "\n\t" + e.name + "\n"
			}
			file := filepath.Join(home, strconv.Itoa(i)+"-"+strconv.Itoa(j))
			if err := os.WriteFile(file, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				slots <- struct{}{}
				defer func() { <-slots }()
				cmd := exec.Command(git, "remote-https", "origin", remote+"x.git")
				cmd.Dir = home
				cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + file, "LC_ALL=C"}
				out, _ := cmd.CombinedOutput()
				native := strings.Contains(string(out), "fatal:")
				cfg := ParseGitConfig([]byte(body))
				if cfg.BadLine != 0 {
					t.Errorf("%q does not parse", body)
					return
				}
				if _, msg := GitConvertError(cfg); (msg != "") != native {
					t.Errorf("%q\n GitConvertError = %q\n native git: %s", body, msg, strings.TrimSpace(string(out)))
				}
			}()
		}
	}
	wg.Wait()
}

// TestGitConvertErrorRefusals covers what GitConvertError refuses beyond
// git's own verdict, each in the direction of refusing: an http variable
// under a URL the remote may not match, a color and another account's home.
// It also pins the line and message GitLoadError carries.
func TestGitConvertErrorRefusals(t *testing.T) {
	for body, want := range map[string]string{ //nolint:gosec // G101: names of git's credential section, no credential
		"[http \"https://other.example/\"]\n\tsslVerify = maybe\n": "bad boolean config value 'maybe' for 'http.sslverify'",
		"[color \"advice\"]\n\thint = red\n":                       "color.advice.hint",
		"[http]\n\tsslCAInfo = ~bob/ca.pem\n":                      "the account bob",
		"[user]\n\tname = x\n[http]\n\tpostBuffer = 1x\n":          "bad numeric config value '1x' for 'http.postbuffer': invalid unit",
		// A name in a section git fetch and git clone read that the port
		// holds no conversion for, which git itself ignores.
		"[core]\n\tnosuchkey = 1\n":                  "'core.nosuchkey' is in a section git fetch and git clone read",
		"[core \"x\"]\n\tfilemode = true\n":          "'core.x.filemode' is in a section",
		"[user \"x\"]\n\tname = y\n":                 "'user.x.name' is in a section",
		"[fetch]\n\tprunee = true\n":                 "'fetch.prunee' is in a section",
		"[remote \"origin\"]\n\turl = https://x/y\n": "git clone then fetches from what this file names",
		"[remote \"up\"]\n\tfetch = main\n":          "is a refspec git dies on when it is malformed",
		"[hook \"x\"]\n\tevent = post-checkout\n":    "has git run a configured command",
		"[clone]\n\tdefaultRemoteName = a/b\n":       "is a remote name git clone checks",
		"[core]\n\tsharedRepository = 0640\n":        "is the file mode 0640",
		"[credential]\n\tuseHttpPath = maybe\n":      "bad boolean config value 'maybe' for 'credential.usehttppath'",
		"[credential]\n\thelper\n":                   "missing value for 'credential.helper'",
		"[submodule \"a\"]\n\tactive = maybe\n":      "bad boolean config value 'maybe' for 'submodule.a.active'",
		"[filter \"lfs\"]\n\trequired = maybe\n":     "bad boolean config value 'maybe' for 'filter.lfs.required'",
		"[protocol \"https\"]\n\tallow = never\n":    "transport 'https' not allowed",
	} {
		if _, msg := GitConvertError(ParseGitConfig([]byte(body))); !strings.Contains(msg, want) {
			t.Errorf("GitConvertError(%q) = %q; want %q", body, msg, want)
		}
	}
	file := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(file, []byte("[user]\n\tname = x\n[core]\n\tcompression = fast\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := GitLoadError([]string{file}); !strings.Contains(got, file+" (line 4: bad numeric config value 'fast' for 'core.compression': invalid unit") {
		t.Errorf("GitLoadError = %q", got)
	}
	ok := "[user]\n\tname = x\n\temail = x@example.com\n\tsigningkey = ABCD\n[core]\n\tautocrlf = input\n\tcompression = 9\n\tpager = less\n\tfsmonitor = true\n[http]\n\tsslVerify = true\n\tpostBuffer = 512m\n\tsslCAInfo = ~/ca.pem\n[http \"https://bodega.example.com/\"]\n\tsslCAInfo = /etc/ca.pem\n[fetch]\n\tprune = true\n" +
		"[alias]\n\tco = checkout\n[pull]\n\trebase = maybe\n[lfs]\n\tanything = 1\n[credential]\n\thelper = osxkeychain\n\tcredentialStore = cache\n[credential \"https://github.com\"]\n\thelper = !gh auth git-credential\n" +
		"[init]\n\tdefaultBranch = main\n[push]\n\tautoSetupRemote = true\n[branch]\n\tsort = -committerdate\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n\trebase = true\n" +
		"[remote \"up\"]\n\turl = https://example.com/x.git\n\tfetch = +refs/heads/*:refs/remotes/up/*\n\tfetch = +refs/pull/*/head:refs/remotes/up/pr/*\n[url \"https://bodega.example.com/git/gh/\"]\n\tinsteadOf = https://github.com/\n" +
		"[maintenance]\n\trepo = /src/x\n\tstrategy = incremental\n[gc]\n\tauto = 0\n[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n" +
		"[fetch \"fsck\"]\n\tzeroPaddedFilemode = ignore\n\tnoSuchId = whatever\n[protocol]\n\tversion = 2\n[submodule]\n\trecurse = true\n\tfetchJobs = 4\n[advice]\n\tdetachedHead = false\n\tnoSuchAdvice = maybe\n"
	if line, msg := GitConvertError(ParseGitConfig([]byte(ok))); msg != "" {
		t.Errorf("valid configuration refused at line %d: %s", line, msg)
	}
}

// TestGitOperationVarsMatchNativeGit compares the conversions gitOpVars holds
// with git fetch and git clone themselves: each variable the table converts
// is given each value below in the global configuration, and both commands
// are run over https against a port nothing listens at, where a command that
// got past its configuration ends "unable to access", and over file:// from a
// repository holding one commit, where it exits 0. The port must refuse the
// value exactly when one of the four runs stops. The serving side of the
// file:// runs reads no configuration, so only the client's conversions are
// held to it.
//
// Not held to it: a refusal that is doctor's own (a value it does not
// interpret), and a conversion git runs only in a state these runs do not
// reach (gitVar.later, and the one value named below).
func TestGitOperationVarsMatchNativeGit(t *testing.T) {
	git := nativeGit254(t)
	home := t.TempDir()
	env := func(global string) []string {
		return []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + global, "LC_ALL=C", "GIT_TERMINAL_PROMPT=0"}
	}
	// A run that outlives its limit is a value that has git start something
	// which keeps the output open, and is reported in place of hanging the
	// package's tests.
	run := func(global string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, git, args...)
		cmd.Dir = home
		cmd.Env = env(global)
		cmd.WaitDelay = time.Second
		out, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Errorf("git %v under %s did not exit within a minute", args, global)
		}
		return string(out), err
	}
	must := func(args ...string) {
		t.Helper()
		if out, err := run(os.DevNull, args...); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	seed, empty := filepath.Join(home, "seed"), filepath.Join(home, "empty")
	must("init", "--quiet", "-b", "main", seed)
	if err := os.WriteFile(filepath.Join(seed, "f.txt"), []byte("x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	must("-C", seed, "add", ".")
	must("-C", seed, "-c", "user.name=a", "-c", "user.email=a@example.com", "commit", "--quiet", "-m", "c")
	must("init", "--quiet", empty)
	const remote = "https://127.0.0.1:1/x.git"
	serve := "--upload-pack=GIT_CONFIG_GLOBAL=" + os.DevNull + " '" + git + "' upload-pack"
	// stops reports whether git fetch or git clone stops under the global
	// configuration file, and what the run that stopped printed.
	stops := func(global, scratch string) (bool, string) {
		if out, _ := run(global, "-C", empty, "fetch", remote); !strings.Contains(out, "unable to access") {
			return true, out
		}
		if out, _ := run(global, "clone", remote, filepath.Join(scratch, "c1")); !strings.Contains(out, "unable to access") {
			return true, out
		}
		if out, err := run(global, "clone", serve, "file://"+seed, filepath.Join(scratch, "c2")); err != nil {
			return true, out
		}
		fresh := filepath.Join(scratch, "f")
		if out, err := run(os.DevNull, "init", "--quiet", fresh); err != nil {
			return true, "init: " + out
		}
		if out, err := run(global, "-C", fresh, "fetch", serve, "file://"+seed); err != nil {
			return true, out
		}
		return false, ""
	}
	const novalue = "\x00"
	values := func(v gitVar) []string {
		switch v.conv {
		case gitBool:
			return []string{"maybe", "true", "no", "1k", "99999999999", "", novalue}
		case gitInt, gitUlong:
			return []string{"maybe", "true", "1", "2", "3", "-1", "0", "1k", "99999999999", "", novalue}
		case gitString, gitAny:
			return []string{"maybe", "", novalue}
		case gitPath:
			return []string{"~nosuchuser-bodega/x", "/nonexistent/x", novalue}
		}
		return append([]string{"maybe", "true", "1", "always", "ALWAYS", "never", "user", "auto", "error", "warn", "ignore", "", novalue}, v.words...)
	}
	// later holds the one value-dependent refusal git reaches only in a state
	// these runs do not: fsck_set_msg_type refuses to demote a fatal message
	// once fsckObjects has index-pack check the pack, and not before.
	later := func(key, value string) bool {
		return key == "fetch.fsck.nulinheader" && (value == "warn" || value == "ignore")
	}
	keys := []string{"fetch.fsck.baddate", "fetch.fsck.nulinheader", "fetch.fsck.nosuchid", "fetch.fsck.skiplist", "protocol.https.allow", "core.pager", "init.defaultbranch", "gc.auto"}
	for key, v := range gitOpVars {
		if v.conv != gitAny && !v.later {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	for i, key := range keys {
		parts := strings.Split(key, ".")
		header, name := "["+parts[0]+"]", parts[len(parts)-1]
		if len(parts) == 3 {
			sub := parts[1]
			if sub == "*" {
				sub = "other"
			}
			header = "[" + parts[0] + " \"" + sub + "\"]"
		}
		probe := ParseGitConfig([]byte(header + "\n\t" + name + " = x\n"))
		_, v, ok, known := probe.Entries[0].lookup()
		if !ok || !known {
			t.Errorf("%s: the table has no conversion for its own key", key)
			continue
		}
		for j, value := range values(v) {
			if later(key, value) {
				continue
			}
			body := header + "\n\t" + name + " = \"" + value + "\"\n"
			if value == novalue {
				body = header + "\n\t" + name + "\n"
			}
			cfg := ParseGitConfig([]byte(body))
			if cfg.BadLine != 0 {
				t.Errorf("%q does not parse", body)
				continue
			}
			e := cfg.Entries[0]
			full, _, _, _ := e.lookup()
			msg, own := v.refuses(full, e.Value, e.HasValue)
			if own {
				continue
			}
			scratch := filepath.Join(home, strconv.Itoa(i)+"-"+strconv.Itoa(j))
			if err := os.MkdirAll(scratch, 0700); err != nil {
				t.Fatal(err)
			}
			global := filepath.Join(scratch, "gitconfig")
			if err := os.WriteFile(global, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				slots <- struct{}{}
				defer func() { <-slots }()
				if native, out := stops(global, scratch); native != (msg != "") {
					t.Errorf("%q\n the port: %q\n native git stops = %v: %s", body, msg, native, strings.TrimSpace(out))
				}
			}()
		}
	}
	wg.Wait()
}

// nativeNpm1120 finds the npm 11.20.0 the type port is of.
func nativeNpm1120(t *testing.T) string {
	t.Helper()
	return oracletest.Npm(t)
}

// runNpmView runs npm view against a registry nothing listens at, with file
// as the user's npmrc and env added to an otherwise empty environment, and
// returns what it printed. The command line sets the log level and the
// registry, which outrank the file and the environment without stopping npm
// validating either.
func runNpmView(t *testing.T, npm, file string, env []string) string {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command(npm, "view", "left-pad", "version", "--registry=https://127.0.0.1:1/", "--loglevel=warn", "--fetch-retries=0", "--cache="+filepath.Join(home, "cache"), "--prefix="+filepath.Join(home, "prefix"))
	cmd.Dir = home
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "NPM_CONFIG_USERCONFIG=" + file, "NPM_CONFIG_GLOBALCONFIG=" + filepath.Join(home, "none"), "NPM_CONFIG_UPDATE_NOTIFIER=false"}, env...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// TestNpmTypesMatchNativeNpm compares the type port with the options npm
// itself warns "invalid config" about, for every typed option holding each
// value below, from an npmrc and from the environment. Where the port says
// it cannot tell, npm's answer is not held against it.
func TestNpmTypesMatchNativeNpm(t *testing.T) {
	npm := nativeNpm1120(t)
	warned := regexp.MustCompile(`(?m)^npm warn invalid config ([^=\s]+)=`)
	var keys []string
	for key := range npmTypes {
		// These two move the files npm reads, which the runner pins.
		if key != "userconfig" && key != "globalconfig" {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	const bare = "\x00"
	values := []string{"abc", "true", "false", "null", "undefined", "", " ", "0", "5", "1e3", "0x10", "0o7", "0b1", "1_000", "Infinity", "-.5", "5.", "+5", "0x", "1e",
		"dev", "none", "warn", "1", "4", "public", "all", "022", "0o22", "18", "999", "511", "512", "00", "0777", "01000", "http://h/", "socks5://h:1", "localhost:8080", "/abs", "rel", "1.2.3", "legacy", bare}
	// A path or list option holding true, false or null stops npm with no
	// output at all, which would hide every other option's warning, so each
	// of those runs alone, on the values that tell its type apart, and
	// counts as refused when npm never reaches the request.
	var batch, solo []string
	for _, key := range keys {
		if npmTypes[key].kind == npmPath || npmTypes[key].list {
			solo = append(solo, key)
		} else {
			batch = append(batch, key)
		}
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	run := func(keys []string, v string, fromEnv bool) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			file := filepath.Join(t.TempDir(), "npmrc")
			var body strings.Builder
			var env []string
			for _, key := range keys {
				switch {
				case fromEnv:
					env = append(env, "npm_config_"+strings.ReplaceAll(key, "-", "_")+"="+v)
				case v == bare:
					body.WriteString(key + "\n")
				default:
					body.WriteString(key + "=" + v + "\n")
				}
			}
			if err := os.WriteFile(file, []byte(body.String()), 0600); err != nil {
				t.Error(err)
				return
			}
			out := runNpmView(t, npm, file, env)
			native := map[string]bool{}
			for _, m := range warned.FindAllStringSubmatch(out, -1) {
				native[m[1]] = true
			}
			for _, key := range keys {
				val := jsValue{word: v, str: true}
				if !fromEnv {
					switch v {
					case bare:
						val = jsTrue
					case "true", "false", "null":
						val = jsValue{word: v}
					}
					// npm/ini trims a value before anything reads it.
					val.word = jsTrim(val.word)
				}
				// npm/ini takes a dotted name set to null for a section.
				if val == jsNull && strings.Contains(key, ".") {
					continue
				}
				refused := native[key] || len(keys) == 1 && !strings.Contains(out, "ECONNREFUSED")
				invalid, unread := npmTypes[key].check(val)
				if !unread && invalid != refused {
					t.Errorf("%s=%q (environment: %v): port says invalid=%v, native npm refused=%v: %s", key, v, fromEnv, invalid, refused, strings.TrimSpace(out))
				}
			}
		}()
	}
	for _, fromEnv := range []bool{false, true} {
		for _, v := range values {
			if fromEnv && (v == bare || jsTrim(v) == "") {
				continue
			}
			run(batch, v, fromEnv)
		}
		for _, key := range solo {
			for _, v := range []string{"true", "false", "null", "undefined", "abc", "dev", "", bare} {
				if fromEnv && (v == bare || v == "") {
					continue
				}
				run([]string{key}, v, fromEnv)
			}
		}
	}
	wg.Wait()
}

// TestNpmStartErrorMatchesNativeNpm compares NpmStartError's reading of an
// unscoped credential with whether npm exits on ERR_INVALID_AUTH, and pins
// the phrases it carries for a type npm reports invalid.
func TestNpmStartErrorMatchesNativeNpm(t *testing.T) {
	npm := nativeNpm1120(t)
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	for _, key := range append(slices.Clone(npmUnscopedAuth), "//127.0.0.1:1/:_authToken", "email", "password", "_authTOKEN") {
		for _, line := range []string{"=abc", "=", "=false", "=null", "=undefined", "=true", "", "[]=abc", "=0"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				slots <- struct{}{}
				defer func() { <-slots }()
				file := filepath.Join(t.TempDir(), "npmrc")
				if err := os.WriteFile(file, []byte("fetch-retries=1\n"+key+line+"\n"), 0600); err != nil {
					t.Error(err)
					return
				}
				native := strings.Contains(runNpmView(t, npm, file, nil), "ERR_INVALID_AUTH")
				if got := NpmStartError(file); (got != "") != native {
					t.Errorf("%s%s: NpmStartError = %q, native npm ERR_INVALID_AUTH = %v", key, line, got, native)
				}
			}()
		}
	}
	wg.Wait()
}

func TestNpmStartErrorNamesTheLine(t *testing.T) {
	file := filepath.Join(t.TempDir(), "npmrc")
	for body, want := range map[string]string{
		"registry=https://r.example/\nfetch-timeout=abc\n":        "line 2 of " + file + ", which sets fetch-timeout to a value npm reports as invalid config",
		"fetch-timeout=abc\nfetch-timeout=5\n_authToken=secret\n": "line 3 of " + file + ", which sets _authToken outside a registry's own //host/: scope",
		"before=2026-01-01\n":     "sets before to a value npm validates in a way doctor does not interpret",
		"fetch-retries[]=1\n":     "sets fetch-retries to a value npm validates in a way doctor does not interpret",
		"maxsockets=${SOCKETS}\n": "sets maxsockets to a value npm validates in a way doctor does not interpret",
		"loglevel=loud\n":         "sets loglevel to a value npm reports as invalid config",
		"registry=https://r.example/\n//r.example/:_authToken=x\n":                                         "",
		"fetch-timeout=abc\nfetch-timeout=5\nstrict-ssl=maybe\nomit=dev\n\n[section]\nfetch-retries=abc\n": "",
	} {
		if err := os.WriteFile(file, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if got := NpmStartError(file); got != want && (want == "" || !strings.Contains(got, want)) {
			t.Errorf("NpmStartError(%q) = %q; want %q", body, got, want)
		}
		if strings.Contains(NpmStartError(file), "secret") {
			t.Errorf("NpmStartError(%q) echoes the credential", body)
		}
	}
	env := func(k string) string { return map[string]string{"NPM_CONFIG_FETCH_TIMEOUT": "abc"}[k] }
	if got := NpmEnvInvalid(env); !strings.Contains(got, "NPM_CONFIG_FETCH_TIMEOUT") {
		t.Errorf("NpmEnvInvalid = %q", got)
	}
	if got := NpmEnvInvalid(func(k string) string {
		return map[string]string{"npm_config_fetch_timeout": "5", "npm_config_proxy": "false"}[k]
	}); got != "" {
		t.Errorf("valid environment refused: %s", got)
	}
}

// F116 R1: a CA plan is refused, before any change is planned, for a client
// that stops on a configured value while it converts its options: the CA
// would be installed for a client that never reaches the handshake.
func TestOptionConversionFailureRefusesCAPlan(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	apt := File{System: manifest.TypeApt, Paths: map[string]string{OSLinux: AptSourcesPath}, Content: "Types: deb\nURIs: " + testBase + "/apt\nSuites: stable\nComponents: main\n"}
	for _, tc := range []struct {
		name  string
		plan  File
		files map[string]string
		env   map[string]string
		names string
	}{
		{name: "git, a boolean git dies on", plan: Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}}),
			files: map[string]string{".gitconfig": "[http]\n\tsslVerify = maybe\n"}, names: "bad boolean config value 'maybe' for 'http.sslverify'"},
		{name: "git, a compression level out of range", plan: Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}}),
			files: map[string]string{".gitconfig": "[core]\n\tcompression = 12\n"}, names: "bad zlib compression level 12"},
		{name: "npm, a credential outside a registry's scope", plan: Npm(testBase, nil),
			files: map[string]string{".npmrc": "_authToken=abc\n"}, names: "ERR_INVALID_AUTH"},
		{name: "npm, a number npm reports invalid and keeps", plan: Npm(testBase, nil),
			files: map[string]string{".npmrc": "fetch-timeout=abc\n"}, names: "fetch-timeout"},
		{name: "npm, the same from the environment", plan: Npm(testBase, nil),
			env: map[string]string{"NPM_CONFIG_MAXSOCKETS": "abc"}, names: "NPM_CONFIG_MAXSOCKETS"},
		{name: "pip, a choice from the environment", plan: Pip(testBase),
			env: map[string]string{"PIP_KEYRING_PROVIDER": "nope"}, names: "PIP_KEYRING_PROVIDER"},
		{name: "pip, a boolean under [install]", plan: Pip(testBase),
			files: map[string]string{".config/pip/pip.conf": "[install]\nupgrade = maybe\n"}, names: "upgrade under [install]"},
		{name: "apt, an option its https method no longer supports", plan: apt,
			files: map[string]string{"etc/apt/apt.conf.d/90tls": "Acquire::https::SslForceVersion \"TLSv1.2\";\n"}, names: "the option 'SslForceVersion' is not supported anymore"},
		{name: "apt, a client certificate that is not there", plan: apt,
			files: map[string]string{"etc/apt/apt.conf.d/90tls": "Acquire::https::bodega.example.com::SslCert \"/missing/client.pem\";\n"}, names: "Could not load client certificate"},
		{name: "helm, a client certificate with no key", plan: Helm(testBase),
			files: map[string]string{".config/helm/repositories.yaml": "apiVersion: \"\"\nrepositories:\n- name: mine\n  url: " + testBase + "/helm/mine\n  certFile: /missing/client.pem\n"}, names: "unable to read cert file"},
		{name: "containerd, a wrong type in the image plugin's table", plan: ContainerdHosts(testBase, "docker.io", "https://registry-1.docker.io"),
			files: map[string]string{"etc/containerd/config.toml": "version = 3\n[plugins.\"io.containerd.cri.v1.images\"]\n  max_concurrent_downloads = \"three\"\n  [plugins.\"io.containerd.cri.v1.images\".registry]\n    config_path = \"/etc/containerd/certs.d\"\n"}, names: "row 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			h := CAHost{Base: testBase, Home: home, Root: home, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n"),
				Getenv: func(key string) string { return tc.env[key] }}
			clean := h
			clean.Getenv = func(string) string { return "" }
			if _, err := AddCA(caPlan(t, home, tc.plan), ca, clean); err != nil {
				t.Fatalf("the plan is refused on a clean host: %v", err)
			}
			for name, body := range tc.files {
				path := filepath.Join(home, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			in, err := AddCA(caPlan(t, home, tc.plan), ca, h)
			if err == nil || !strings.Contains(err.Error(), tc.names) || len(in.Changes) != 0 || len(in.Step) != 0 {
				t.Errorf("CA plan accepted: err=%v changes=%d step=%v; want a refusal naming %q", err, len(in.Changes), in.Step, tc.names)
			}
		})
	}
}

func TestAudit25GitFetchConversionRefusesCAPlan(t *testing.T) {
	git := oracletest.Git(t)
	home := t.TempDir()
	target := filepath.Join(home, ".gitconfig")
	bad := "[fetch]\n\tprune = maybe\n"
	if err := os.WriteFile(target, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(home, "repo")
	init := exec.Command(git, "init", "--quiet", repo)
	init.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + target}
	if out, err := init.CombinedOutput(); err != nil {
		t.Fatalf("init: %v: %s", err, out)
	}
	fetch := exec.Command(git, "-C", repo, "fetch", "https://127.0.0.1:1/audit.git")
	fetch.Env = init.Env
	out, err := fetch.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "bad boolean config value 'maybe' for 'fetch.prune'") {
		t.Fatalf("native fetch: %v: %s", err, out)
	}
	t.Logf("native fetch: %s", out)
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	plan := caPlan(t, home, Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}}))
	in, err := AddCA(plan, ca, CAHost{Base: testBase, Home: home, Root: home, GOOS: OSLinux})
	if err == nil || !strings.Contains(err.Error(), "fetch.prune") || len(in.Changes) != 0 {
		t.Errorf("native-invalid fetch accepted: err=%v changes=%d", err, len(in.Changes))
	}
}

func TestAudit25HelmMissingPairRefusesCAPlan(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".config/helm/repositories.yaml")
	cert, key := filepath.Join(home, "missing.crt"), filepath.Join(home, "missing.key")
	body := "repositories:\n- name: bodega\n  url: " + testBase + "/helm\n  certFile: " + cert + "\n  keyFile: " + key + "\n"
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	in, err := AddCA(caPlan(t, home, Helm(testBase)), ca, CAHost{Base: testBase, Home: home, Root: home, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")})
	if err == nil || !strings.Contains(err.Error(), "cert") || len(in.Changes) != 0 || len(in.Step) != 0 {
		t.Errorf("unloadable Helm pair accepted: err=%v changes=%d step=%v", err, len(in.Changes), in.Step)
	}
}

func TestAudit25MissingPipOracleFailsInCI(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.v", "-test.run=^TestPipInstallOptionsMatchNativePip$")
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "PATH=") && !strings.HasPrefix(e, "CI=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "CI=true", "PATH="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("missing native pip oracle passed CI:\n%s", out)
	}
}

func TestAudit25ContainerdV2ConversionRefusesCAPlan(t *testing.T) {
	home := t.TempDir()
	file := filepath.Join(home, "etc/containerd/config.toml")
	body := "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\"]\nmax_concurrent_downloads = \"three\"\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	in, err := AddCA(caPlan(t, home, ContainerdHosts(testBase, "docker.io", "https://registry-1.docker.io")), ca, CAHost{Base: testBase, Home: home, Root: home, GOOS: OSLinux})
	if err == nil || len(in.Changes) != 0 {
		t.Errorf("unloadable version 2 CRI policy accepted: err=%v changes=%d", err, len(in.Changes))
	}
}

// TestContainerdCRITablesDecodeAsContainerdDoes pins what makes containerd
// v2.2.0 serve no CRI pull for each config.toml format: a wrong type or a
// refused value in the image, runtime or CRI plugin's table, read from the
// one table versions 1 and 2 keep them in as its migration moves the keys.
func TestContainerdCRITablesDecodeAsContainerdDoes(t *testing.T) {
	const v2 = "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\"]\n"
	const v3 = "version = 3\n"
	for name, tc := range map[string]struct{ body, invalid, err string }{
		"v2 as kubeadm writes it": {body: v2 + "sandbox_image = \"registry.k8s.io/pause:3.10\"\nmax_concurrent_downloads = 3\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n" +
			"[plugins.\"io.containerd.grpc.v1.cri\".containerd]\nsnapshotter = \"overlayfs\"\ndefault_runtime_name = \"runc\"\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]\nruntime_type = \"io.containerd.runc.v2\"\nsandbox_mode = \"podsandbox\"\n" +
			"[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc.options]\nSystemdCgroup = true\n[plugins.\"io.containerd.grpc.v1.cri\".cni]\nbin_dir = \"/opt/cni/bin\"\n"},
		"v1 as containerd 1.x wrote it": {body: "[plugins.cri]\nstream_server_port = \"0\"\n[plugins.cri.registry]\nconfig_path = \"/etc/containerd/certs.d\"\n"},
		"v1 image key":                  {body: "[plugins.cri]\nmax_concurrent_downloads = \"three\"\n", invalid: "what it migrates its version 1 CRI table into"},
		"v2 image duration":             {body: v2 + "image_pull_progress_timeout = \"soon\"\n", invalid: "invalid image pull progress timeout"},
		"v2 runtime key":                {body: v2 + "enable_selinux = \"yes\"\n", invalid: "CRI runtime plugin"},
		"v2 server duration":            {body: v2 + "stream_idle_timeout = \"soon\"\n", invalid: "invalid stream idle timeout"},
		"v2 moved key":                  {body: v2 + "sandbox_image = 5\n", invalid: "what it migrates its version 2 CRI table into"},
		"v2 containerd not a table":     {body: v2 + "containerd = \"runc\"\n", invalid: "what it migrates"},
		"v2 default runtime undefined":  {body: v2 + "[plugins.\"io.containerd.grpc.v1.cri\".containerd]\ndefault_runtime_name = \"kata\"\n", invalid: "no corresponding runtime configured"},
		"v2 default runtime defined":    {body: v2 + "[plugins.\"io.containerd.grpc.v1.cri\".containerd]\ndefault_runtime_name = \"kata\"\n[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.kata]\nruntime_type = \"io.containerd.kata.v2\"\n"},
		"v2 default runtime, imports":   {body: "imports = [\"/etc/containerd/conf.d/*.toml\"]\n" + v2 + "[plugins.\"io.containerd.grpc.v1.cri\".containerd]\ndefault_runtime_name = \"kata\"\n"},
		"v2 beside a v3 table":          {body: v2 + "[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/x\"\n", err: "does not follow that merge"},
		"v1 beside the long name":       {body: "[plugins.cri]\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/x\"\n", err: "does not follow that merge"},
		"v3 runtime key":                {body: v3 + "[plugins.\"io.containerd.cri.v1.runtime\"]\nmax_container_log_line_size = \"big\"\n", invalid: "CRI runtime plugin"},
		"v3 runtime io_type":            {body: v3 + "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc]\nio_type = \"pipe\"\n", invalid: "`io_type` can only be"},
		"v3 cgroup_writable":            {body: v3 + "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc]\ncgroup_writable = true\n", invalid: "doctor does not interpret"},
		"v3 server key":                 {body: v3 + "[plugins.\"io.containerd.grpc.v1.cri\"]\ndisable_tcp_service = \"no\"\n", invalid: "CRI plugin"},
		"v3 stream key without TLS":     {body: v3 + "[plugins.\"io.containerd.grpc.v1.cri\".x509_key_pair_streaming]\ntls_cert_file = \"/c.pem\"\n", invalid: "EnableTLSStreaming is not set"},
		"v3 legacy keys are unknown":    {body: v3 + "[plugins.\"io.containerd.grpc.v1.cri\"]\nsandbox_image = 5\nmax_concurrent_downloads = \"three\"\n"},
		"v3 as containerd 2.x writes":   {body: v3 + "[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc.options]\nSystemdCgroup = true\n"},
	} {
		r, err := ReadContainerdConfig([]byte(tc.body))
		switch {
		case tc.err != "":
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err = %v; want one naming %q", name, err, tc.err)
			}
		case err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.invalid == "" && r.Invalid != "":
			t.Errorf("%s: refused a configuration containerd starts its CRI plugins on: %s", name, r.Invalid)
		case !strings.Contains(r.Invalid, tc.invalid):
			t.Errorf("%s: Invalid = %q; want %q", name, r.Invalid, tc.invalid)
		}
	}
}

// TestPipIndexPolicyFollowsPipOrder pins which no-index pip install runs
// with, by pip's own order of [global], [install] and the environment, and
// that the pypi-url alias is reported wherever it is set.
func TestPipIndexPolicyFollowsPipOrder(t *testing.T) {
	layer := func(body string) []PipLayer { return []PipLayer{{File: "pip.conf", Data: []byte(body)}} }
	env := func(kv ...string) func(string) string {
		return func(key string) string {
			for i := 0; i < len(kv); i += 2 {
				if kv[i] == key {
					return kv[i+1]
				}
			}
			return ""
		}
	}
	for name, tc := range map[string]struct {
		body   string
		getenv func(string) string
		want   string
	}{
		"unset":                        {body: "[global]\nindex-url = https://x/simple/\n"},
		"global":                       {body: "[global]\nno-index = true\n", want: "[global]"},
		"global spelled as pip folds":  {body: "[global]\n--No_Index = YES\n", want: "[global]"},
		"install replaces global":      {body: "[global]\nno-index = true\n[install]\nno-index = false\n"},
		"install sets it":              {body: "[global]\nno-index = 0\n[install]\nno-index = on\n", want: "[install]"},
		"another command's section":    {body: "[download]\nno-index = true\n"},
		"environment replaces a file":  {body: "[install]\nno-index = true\n", getenv: env("PIP_NO_INDEX", "0")},
		"environment sets it":          {body: "[global]\nno-index = false\n", getenv: env("PIP_NO_INDEX", "1"), want: "PIP_NO_INDEX"},
		"an empty variable is not set": {body: "[global]\nno-index = true\n", getenv: env("PIP_NO_INDEX", ""), want: "[global]"},
	} {
		if got := PipNoIndex(layer(tc.body), tc.getenv); (got == "") != (tc.want == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: PipNoIndex = %q; want one naming %q", name, got, tc.want)
		}
	}
	later := []PipLayer{{File: "a.conf", Data: []byte("[global]\nno-index = true\n")}, {File: "b.conf", Data: []byte("[global]\nno-index = false\n")}}
	if got := PipNoIndex(later, nil); got != "" {
		t.Errorf("a later file's value did not replace an earlier one's: %q", got)
	}
	for name, tc := range map[string]struct {
		body   string
		getenv func(string) string
		want   string
	}{
		"unset":       {body: "[global]\nindex-url = https://x/simple/\n"},
		"global":      {body: "[global]\npypi-url = https://x/simple/\n", want: "[global]"},
		"install":     {body: "[install]\nPyPI_URL = https://x/simple/\n", want: "[install]"},
		"environment": {body: "", getenv: env("PIP_PYPI_URL", "https://x/simple/"), want: "PIP_PYPI_URL"},
	} {
		if got := PipIndexAlias(layer(tc.body), tc.getenv); (got == "") != (tc.want == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: PipIndexAlias = %q; want one naming %q", name, got, tc.want)
		}
	}
}

// TestPipIndexPolicyMatchesNativePip holds PipNoIndex and PipIndexAlias
// against pip install's own choice of indexes: pip download prints "Looking
// in indexes" with each index it is about to ask and nothing of the kind
// under no-index, and an index set through pypi-url is one it names there.
func TestPipIndexPolicyMatchesNativePip(t *testing.T) {
	python := nativePip261(t)
	const index, alias = "http://127.0.0.1:9/index/", "http://127.0.0.1:9/alias/"
	for name, tc := range map[string]struct {
		body string
		env  []string
	}{
		"plain":               {body: "[global]\nindex-url = " + index + "\n"},
		"global no-index":     {body: "[global]\nindex-url = " + index + "\nno-index = true\n"},
		"install overrides":   {body: "[global]\nindex-url = " + index + "\nno-index = true\n[install]\nno-index = false\n"},
		"environment sets":    {body: "[global]\nindex-url = " + index + "\n", env: []string{"PIP_NO_INDEX=1"}},
		"environment unsets":  {body: "[global]\nindex-url = " + index + "\nno-index = true\n", env: []string{"PIP_NO_INDEX=0"}},
		"alias":               {body: "[global]\npypi-url = " + alias + "\n"},
		"alias after index":   {body: "[global]\nindex-url = " + index + "\npypi-url = " + alias + "\n"},
		"alias from the env":  {body: "[global]\nindex-url = " + index + "\n", env: []string{"PIP_PYPI_URL=" + alias}},
		"download's own bool": {body: "[global]\nindex-url = " + index + "\n[download]\nno-index = true\n"},
	} {
		home := t.TempDir()
		file := filepath.Join(home, "pip.conf")
		if err := os.WriteFile(file, []byte(tc.body), 0600); err != nil {
			t.Fatal(err)
		}
		// pip install and pip download share the index options; install is
		// what the configuration is judged for, so its section is read.
		cmd := exec.Command(python, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--no-deps", "--no-cache-dir", "--disable-pip-version-check", "--retries", "0", "--timeout", "1", "--target", filepath.Join(home, "t"), "bodega-ca-audit-does-not-exist==1.0.0")
		cmd.Dir = home
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "PIP_CONFIG_FILE=" + file}, tc.env...)
		out, _ := cmd.CombinedOutput()
		getenv := func(key string) string {
			for _, kv := range tc.env {
				if k, v, _ := strings.Cut(kv, "="); k == key {
					return v
				}
			}
			return ""
		}
		layers := []PipLayer{{File: file, Data: []byte(tc.body)}}
		if native, got := !strings.Contains(string(out), "Looking in indexes"), PipNoIndex(layers, getenv) != ""; native != got {
			t.Errorf("%s: PipNoIndex says pip asks no index = %v, native pip = %v: %s", name, got, native, strings.TrimSpace(string(out)))
		}
		if native, got := strings.Contains(string(out), alias), PipIndexAlias(layers, getenv) != ""; native && !got {
			t.Errorf("%s: native pip asks the index pypi-url names and PipIndexAlias reports none: %s", name, strings.TrimSpace(string(out)))
		}
	}
}

// TestHelmEntryMovedToBodegaKeepsItsPairObligation covers the entry a plan
// moves to bodega from another URL: it keeps the certFile and keyFile it had,
// helm loads them with the caFile the install adds, and a pair that does not
// load is refused before anything is written.
func TestHelmEntryMovedToBodegaKeepsItsPairObligation(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	target := filepath.Join(home, ".config/helm/repositories.yaml")
	body := "repositories:\n- name: bodega\n  url: https://old.example/helm\n  certFile: " + filepath.Join(home, "missing.crt") + "\n  keyFile: " + filepath.Join(home, "missing.key") + "\n"
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	in, err := AddCA(caPlan(t, home, Helm(testBase)), ca, CAHost{Base: testBase, Home: home, Root: home, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")})
	if err == nil || !strings.Contains(err.Error(), "unable to read cert file") || len(in.Changes) != 0 || len(in.Step) != 0 {
		t.Errorf("a moved entry's unloadable pair was accepted: err=%v changes=%d step=%v", err, len(in.Changes), in.Step)
	}
}

func TestAudit26NpmSectionValueMatchesNativeNpm(t *testing.T) {
	npm := nativeNpm1120(t)
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	file := filepath.Join(home, ".npmrc")
	body := "registry=" + testBase + "/npm/\n[ca]\nx=1\n"
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(npm, "view", "left-pad", "--registry=https://127.0.0.1:1/", "--fetch-retries=0", "--fetch-timeout=1000", "--loglevel=error")
	cmd.Dir = home
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "NPM_CONFIG_USERCONFIG=" + file, "NPM_CONFIG_GLOBALCONFIG=" + filepath.Join(home, "empty-global")}
	out, nativeErr := cmd.CombinedOutput()
	if nativeErr == nil || !strings.Contains(string(out), "Cannot convert object to primitive value") {
		t.Fatalf("native npm control: %v: %s", nativeErr, out)
	}
	t.Logf("npm 11.20.0: %v: %s", nativeErr, out)
	in, err := AddCA(caPlan(t, home, Npm(testBase, nil)), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux})
	if err == nil || len(in.Changes) != 0 {
		t.Errorf("AddCA accepted npm's fatal nested ca: err=%v changes=%d", err, len(in.Changes))
	}
}

func TestAudit26MissingHelmOracleFailsInCI(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestHelmFileLoadsAsHelmLoadsIt$", "-test.v")
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "PATH=") && !strings.HasPrefix(e, "CI=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "CI=true", "PATH="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("missing native Helm passed CI:\n%s", out)
	}
}

// F116 R1, R2: npmDefined is the option list of the npm the port is of.
func TestNpmDefinedOptionsMatchNativeNpm(t *testing.T) {
	npm := oracletest.Npm(t)
	home := t.TempDir()
	cmd := exec.Command(npm, "config", "ls", "-l", "--json")
	cmd.Dir = home
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "NPM_CONFIG_USERCONFIG=" + filepath.Join(home, "no-user"), "NPM_CONFIG_GLOBALCONFIG=" + filepath.Join(home, "no-global")}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("npm config ls -l --json: %v", err)
	}
	var native map[string]any
	if err := json.Unmarshal(out, &native); err != nil {
		t.Fatal(err)
	}
	for name := range native {
		if !npmDefined[name] {
			t.Errorf("npm defines %s, which npmDefined lacks", name)
		}
	}
	for name := range npmDefined {
		if _, ok := native[name]; !ok {
			t.Errorf("npmDefined holds %s, which npm does not define", name)
		}
	}
}

// F116 R1, R2: the one npm decoder reads what a section header or a dotted
// null builds the way npm/ini does. Native npm is the oracle: on each file
// it either reaches the request, which nothing answers, or stops before it,
// and the decoder names a line exactly where npm stops. Where the decoder
// refuses more than npm stops on, the case says so.
func TestNpmObjectLinesMatchNativeNpm(t *testing.T) {
	npm := oracletest.Npm(t)
	for _, tc := range []struct {
		body string
		// stricter is a file the decoder refuses and this npm command runs
		// on: an object npm reads only for another package or command.
		stricter bool
	}{
		{body: "[ca]\nx=1\n"},
		{body: "[\"ca\"]\nx=1\n"},
		{body: "[cafile]\n"},
		{body: "[registry.x]\n"},
		{body: "ca.x=null\n"},
		{body: "[corp]\nx=1\n[ca]\ny=1\n"},
		{body: "[corp]\nx=1\n"},
		{body: "[corp]\ncafile=/x\nca.x=null\n"},
		{body: "[corp.ca]\nx=1\n"},
		{body: "[__proto__]\nca=1\n"},
		{body: "corp=1\n[corp]\nx=1\n"},
		{body: "corp.ca=null\n"},
		{body: "[//h.example/]\nx=1\n"},
		{body: "[@corp:registry]\nx=1\n", stricter: true},
		{body: "[${F116_SECTION}]\nx=1\n", stricter: true},
	} {
		file := filepath.Join(t.TempDir(), "npmrc")
		if err := os.WriteFile(file, []byte("fetch-timeout=1000\n"+tc.body), 0600); err != nil {
			t.Fatal(err)
		}
		out := runNpmView(t, npm, file, nil)
		reached := strings.Contains(out, "ECONNREFUSED")
		refused := NpmUnclassified(file)
		switch {
		case !reached && refused == "":
			t.Errorf("%q: npm stops before the request and the decoder names no line:\n%s", tc.body, out)
		case reached && refused != "" && !tc.stricter:
			t.Errorf("%q: npm reaches the request and the decoder refuses it: %s", tc.body, refused)
		case tc.stricter && (!reached || refused == ""):
			t.Errorf("%q: want npm running and the decoder refusing; reached=%v refused=%q", tc.body, reached, refused)
		}
	}
}

func TestAudit27ContainerdStartupObligations(t *testing.T) {
	for name, extra := range map[string]string{
		"missing required plugin": "required_plugins = [\"io.containerd.audit.v1.missing\"]\n",
		"metadata plugin type":    "[plugins.\"io.containerd.metadata.v1.bolt\"]\ncontent_sharing_policy = 42\n",
	} {
		t.Run(name, func(t *testing.T) {
			raw := []byte("version = 3\n" + extra + "[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n")
			eff, err := ResolveContainerdConfig("", filepath.Join(t.TempDir(), "config.toml"), raw)
			if err == nil && eff.Invalid == "" && !eff.CRIDisabled {
				t.Errorf("accepted a parent policy containerd cannot start: config_path=%q", eff.ConfigPath)
			}
		})
	}
}

func TestAudit27HelmNullEntryMatchesNative(t *testing.T) {
	helm := oracletest.Helm(t)
	home := t.TempDir()
	file := filepath.Join(home, "repositories.yaml")
	body := "repositories:\n- null\n- name: bodega\n  url: https://127.0.0.1:1/helm\n"
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(helm, "repo", "update", "audit-nonexistent", "--repository-config", file)
	cmd.Dir = home
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "HELM_REPOSITORY_CONFIG=" + file}
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "invalid memory address or nil pointer dereference") {
		t.Fatalf("native control: %v: %s", err, out)
	}
	t.Logf("Helm v4.3.0: %v: %s", err, out)
	if _, err := LoadHelmFile(file); err == nil {
		t.Error("accepted a repository file that aborts Helm before any request")
	}
}

// F116 R1, R2: refusing a file helm cannot start on must not refuse the file
// helm itself writes. Helm v4.3.0 adds a repository against a local index, and
// what it wrote loads.
func TestHelmRepoAddFileIsAccepted(t *testing.T) {
	helm := oracletest.Helm(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index.yaml" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("apiVersion: v1\nentries: {}\ngenerated: \"2026-01-01T00:00:00Z\"\n"))
	}))
	defer srv.Close()
	home := t.TempDir()
	file := filepath.Join(home, "repositories.yaml")
	cmd := exec.Command(helm, "repo", "add", "bodega", srv.URL, "--repository-config", file, "--repository-cache", filepath.Join(home, "cache"))
	cmd.Dir = home
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helm repo add: %v: %s", err, out)
	}
	doc, err := LoadHelmFile(file)
	if err != nil {
		t.Fatalf("refused the file helm repo add wrote: %v", err)
	}
	if len(doc.Repositories) != 1 || doc.Repositories[0].Name != "bodega" || doc.Repositories[0].URL != srv.URL {
		written, _ := os.ReadFile(file)
		t.Errorf("read %+v from:\n%s", doc.Repositories, written)
	}
}

func TestAudit28ContainerdOperationValidity(t *testing.T) {
	for name, extra := range map[string]string{
		"metadata policy":     "[plugins.\"io.containerd.metadata.v1.bolt\"]\ncontent_sharing_policy = \"audit-unknown\"\n",
		"missing snapshotter": "[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = \"audit-missing\"\n",
		"runtime platform":    "[plugins.\"io.containerd.cri.v1.images\".runtime_platforms.runc]\nplatform = \"linux/amd64/bad/extra\"\n",
		"debug level":         "[debug]\nlevel = \"audit-unknown\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if name != "missing snapshotter" {
				extra = "[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = \"native\"\n" + extra
			}
			raw := []byte("version = 3\nrequired_plugins = [\"io.containerd.cri.v1.images\"]\n" + extra + "[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n")
			eff, err := ResolveContainerdConfig("", filepath.Join(t.TempDir(), "config.toml"), raw)
			if err == nil && eff.Invalid == "" && !eff.CRIDisabled {
				t.Errorf("accepted a parent policy containerd cannot start: config_path=%q", eff.ConfigPath)
			}
		})
	}
}

func TestAudit29ContainerdComposedStartupValidity(t *testing.T) {
	for name, tc := range map[string]struct{ snapshotter, extra string }{
		"unconfigured snapshotter": {"devmapper", ""},
		"two content providers": {
			"native", "[proxy_plugins.audit-content]\ntype = \"content\"\naddress = \"/tmp/audit-content.sock\"\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.toml")
			conf := "version = 3\nrequired_plugins = [\"io.containerd.cri.v1.images\"]\n[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = \"native\"\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n" + tc.extra
			conf = strings.ReplaceAll(conf, "snapshotter = \"native\"", "snapshotter = \""+tc.snapshotter+"\"")

			eff, err := ResolveContainerdConfig("", file, []byte(conf))
			if err == nil && eff.Invalid == "" && !eff.CRIDisabled {
				t.Errorf("accepted a composed configuration containerd v2.2.0 cannot start: config_path=%q", eff.ConfigPath)
			}
		})
	}
}

func TestAudit30ContainerdComposedStartupValidity(t *testing.T) {
	for name, tc := range map[string]struct{ snapshotter, extra string }{
		"no implicit differ for platform": {"native", "[[plugins.\"io.containerd.transfer.v1.local\".unpack_config]]\nplatform = \"windows/amd64\"\nsnapshotter = \"native\"\n"},
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.toml")
			conf := "version = 3\nrequired_plugins = [\"io.containerd.cri.v1.images\"]\n[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = \"native\"\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n" + tc.extra
			conf = strings.ReplaceAll(conf, "snapshotter = \"native\"", "snapshotter = \""+tc.snapshotter+"\"")

			eff, err := ResolveContainerdConfig("", file, []byte(conf))
			if err == nil && eff.Invalid == "" && !eff.CRIDisabled {
				t.Errorf("accepted a composed configuration containerd v2.2.0 cannot start: config_path=%q", eff.ConfigPath)
			}
		})
	}
}

func TestAudit31ContainerdComposedStartupValidity(t *testing.T) {
	for name, tc := range map[string]struct{ snapshotter, extra string }{
		"CRI server rejects stream port": {"native", "[plugins.\"io.containerd.grpc.v1.cri\"]\nstream_server_address = \"127.0.0.1\"\nstream_server_port = \"65536\"\n"},
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.toml")
			conf := "version = 3\nrequired_plugins = [\"io.containerd.cri.v1.images\"]\n[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = \"native\"\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n" + tc.extra
			conf = strings.ReplaceAll(conf, "snapshotter = \"native\"", "snapshotter = \""+tc.snapshotter+"\"")

			eff, err := ResolveContainerdConfig("", file, []byte(conf))
			if err == nil && eff.Invalid == "" && !eff.CRIDisabled {
				t.Errorf("accepted a composed configuration containerd v2.2.0 cannot start: config_path=%q", eff.ConfigPath)
			}
		})
	}
}

func TestAudit32ContainerdComposedStartupValidity(t *testing.T) {
	for name, tc := range map[string]struct{ snapshotter, extra string }{
		"command rejects grpc listener":    {"native", "[grpc]\ntcp_address = \"127.0.0.1:65536\"\n"},
		"command rejects metrics listener": {"native", "[metrics]\naddress = \"127.0.0.1:65536\"\n"},
		"command rejects debug listener":   {"native", "[debug]\naddress = \"127.0.0.1:65536\"\n"},
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.toml")
			conf := "version = 3\nrequired_plugins = [\"io.containerd.cri.v1.images\"]\n[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = \"native\"\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n" + tc.extra
			conf = strings.ReplaceAll(conf, "snapshotter = \"native\"", "snapshotter = \""+tc.snapshotter+"\"")

			eff, err := ResolveContainerdConfig("", file, []byte(conf))
			if err == nil && eff.Invalid == "" && !eff.CRIDisabled {
				t.Errorf("accepted a composed configuration containerd v2.2.0 cannot start: config_path=%q", eff.ConfigPath)
			}
		})
	}
}

func TestAudit33ContainerdProxyConstructionValidity(t *testing.T) {
	for name, tc := range map[string]struct{ snapshotter, extra string }{
		"proxy constructor rejects address":           {"audit", "[proxy_plugins.audit]\ntype = \"snapshot\"\naddress = \"/run/a%zz.sock\"\n"},
		"collected proxy constructor rejects address": {"native", "[proxy_plugins.audit]\ntype = \"snapshot\"\naddress = \"/run/a%zz.sock\"\n"},
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.toml")
			conf := "version = 3\nrequired_plugins = [\"io.containerd.cri.v1.images\"]\n[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = \"native\"\n[plugins.\"io.containerd.cri.v1.images\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n" + tc.extra
			conf = strings.ReplaceAll(conf, "snapshotter = \"native\"", "snapshotter = \""+tc.snapshotter+"\"")

			eff, err := ResolveContainerdConfig("", file, []byte(conf))
			if err == nil && eff.Invalid == "" && !eff.CRIDisabled {
				t.Errorf("accepted a composed configuration containerd v2.2.0 cannot start: config_path=%q", eff.ConfigPath)
			}
		})
	}
}

// TestGitHTTPKeysAreModeledOrAtDefault holds the Git reader to one rule:
// every http variable git reads is on gitHTTPModeled or gitHTTPUnmodeled and
// never both, and a variable on the second passes GitLoadError only at git's
// default. A non-default value refuses, in [http] and under a URL, naming the
// file, the section and the variable.
func TestGitHTTPKeysAreModeledOrAtDefault(t *testing.T) {
	for name := range gitHTTPVars {
		_, unmodeled := gitHTTPUnmodeled[name]
		if modeled := slices.Contains(gitHTTPModeled, name); modeled == unmodeled {
			t.Errorf("http.%s: on the modeled list %v and on the unmodeled list %v; want exactly one", name, modeled, unmodeled)
		}
	}
	for _, name := range gitHTTPModeled {
		if _, ok := gitHTTPVars[name]; !ok {
			t.Errorf("gitHTTPModeled holds %s, which http_options does not read", name)
		}
	}
	dir := t.TempDir()
	load := func(body string) (string, string) {
		file := filepath.Join(dir, "gitconfig")
		if err := os.WriteFile(file, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return file, GitLoadError([]string{file})
	}
	const scope = `[http "https://bodega.example.com/"]`
	for name, d := range gitHTTPUnmodeled {
		if _, ok := gitHTTPVars[name]; !ok {
			t.Errorf("gitHTTPUnmodeled holds %s, which http_options does not read", name)
		}
		set, unset := "/etc/x", ""
		switch {
		case d.isBool:
			set, unset = strconv.FormatBool(!d.value), strconv.FormatBool(d.value)
		case name == "sslversion":
			set = "tlsv1.3"
		}
		for _, header := range []string{"[http]", scope} {
			body := "[user]\n\tname = Kept\n" + header + "\n\tsslCAInfo = /etc/ca.pem\n\t" + name + " = " + set + "\n"
			file, got := load(body)
			for _, want := range []string{file + " (line 5: ", "'http." + name + "'", "the section " + header} {
				if !strings.Contains(got, want) {
					t.Errorf("%s under %s set to %q: GitLoadError = %q; want it to name %q", name, header, set, got, want)
				}
			}
			if !d.isBool && !d.emptyIsUnset {
				continue
			}
			if _, got := load(header + "\n\t" + name + " = " + unset + "\n"); got != "" {
				t.Errorf("%s under %s at git's default %q is refused: %s", name, header, unset, got)
			}
		}
	}
	// A boolean with no = is true, which is the default of one and not of the other.
	if _, got := load("[http]\n\tsslVerify\n"); got != "" {
		t.Errorf("a bare http.sslVerify is true, git's default, and is refused: %s", got)
	}
	if _, got := load("[http]\n\tsslCertPasswordProtected\n"); !strings.Contains(got, "'http.sslcertpasswordprotected'") {
		t.Errorf("a bare http.sslCertPasswordProtected is true and passes: %q", got)
	}
	// A later assignment at the default does not clear an earlier one doctor cannot follow.
	if _, got := load("[http]\n\tsslVerify = false\n\tsslVerify = true\n"); !strings.Contains(got, "line 2: 'http.sslverify'") {
		t.Errorf("an sslVerify = false ahead of a later true passes: %q", got)
	}
	// What bodega writes, beside settings that leave the handshake alone, stays accepted.
	ok := "[url \"https://bodega.example.com/git/\"]\n\tinsteadOf = https://github.com/\n" + scope + "\n\tsslCAInfo = /home/u/.config/bodega/ca.pem\n" +
		"[http]\n\tpostBuffer = 512m\n\tproxy = http://proxy.example:3128\n\tuserAgent = x\n\textraHeader = X-A: b\n\tsslVerify = yes\n\tsslVersion =\n\tnoSuchKey = 1\n"
	if _, got := load(ok); got != "" {
		t.Errorf("a configuration that sets bodega's URL and CA is refused: %s", got)
	}
}
