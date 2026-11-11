package clientconf

import (
	"bytes"
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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"gopkg.in/yaml.v3"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/distinfo"
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

// F116 R1: Maven's CA goes into the JVM trust store, one keytool import per
// certificate that store lacks, each reading a file the plan writes; a store
// already holding the CA takes no import, and a keystore the JVM is pointed
// at is the one edited.
func TestAddCAImportsIntoTheJVMTrustStore(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	otherPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(append(slices.Clone(caPEM), otherPEM...))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	// macOS, where no system store install exists: Maven needs none.
	h := CAHost{Base: testBase, Home: home, GOOS: OSDarwin, JVM: JVMStore{Keytool: "/jdk/bin/keytool"}}
	in, err := AddCA(caPlan(t, home, Maven(testBase, nil)...), ca, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Imports) != 2 || in.Step != nil || !strings.Contains(in.Notes[manifest.TypeMaven], "gradle --stop") {
		t.Fatalf("imports = %v, step %v, notes %v; want one import per certificate, no system step and the daemon note", in.Imports, in.Step, in.Notes)
	}
	for i, cmd := range in.Imports {
		alias, file := cmd[len(cmd)-3], cmd[len(cmd)-1]
		want := []string{"/jdk/bin/keytool", "-importcert", "-noprompt", "-trustcacerts", "-cacerts", "-storepass", "changeit", "-alias", alias, "-file", file}
		if !slices.Equal(cmd, want) || !strings.HasPrefix(alias, "bodega-ca-") || filepath.Dir(file) != filepath.Join(home, ".config/bodega") {
			t.Errorf("import %d = %v", i, cmd)
		}
		// What keytool reads is what the plan writes: one certificate.
		if got := changeAt(t, in.Changes, file); string(got.New) != string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certs[i].Raw})) {
			t.Errorf("%s = %s, want certificate %d alone", file, got.New, i+1)
		}
	}
	if in.Imports[0][8] == in.Imports[1][8] {
		t.Errorf("two certificates share the alias %s", in.Imports[0][8])
	}

	// A failed import leaves the file written and the store without the CA:
	// the import is planned again. Once the store holds both, nothing is.
	if _, err := Apply(in.Changes, ".bak"); err != nil {
		t.Fatal(err)
	}
	h.JVMTrusted = ca.Certs[:1]
	retry, err := AddCA(caPlan(t, home, Maven(testBase, nil)...), ca, h)
	if err != nil || len(retry.Imports) != 1 || retry.Imports[0][8] != in.Imports[1][8] {
		t.Errorf("retry with one certificate imported = %v, %v; want the other's import alone", retry.Imports, err)
	}
	h.JVMTrusted = ca.Certs
	done, err := AddCA(caPlan(t, home, Maven(testBase, nil)...), ca, h)
	if err != nil || len(done.Imports) != 0 || len(done.Notes) != 0 {
		t.Errorf("a store holding the CA = imports %v, notes %v, %v; want none", done.Imports, done.Notes, err)
	}
	for _, c := range done.Changes {
		if !c.Unchanged() {
			t.Errorf("a store holding the CA still changes %s", c.Target)
		}
	}
}

// F116 R1: the JVM store is the JDK at JAVA_HOME's, or the keystore
// MAVEN_OPTS points the JVM at, and a password an operator set is not printed.
func TestResolveJVMStore(t *testing.T) {
	env := map[string]string{"JAVA_HOME": "/opt/jdk"}
	getenv := func(k string) string { return env[k] }
	none := func(string) (string, error) { return "", os.ErrNotExist }
	s, err := ResolveJVMStore(getenv, none)
	if err != nil || s.Keytool != "/opt/jdk/bin/keytool" || !slices.Contains(s.ImportCommand("a", "f"), "-cacerts") {
		t.Errorf("JAVA_HOME = %+v, %v", s, err)
	}
	env["JAVA_TOOL_OPTIONS"] = "-Djavax.net.ssl.trustStore=/etc/a.jks"
	env["MAVEN_OPTS"] = "-Xmx1g -Djavax.net.ssl.trustStore=/etc/b.p12 -Djavax.net.ssl.trustStorePassword=hunter2"
	s, _ = ResolveJVMStore(getenv, none)
	cmd := s.ImportCommand("a", "f")
	if s.Keystore != "/etc/b.p12" || slices.Contains(cmd, "-cacerts") || !slices.Contains(cmd, "hunter2") {
		t.Errorf("MAVEN_OPTS keystore = %+v, %v", s, cmd)
	}
	if shown := RedactJVMCommand(cmd); strings.Contains(shown, "hunter2") || !strings.Contains(shown, "-keystore /etc/b.p12") {
		t.Errorf("printed command = %q", shown)
	}
	delete(env, "JAVA_HOME")
	if _, err := ResolveJVMStore(getenv, none); err == nil || !strings.Contains(err.Error(), "JAVA_HOME") {
		t.Errorf("no keytool and no JAVA_HOME = %v, want a refusal naming JAVA_HOME", err)
	}
	caPEM, _, _ := testCA(t, "bodega.example.com")
	if got := ParseKeytoolList(append([]byte("Alias name: x\nnot a cert\n"), caPEM...)); len(got) != 1 {
		t.Errorf("ParseKeytoolList = %d certificates, want 1", len(got))
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

func TestReviewMavenCAPlansTrustInstallation(t *testing.T) {
	pem, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(pem)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	plan := caPlan(t, home, Maven(testBase, nil)...)
	in, err := AddCA(plan, ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")})
	if err != nil {
		t.Fatal(err)
	}
	changed := len(in.Changes) != len(plan) || len(in.Step) > 0
	for i := range plan {
		changed = changed || string(plan[i].New) != string(in.Changes[i].New)
	}
	if !changed {
		t.Fatalf("--ca-file added no trust write or step; only notes: %v", in.Notes)
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
		{"cargo", Cargo(testBase), "[build]\njobs = 7\n", "jobs = 7"},
		{"podman", RegistriesConf(testBase, []string{"docker.io"}), "unqualified-search-registries = [\"registry.corp.example\"]\n", "unqualified-search-registries"},
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

func TestAuditJVMSelectsJSSEStore(t *testing.T) {
	home := t.TempDir()
	jsse := filepath.Join(home, "lib/security/jssecacerts")
	if err := os.MkdirAll(filepath.Dir(jsse), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsse, []byte("store fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := ResolveJVMStore(func(k string) string {
		if k == "JAVA_HOME" {
			return home
		}
		return ""
	}, func(string) (string, error) { return "", os.ErrNotExist })
	if err != nil {
		t.Fatal(err)
	}
	if s.Keystore != jsse || slices.Contains(s.ImportCommand("bodega", "ca.pem"), "-cacerts") {
		t.Fatalf("JSSE store exists, but resolved store=%q and import=%v; want %s", s.Keystore, s.ImportCommand("bodega", "ca.pem"), jsse)
	}
}

//nolint:gosec // G101: the review's fixture password, set only in this test's environment
func TestAuditJVMErrorsDoNotPrintTrustStorePassword(t *testing.T) {
	const secret = "audit-only-keystore-password"
	t.Setenv("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStorePassword="+secret)
	keytool := filepath.Join(t.TempDir(), "keytool")
	script := "#!/bin/sh\nprintf '%s\\n' \"Picked up JAVA_TOOL_OPTIONS: $JAVA_TOOL_OPTIONS\"\nexit 1\n"
	if err := os.WriteFile(keytool, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := (JVMStore{Keytool: keytool, Password: secret}).Trusted()
	if err == nil {
		t.Fatal("fixture command must fail")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("keytool failure leaked trustStorePassword: %v", err)
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
	gems := Rubygems(testBase)
	git := Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}})
	pkgConf := "# bodega pkg repository. Install as x.\n# written for FreeBSD 15\n\nFreeBSD: { enabled: no }\n\nbodega: {\n  url: \"" + testBase + "/freebsd/${ABI}\",\n  enabled: yes\n}\n"
	for _, tc := range []struct {
		name   string
		file   File
		before string
		// keep stays, want arrives and gone leaves.
		keep, want, gone []string
	}{
		{"gemrc", gems[0], "---\n# house style\ngem: --no-document\n:sources:\n- https://rubygems.org/\n",
			[]string{"# house style", "gem: --no-document"}, []string{"- " + testBase + "/rubygems/"}, []string{"rubygems.org"}},
		{"bundler", gems[1], "---\nBUNDLE_JOBS: \"4\"\n", []string{"BUNDLE_JOBS"}, []string{"BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/"}, nil},
		{"helm", Helm(testBase), "apiVersion: \"\"\ngenerated: \"0001-01-01T00:00:00Z\"\nrepositories:\n  - name: corp\n    url: https://charts.corp.example\n  - name: bodega\n    url: https://old.example/helm\n",
			[]string{"name: corp", "url: https://charts.corp.example"}, []string{testBase + "/helm"}, []string{"old.example"}},
		{"apt", AptArchive(testBase, "noble", nil), "Types: deb\nURIs: https://corp.example/apt\nSuites: stable\nComponents: main\n\n# ours\nTypes: deb\nURIs: " + testBase + "/apt/\nSuites: noble\nComponents: main\nTrusted: yes\n",
			[]string{"URIs: https://corp.example/apt", "Suites: stable"}, []string{"Suites: noble", "Signed-By: "}, []string{"Components: main\nTrusted", "Trusted: yes"}},
		{"pkg", at(File{System: manifest.TypeFreeBSD, Content: pkgConf}, pkgrepos.ClientConfPath),
			"# bodega pkg repository. Install as x.\n# written for FreeBSD 14\n\ncorp: {\n  url: \"https://pkg.corp.example\", # {\n  enabled: yes\n}\nbodega: { url: \"https://old.example\" }\n",
			[]string{"corp: {", "https://pkg.corp.example"}, []string{"written for FreeBSD 15", "FreeBSD: { enabled: no }", testBase + "/freebsd/${ABI}"}, []string{"old.example", "FreeBSD 14"}},
		{"make.conf", at(MakeConf(testBase), "/etc/make.conf"), "WITH_PKGNG=yes\nMASTER_SITE_OVERRIDE= https://old.example/ \\\n\thttps://older.example/\n.include \"" + DistfilesCheckPath + "\"\nCFLAGS+= -O2\n",
			[]string{"WITH_PKGNG=yes", "CFLAGS+= -O2"}, []string{"MASTER_SITE_OVERRIDE?= " + testBase, "MASTER_SITE_BACKUP?= ", "CFLAGS+= -O2\n.include \"" + DistfilesCheckPath + "\"\n"}, []string{"old.example", "older.example"}},
		{"dnf", Rpm(testBase, []string{"baseos"}), "[bodega-baseos]\nname=old\nbaseurl=https://old.example/a\n    https://old.example/b\nproxy=http://proxy.corp.example\n\n[corp]\nbaseurl=https://rpm.corp.example\n",
			[]string{"proxy=http://proxy.corp.example", "[corp]", "baseurl=https://rpm.corp.example"}, []string{"baseurl=" + testBase + "/rpm/baseos/"}, []string{"old.example"}},
		{"cargo", Cargo(testBase), "[source.crates-io]\nreplace-with = \"corp\" # was\n\n[net]\nretry = 3\n",
			[]string{"[net]", "retry = 3"}, []string{"replace-with = \"bodega\"", "sparse+" + testBase}, []string{"corp"}},
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

// F116 R1: a file whose form the merge cannot edit is refused with the next
// step, never written saying something other than the plan.
func TestAddCARefusesAMergeThatWouldNotHold(t *testing.T) {
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		file   File
		before string
	}{
		"cargo inline table": {Cargo(testBase), "source = { crates-io = { replace-with = \"corp\" } }\n"},
		"gemrc flow mapping": {Rubygems(testBase)[0], "{ \":sources\": [\"https://rubygems.org/\"] }\n"},
		"podman dotted keys": {RegistriesConf(testBase, []string{"docker.io"}), "registry = [ { prefix = \"docker.io\", location = \"corp.example\" } ]\n"},
	} {
		home := t.TempDir()
		target := filepath.Join(home, strings.TrimPrefix(tc.file.Path(OSLinux), "~"))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(tc.before), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := AddCA(caPlan(t, home, tc.file), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")})
		if err == nil || !strings.Contains(err.Error(), "move the file aside") || !strings.Contains(err.Error(), target) {
			t.Errorf("%s: AddCA = %v, want a refusal naming %s and the next step", name, err, target)
		}
	}
}

// F116 R1, R2: the store ResolveJVMStore names is the one doctor reads and
// keytool imports into, and a failed keytool reports its own error with nothing that
// reads as a password in it.
func TestJVMStoreIsTheOneKeytoolIsHanded(t *testing.T) {
	const secret = "hunter2-keystore"
	jdk := t.TempDir()
	jsse, args := filepath.Join(jdk, "lib/security/jssecacerts"), filepath.Join(jdk, "args")
	caPEM, _, _ := testCA(t, "bodega.example.com")
	script := "#!/bin/sh\necho \"$@\" >> " + args + "\ncase \"$*\" in *-importcert*) echo 'Picked up JAVA_TOOL_OPTIONS: -Dx.password=" + secret + "'; echo 'keytool error: storepass=" + secret + " refused for " + secret + "'; exit 1;; esac\nexit 1\n"
	held, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	p12, err := pkcs12.Modern.EncodeTrustStore(held.Certs, secret)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{jsse: string(p12), filepath.Join(jdk, "bin/keytool"): script} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := map[string]string{"JAVA_HOME": jdk, "MAVEN_OPTS": "-Djavax.net.ssl.trustStorePassword=" + secret}
	store, err := ResolveJVMStore(func(k string) string { return env[k] }, func(string) (string, error) { return "", os.ErrNotExist })
	if err != nil {
		t.Fatal(err)
	}
	certs, err := store.Trusted()
	if err != nil || len(certs) != 1 {
		t.Fatalf("Trusted = %d certificates, %v", len(certs), err)
	}
	if ran, _ := os.ReadFile(args); len(ran) != 0 {
		t.Fatalf("listing the store ran keytool: %s", ran)
	}
	other, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(other)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	in, err := AddCA(caPlan(t, home, Maven(testBase, nil)...), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, JVM: store, JVMTrusted: certs})
	if err != nil || len(in.Imports) != 1 {
		t.Fatalf("AddCA = %d imports, %v", len(in.Imports), err)
	}
	err = RunJVMCommand(in.Imports[0])
	if err == nil || !strings.Contains(err.Error(), "keytool error") || strings.Contains(err.Error(), secret) {
		t.Errorf("failed import = %v, want keytool's own error without the password", err)
	}
	ran, _ := os.ReadFile(args)
	for _, line := range strings.Split(strings.TrimSpace(string(ran)), "\n") {
		if !strings.Contains(line, "-keystore "+jsse) || strings.Contains(line, "-cacerts") {
			t.Errorf("keytool ran %q, want the JSSE store %s", line, jsse)
		}
	}
	if strings.Contains(string(ran), "-list") || !strings.Contains(string(ran), "-importcert") {
		t.Errorf("keytool ran %q, want the import alone: the store is listed from its file", ran)
	}
}

func TestIndependentCANamedEntryPreservation(t *testing.T) {
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
		{"apt", AptArchive(testBase, "noble", nil), "Types: deb\nURIs: " + testBase + "/apt/\nSuites: noble\nComponents: main\nArchitectures: amd64\n", "Architectures: amd64"},
		{"podman", RegistriesConf(testBase, []string{"docker.io"}), "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\nmirror-by-digest-only = true\n", "mirror-by-digest-only = true"},
		{"helm", Helm(testBase), HelmDocument(HelmRepository(testBase, "certFile: /etc/helm/client.crt", "keyFile: /etc/helm/client.key")), "certFile: /etc/helm/client.crt"},
		{"pkg", File{System: manifest.TypeFreeBSD, Paths: map[string]string{OSLinux: "/usr/local/etc/pkg/repos/bodega.conf"}, Content: "bodega: { url: \"" + testBase + "/freebsd\", enabled: yes }\n"}, "bodega: { url: \"" + testBase + "/freebsd\", enabled: yes, priority: 10 }\n", "priority: 10"},
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
	ucl := fileKind{blocks: mergeUCL, holds: uclHolds}
	registries := fileKind{blocks: mergeRegistries, holds: registriesHold}
	helm := fileKind{blocks: func(o, p []string) []string { return mergeYAML(o, p, "repositories") }, holds: yamlHolds("repositories")}
	pkgPlan := "bodega: {\n  url: \"https://b/freebsd/${ABI}\",\n  signature_type: \"none\",\n  enabled: yes\n}\n"
	registryPlan := "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n\n[[registry.mirror]]\nlocation = \"b/docker.io\"\n"
	for _, tc := range []struct {
		name         string
		kind         fileKind
		old, planned string
		want         string
	}{
		{"pkg object over several lines", ucl, "# mine\nbodega: {\n  url: \"https://old/x\", # was\n  priority: 10\n}\n", pkgPlan,
			"# mine\nbodega: {\n  url: \"https://b/freebsd/${ABI}\", # was\n  priority: 10,\n  signature_type: \"none\",\n  enabled: yes\n}\n"},
		{"pkg object holding a nested object", ucl, "bodega: {\n  url: \"https://old/x\",\n  env: {\n    A: b\n  },\n  enabled: no,\n}\n", pkgPlan,
			"bodega: {\n  url: \"https://b/freebsd/${ABI}\",\n  env: {\n    A: b\n  },\n  enabled: yes,\n  signature_type: \"none\"\n}\n"},
		{"empty pkg object beside a bare variable", ucl, "bodega: {}\nother { url = pkg+http://x/${ABI}; }\n", pkgPlan,
			"bodega: { url: \"https://b/freebsd/${ABI}\", signature_type: \"none\", enabled: yes }\nother { url = pkg+http://x/${ABI}; }\n"},
		{"registry keeps its mirrors and their order", registries,
			"[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\nblocked = false\n\n[[registry.mirror]]\nlocation = \"corp/docker.io\"\n\n[[registry.mirror]]\nlocation = \"b/docker.io\"\ninsecure = true\npull-from-mirror = \"all\"\n", registryPlan,
			"[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\nblocked = false\n\n[[registry.mirror]]\nlocation = \"corp/docker.io\"\n\n[[registry.mirror]]\nlocation = \"b/docker.io\"\npull-from-mirror = \"all\"\n"},
		{"a new mirror leads the registry's own", registries, "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n\n[[registry.mirror]]\nlocation = \"corp/docker.io\"\n", registryPlan,
			"[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n\n[[registry.mirror]]\nlocation = \"b/docker.io\"\n\n[[registry.mirror]]\nlocation = \"corp/docker.io\"\n"},
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
	if _, err := ucl.merge([]byte("bodega: {\n  url: \"https://old/x\n"), []byte(pkgPlan)); err == nil {
		t.Error("an object with no closing brace was merged, not refused")
	}
}

// TestPipOptionsReadsPipsGrammar pins the reader the trust probe shares with
// the merge: a colon delimits, a deeper line continues the option above it,
// and the last assignment wins.
func TestPipOptionsReadsPipsGrammar(t *testing.T) {
	got := PipOptions([]byte("[global]\nIndex_URL: https://b/simple\ncert = /a.pem\nfind-links =\n  cert=/not.pem\n  # note\n  /srv/wheels\ncert=/b.pem\n[install]\n  no-compile = true\n"))
	want := map[string]string{"global.index-url": "https://b/simple", "global.cert": "/b.pem", "global.find-links": "cert=/not.pem\n/srv/wheels", "install.no-compile": "true"}
	if !maps.Equal(got, want) {
		t.Fatalf("PipOptions = %q, want %q", got, want)
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
		{"composer", Composer(testBase), `{"repositories":{"bodega":{"type":"composer","url":"https://old.example/composer/","only":["corp/*"],"options":{"http":{"timeout":45}}}}}`, `"corp/*"`},
		{"maven", Maven(testBase, nil)[0], "<settings><mirrors><mirror><id>bodega</id><url>https://old.example/maven/</url><mirrorOf>*</mirrorOf><mirrorOfLayouts>default</mirrorOfLayouts></mirror></mirrors></settings>\n", "<mirrorOfLayouts>default</mirrorOfLayouts>"},
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
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
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
	write(filepath.Join(home, ".config/composer/config.json"), `{"repositories":[{"type":"composer","url":"`+testBase+`/composer","only":["a/*"]},{"type":"composer","url":"`+testBase+`/composer","only":["b/*"]},{"packagist.org":false}]}`)
	write(filepath.Join(home, ".m2/settings.xml"), "<settings>\n  <mirrors>\n    <mirror>\n      <id>corp</id>\n      <mirrorOf>central</mirrorOf>\n      <url>https://corp/</url>\n    </mirror>\n    <mirror>\n      <id>bodega</id>\n      <blocked>true</blocked>\n      <name>ours</name>\n    </mirror>\n  </mirrors>\n</settings>\n")
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
		for _, f := range []File{Git(testBase, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}}), pip, Composer(testBase), Maven(testBase, nil)[0]} {
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
		filepath.Join(home, ".config/composer/config.json"): {`"name": "bodega"`, `"a/*"`, `"b/*"`},
		filepath.Join(home, ".m2/settings.xml"):             {"<id>corp</id>", "<name>ours</name>", "<url>" + testBase + "/maven/</url>", "<mirrorOf>*</mirrorOf>"},
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
		if strings.Contains(string(got), "<blocked>") {
			t.Errorf("%s keeps bodega's mirror blocked:\n%s", path, got)
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

// F116 R1, R2: podman reads the first certs.d directory that exists for a
// host, and pip loads its files in one order, with PIP_CONFIG_FILE displacing
// the per-user ones.
func TestTrustSourceSelection(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	const host = "bodega.internal:8443"
	dirs := []string{filepath.Join(root, "etc/docker/certs.d", host), filepath.Join(root, "etc/containers/certs.d", host), filepath.Join(home, ".config/containers/certs.d", host)}
	if got := PodmanCertDir(home, root, host); got != "" {
		t.Errorf("no directory exists and podman is given %s", got)
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if got := PodmanCertDir(home, root, host); got != d {
			t.Errorf("podman reads %s; want %s, the first that exists", got, d)
		}
	}
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
		{"maven-cdata", Maven(testBase, nil)[0], "<settings><mirrors><mirror><id>bodega</id><url><![CDATA[https://old.example/maven/]]></url><mirrorOf>*</mirrorOf><mirrorOfLayouts>default</mirrorOfLayouts></mirror></mirrors></settings>\n", "<mirrorOfLayouts>default</mirrorOfLayouts>"},
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
		"maven mirror named twice":      {Maven(testBase, nil)[0], "<settings><mirrors><mirror><id>bodega</id><url>https://a/</url></mirror><mirror><id>bodega</id><url>https://b/</url><name>second</name></mirror></mirrors></settings>\n", nil, "2 times"},
		"maven url holding markup":      {Maven(testBase, nil)[0], "<settings><mirrors><mirror><id>bodega</id><url>https://a/<!-- was b --></url></mirror></mirrors></settings>\n", nil, "markup"},
		"maven file that is not XML":    {Maven(testBase, nil)[0], "<settings><mirrors><mirror><id>bodega</id>\n", nil, "not XML"},
		"maven second mirrors element":  {Maven(testBase, nil)[0], "<settings><mirrors/><mirrors><mirror><id>corp</id></mirror></mirrors></settings>\n", nil, "more than one <mirrors>"},
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

// F116 R1: bodega's Maven mirror is edited where the XML tokenizer finds
// it. A CDATA value is replaced between its tags, a blocked flag goes on its
// own, every other element and mirror stays byte for byte, a commented-out
// mirror is not the live one, and a second merge changes nothing.
func TestMavenMirrorEditsInPlace(t *testing.T) {
	planned := []byte(Maven(testBase, nil)[0].Content)
	decoy := "<!-- <mirrors><mirror><id>bodega</id><url>https://decoy/</url></mirror></mirrors> -->"
	corp := "<mirror><id>corp</id><url>https://corp.example/</url><mirrorOf>central</mirrorOf></mirror>"
	old := "<?xml version=\"1.0\"?>\n<settings xmlns=\"http://maven.apache.org/SETTINGS/1.2.0\">\n  " + decoy + "\n  <servers><server><id>corp</id></server></servers>\n  <mirrors>\n    <mirror>\n      <id> bodega </id>\n      <url><![CDATA[https://old.example/maven/]]></url>\n      <blocked>true</blocked>\n      <mirrorOfLayouts>default</mirrorOfLayouts>\n    </mirror>\n    " + corp + "\n  </mirrors>\n</settings>\n"
	got, err := mergeMavenMirror([]byte(old), planned)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{decoy, corp, "<servers><server><id>corp</id></server></servers>", "<id> bodega </id>",
		"<url>" + testBase + "/maven/</url>", "<mirrorOfLayouts>default</mirrorOfLayouts>\n      <mirrorOf>*</mirrorOf>\n    </mirror>"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("the merge lost or misplaced %q:\n%s", want, got)
		}
	}
	for _, gone := range []string{"blocked", "old.example", "CDATA"} {
		if strings.Contains(string(got), gone) {
			t.Errorf("the merge kept %q:\n%s", gone, got)
		}
	}
	again, err := mergeMavenMirror(got, planned)
	if err != nil || string(again) != string(got) {
		t.Errorf("a second merge changed the file (%v):\n%s", err, again)
	}
	// A CDATA value already the plan's is left as the host wrote it.
	same := "<settings><mirrors><mirror><id>bodega</id><mirrorOf>*</mirrorOf><url><![CDATA[" + testBase + "/maven/]]></url></mirror></mirrors></settings>\n"
	if got, err := mergeMavenMirror([]byte(same), planned); err != nil || string(got) != same {
		t.Errorf("a mirror already reading as the plan sets it was rewritten (%v):\n%s", err, got)
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

func TestAudit8CAGradlePreservesUnrelatedPolicy(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	files := Maven(testBase, nil)
	target := filepath.Join(home, ".gradle/init.d/bodega.gradle")
	keep := "allprojects { project -> project.tasks.withType(JavaCompile).configureEach { options.encoding = 'UTF-8' } }\n"
	old := files[1].Content + "\n" + keep
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	in, err := AddCA(caPlan(t, home, files...), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSLinux, JVMTrusted: ca.Certs})
	if err != nil {
		if !strings.Contains(err.Error(), target) {
			t.Fatalf("refusal does not name the script: %v", err)
		}
		if got, _ := os.ReadFile(target); string(got) != old {
			t.Fatal("refusal changed the script")
		}
		return
	}
	if _, err := Apply(in.Changes, ".audit"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), keep) {
		t.Fatalf("CA apply silently removed Gradle's unrelated compiler policy from %s", target)
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

// TestGradleInitMergeKeepsLinesAroundBodegasBlock covers the script on both
// sides of bodega's rendering, a move to another URL, and the edit inside the
// rendering that the merge refuses.
func TestGradleInitMergeKeepsLinesAroundBodegasBlock(t *testing.T) {
	was, now := gradleInit("https://old.example/maven/"), gradleInit(testBase+"/maven/")
	before, after := "// site policy\n", "\nallprojects { }\n"
	got, err := mergeGradleInit([]byte(before+was+after), []byte(now))
	if err != nil || string(got) != before+now+after {
		t.Fatalf("merge = %v\n%s", err, got)
	}
	if again, err := mergeGradleInit(got, []byte(now)); err != nil || string(again) != string(got) {
		t.Fatalf("second merge changed the script: %v", err)
	}
	if got, err := mergeGradleInit([]byte(" \n"), []byte(now)); err != nil || string(got) != now {
		t.Fatalf("an empty script is not written whole: %v", err)
	}
	edited := strings.Replace(was, "name = 'bodega'", "name = 'mine'", 1)
	if _, err := mergeGradleInit([]byte(edited), []byte(now)); err == nil {
		t.Fatal("a script edited inside bodega's lines was replaced")
	}
}

// F116 R1, R2: what a JVM trusts is read from the keystore file in each form
// a JDK ships or keytool writes, and a store that cannot be read is an error,
// never an empty store.
func TestJVMStoreReadsTheKeystoreFile(t *testing.T) {
	const pass = "hunter2-keystore"
	caPEM, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	jks := keystore.New()
	if err := jks.SetTrustedCertificateEntry("bodega", keystore.TrustedCertificateEntry{
		CreationTime: time.Now(), Certificate: keystore.Certificate{Type: "X.509", Content: ca.Certs[0].Raw},
	}); err != nil {
		t.Fatal(err)
	}
	var jksFile bytes.Buffer
	if err := jks.Store(&jksFile, []byte(pass)); err != nil {
		t.Fatal(err)
	}
	p12, err := pkcs12.Modern.EncodeTrustStore(ca.Certs, pass)
	if err != nil {
		t.Fatal(err)
	}
	bare, err := pkcs12.Passwordless.EncodeTrustStore(ca.Certs, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		data     []byte
		password string
		want     int
	}{
		"jks":                   {jksFile.Bytes(), pass, 1},
		"pkcs12":                {p12, pass, 1},
		"pkcs12 without a MAC":  {bare, "", 1},
		"jks, wrong password":   {jksFile.Bytes(), "wr0ng-pass", -1},
		"pkcs12 wrong password": {p12, "wr0ng-pass", -1},
		"not a keystore":        {[]byte("store"), pass, -1},
		"truncated jks":         {jksFile.Bytes()[:40], pass, -1},
	} {
		file := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(file, tc.data, 0o600); err != nil {
			t.Fatal(err)
		}
		certs, err := (JVMStore{Keystore: file, Password: tc.password}).Trusted()
		switch {
		case tc.want < 0 && err == nil:
			t.Errorf("%s: Trusted = %d certificates, want an error", name, len(certs))
		case tc.want < 0 && (strings.Contains(err.Error(), "wr0ng-pass") || !strings.Contains(err.Error(), file)):
			t.Errorf("%s: error %q must name the file and not the password", name, err)
		case tc.want >= 0 && (err != nil || len(certs) != tc.want || !bytes.Equal(certs[0].Raw, ca.Certs[0].Raw)):
			t.Errorf("%s: Trusted = %d certificates, %v", name, len(certs), err)
		}
	}
	if _, err := (JVMStore{Keytool: filepath.Join(dir, "bin/keytool")}).Trusted(); err == nil || !strings.Contains(err.Error(), "JAVA_HOME") {
		t.Errorf("a JDK with no cacerts: Trusted = %v, want an error naming JAVA_HOME", err)
	}
	// The cacerts is found where keytool -cacerts writes: under the JDK.
	cacerts := filepath.Join(dir, "jdk/lib/security/cacerts")
	if err := os.MkdirAll(filepath.Dir(cacerts), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cacerts, bare, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := ResolveJVMStore(func(k string) string {
		if k == "JAVA_HOME" {
			return filepath.Join(dir, "jdk")
		}
		return ""
	}, func(string) (string, error) { return "", os.ErrNotExist })
	if err != nil || store.Cacerts != cacerts {
		t.Fatalf("ResolveJVMStore = %+v, %v; want cacerts %s", store, err, cacerts)
	}
	if certs, err := store.Trusted(); err != nil || len(certs) != 1 {
		t.Errorf("the JDK's cacerts: Trusted = %d certificates, %v", len(certs), err)
	}
}

// F116 R1, R2: the keystore reader agrees with keytool, the oracle, on the
// JDK's own cacerts and on a store keytool wrote in each type.
func TestJVMStoreAgreesWithKeytool(t *testing.T) {
	keytool, err := exec.LookPath("keytool")
	if err != nil {
		t.Skip("native keytool is not installed")
	}
	list := func(args ...string) []*x509.Certificate {
		t.Helper()
		out, err := exec.Command(keytool, append([]string{"-list", "-rfc", "-storepass", "changeit"}, args...)...).Output()
		if err != nil {
			t.Skipf("keytool does not list %v: %v", args, err)
		}
		return ParseKeytoolList(out)
	}
	same := func(what string, got, want []*x509.Certificate) {
		t.Helper()
		sums := func(certs []*x509.Certificate) []string {
			var out []string
			for _, c := range certs {
				sum := sha256.Sum256(c.Raw)
				out = append(out, hex.EncodeToString(sum[:]))
			}
			slices.Sort(out)
			return out
		}
		if len(want) == 0 || !slices.Equal(sums(got), sums(want)) {
			t.Errorf("%s: read %d certificates, keytool lists %d", what, len(got), len(want))
		}
	}
	store, err := ResolveJVMStore(os.Getenv, exec.LookPath)
	if err != nil {
		t.Fatal(err)
	}
	if store.Keystore == "" && store.Cacerts != "" {
		got, err := store.Trusted()
		if err != nil {
			t.Fatalf("%s: %v", store.Cacerts, err)
		}
		same(store.Cacerts, got, list("-cacerts"))
	}
	caPEM, _, _ := testCA(t, "bodega.example.com")
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"JKS", "PKCS12"} {
		file := filepath.Join(dir, kind)
		if out, err := exec.Command(keytool, "-importcert", "-noprompt", "-trustcacerts", "-alias", "bodega", "-file", caFile,
			"-keystore", file, "-storetype", kind, "-storepass", "changeit").CombinedOutput(); err != nil {
			t.Fatalf("keytool -importcert into %s: %v\n%s", kind, err, out)
		}
		got, err := (JVMStore{Keystore: file}).Trusted()
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		same(kind, got, list("-keystore", file))
	}
}

// nativeNpm gates a test that holds doctor's reading of an npmrc against
// npm's own. A developer's machine without npm skips it. CI does not: its
// test job installs a pinned Node, so a missing npm there is a broken job
// that would otherwise pass every oracle test unrun.
func nativeNpm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("npm"); err != nil {
		if os.Getenv("CI") == "true" {
			t.Fatal("native npm is required in CI: the test job installs it with actions/setup-node")
		}
		t.Skip("native npm is not installed")
	}
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

func TestAudit9CADistfilesCompanionPreservesUnrelatedPolicy(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	env, err := (distinfo.EnvironmentSpec{}).Load()
	if err != nil {
		t.Fatal(err)
	}
	home, root := t.TempDir(), t.TempDir()
	main := MakeConf(testBase)
	main.Paths = map[string]string{OSLinux: main.Path(OSFreeBSD)}
	companion := File{System: main.System, Paths: map[string]string{OSLinux: DistfilesCheckPath}, Content: string(env.ClientCheck())}
	target := filepath.Join(home, DistfilesCheckPath)
	keep := "CFLAGS+= -fstack-protector-strong\n"
	old := companion.Content + "\n" + keep
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	in, err := AddCA(caPlan(t, home, main, companion), ca, CAHost{Base: testBase, Home: home, Root: root, GOOS: OSFreeBSD})
	if err != nil {
		if !strings.Contains(err.Error(), target) {
			t.Fatalf("refusal does not name the companion script: %v", err)
		}
		if got, _ := os.ReadFile(target); string(got) != old {
			t.Fatal("refusal changed the companion script")
		}
		return
	}
	if _, err := Apply(in.Changes, ".audit"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), keep) {
		t.Fatalf("CA apply silently removed unrelated compiler policy from %s", target)
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
	const rendered = "# bodega distfiles client check\nBODEGA_DISTFILES_DRIFT=\n"
	for name, tc := range map[string]struct {
		old     string
		want    string
		refused bool
	}{
		"blank":                {" \n", rendered, false},
		"same":                 {rendered, rendered, false},
		"lines around":         {"# mine\n" + rendered + "CFLAGS+= -O2\n", "# mine\n" + rendered + "CFLAGS+= -O2\n", false},
		"an older rendering":   {"# bodega distfiles client check\nBODEGA_DISTFILES_DRIFT= old\n", "", true},
		"edited inside":        {"# bodega distfiles client check\nCFLAGS+= -O2\nBODEGA_DISTFILES_DRIFT=\n", "", true},
		"another file's lines": {"CFLAGS+= -O2\n", "", true},
	} {
		home := t.TempDir()
		main := MakeConf(testBase)
		main.Paths = map[string]string{OSLinux: main.Path(OSFreeBSD)}
		companion := File{System: main.System, Paths: map[string]string{OSLinux: DistfilesCheckPath}, Content: rendered}
		target := filepath.Join(home, DistfilesCheckPath)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(tc.old), 0600); err != nil {
			t.Fatal(err)
		}
		in, err := AddCA(caPlan(t, home, main, companion), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSFreeBSD})
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
		again, err := AddCA(caPlan(t, home, main, companion), ca, CAHost{Base: testBase, Home: home, Root: t.TempDir(), GOOS: OSFreeBSD})
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
	if _, err := exec.LookPath("git"); err != nil {
		if os.Getenv("CI") == "true" {
			t.Fatal("native git is required in CI")
		}
		t.Skip("native git is not installed")
	}
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
	if _, err := exec.LookPath("git"); err != nil {
		if os.Getenv("CI") == "true" {
			t.Fatal("native git is required in CI")
		}
		t.Skip("native git is not installed")
	}
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
// sh ends a comment at the newline, where make and systemd's environment.d
// join lines before they look for one.
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
		{"make comment", makeRules, []string{`# note \`, `A=b`, `C=d`}, []bool{false, true, false}},
		{"make escaped backslash", makeRules, []string{`A=b\\`, `C=d`}, []bool{false, false}},
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
	bundler := Rubygems(testBase)[1]
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
		{"BUNDLE_USER_CONFIG", bundler, func(f string) map[string]string { return map[string]string{"BUNDLE_USER_CONFIG": f} }, "config",
			"---\nBUNDLE_JOBS: \"4\"\n", testBase},
		{"BUNDLE_USER_HOME", bundler, func(f string) map[string]string { return map[string]string{"BUNDLE_USER_HOME": filepath.Dir(f)} }, "config",
			"---\nBUNDLE_JOBS: \"4\"\n", testBase},
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

func TestAudit12CargoCAPlansTheWinningFile(t *testing.T) {
	raw, _, _ := testCA(t, "bodega.example.com")
	ca, err := ParseCA(raw)
	if err != nil {
		t.Fatal(err)
	}
	home, root := t.TempDir(), t.TempDir()
	target := filepath.Join(home, ".cargo", "config")
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	old := "[source.crates-io]\nregistry = \"sparse+https://index.crates.io/\"\n[build]\njobs = 3\n"
	if err := os.WriteFile(target, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	h := CAHost{Base: testBase, Home: home, Root: root, GOOS: OSLinux, OSRelease: []byte("ID=ubuntu\n")}
	in, err := AddCA(caPlan(t, home, Cargo(testBase)), ca, h)
	if err != nil {
		t.Fatal(err)
	}
	c := changeAt(t, in.Changes, target)
	for _, want := range []string{testBase, "jobs = 3"} {
		if !strings.Contains(string(c.New), want) {
			t.Fatalf("winning Cargo file does not contain %s:\n%s", want, c.New)
		}
	}
}
