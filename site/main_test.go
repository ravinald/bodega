package main

import (
	"bytes"
	stdhtml "html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func buildSite(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	coverage := filepath.Join(dir, "coverage.json")
	write(coverage, []byte(`{"revision":"abc","evaluatedAt":"2026-01-01T00:00:00Z","summary":"s","packages":[{"id":"apt","verdict":"Ready","reason":"r","coverage":"90%","features":[{"label":"L","description":"D","value":"yes"}]}]}`))
	out := filepath.Join(dir, "site")
	if broken := build("..", out, ".", "v0.0.0-test", strings.Repeat("0", 40), "/", coverage); broken != 0 {
		t.Fatalf("the site has %d broken internal links, want 0", broken)
	}
	return out
}

func readPage(t *testing.T, out, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(out, name))
	if err != nil {
		t.Fatalf("the build wrote no %s: %v", name, err)
	}
	return string(b)
}

func wantAll(t *testing.T, name, body string, wants map[string]string) {
	t.Helper()
	for what, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %s: no %q", name, what, want)
		}
	}
}

var (
	tagWithAttrs = regexp.MustCompile(`(?is)<(script|link|img|source|iframe|video|audio|embed|object)\b([^>]*)>`)
	loadAttr     = regexp.MustCompile(`(?is)\b(?:src|href|data|srcset|poster)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	relAttr      = regexp.MustCompile(`(?is)\brel\s*=\s*["']?([a-z -]+)`)
	styleBlock   = regexp.MustCompile(`(?is)<style\b[^>]*>(.*?)</style>`)
	styleAttr    = regexp.MustCompile(`(?is)\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	cssLoad      = regexp.MustCompile(`(?i)(?:url\(\s*['"]?|@import\s+['"])([^'")\s]+)`)
	remote       = regexp.MustCompile(`(?i)^(?:https?:)?//`)
)

// remoteLoads lists every script, stylesheet, font, image and frame a page
// fetches from another origin as it loads: an absolute http(s) URL, or the
// scheme-relative form that means the same thing. A link a reader follows is
// not a load, so an <a href> never counts.
func remoteLoads(page string) []string {
	var found []string
	add := func(u string) {
		if u = strings.TrimSpace(stdhtml.UnescapeString(u)); remote.MatchString(u) {
			found = append(found, u)
		}
	}
	for _, m := range tagWithAttrs.FindAllStringSubmatch(page, -1) {
		if strings.EqualFold(m[1], "link") {
			// rel=stylesheet, preload, icon and the rest are fetched; a
			// canonical or alternate link only names another page.
			if rel := relAttr.FindStringSubmatch(m[2]); rel != nil && (strings.Contains(rel[1], "canonical") || strings.Contains(rel[1], "alternate")) {
				continue
			}
		}
		for _, a := range loadAttr.FindAllStringSubmatch(m[2], -1) {
			for _, part := range strings.Split(a[1]+a[2]+a[3], ",") { // srcset holds several
				if f := strings.Fields(part); len(f) > 0 {
					add(f[0])
				}
			}
		}
	}
	css := styleBlock.FindAllStringSubmatch(page, -1)
	css = append(css, styleAttr.FindAllStringSubmatch(page, -1)...)
	for _, block := range css {
		for _, m := range cssLoad.FindAllStringSubmatch(strings.Join(block[1:], " "), -1) {
			add(m[1])
		}
	}
	return found
}

func TestRemoteLoadsFindsEveryForm(t *testing.T) {
	for form, page := range map[string]string{
		"a script from a CDN":           `<script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>`,
		"a scheme-relative script":      `<script src="//cdn.example.com/a.js"></script>`,
		"a stylesheet":                  `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">`,
		"a preloaded font":              `<link rel=preload as=font href=https://fonts.scalar.com/inter-latin.woff2>`,
		"an image":                      `<img alt="" src='http://example.com/pixel.gif'>`,
		"a srcset":                      `<img src="/a.png" srcset="/a.png 1x, https://example.com/a2.png 2x">`,
		"a font in a style block":       `<style>@font-face { src: url(https://fonts.scalar.com/inter-latin.woff2) format("woff2"); }</style>`,
		"an imported stylesheet":        `<style>@import "https://example.com/theme.css";</style>`,
		"an image in a style attribute": `<div style="background: url('https://example.com/bg.png')"></div>`,
	} {
		if got := remoteLoads(page); len(got) != 1 {
			t.Errorf("%s: remoteLoads found %v, want the one remote URL", form, got)
		}
	}
	local := `<a href="https://github.com/ravinald/bodega">Source</a><link rel="canonical" href="https://bodega.example.com/api/"><script src="/scalar/standalone.js?v=1"></script><link rel="stylesheet" href="/site.css"><img src="assets/a.png"><style>@font-face { src: url(/fonts/a.woff2); }</style>`
	if got := remoteLoads(local); len(got) != 0 {
		t.Errorf("remoteLoads reports %v on a page that loads nothing from another origin", got)
	}
}

func TestVendoredScalarMatchesItsRecord(t *testing.T) {
	s, err := vendoredScalar(".")
	if err != nil {
		t.Fatalf("%v; if the bundle was updated on purpose, run site/scripts/update-scalar.sh so the record is written with it", err)
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(s.Version) || s.Package != "@scalar/api-reference" {
		t.Errorf("scalar.json records %s at version %q, want @scalar/api-reference at one exact release", s.Package, s.Version)
	}

	// The same record beside a bundle one byte longer has to be refused.
	dir := t.TempDir()
	vendored := filepath.Join("static", "scalar")
	for _, name := range []string{"scalar.json", s.File} {
		b, err := os.ReadFile(filepath.Join(vendored, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == s.File {
			b = append(b, '\n')
		}
		write(filepath.Join(dir, vendored, name), b)
	}
	if _, err := vendoredScalar(dir); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Errorf("a bundle whose sha256 is not the recorded one was accepted: err = %v", err)
	}
	if _, err := vendoredScalar(t.TempDir()); err == nil {
		t.Error("a site with no vendored bundle was accepted")
	}
}

func TestBuildPublishesAPIReference(t *testing.T) {
	out := buildSite(t)
	api := readPage(t, out, "api/index.html")

	if loads := remoteLoads(api); len(loads) != 0 {
		t.Errorf("/api/ loads from another origin, which hands every reader's visit to a third party: %v", loads)
	}
	s, err := vendoredScalar(".")
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, "api/index.html", api, map[string]string{
		"the site header":                          `<header class="head">`,
		"the way back to the docs":                 `<a href="/docs/">Docs</a>`,
		"the navigation entry, marked current":     `<a href="/api/" class="here">API</a>`,
		"the vendored bundle":                      `<script src="/scalar/` + s.File + `?v=` + s.SHA256[:12] + `"></script>`,
		"Scalar's documented call":                 `Scalar.createApiReference("#reference", {`,
		"the document it renders":                  `"url":"/api/openapi.yaml"`,
		"telemetry off":                            `"telemetry":false`,
		"no hosted fonts":                          `"withDefaultFonts":false`,
		"no request client button":                 `"hideClientButton":true`,
		"no test request button":                   `"hideTestRequestButton":true`,
		"no developer tools":                       `"showDeveloperTools":"never"`,
		"no MCP hook":                              `"mcp":{"disabled":true}`,
		"no agent":                                 `"agent":{"disabled":true}`,
		"the modern layout":                        `"layout":"modern"`,
		"the document for a reader with no script": `<noscript>`,
	})
	// The bundle mounts itself, unconfigured, on an element with this id.
	if strings.Contains(api, `id="api-reference"`) {
		t.Error(`/api/ has an element with id "api-reference": Scalar mounts a second, default-configured reference there, which fetches fonts from scalar.com`)
	}

	spec, err := os.ReadFile(filepath.Join("..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := readPage(t, out, "api/openapi.yaml"); got != string(spec) {
		t.Error("/api/openapi.yaml is not api/openapi.yaml byte for byte, so the download is not the document the page renders")
	}
	bundle, err := os.ReadFile(filepath.Join("static", "scalar", s.File))
	if err != nil {
		t.Fatal(err)
	}
	if got := readPage(t, out, "scalar/"+s.File); got != string(bundle) {
		t.Error("the published bundle is not the vendored one")
	}
	if _, err := os.Stat(filepath.Join(out, "api", "schemas.html")); err == nil {
		t.Error("the build still writes api/schemas.html, a page of the renderer Scalar replaced")
	}

	wantAll(t, "the front page", readPage(t, out, "index.html"), map[string]string{"the navigation entry": `<a href="/api/">API</a>`})
	wantAll(t, "the docs index", readPage(t, out, "docs/index.html"), map[string]string{
		"the API reference group": `<h2>API reference</h2>`,
		"the API reference":       `<a href="/api/">API reference</a>`,
	})
	wantAll(t, "a doc page's contents column", readPage(t, out, "docs/quickstart.html"), map[string]string{
		"the API reference row": `<a href="/api/">API reference</a>`,
	})
	wantAll(t, "the REST API usage page", readPage(t, out, "docs/usage/rest-api.html"), map[string]string{
		"the rendered reference":                   `<a href="/api/">API reference</a>, published at <code>/api/</code>`,
		"where a new operator starts":              `its introduction is where a new operator starts`,
		"the document's repository path, rendered": `<a href="/api/"><code>api/openapi.yaml</code></a>`,
	})
}

var docsLink = regexp.MustCompile(`\]\((\.\./docs/[^)\s]+)\)`)

// The OpenAPI document links the docs by a path relative to /api/, where
// Scalar renders it. Nothing follows those links: they sit in a YAML file the
// generator copies and a script renders. Each has to be a page, and an anchor
// on it, that this build writes.
func TestOpenAPIDocsLinksResolve(t *testing.T) {
	out := buildSite(t)
	raw, err := os.ReadFile(filepath.Join("..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	links := docsLink.FindAllStringSubmatch(string(raw), -1)
	if len(links) < 10 {
		t.Fatalf("api/openapi.yaml links %d docs pages; every tag links one", len(links))
	}
	for _, m := range links {
		rel, frag, _ := strings.Cut(m[1], "#")
		name := filepath.Join(out, "api", filepath.FromSlash(rel))
		page, err := os.ReadFile(name)
		if err != nil {
			t.Errorf("api/openapi.yaml links %s, and the site has no such page", m[1])
			continue
		}
		if frag != "" && !bytes.Contains(page, []byte(`id="`+frag+`"`)) {
			t.Errorf("api/openapi.yaml links %s, and that page has no element with that id", m[1])
		}
	}
}
