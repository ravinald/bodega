package main

import (
	"bytes"
	"context"
	"fmt"
	stdhtml "html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"gopkg.in/yaml.v3"
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

var stylesheetLink = regexp.MustCompile(`(?is)<link\b[^>]*>`)

// stylesheetLoads follows every stylesheet of this site that a page links,
// and each one those import, and lists what they fetch from another origin.
// It reads the rules rather than watching a browser apply them, because a
// browser fetches only what the rules it happens to match name: a dark-mode
// background or an unused face would pass on the day of the test.
func stylesheetLoads(t *testing.T, out, page string) []string {
	t.Helper()
	var found []string
	seen := map[string]bool{}
	var read func(href, from string)
	read = func(href, from string) {
		u, err := url.Parse(strings.TrimSpace(stdhtml.UnescapeString(href)))
		if err != nil || u.Scheme != "" || u.Host != "" || u.Path == "" {
			return // a remote sheet is remoteLoads' finding, or this function's own below
		}
		name := u.Path
		if !strings.HasPrefix(name, "/") {
			name = path.Join(path.Dir(from), name)
		}
		if seen[name] {
			return
		}
		seen[name] = true
		css, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(name)))
		if err != nil {
			t.Errorf("%s links the stylesheet %s, which the build did not write: %v", from, href, err)
			return
		}
		for _, m := range cssLoad.FindAllStringSubmatch(string(css), -1) {
			switch {
			case remote.MatchString(m[1]):
				found = append(found, name+": "+m[1])
			case strings.HasSuffix(strings.SplitN(m[1], "?", 2)[0], ".css"):
				read(m[1], name)
			}
		}
	}
	for _, link := range stylesheetLink.FindAllString(page, -1) {
		rel := relAttr.FindStringSubmatch(link)
		if rel == nil || !strings.Contains(strings.ToLower(rel[1]), "stylesheet") {
			continue
		}
		for _, a := range loadAttr.FindAllStringSubmatch(link, -1) {
			read(a[1]+a[2]+a[3], "/api/index.html")
		}
	}
	return found
}

// documentLoads lists what the OpenAPI document would make its viewer fetch
// from another origin. Scalar renders descriptions as Markdown, and renders a
// collapsed tag, operation or schema only once a reader opens it, so a
// browser that loads the page sees the introduction and little else. This
// reads every string in the document as Markdown instead, wherever it sits:
// stricter than Scalar, which renders only some fields, and that is the side
// to err on.
func documentLoads(spec []byte) ([]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		return nil, fmt.Errorf("the OpenAPI document is not YAML: %w", err)
	}
	var found []string
	var walk func(n *yaml.Node) error
	walk = func(n *yaml.Node) error {
		// No URL on another origin is written without "//".
		if n.Kind == yaml.ScalarNode && strings.Contains(n.Value, "//") {
			var rendered bytes.Buffer
			if err := md.Convert([]byte(n.Value), &rendered); err != nil {
				return fmt.Errorf("line %d: %w", n.Line, err)
			}
			for _, u := range remoteLoads(rendered.String()) {
				found = append(found, fmt.Sprintf("line %d: %s", n.Line, u))
			}
		}
		for _, c := range n.Content {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	return found, walk(&doc)
}

// browserLoads serves the built site on loopback, opens one of its pages in
// headless Chrome, waits until the page shows the text ready, and lists every
// request the page made to anywhere but the site. It is the one check that
// runs the vendored bundle, so it is the one that sees what Scalar itself
// fetches: a font, a telemetry call, an asset a new release adds by default.
// Chrome resolves no name while it runs, so a request this reports was
// attempted and never sent.
func browserLoads(t *testing.T, out, page, ready string) []string {
	t.Helper()
	site := httptest.NewServer(http.FileServer(http.Dir(out)))
	defer site.Close()

	// Chrome's sandbox guards against hostile pages, and this one loads only
	// the site's own pages from a local server with every other host name
	// unresolvable. Ubuntu 23.10 and later refuse the unprivileged user
	// namespace the sandbox needs, so with it Chrome exits before the page
	// loads on those hosts and on GitHub's runners.
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoSandbox,
		chromedp.Flag("host-resolver-rules", "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"))
	alloc, stop := chromedp.NewExecAllocator(context.Background(), opts...)
	defer stop()
	ctx, closeTab := chromedp.NewContext(alloc)
	defer closeTab()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	var mu sync.Mutex
	var requests, elsewhere []string
	record := func(u string) {
		mu.Lock()
		defer mu.Unlock()
		requests = append(requests, u)
		switch strings.ToLower(strings.SplitN(u, ":", 2)[0]) {
		case "data", "blob", "about":
			return // made of bytes the page already holds
		}
		if !strings.HasPrefix(u, site.URL+"/") {
			elsewhere = append(elsewhere, u)
		}
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(requests)
	}
	err := chromedp.Listen(ctx, func(ev any) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			record(e.Request.URL)
		case *network.EventWebSocketCreated:
			record(e.URL)
		}
	})
	if err == nil {
		_, err = chromedp.Call(ctx, network.Enable, network.EnableParams{})
	}
	if err != nil {
		t.Fatalf("no headless browser to load %s in: %v. This check runs the page in Chrome or Chromium, which chromedp looks for under its usual names on PATH and in /Applications; install one and run the test again", page, err)
	}

	shows := fmt.Sprintf(`(document.querySelector("#reference")?.innerText ?? "").includes(%q)`, ready)
	err = chromedp.Do(ctx, chromedp.Navigate(site.URL+page))
	if err == nil {
		_, err = chromedp.Run(ctx, chromedp.Poll[bool](shows, chromedp.WithPollingTimeout(time.Minute)))
	}
	if err != nil {
		t.Fatalf("%s never showed %q in headless Chrome, so nothing says the reference rendered: %v (requests so far: %v)", page, ready, err, requests)
	}
	// The introduction is on screen; give what it embeds a second with no
	// new request before calling the page loaded.
	for seen, quiet := count(), 0; quiet < 4 && ctx.Err() == nil; {
		time.Sleep(250 * time.Millisecond)
		if n := count(); n != seen {
			seen, quiet = n, 0
		} else {
			quiet++
		}
	}
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), elsewhere...)
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

	s, err := vendoredScalar(".")
	if err != nil {
		t.Fatal(err)
	}
	// Four readers, because no one of them sees every load: the HTML the
	// generator wrote, the stylesheets that HTML links, the document Scalar
	// renders as a reader opens each part of it, and Scalar's own script.
	loads := remoteLoads(api)
	loads = append(loads, stylesheetLoads(t, out, api)...)
	inDocument, err := documentLoads([]byte(readPage(t, out, "api/openapi.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	loads = append(loads, inDocument...)
	loads = append(loads, browserLoads(t, out, "/api/", referenceReady)...)
	if len(loads) != 0 {
		t.Errorf("/api/ loads from another origin, which hands every reader's visit to a third party: %v", loads)
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
		"the rendered reference":               `<a href="/api/">API reference</a>, published at <code>/api/</code>`,
		"where a new operator starts":          `its introduction is where a new operator starts`,
		"the document itself, as the download": `<a href="/api/openapi.yaml" title="Download the OpenAPI document"><code>api/openapi.yaml</code></a>`,
	})
}

// referenceReady is a heading of the introduction in info.description. Scalar
// showing it means the bundle ran, fetched the document and rendered its
// Markdown.
const referenceReady = "First requests"

// Each reader of the page's loads has to see the load only it can see, or a
// clean result from it says nothing.
func TestReferenceLoadChecksSeeEachSource(t *testing.T) {
	out := buildSite(t)
	const probe = "https://probe.invalid/pixel.png"

	sheet := `<link rel="stylesheet" href="/probe.css?v=1">`
	write(filepath.Join(out, "probe.css"), []byte(`@import "nested/more.css"; @media (prefers-color-scheme: dark) { body { background: url(`+probe+`) } }`))
	write(filepath.Join(out, "nested", "more.css"), []byte(`@font-face { font-family: x; src: url("//probe.invalid/x.woff2") }`))
	if got := stylesheetLoads(t, out, sheet); len(got) != 2 {
		t.Errorf("stylesheetLoads found %v, want the image a media query holds and the font an imported sheet names", got)
	}
	if got := stylesheetLoads(t, out, readPage(t, out, "api/index.html")); len(got) != 0 {
		t.Errorf("stylesheetLoads reports %v in the site's own stylesheet", got)
	}

	inDocument, err := documentLoads([]byte(`openapi: 3.0.3
info:
  description: |
    Read [the docs](https://bodega.example.com/docs/) at https://bodega.example.com.
tags:
  - name: last
    description: "A tag a reader has to open. ![probe](` + probe + `)"
paths:
  /a:
    get:
      description: |
        An operation below the fold.

        ![probe][pixel]

        [pixel]: ` + probe + `
      responses:
        "200":
          description: <img src="` + probe + `" alt="">
components:
  schemas:
    S:
      properties:
        p:
          description: Raw <picture><source srcset="//probe.invalid/a.png 2x"></picture>.
          example: https://bodega.example.com/api/v1/status
`))
	if err != nil || len(inDocument) != 4 {
		t.Errorf("documentLoads found %v (err %v), want the probe in a tag, an operation, a response and a schema, and no link or example URL", inDocument, err)
	}

	// Scalar renders the introduction on load, so an image there is a request
	// only a browser running the bundle makes.
	spec := filepath.Join(out, "api", "openapi.yaml")
	document := readPage(t, out, "api/openapi.yaml")
	const opens = "  description: |\n"
	if !strings.Contains(document, opens) {
		t.Fatal("api/openapi.yaml no longer opens info.description as a block scalar, so this test has nowhere to put its probe")
	}
	write(spec, []byte(strings.Replace(document, opens, opens+"    ![probe]("+probe+")\n\n", 1)))
	if got := browserLoads(t, out, "/api/", referenceReady); len(got) != 1 || got[0] != probe {
		t.Errorf("browserLoads saw %v, want the one image Scalar loads from info.description", got)
	}
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

func TestRESTAPIOffersRawDownload(t *testing.T) {
	out := buildSite(t)
	page := readPage(t, out, "docs/usage/rest-api.html")
	rawDownload := regexp.MustCompile(`<a\b[^>]*\bhref="/api/openapi\.yaml"[^>]*>`)
	if !rawDownload.MatchString(page) {
		t.Fatal("REST API offers no link to /api/openapi.yaml; the advertised document link leads to the viewer")
	}
}
