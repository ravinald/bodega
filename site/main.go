// sitegen renders bodega's README, docs/ and coverage feed into the static
// project website. site/scripts/deploy.py runs it; see site/README.md.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	stdhtml "html"
	"html/template"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
)

const repoURL = "https://github.com/ravinald/bodega"

type page struct {
	Src   string // repository path the page was rendered from, empty when generated
	Out   string // path under the base
	Title string
	Group string
	Kind  string // home, doc, page, colophon
	Body  template.HTML
	// Outline is the page's h2 headings, each with the h3s under it: the two
	// levels the contents column opens below the page's own entry.
	Outline []heading
}

type heading struct {
	Title, ID string
	Children  []heading
}

type entry struct {
	Num         string
	Title, Href string
	Here        bool
	Children    []heading
}

type group struct {
	Name    string
	Entries []entry
	Here    bool
}

type siteInfo struct {
	Base, Version, Commit string
	CSSVersion            string // content hash of site.css, so a changed stylesheet gets a URL no browser has cached
}

// A doc source and the contents group it is listed under. Usage sections are
// named by their ## heading and become pages of their own. The "api" source
// is the page Scalar renders the OpenAPI document on.
type source struct{ group, src, section string }

var contents = []source{
	{"Install and deploy", "docs/quickstart.md", ""},
	{"Install and deploy", "docs/usage.md", "Platforms"},
	{"Install and deploy", "docs/usage.md", "Configuration"},
	{"Install and deploy", "docs/usage.md", "Running under systemd"},
	{"Install and deploy", "docs/usage.md", "Running under rc.d"},
	{"Install and deploy", "docs/usage.md", "HTTP Server"},
	{"Packages and storage", "docs/usage.md", "Manifest Structure"},
	{"Packages and storage", "docs/usage.md", "Pipeline"},
	{"Packages and storage", "docs/usage.md", "Proxy/Cache"},
	{"Packages and storage", "docs/usage.md", "Storage Layout"},
	{"Packages and storage", "docs/usage.md", "Checksum Verification"},
	{"Packages and storage", "docs/usage.md", "Manifest Integrity"},
	{"Policy and identity", "docs/usage.md", "Authentication"},
	{"Policy and identity", "docs/usage.md", "Supply Chain Management"},
	{"Policy and identity", "docs/usage.md", "Attestations"},
	{"Policy and identity", "docs/usage.md", "Integrations"},
	{"Policy and identity", "docs/threat-model.md", ""},
	{"Policy and identity", "docs/slsa.md", ""},
	{"Policy and identity", "SECURITY.md", ""},
	{"Daily operations", "docs/runbook.md", ""},
	{"Daily operations", "docs/usage.md", "Audit Trail"},
	{"Daily operations", "docs/usage.md", "Inventory"},
	{"Daily operations", "docs/usage.md", "TUI"},
	{"Daily operations", "docs/usage.md", "Web Dashboard"},
	{"Quarantine a release", "docs/quarantine/README.md", ""},
	{"Quarantine a release", "docs/quarantine/cli.md", ""},
	{"Quarantine a release", "docs/quarantine/tui.md", ""},
	{"Quarantine a release", "docs/quarantine/api.md", ""},
	{"Reference", "docs/usage.md", "Commands"},
	{"Reference", "docs/usage.md", "Global Flags"},
	{"Reference", "docs/usage.md", "REST API"},
	{"Reference", "docs/usage.md", ""},
	{"Reference", "coverage", ""},
	{"API reference", "api", ""},
	{"Project", "docs/design.md", ""},
	{"Project", "CONTRIBUTING.md", ""},
	{"Project", "docs/usage.md", "Development"},
}

// githubIDs reproduces GitHub's heading anchors, so the links the docs already
// carry (usage.md#storage-layout) land where they do on github.com.
type githubIDs struct{ seen map[string]int }

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

func (g *githubIDs) Generate(value []byte, _ ast.NodeKind) []byte {
	id := slug(string(value))
	if n, ok := g.seen[id]; ok {
		g.seen[id] = n + 1
		id = fmt.Sprintf("%s-%d", id, n+1)
	} else {
		g.seen[id] = 0
	}
	return []byte(id)
}

func (g *githubIDs) Put(value []byte) { g.seen[string(value)] = 0 }

type generator struct {
	repo, base, commit string
	outOf              map[string]string // repository path > output path
	usageSection       map[string]string // anchor in usage.md > output path of its section
}

var md = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
	goldmark.WithRendererOptions(html.WithUnsafe()),
)

func parse(src []byte) ast.Node {
	ctx := parser.NewContext(parser.WithIDs(&githubIDs{seen: map[string]int{}}))
	return md.Parser().Parse(text.NewReader(src), parser.WithContext(ctx))
}

func headingID(n *ast.Heading) string {
	if v, ok := n.AttributeString("id"); ok {
		if b, ok := v.([]byte); ok {
			return string(b)
		}
	}
	return ""
}

func usageOut(section string) string {
	if section == "" {
		return "docs/usage/"
	}
	return "docs/usage/" + slug(section) + ".html"
}

func docOut(src string) string {
	switch src {
	case "README.md":
		return ""
	case "SECURITY.md", "CONTRIBUTING.md":
		return "docs/" + strings.ToLower(strings.TrimSuffix(src, ".md")) + ".html"
	case "docs/quarantine/README.md":
		return "docs/quarantine/"
	}
	return strings.TrimSuffix(src, ".md") + ".html"
}

// rewrite maps a link written for GitHub onto the site: the README and docs
// become site pages, images are copied, and any other repository path goes to
// the file on GitHub at the commit the site was built from.
func (g *generator) rewrite(dest, srcPath string) string {
	if dest == "" || strings.Contains(dest, "://") || strings.HasPrefix(dest, "mailto:") {
		return dest
	}
	frag := ""
	if i := strings.Index(dest, "#"); i >= 0 {
		dest, frag = dest[:i], dest[i+1:]
	}
	p := srcPath
	if dest != "" {
		p = path.Clean(path.Join(path.Dir(srcPath), dest))
	}
	if p == "docs/usage.md" {
		if out, ok := g.usageSection[frag]; ok {
			return g.base + out + "#" + frag
		}
		return g.base + usageOut("") + withFrag(frag)
	}
	if dest == "" {
		return "#" + frag
	}
	if p == "docs/quarantine" {
		p = "docs/quarantine/README.md"
	}
	if out, ok := g.outOf[p]; ok {
		return g.base + out + withFrag(frag)
	}
	if strings.HasPrefix(p, "docs/images/") || strings.HasPrefix(p, "assets/") {
		return g.base + p
	}
	kind := "blob"
	if strings.HasSuffix(dest, "/") {
		kind = "tree"
	}
	return fmt.Sprintf("%s/%s/%s/%s%s", repoURL, kind, g.commit, p, withFrag(frag))
}

func withFrag(f string) string {
	if f == "" {
		return ""
	}
	return "#" + f
}

func (g *generator) render(src []byte, srcPath string) (string, string) {
	doc := parse(src)
	title := ""
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Heading:
			if n.Level == 1 && title == "" {
				title = string(n.Text(src)) //nolint:staticcheck // plain text is what a title needs
			}
		case *ast.Link:
			n.Destination = []byte(g.rewrite(string(n.Destination), srcPath))
		case *ast.Image:
			n.Destination = []byte(g.rewrite(string(n.Destination), srcPath))
		}
		return ast.WalkContinue, nil
	})
	sectionLevel := 2
	if srcPath == "docs/usage.md" {
		sectionLevel = 3 // demote makes each ### a page's h2
	}
	g.addIcons(doc, src, sectionLevel)
	var buf bytes.Buffer
	if err := md.Renderer().Render(&buf, src, doc); err != nil {
		log.Fatal(err)
	}
	out := buf.String()
	out = strings.ReplaceAll(out, "<table>", `<div class="table"><table>`)
	out = strings.ReplaceAll(out, "</table>", "</table></div>")
	return out, title
}

var (
	h2Start     = regexp.MustCompile(`<h2 id="([^"]+)">`)
	headingTag  = regexp.MustCompile(`<(/?)h([1-6])([ >])`)
	readmeImage = regexp.MustCompile(`(?m)^<img src="assets/emblem/[^\n]*\n`)
	badges      = regexp.MustCompile(`(?m)^\[!\[.*$\n?`)
)

// demote turns a section's ## into the page's h1 and moves every heading
// below it up one level, so a split usage page reads like a page of its own.
func demote(s string) string {
	return headingTag.ReplaceAllStringFunc(s, func(m string) string {
		parts := headingTag.FindStringSubmatch(m)
		n, _ := strconv.Atoi(parts[2])
		return "<" + parts[1] + "h" + strconv.Itoa(n-1) + parts[3]
	})
}

func main() {
	repo := flag.String("repo", ".", "bodega checkout")
	out := flag.String("out", "out", "output directory, which becomes the base path on the host")
	tmplDir := flag.String("tmpl", ".", "directory holding layout.html, site.css, pages/ and static/")
	version := flag.String("version", "", "release named in the footer: git describe at -commit, as the Makefile stamps the binary")
	commit := flag.String("commit", "", "full commit the pages were rendered from")
	base := flag.String("base", "/", "path the site is served under")
	coverage := flag.String("coverage", "", "coverage.json exported by site/scripts/coverage.py")
	flag.Parse()

	if broken := build(*repo, *out, *tmplDir, *version, *commit, *base, *coverage); broken > 0 {
		log.Fatalf("%d broken internal links", broken)
	}
}

// build writes the whole site under out and returns how many internal links
// and anchors in it resolve to nothing.
func build(repo, out, tmplDir, version, commit, base, coverage string) int {
	if version == "" || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) {
		log.Fatal("-version and a full 40-hex -commit are required; site/scripts/deploy.py supplies both from git")
	}
	css, err := os.ReadFile(filepath.Join(tmplDir, "site.css"))
	if err != nil {
		log.Fatalf("read the stylesheet: %v", err)
	}
	cssSum := sha256.Sum256(css)
	info := siteInfo{Base: base, Version: version, Commit: commit, CSSVersion: hex.EncodeToString(cssSum[:6])}

	scalar, err := vendoredScalar(tmplDir)
	if err != nil {
		log.Fatalf("%v; run site/scripts/update-scalar.sh with the version to vendor, then rebuild", err)
	}

	g := &generator{repo: repo, base: base, commit: info.Commit, outOf: map[string]string{}, usageSection: map[string]string{}}
	for _, c := range contents {
		if c.src != "coverage" && c.src != "docs/usage.md" && c.src != "api" {
			g.outOf[c.src] = docOut(c.src)
		}
	}
	g.outOf["README.md"] = ""
	// A doc links the OpenAPI document by its repository path, which is the
	// raw YAML on GitHub and the rendered reference here.
	g.outOf["api/openapi.yaml"] = apiDir
	g.outOf["api"] = apiDir

	usageSrc := read(repo, "docs/usage.md")
	section := ""
	_ = ast.Walk(parse(usageSrc), func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if h, ok := n.(*ast.Heading); ok && entering {
			if h.Level == 2 {
				section = string(h.Text(usageSrc)) //nolint:staticcheck // plain text matches the contents list
			}
			if h.Level >= 2 && section != "Table of Contents" {
				g.usageSection[headingID(h)] = usageOut(section)
			}
		}
		return ast.WalkContinue, nil
	})

	var pages []*page
	byKey := map[string]*page{}
	key := func(c source) string { return c.src + "#" + c.section }

	readme := read(repo, "README.md")
	readme = badges.ReplaceAll(readme, nil)
	readme = readmeImage.ReplaceAll(readme, nil)
	body, title := g.render(readme, "README.md")
	pages = append(pages, &page{Src: "README.md", Out: "index.html", Title: title, Kind: "home", Body: template.HTML(body)})

	usageHTML, _ := g.render(usageSrc, "docs/usage.md")
	chunks := map[string]string{}
	locs := h2Start.FindAllStringIndex(usageHTML, -1)
	intro := usageHTML[:locs[0][0]]
	for i, l := range locs {
		end := len(usageHTML)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		chunk := usageHTML[l[0]:end]
		h := regexp.MustCompile(`^<h2 id="[^"]+">(.*?)</h2>`).FindStringSubmatch(chunk)
		chunks[stdhtml.UnescapeString(stripTags(h[1]))] = chunk
	}

	for _, c := range contents {
		p := &page{Src: c.src, Group: c.group, Kind: "doc"}
		switch {
		case c.src == "api":
			p.Out, p.Title, p.Src, p.Kind = apiDir+"index.html", "API reference", apiSpec, "api"
			p.Body = apiBody(base, scalar)
		case c.src == "coverage":
			p.Out, p.Title, p.Src = "coverage.html", "Package support", ""
			p.Body = template.HTML("<h1>Package support</h1>\n" + renderCoverage(coverage, base))
		case c.src == "docs/usage.md" && c.section == "":
			p.Out, p.Title = "docs/usage/index.html", "Usage"
			toc := demote(chunks["Table of Contents"])
			toc = strings.Replace(toc, ">Table of Contents</h1>", ">Sections</h2>", 1)
			toc = strings.Replace(toc, "<h1 ", "<h2 ", 1)
			p.Body = template.HTML(intro + toc)
		case c.src == "docs/usage.md":
			chunk, ok := chunks[c.section]
			if !ok {
				log.Fatalf("docs/usage.md has no section %q", c.section)
			}
			p.Out, p.Title = usageOut(c.section), c.section
			p.Body = template.HTML(demote(chunk))
		default:
			b, t := g.render(read(repo, c.src), c.src)
			p.Out, p.Title = indexed(docOut(c.src)), t
			p.Body = template.HTML(b)
		}
		p.Outline = outline(string(p.Body))
		pages = append(pages, p)
		byKey[key(c)] = p
	}

	extra, _ := filepath.Glob(filepath.Join(tmplDir, "pages", "*.html"))
	for _, e := range extra {
		b := read("", e)
		b = bytes.ReplaceAll(b, []byte("{{base}}"), []byte(base))
		t := "bodega"
		if m := regexp.MustCompile(`<h1[^>]*>(.*?)</h1>`).FindSubmatch(b); m != nil {
			t = stdhtml.UnescapeString(string(m[1]))
		}
		name := strings.TrimSuffix(filepath.Base(e), ".html")
		pages = append(pages, &page{Out: name + ".html", Title: t, Kind: name, Body: template.HTML(b)})
	}

	layout := template.Must(template.New("layout.html").Funcs(template.FuncMap{
		"titleCase": strings.ToUpper,
		"hasPrefix": strings.HasPrefix,
	}).ParseFiles(filepath.Join(tmplDir, "layout.html")))
	for _, p := range pages {
		var groups []group
		var here entry
		n := 0
		for _, c := range contents {
			n++
			target := byKey[key(c)]
			if len(groups) == 0 || groups[len(groups)-1].Name != c.group {
				groups = append(groups, group{Name: c.group})
			}
			gr := &groups[len(groups)-1]
			e := entry{Num: strconv.Itoa(n), Title: target.Title, Href: base + strings.TrimSuffix(target.Out, "index.html"), Here: target == p, Children: target.Outline}
			gr.Entries = append(gr.Entries, e)
			if e.Here {
				gr.Here, here = true, e
			}
		}
		var buf bytes.Buffer
		if err := layout.Execute(&buf, struct {
			*page
			Site     siteInfo
			Contents []group
			Here     entry
		}{p, info, groups, here}); err != nil {
			log.Fatal(err)
		}
		write(filepath.Join(out, p.Out), buf.Bytes())
	}

	docsIndex := contentsPage(contents, byKey, base)
	var buf bytes.Buffer
	if err := layout.Execute(&buf, struct {
		*page
		Site     siteInfo
		Contents []group
		Here     entry
	}{docsIndex, info, nil, entry{}}); err != nil {
		log.Fatal(err)
	}
	write(filepath.Join(out, docsIndex.Out), buf.Bytes())

	copyTree(filepath.Join(repo, "docs", "images"), filepath.Join(out, "docs", "images"))
	copyTree(filepath.Join(repo, "assets", "emblem"), filepath.Join(out, "assets", "emblem"))
	copyTree(filepath.Join(tmplDir, "static"), out)
	copyFile(filepath.Join(tmplDir, "site.css"), filepath.Join(out, "site.css"))
	copyFile(filepath.Join(repo, "assets", "favicon.ico"), filepath.Join(out, "favicon.ico"))
	copyFile(filepath.Join(repo, "assets", "app", "icon-180.png"), filepath.Join(out, "icon-180.png"))
	write(filepath.Join(out, apiSpec), read(repo, "api/openapi.yaml"))
	// The snapshot the coverage page was rendered from. nginx answers /data/coverage.json
	// from the live feed instead, so this copy only serves a local build and the link check.
	copyFile(coverage, filepath.Join(out, "data", "coverage.json"))

	fmt.Printf("%d pages, bodega %s (%s)\n", len(pages)+1, info.Version, info.Commit)
	return checkLinks(out, base)
}

const (
	apiDir  = "api/"
	apiSpec = apiDir + "openapi.yaml"
)

// scalarBundle is the record site/scripts/update-scalar.sh writes beside the
// bundle it vendors.
type scalarBundle struct {
	Package string `json:"package"`
	Version string `json:"version"`
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
}

// vendoredScalar reads that record and refuses a bundle whose digest is not
// the recorded one: the page runs this file in the reader's browser, so an
// edit nobody recorded must stop the build rather than ship.
func vendoredScalar(tmplDir string) (scalarBundle, error) {
	dir := filepath.Join(tmplDir, "static", "scalar")
	var s scalarBundle
	record, err := os.ReadFile(filepath.Join(dir, "scalar.json"))
	if err != nil {
		return s, fmt.Errorf("the vendored Scalar bundle has no record: %w", err)
	}
	if err := json.Unmarshal(record, &s); err != nil {
		return s, fmt.Errorf("%s: %w", filepath.Join(dir, "scalar.json"), err)
	}
	if s.File != filepath.Base(s.File) || s.File == "" || s.Version == "" {
		return s, fmt.Errorf("%s names file %q at version %q, and needs a bare file name and a version", filepath.Join(dir, "scalar.json"), s.File, s.Version)
	}
	bundle, err := os.ReadFile(filepath.Join(dir, s.File))
	if err != nil {
		return s, fmt.Errorf("the vendored Scalar bundle is missing: %w", err)
	}
	sum := sha256.Sum256(bundle)
	if got := hex.EncodeToString(sum[:]); got != s.SHA256 {
		return s, fmt.Errorf("%s has sha256 %s, and scalar.json records %s for %s %s", filepath.Join(dir, s.File), got, s.SHA256, s.Package, s.Version)
	}
	return s, nil
}

// apiBody is Scalar's documented HTML integration: a mount point, the
// standalone bundle, and one createApiReference call. The mount point is not
// named "api-reference": the bundle mounts itself on an element with that id,
// with its defaults, which fetch fonts from scalar.com and show its agent
// beside the reference configured here. Everything the page loads is
// on this origin. The request client stays hidden because a request from this
// site to a reader's own bodega server would be cross-origin and carry their
// token; the other switches keep Scalar from reaching scalar.com for
// telemetry, fonts, its MCP hook and its agent.
func apiBody(base string, s scalarBundle) template.HTML {
	spec := template.HTMLEscapeString(base + apiSpec)
	config, err := json.Marshal(map[string]any{
		"url":                   base + apiSpec,
		"telemetry":             false,
		"withDefaultFonts":      false,
		"hideClientButton":      true,
		"hideTestRequestButton": true,
		"showDeveloperTools":    "never",
		"mcp":                   map[string]bool{"disabled": true},
		"agent":                 map[string]bool{"disabled": true},
		"layout":                "modern",
	})
	if err != nil {
		log.Fatal(err)
	}
	return template.HTML(fmt.Sprintf(`<noscript><h1>API reference</h1><p>This page renders bodega's OpenAPI document with a script. Without one, read the document itself: <a href="%s">openapi.yaml</a>.</p></noscript>
<div id="reference"></div>
<script src="%sscalar/%s?v=%.12s"></script>
<script>Scalar.createApiReference("#reference", %s);</script>
`, spec, template.HTMLEscapeString(base), template.HTMLEscapeString(s.File), s.SHA256, config))
}

func indexed(out string) string {
	if strings.HasSuffix(out, "/") {
		return out + "index.html"
	}
	return out
}

// contentsPage is /docs/: the contents column set as a page of its own, the
// way a book's contents page reads.
func contentsPage(contents []source, byKey map[string]*page, base string) *page {
	var b strings.Builder
	b.WriteString("<h1>Documentation</h1>\n<p>Every page below is generated from the Markdown in the repository, so it matches the source at the commit named in the footer.</p>\n")
	cur := ""
	n := 0
	for _, c := range contents {
		n++
		if c.group != cur {
			if cur != "" {
				b.WriteString("</ol>\n")
			}
			cur = c.group
			fmt.Fprintf(&b, "<h2>%s</h2>\n<ol class=\"contents\">\n", template.HTMLEscapeString(c.group))
		}
		p := byKey[c.src+"#"+c.section]
		fmt.Fprintf(&b, "<li><span>%d</span><a href=\"%s%s\">%s</a></li>\n", n, base, strings.TrimSuffix(p.Out, "index.html"), template.HTMLEscapeString(p.Title))
	}
	b.WriteString("</ol>\n")
	return &page{Out: "docs/index.html", Title: "Documentation", Kind: "page", Body: template.HTML(b.String())}
}

var outlineHeading = regexp.MustCompile(`<h([23]) id="([^"]+)">(.*?)</h[23]>`)

// outline nests each h3 under the h2 before it. An h3 with no h2 above it is
// listed at the top level rather than dropped.
func outline(body string) []heading {
	var out []heading
	for _, m := range outlineHeading.FindAllStringSubmatch(body, -1) {
		h := heading{ID: m[2], Title: stdhtml.UnescapeString(stripTags(m[3]))}
		if m[1] == "2" || len(out) == 0 {
			out = append(out, h)
			continue
		}
		last := &out[len(out)-1]
		last.Children = append(last.Children, h)
	}
	return out
}

var tags = regexp.MustCompile(`<[^>]+>`)

func stripTags(s string) string { return tags.ReplaceAllString(s, "") }

type coverageFeed struct {
	Revision    string `json:"revision"`
	EvaluatedAt string `json:"evaluatedAt"`
	Summary     string `json:"summary"`
	Packages    []struct {
		ID       string `json:"id"`
		Verdict  string `json:"verdict"`
		Reason   string `json:"reason"`
		Coverage string `json:"coverage"`
		Features []struct {
			Label, Description, Value, Evidence, State string
		} `json:"features"`
		Runs []struct {
			Text, Title, Class string
		} `json:"runs"`
	} `json:"packages"`
	Scoring struct {
		VerdictRules []struct {
			Verdict, Rule string
		} `json:"verdictRules"`
		FeatureWeights []struct {
			Weight   int      `json:"weight"`
			Features []string `json:"features"`
		} `json:"featureWeights"`
		FeatureValues []struct {
			Value, Counts string
		} `json:"featureValues"`
	} `json:"scoring"`
}

// renderCoverage sets the evaluated package report as tables at build time.
// site/scripts/deploy.py re-renders this page each time it publishes the feed.
func renderCoverage(file, base string) string {
	if file == "" {
		log.Fatal("-coverage is required: the coverage.json site/scripts/coverage.py writes")
	}
	var f coverageFeed
	if err := json.Unmarshal(read("", file), &f); err != nil {
		log.Fatalf("reading %s: %v", file, err)
	}
	if len(f.Packages) == 0 {
		log.Fatalf("%s lists no packages", file)
	}
	sort.Slice(f.Packages, func(i, j int) bool { return f.Packages[i].ID < f.Packages[j].ID })
	e := template.HTMLEscapeString
	var b strings.Builder
	fmt.Fprintf(&b, "<p class=\"lede\">%s</p>\n", e(f.Summary))
	fmt.Fprintf(&b, "<p>Evaluated %s against build <a href=\"%s/commit/%s\"><code>%s</code></a>. The <a href=\"/data/coverage.json\">current feed</a> may be newer than this page. Feature coverage and real-client test results are reported separately: a type can have every feature and still lack the runs that show it working.</p>\n",
		e(strings.Replace(strings.TrimSuffix(f.EvaluatedAt, ":00Z"), "T", " ", 1)+" UTC"), repoURL, e(f.Revision), e(f.Revision))

	b.WriteString("<h2 id=\"by-type\">By package type</h2>\n<p class=\"legend\">Features: <span class=\"v-yes\">yes</span> <span class=\"v-partial\">part</span> <span class=\"v-no\">no</span> <span class=\"v-na\">– not applicable</span></p>\n<div class=\"table\"><table class=\"coverage\">\n<thead><tr><th data-sort=\"type\" aria-sort=\"ascending\">Type</th><th data-sort=\"rank\">Verdict</th><th data-sort=\"coverage\">Coverage</th>")
	for _, ft := range f.Packages[0].Features {
		fmt.Fprintf(&b, "<th class=\"feature\" title=\"%s\"><span>%s</span></th>", e(ft.Description), e(ft.Label))
	}
	b.WriteString("</tr></thead>\n<tbody>\n")
	marks := map[string]string{"yes": "yes", "no": "no", "partial": "part", "n/a": "–"}
	for _, p := range f.Packages {
		fmt.Fprintf(&b, "<tr data-type=\"%s\" data-rank=\"%d\" data-coverage=\"%d\"><th scope=\"row\">", e(p.ID), verdictRank(p.Verdict), coveragePercent(p.Coverage))
		fmt.Fprintf(&b, "%s<a href=\"#%s\">%s</a></th><td class=\"verdict %s\">%s</td><td class=\"num\">%s</td>", labelIcon(base, p.ID), e(p.ID), e(p.ID), verdictClass(p.Verdict), e(p.Verdict), e(p.Coverage))
		for _, ft := range p.Features {
			mark, ok := marks[ft.Value]
			if !ok {
				mark = ft.Value
			}
			fmt.Fprintf(&b, "<td class=\"mark v-%s\">%s</td>", e(strings.ReplaceAll(ft.Value, "/", "")), e(mark))
		}
		b.WriteString("</tr>\n")
	}
	b.WriteString("</tbody></table></div>\n" + sortScript)

	b.WriteString("<h2 id=\"evidence\">Evidence</h2>\n<dl class=\"evidence\">\n")
	for _, p := range f.Packages {
		fmt.Fprintf(&b, "<dt id=\"%s\">%s%s <span class=\"verdict %s\">%s</span> <span>%s</span></dt>\n<dd><p>%s.</p>", e(p.ID), labelIcon(base, p.ID), e(p.ID), verdictClass(p.Verdict), e(p.Verdict), e(p.Coverage), e(capitalize(p.Reason)))
		if len(p.Runs) > 0 {
			b.WriteString("<ul class=\"runs\">")
			for _, r := range p.Runs {
				fmt.Fprintf(&b, "<li class=\"%s\">%s <small>%s</small></li>", e(r.Class), e(r.Text), e(r.Title))
			}
			b.WriteString("</ul>")
		} else {
			b.WriteString("<p class=\"none\">No current real-client run.</p>")
		}
		var notes []string
		for _, ft := range p.Features {
			if ft.Evidence != "" {
				notes = append(notes, fmt.Sprintf("<li><strong>%s</strong>: %s</li>", e(ft.Label), e(ft.Evidence)))
			}
		}
		if len(notes) > 0 {
			b.WriteString("<details><summary>Where each feature is implemented</summary><ul class=\"notes\">" + strings.Join(notes, "") + "</ul></details>")
		}
		b.WriteString("</dd>\n")
	}
	b.WriteString("</dl>\n")

	b.WriteString("<h2 id=\"reading\">How to read it</h2>\n<p>A verdict is the first rule below that matches, read top to bottom.</p>\n<div class=\"table\"><table><thead><tr><th>Verdict</th><th>When</th></tr></thead><tbody>\n")
	for _, r := range f.Scoring.VerdictRules {
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td></tr>\n", e(r.Verdict), e(r.Rule))
	}
	b.WriteString("</tbody></table></div>\n<p>Coverage weighs each applicable feature:</p>\n<div class=\"table\"><table><thead><tr><th>Weight</th><th>Features</th></tr></thead><tbody>\n")
	for _, w := range f.Scoring.FeatureWeights {
		fmt.Fprintf(&b, "<tr><td>×%d</td><td>%s</td></tr>\n", w.Weight, e(strings.Join(w.Features, ", ")))
	}
	b.WriteString("</tbody></table></div>\n<div class=\"table\"><table><thead><tr><th>Value</th><th>Counts as</th></tr></thead><tbody>\n")
	for _, v := range f.Scoring.FeatureValues {
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td></tr>\n", e(v.Value), e(v.Counts))
	}
	b.WriteString("</tbody></table></div>\n<p>What each feature column means:</p>\n<dl class=\"features\">\n")
	for _, ft := range f.Packages[0].Features {
		fmt.Fprintf(&b, "<dt>%s</dt><dd>%s</dd>\n", e(ft.Label), e(ft.Description))
	}
	b.WriteString("</dl>\n")
	return b.String()
}

// verdictRank orders verdicts from best to worst, so sorting by verdict reads
// as a severity scale rather than alphabetically. An unknown verdict sorts last.
func verdictRank(v string) int {
	for i, name := range []string{"Ready", "Usable", "Partial", "Not yet", "Unverified", "Not served"} {
		if v == name {
			return i
		}
	}
	return 99
}

func coveragePercent(c string) int {
	n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(c), "%"))
	if err != nil {
		return -1
	}
	return n
}

// sortScript turns the Type, Verdict and Coverage headers into buttons that
// sort the rows, each click flipping the direction. Without JavaScript the
// headers stay plain and the rows keep the build's alphabetical order.
const sortScript = `<script>
(function () {
  var table = document.querySelector("table.coverage"), body = table.tBodies[0];
  var heads = table.querySelectorAll("th[data-sort]");
  function key(row, k) { return k === "type" ? row.dataset.type : Number(row.dataset[k]); }
  heads.forEach(function (th) {
    var button = document.createElement("button");
    button.type = "button";
    button.textContent = th.textContent;
    th.textContent = "";
    th.appendChild(button);
    button.addEventListener("click", function () {
      var k = th.dataset.sort, dir = th.getAttribute("aria-sort") === "ascending" ? -1 : 1;
      heads.forEach(function (h) { h.removeAttribute("aria-sort"); });
      th.setAttribute("aria-sort", dir === 1 ? "ascending" : "descending");
      Array.from(body.rows).sort(function (a, b) {
        var x = key(a, k), y = key(b, k);
        if (x < y) return -dir;
        if (x > y) return dir;
        return a.dataset.type < b.dataset.type ? -1 : 1;
      }).forEach(function (row) { body.appendChild(row); });
    });
  });
})();
</script>
`

// verdictClass names the CSS class for a verdict: "Not yet" becomes "v-not-yet".
func verdictClass(v string) string {
	return "v-" + strings.ReplaceAll(strings.ToLower(v), " ", "-")
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

var (
	idAttr   = regexp.MustCompile(`\sid="([^"]+)"`)
	linkAttr = regexp.MustCompile(`\s(?:href|src)="([^"]+)"`)
)

// checkLinks resolves every link under the base, and every fragment, against
// the files just written. A miss is printed and counted.
func checkLinks(out, base string) int {
	ids := map[string]map[string]bool{}
	var files []string
	_ = filepath.Walk(out, func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(p, ".html") {
			files = append(files, p)
			set := map[string]bool{}
			for _, m := range idAttr.FindAllStringSubmatch(string(read("", p)), -1) {
				set[stdhtml.UnescapeString(m[1])] = true
			}
			ids[p] = set
		}
		return nil
	})
	sort.Strings(files)
	broken := 0
	for _, f := range files {
		for _, m := range linkAttr.FindAllStringSubmatch(string(read("", f)), -1) {
			link := stdhtml.UnescapeString(m[1])
			u, err := url.Parse(link)
			if err != nil || u.Scheme != "" || u.Host != "" {
				continue
			}
			target := f
			switch {
			case u.Path == "":
			case strings.HasPrefix(u.Path, base):
				target = filepath.Join(out, strings.TrimPrefix(u.Path, base))
			case strings.HasPrefix(u.Path, "/"):
				continue
			default:
				target = filepath.Join(filepath.Dir(f), u.Path)
			}
			if st, err := os.Stat(target); err == nil && st.IsDir() {
				target = filepath.Join(target, "index.html")
			}
			if _, err := os.Stat(target); err != nil {
				fmt.Printf("%s: missing %s\n", f, link)
				broken++
			} else if u.Fragment != "" && strings.HasSuffix(target, ".html") && !ids[target][u.Fragment] {
				fmt.Printf("%s: missing fragment %s\n", f, link)
				broken++
			}
		}
	}
	fmt.Printf("%d pages checked, %d broken\n", len(files), broken)
	return broken
}

func read(dir, p string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, p))
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func write(p string, b []byte) {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		log.Fatal(err)
	}
}

func copyFile(from, to string) {
	in, err := os.Open(from)
	if err != nil {
		log.Fatal(err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		log.Fatal(err)
	}
	o, err := os.Create(to)
	if err != nil {
		log.Fatal(err)
	}
	defer o.Close()
	if _, err := io.Copy(o, in); err != nil {
		log.Fatal(err)
	}
}

func copyTree(from, to string) {
	err := filepath.Walk(from, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		copyFile(p, filepath.Join(to, rel))
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}

// iconTerms maps a word naming an operating system or package ecosystem to
// the Simple Icons slug drawn before it. Words with an everyday meaning (go,
// binary, ports) are left out: an icon before "ports" in a sentence about TCP
// would be wrong more often than right.
var iconTerms = map[string]string{
	"apt": "debian", "Debian": "debian", "Ubuntu": "ubuntu",
	"rpm": "redhat", "dnf": "redhat", "RHEL": "redhat", "Rocky": "rockylinux", "Rocky Linux": "rockylinux",
	"Linux": "linux", "FreeBSD": "freebsd", "freebsd": "freebsd", "pkg": "freebsd", "macOS": "apple",
	"pypi": "pypi", "PyPI": "pypi", "pip": "pypi", "npm": "npm", "cargo": "rust", "Cargo": "rust",
	"gomod": "go", "GOPROXY": "go", "git": "git", "Git": "git", "helm": "helm", "Helm": "helm",
	"oci": "opencontainersinitiative", "OCI": "opencontainersinitiative", "Docker": "docker",
	"maven": "apachemaven", "Maven": "apachemaven", "rubygems": "rubygems", "RubyGems": "rubygems",
}

var iconWord = func() *regexp.Regexp {
	words := make([]string, 0, len(iconTerms))
	for w := range iconTerms {
		words = append(words, regexp.QuoteMeta(w))
	}
	// Longest first, so "Rocky Linux" wins over "Rocky".
	sort.Slice(words, func(i, j int) bool {
		return len(words[i]) > len(words[j]) || len(words[i]) == len(words[j]) && words[i] < words[j]
	})
	return regexp.MustCompile(strings.Join(words, "|"))
}()

func iconSVG(base, slug string) string {
	return fmt.Sprintf(`<svg class="ico ico-%s" aria-hidden="true" focusable="false"><use href="%sicons.svg#i-%s"></use></svg>`, slug, base, slug)
}

// standalone reports whether the match at val[i:j] is a word on its own:
// apt-get, npm/lodash, go.mod and GitHub are not the terms they start with,
// while a sentence ending "...for apt." is.
func standalone(val []byte, i, j int) bool {
	glued := func(r byte) bool {
		return r == '-' || r == '_' || r == '/' || r == '@' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
	}
	if i > 0 && (glued(val[i-1]) || val[i-1] == '.') {
		return false
	}
	if j < len(val) && glued(val[j]) {
		return false
	}
	if j+1 < len(val) && val[j] == '.' && glued(val[j+1]) {
		return false
	}
	return true
}

// addIcons draws an icon before the first plain-text mention of each
// ecosystem in each section, the part of a page under one rendered h2. Code,
// headings and link text never get one: code is a literal someone pastes, and
// a heading or link already stands out. A table cell holding nothing but a
// term is a row label, so it gets one wherever it sits.
func (g *generator) addIcons(doc ast.Node, src []byte, sectionLevel int) {
	var events []ast.Node
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch n := n.(type) {
		case *ast.Heading:
			if n.Level <= sectionLevel {
				events = append(events, n)
			}
			return ast.WalkSkipChildren, nil
		case *ast.CodeSpan, *ast.Link, *ast.AutoLink, *ast.Image, *ast.FencedCodeBlock, *ast.CodeBlock, *ast.HTMLBlock, *ast.RawHTML:
			return ast.WalkSkipChildren, nil
		case *east.TableCell:
			events = append(events, n)
			return ast.WalkSkipChildren, nil
		case *ast.Text:
			events = append(events, n)
		}
		return ast.WalkContinue, nil
	})
	seen := map[string]bool{}
	for _, ev := range events {
		switch n := ev.(type) {
		case *ast.Heading:
			seen = map[string]bool{}
		case *east.TableCell:
			g.labelCell(n, src)
		case *ast.Text:
			g.iconText(n, src, seen)
		}
	}
}

func (g *generator) iconNode(slug string) ast.Node {
	s := ast.NewString([]byte(iconSVG(g.base, slug)))
	s.SetCode(true) // goldmark writes a code String unescaped
	return s
}

func (g *generator) iconText(n *ast.Text, src []byte, seen map[string]bool) {
	if n.IsRaw() {
		return
	}
	seg := n.Segment
	val := seg.Value(src)
	parent, cur := n.Parent(), 0
	for _, m := range iconWord.FindAllIndex(val, -1) {
		slug := iconTerms[string(val[m[0]:m[1]])]
		if seen[slug] || !standalone(val, m[0], m[1]) {
			continue
		}
		seen[slug] = true
		if m[0] > cur {
			parent.InsertBefore(parent, n, ast.NewTextSegment(text.NewSegment(seg.Start+cur, seg.Start+m[0])))
		}
		parent.InsertBefore(parent, n, g.iconNode(slug))
		cur = m[0]
	}
	n.Segment = seg.WithStart(seg.Start + cur)
}

func (g *generator) labelCell(cell *east.TableCell, src []byte) {
	only := cell.FirstChild()
	if only == nil || only.NextSibling() != nil {
		return
	}
	inner := ast.Node(only)
	if cs, ok := only.(*ast.CodeSpan); ok {
		if inner = cs.FirstChild(); inner == nil || inner.NextSibling() != nil {
			return
		}
	}
	t, ok := inner.(*ast.Text)
	if !ok {
		return
	}
	if slug, ok := iconTerms[strings.TrimSpace(string(t.Segment.Value(src)))]; ok {
		cell.InsertBefore(cell, only, g.iconNode(slug))
	}
}

// labelIcon is the icon for a coverage row named by a package type, or nothing
// for a type with no mark.
func labelIcon(base, id string) string {
	if slug, ok := iconTerms[id]; ok {
		return iconSVG(base, slug)
	}
	return ""
}
