// sitegen renders bodega's README, docs/ and coverage feed into the static
// project website. site/scripts/deploy.py runs it; see site/README.md.
package main

import (
	"bytes"
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
}

type entry struct {
	Num         string
	Title, Href string
	Here        bool
}

type group struct {
	Name    string
	Entries []entry
}

type siteInfo struct {
	Base, Version, Commit string
}

// A doc source and the contents group it is listed under. Usage sections are
// named by their ## heading and become pages of their own.
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

	if *version == "" || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(*commit) {
		log.Fatal("-version and a full 40-hex -commit are required; site/scripts/deploy.py supplies both from git")
	}
	info := siteInfo{Base: *base, Version: *version, Commit: *commit}

	g := &generator{repo: *repo, base: *base, commit: info.Commit, outOf: map[string]string{}, usageSection: map[string]string{}}
	for _, c := range contents {
		if c.src != "coverage" && c.src != "docs/usage.md" {
			g.outOf[c.src] = docOut(c.src)
		}
	}
	g.outOf["README.md"] = ""

	usageSrc := read(*repo, "docs/usage.md")
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

	readme := read(*repo, "README.md")
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
		case c.src == "coverage":
			p.Out, p.Title, p.Src = "coverage.html", "Package support", ""
			p.Body = template.HTML("<h1>Package support</h1>\n" + renderCoverage(*coverage, *base))
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
			b, t := g.render(read(*repo, c.src), c.src)
			p.Out, p.Title = indexed(docOut(c.src)), t
			p.Body = template.HTML(b)
		}
		pages = append(pages, p)
		byKey[key(c)] = p
	}

	extra, _ := filepath.Glob(filepath.Join(*tmplDir, "pages", "*.html"))
	for _, e := range extra {
		b := read("", e)
		b = bytes.ReplaceAll(b, []byte("{{base}}"), []byte(*base))
		t := "bodega"
		if m := regexp.MustCompile(`<h1[^>]*>(.*?)</h1>`).FindSubmatch(b); m != nil {
			t = stdhtml.UnescapeString(string(m[1]))
		}
		name := strings.TrimSuffix(filepath.Base(e), ".html")
		pages = append(pages, &page{Out: name + ".html", Title: t, Kind: name, Body: template.HTML(b)})
	}

	layout := template.Must(template.New("layout.html").Funcs(template.FuncMap{
		"titleCase": strings.ToUpper,
	}).ParseFiles(filepath.Join(*tmplDir, "layout.html")))
	for _, p := range pages {
		var groups []group
		n := 0
		for _, c := range contents {
			n++
			target := byKey[key(c)]
			if len(groups) == 0 || groups[len(groups)-1].Name != c.group {
				groups = append(groups, group{Name: c.group})
			}
			gr := &groups[len(groups)-1]
			gr.Entries = append(gr.Entries, entry{Num: fmt.Sprintf("%02d", n), Title: target.Title, Href: *base + strings.TrimSuffix(target.Out, "index.html"), Here: target == p})
		}
		var buf bytes.Buffer
		if err := layout.Execute(&buf, struct {
			*page
			Site     siteInfo
			Contents []group
		}{p, info, groups}); err != nil {
			log.Fatal(err)
		}
		write(filepath.Join(*out, p.Out), buf.Bytes())
	}

	docsIndex := contentsPage(pages, byKey, *base)
	var buf bytes.Buffer
	if err := layout.Execute(&buf, struct {
		*page
		Site     siteInfo
		Contents []group
	}{docsIndex, info, nil}); err != nil {
		log.Fatal(err)
	}
	write(filepath.Join(*out, docsIndex.Out), buf.Bytes())

	copyTree(filepath.Join(*repo, "docs", "images"), filepath.Join(*out, "docs", "images"))
	copyTree(filepath.Join(*repo, "assets", "emblem"), filepath.Join(*out, "assets", "emblem"))
	copyTree(filepath.Join(*tmplDir, "static"), *out)
	copyFile(filepath.Join(*tmplDir, "site.css"), filepath.Join(*out, "site.css"))
	copyFile(filepath.Join(*repo, "assets", "favicon.ico"), filepath.Join(*out, "favicon.ico"))
	copyFile(filepath.Join(*repo, "assets", "app", "icon-180.png"), filepath.Join(*out, "icon-180.png"))
	// The snapshot the coverage page was rendered from. nginx answers /data/coverage.json
	// from the live feed instead, so this copy only serves a local build and the link check.
	copyFile(*coverage, filepath.Join(*out, "data", "coverage.json"))

	fmt.Printf("%d pages, bodega %s (%s)\n", len(pages)+1, info.Version, info.Commit)
	if broken := checkLinks(*out, *base); broken > 0 {
		log.Fatalf("%d broken internal links", broken)
	}
}

func indexed(out string) string {
	if strings.HasSuffix(out, "/") {
		return out + "index.html"
	}
	return out
}

// contentsPage is /docs/: the contents column set as a page of its own, the
// way a book's contents page reads.
func contentsPage(pages []*page, byKey map[string]*page, base string) *page {
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
		fmt.Fprintf(&b, "<li><span>%02d</span><a href=\"%s%s\">%s</a></li>\n", n, base, strings.TrimSuffix(p.Out, "index.html"), template.HTMLEscapeString(p.Title))
	}
	b.WriteString("</ol>\n")
	return &page{Out: "docs/index.html", Title: "Documentation", Kind: "page", Body: template.HTML(b.String())}
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
		fmt.Fprintf(&b, "<a href=\"#%s\">%s</a></th><td class=\"verdict %s\">%s</td><td class=\"num\">%s</td>", e(p.ID), e(p.ID), verdictClass(p.Verdict), e(p.Verdict), e(p.Coverage))
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
		fmt.Fprintf(&b, "<dt id=\"%s\">%s <span class=\"verdict %s\">%s</span> <span>%s</span></dt>\n<dd><p>%s.</p>", e(p.ID), e(p.ID), verdictClass(p.Verdict), e(p.Verdict), e(p.Coverage), e(capitalize(p.Reason)))
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
