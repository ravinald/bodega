package clientconf

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// Where the maven system's two files go. The init script lives under Gradle's
// user home, which GRADLE_USER_HOME moves; the plan names the default.
const (
	MavenSettingsPath = "~/.m2/settings.xml"
	GradleInitPath    = "~/.gradle/init.d/bodega.gradle"
)

// The wrappers' distribution hosts. Each downloads its build tool from one of
// these before any repository setting is read, so only a binary_upstreams
// namespace on the same host reaches them.
const (
	mavenCentralURL = "https://repo.maven.apache.org/maven2/"
	gradleDistURL   = "https://services.gradle.org/"
)

// Maven renders the two files that send Maven and Gradle to bodega's
// repository: a settings.xml whose one mirror takes every repository a POM
// names, and a Gradle init script that replaces every repository a build
// names. Maven reads no init script, and Gradle reads settings.xml's mirrors
// only when a build opts in, so a host given one file still fetches from
// Maven Central through the other tool.
//
// The settings.xml is merged into an existing one by MergeMavenSettings when
// a plan is applied. The init script is bodega's own file and is replaced.
func Maven(base string, binaryUpstreams map[string]config.BinaryUpstream) []File {
	root := trim(base) + "/maven/"
	return []File{
		{
			System: manifest.TypeMaven,
			Label:  "Maven settings.xml",
			Paths:  everywhere(MavenSettingsPath),
			Content: "<settings>\n  <mirrors>\n    <mirror>\n      <id>bodega</id>\n      <mirrorOf>*</mirrorOf>\n      <url>" +
				xmlText(root) + "</url>\n    </mirror>\n  </mirrors>\n</settings>\n",
			Notes: append([]string{"An existing settings.xml keeps its servers, profiles and every other setting; its <mirrors> become bodega's alone, since a second mirror would take some repositories around bodega"},
				MavenWrapperNotes(base, binaryUpstreams)...),
		},
		{
			System:  manifest.TypeMaven,
			Label:   "Gradle init script",
			Paths:   everywhere(GradleInitPath),
			Content: gradleInit(root),
		},
	}
}

// MavenWrapperNotes says how each project's wrapper is pointed at bodega. The
// Maven and Gradle wrappers download the build tool itself from
// distributionUrl before settings.xml or any init script applies, and the
// property lives in a file each project commits, which doctor does not edit.
func MavenWrapperNotes(base string, binaryUpstreams map[string]config.BinaryUpstream) []string {
	wrapper := func(tool, file, upstream, path, extra string) string {
		ns := binaryNamespaceFor(binaryUpstreams, upstream)
		note := fmt.Sprintf("The %s wrapper downloads %s before reading either file: in each project's %s, which doctor does not edit, set distributionUrl=%s/binaries/%s/%s",
			tool, tool, file, trim(base), nsOrPlaceholder(ns), path)
		switch {
		case ns == "":
			note += fmt.Sprintf(", once the server has a binary_upstreams namespace in open mode whose url is %s", upstream)
		case binaryUpstreams[ns].Mode != config.UpstreamModeOpen:
			note += fmt.Sprintf(", once binary_upstreams[%q] is in open mode or catalogs each distribution, since a catalog namespace answers 404 for any other", ns)
		}
		return note + extra
	}
	return []string{
		wrapper("Maven", ".mvn/wrapper/maven-wrapper.properties", mavenCentralURL,
			"org/apache/maven/apache-maven/<version>/apache-maven-<version>-bin.zip",
			"; a wrapperUrl, where the file has one, takes "+trim(base)+"/maven/ in place of "+mavenCentralURL),
		wrapper("Gradle", "gradle/wrapper/gradle-wrapper.properties", gradleDistURL,
			"distributions/gradle-<version>-bin.zip", "; distributionSha256Sum still matches, since bodega serves the bytes unchanged"),
	}
}

func nsOrPlaceholder(ns string) string {
	if ns == "" {
		return "<namespace>"
	}
	return ns
}

// binaryNamespaceFor is the binary_upstreams namespace whose url is upstream,
// compared by scheme, host and path with trailing slashes ignored, or "".
// Two such namespaces resolve to the first in sorted order, so two renders of
// one config agree.
func binaryNamespaceFor(binaryUpstreams map[string]config.BinaryUpstream, upstream string) string {
	want, err := url.Parse(upstream)
	if err != nil {
		return ""
	}
	var found []string
	for ns, up := range binaryUpstreams {
		u, err := url.Parse(up.URL)
		if err != nil || !strings.EqualFold(u.Scheme, want.Scheme) || !strings.EqualFold(u.Host, want.Host) ||
			strings.Trim(u.Path, "/") != strings.Trim(want.Path, "/") {
			continue
		}
		found = append(found, ns)
	}
	if len(found) == 0 {
		return ""
	}
	sort.Strings(found)
	return found[0]
}

// gradleInit is the init script for a repository at root. Every network
// repository a build names, in its settings, its plugin resolution, a
// buildscript block or a project, is removed as it is added, and bodega's is
// added in its place. Repositories on the local disk (mavenLocal(), flatDir)
// stay, since they reach no host. The plugin portal is the default only of an
// empty pluginManagement list, so adding bodega there replaces it too.
//
// Project repositories are added only under PREFER_PROJECT, the default: a
// build in FAIL_ON_PROJECT_REPOS fails when anything, an init script
// included, adds one, and PREFER_SETTINGS reads the settings' list, which
// carries bodega already.
func gradleInit(root string) string {
	insecure := ""
	if strings.HasPrefix(root, "http://") {
		insecure = "\n            allowInsecureProtocol = true"
	}
	return `// Written by bodega doctor --configure maven, and replaced whole on every
// run. Every network repository a build names is removed, and bodega's added
// in its place, so a dependency or plugin bodega does not serve fails to
// resolve rather than resolving around it.
def bodegaUrl = ` + groovyQuote(root) + `

def keepRepository = { ArtifactRepository repo ->
    if (repo instanceof FlatDirectoryArtifactRepository) {
        return true
    }
    if (!(repo instanceof UrlArtifactRepository) || repo.url == null) {
        return false
    }
    repo.url.scheme == 'file' || (repo instanceof MavenArtifactRepository && repo.url.toString() == bodegaUrl)
}

def bodegaOnly = { RepositoryHandler repos, boolean add ->
    repos.all { ArtifactRepository repo ->
        if (!keepRepository(repo)) {
            repos.remove(repo)
        }
    }
    if (add) {
        repos.maven {
            name = 'bodega'
            url = bodegaUrl` + insecure + `
        }
    }
}

def hasResolutionManagement = org.gradle.util.GradleVersion.current() >= org.gradle.util.GradleVersion.version('6.8')
def projectRepositories = true

beforeSettings { settings ->
    bodegaOnly(settings.buildscript.repositories, true)
    bodegaOnly(settings.pluginManagement.repositories, true)
    if (hasResolutionManagement) {
        bodegaOnly(settings.dependencyResolutionManagement.repositories, true)
    }
}

settingsEvaluated { settings ->
    if (hasResolutionManagement) {
        projectRepositories = settings.dependencyResolutionManagement.repositoriesMode.get().name() == 'PREFER_PROJECT'
    }
}

allprojects { project ->
    bodegaOnly(project.buildscript.repositories, true)
    bodegaOnly(project.repositories, projectRepositories)
}
`
}

var gradleInitURL = regexp.MustCompile(`(?m)^def bodegaUrl = '((?:[^'\\\n]|\\.)*)'$`)

// mergeGradleInit returns old with the init script bodega rendered into it
// replaced by planned, keeping every line around that script. Which lines are
// bodega's is settled by rendering the script again for the URL old names and
// finding it there byte for byte, which needs no Groovy parser. A script that
// does not hold that rendering was edited inside bodega's own lines, or was
// written by a release whose template differed, and replacing it whole would
// delete what its owner wrote, so it is an error for the caller to refuse.
func mergeGradleInit(old, planned []byte) ([]byte, error) {
	if len(bytes.TrimSpace(old)) == 0 {
		return planned, nil
	}
	for _, m := range gradleInitURL.FindAllSubmatch(old, -1) {
		root := strings.NewReplacer(`\\`, `\`, `\'`, `'`).Replace(string(m[1]))
		was := []byte(gradleInit(root))
		if at := bytes.Index(old, was); at >= 0 {
			return slices.Concat(old[:at], planned, old[at+len(was):]), nil
		}
	}
	return nil, errors.New("the script is not the one bodega doctor writes with lines of your own before or after it: it differs inside bodega's own lines, which this merge replaces as one block and does not edit")
}

// groovyQuote single-quotes s as a Groovy string literal.
func groovyQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// xmlText escapes s for an XML text node.
func xmlText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

const (
	mirrorsOpen   = "<mirrors>"
	mirrorsClose  = "</mirrors>"
	mirrorsEmpty  = "<mirrors/>"
	settingsClose = "</settings>"
)

// MergeMavenSettings returns existing with its <mirrors> element replaced by
// planned's, or planned's added before </settings> when existing has none.
// Everything else in existing (servers, profiles, proxies, comments, the XML
// declaration and namespaces) is kept byte for byte, which no XML decoder and
// encoder round trip does. The tags are found with comments masked out, so a
// <mirrors> inside the commented examples Maven's own settings.xml ships with
// is not mistaken for the live one. A file with no <mirrors> and no
// </settings>, or an unclosed <mirrors>, is not one Maven reads, and planned
// replaces it; the backup keeps what it held.
//
// The served setup script implements the same rule in awk, and a test holds
// the two to identical output.
func MergeMavenSettings(existing, planned []byte) []byte {
	old, plan := string(existing), string(planned)
	block, ok := mirrorsBlock(plan)
	if !ok || strings.TrimSpace(old) == "" {
		return planned
	}
	masked := maskXMLComments(old)
	var out string
	switch i, j := strings.Index(masked, mirrorsOpen), strings.Index(masked, mirrorsEmpty); {
	case i >= 0:
		k := strings.Index(masked[i:], mirrorsClose)
		if k < 0 {
			return planned
		}
		out = old[:i] + block + old[i+k+len(mirrorsClose):]
	case j >= 0:
		out = old[:j] + block + old[j+len(mirrorsEmpty):]
	default:
		k := strings.LastIndex(masked, settingsClose)
		if k < 0 {
			return planned
		}
		out = old[:k] + "  " + block + "\n" + old[k:]
	}
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return []byte(out)
}

// mavenLeaf is one child element of a <mirror>: where its tags stand and the
// character data between them.
type mavenLeaf struct {
	name string
	// open and close are the byte ranges of the start and end tags.
	open, close [2]int
	text        string
	// simple says the element holds character data and nothing else, CDATA
	// included, so replacing what stands between its tags replaces its value
	// and nothing more.
	simple bool
}

// mavenMirrorAt is one <mirror> of a settings.xml and where it stands.
type mavenMirrorAt struct {
	open, close [2]int
	leaves      []mavenLeaf
}

func (m mavenMirrorAt) named(name string) []mavenLeaf {
	var out []mavenLeaf
	for _, l := range m.leaves {
		if l.name == name {
			out = append(out, l)
		}
	}
	return out
}

// mavenDoc is where the parts of a settings.xml a mirror edit touches stand,
// as an XML tokenizer reads them: comments, CDATA, namespaces and entity
// references are its to tell apart, not a text search's.
type mavenDoc struct {
	// settingsClose is where </settings> opens.
	settingsClose int
	// mirrors are the tags of <settings><mirrors>, nil for a file without
	// one. The end tag of <mirrors/> is empty.
	mirrors *[2][2]int
	mirror  []mavenMirrorAt
}

// readMavenSettings locates the mirrors of a settings.xml. It refuses a
// document the tokenizer does not read to its end, one whose root is not
// <settings>, and one holding a second <mirrors>.
func readMavenSettings(data []byte) (mavenDoc, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var doc mavenDoc
	var path []string
	closed := false
	for {
		from := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return doc, fmt.Errorf("it is not XML this merge reads to its end: %w", err)
		}
		to := int(dec.InputOffset())
		at := [2]int{from, to}
		// leaf is the <mirror> child the token stands in, when it stands in one.
		var leaf *mavenLeaf
		if len(path) >= 4 && path[1] == "mirrors" && path[2] == "mirror" {
			m := &doc.mirror[len(doc.mirror)-1]
			leaf = &m.leaves[len(m.leaves)-1]
		}
		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			switch {
			case len(path) == 1 && t.Name.Local != "settings":
				return doc, fmt.Errorf("its root element is <%s>, not <settings>", t.Name.Local)
			case len(path) == 2 && t.Name.Local == "mirrors":
				if doc.mirrors != nil {
					return doc, errors.New("it holds more than one <mirrors> element")
				}
				doc.mirrors = &[2][2]int{at}
			case len(path) == 3 && path[1] == "mirrors" && t.Name.Local == "mirror":
				doc.mirror = append(doc.mirror, mavenMirrorAt{open: at})
			case len(path) == 4 && path[1] == "mirrors" && path[2] == "mirror":
				m := &doc.mirror[len(doc.mirror)-1]
				m.leaves = append(m.leaves, mavenLeaf{name: t.Name.Local, open: at, simple: true})
			case leaf != nil:
				leaf.simple = false
			}
		case xml.EndElement:
			switch {
			case len(path) == 1:
				doc.settingsClose, closed = from, true
			case len(path) == 2 && t.Name.Local == "mirrors":
				doc.mirrors[1] = at
			case len(path) == 3 && path[1] == "mirrors" && t.Name.Local == "mirror":
				doc.mirror[len(doc.mirror)-1].close = at
			case len(path) == 4 && leaf != nil:
				leaf.close = at
			}
			path = path[:len(path)-1]
		case xml.CharData:
			if leaf != nil && len(path) == 4 {
				leaf.text += string(t)
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
			if leaf != nil {
				leaf.simple = false
			}
		}
	}
	if !closed {
		return doc, errors.New("it holds no <settings> element")
	}
	return doc, nil
}

// mergeMavenMirror is MergeMavenSettings for a plan that edits the mirror
// named bodega and leaves the rest of <mirrors> alone: that mirror takes the
// plan's id, mirrorOf and url and keeps its other elements (mirrorOfLayouts,
// name), and the host's other mirrors stay, bodega's ahead of them when it is
// new, since Maven takes the first mirror that matches a repository. A
// <blocked>true</blocked> in bodega's mirror is removed on its own: Maven
// refuses every request through a blocked mirror.
//
// Every edit is a splice at a position the XML tokenizer gave, so the bytes
// outside the values the plan sets are the host's own. A value written as
// CDATA is character data like any other and is replaced between its tags. A
// file the edit cannot be placed in that way is refused, naming what stands
// in the way, and never replaced: a mirror named bodega twice, one of the
// plan's elements given twice or holding markup of its own, a document the
// tokenizer does not read.
func mergeMavenMirror(existing, planned []byte) ([]byte, error) {
	if len(bytes.TrimSpace(existing)) == 0 {
		return planned, nil
	}
	plan, err := readMavenSettings(planned)
	if err != nil || len(plan.mirror) != 1 {
		return nil, fmt.Errorf("the planned settings.xml does not hold one mirror (%v)", err)
	}
	block := string(planned[plan.mirrors[0][0]:plan.mirrors[1][1]])
	// own is the plan's mirror with the whitespace leading it, as it stands
	// under <mirrors>.
	own := string(planned[plan.mirrors[0][1]:plan.mirror[0].close[1]])
	want := plan.mirror[0].leaves
	ids := plan.mirror[0].named("id")
	if len(ids) != 1 {
		return nil, errors.New("the planned mirror does not hold one id")
	}
	id := strings.TrimSpace(ids[0].text)

	doc, err := readMavenSettings(existing)
	if err != nil {
		return nil, err
	}
	old := string(existing)
	type edit struct {
		from, to int
		text     string
	}
	var edits []edit
	added := 0
	switch {
	case doc.mirrors == nil:
		edits, added = []edit{{doc.settingsClose, doc.settingsClose, "  " + block + "\n"}}, 1
	case doc.mirrors[1][0] == doc.mirrors[1][1]:
		edits, added = []edit{{doc.mirrors[0][0], doc.mirrors[0][1], block}}, 1
	default:
		var mine []mavenMirrorAt
		for _, m := range doc.mirror {
			for _, l := range m.named("id") {
				if !l.simple {
					return nil, errors.New("a mirror's <id> holds markup, so which mirror is bodega's cannot be told")
				}
				if strings.TrimSpace(l.text) == id {
					mine = append(mine, m)
					break
				}
			}
		}
		if len(mine) > 1 {
			return nil, fmt.Errorf("it defines the mirror %s %d times, and which one Maven's other settings were written for cannot be told", id, len(mine))
		}
		if len(mine) == 0 {
			edits, added = []edit{{doc.mirrors[0][1], doc.mirrors[0][1], own}}, 1
			break
		}
		m := mine[0]
		lead, last := "", m.open[1]
		if len(m.leaves) > 0 {
			last = m.leaves[len(m.leaves)-1].close[1]
			if gap := old[m.open[1]:m.leaves[0].open[0]]; strings.TrimSpace(gap) == "" {
				lead = gap
			}
		}
		for _, l := range m.named("blocked") {
			switch {
			case !l.simple:
				return nil, fmt.Errorf("the mirror %s holds a <blocked> element with markup inside it", id)
			case strings.TrimSpace(l.text) == "true":
				from := l.open[0]
				for from > 0 && strings.ContainsRune(" \t", rune(old[from-1])) {
					from--
				}
				if from > 0 && old[from-1] == '\n' {
					from--
				}
				edits = append(edits, edit{max(from, m.open[1]), l.close[1], ""})
			}
		}
		var missing string
		for _, w := range want {
			raw := string(planned[w.open[1]:w.close[0]])
			switch have := m.named(w.name); {
			case len(have) == 0:
				missing += lead + string(planned[w.open[0]:w.close[1]])
			case len(have) > 1:
				return nil, fmt.Errorf("the mirror %s holds <%s> %d times", id, w.name, len(have))
			case !have[0].simple:
				return nil, fmt.Errorf("the <%s> of the mirror %s holds markup other than its text", w.name, id)
			case strings.TrimSpace(have[0].text) != strings.TrimSpace(w.text):
				edits = append(edits, edit{have[0].open[1], have[0].close[0], raw})
			}
		}
		if missing != "" {
			edits = append(edits, edit{last, last, missing})
		}
	}
	slices.SortStableFunc(edits, func(a, b edit) int { return b.from - a.from })
	out := old
	for _, e := range edits {
		out = out[:e.from] + e.text + out[e.to:]
	}
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if err := mavenKeeps(doc, []byte(out), want, id, added); err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// mavenKeeps checks a merged settings.xml against the document it was merged
// from: the mirror named id reads as the plan sets it, once, and every other
// element of every mirror the host had reads as it did.
func mavenKeeps(old mavenDoc, merged []byte, want []mavenLeaf, id string, added int) error {
	now, err := readMavenSettings(merged)
	if err != nil {
		return fmt.Errorf("with bodega's mirror merged in %w", err)
	}
	if len(now.mirror) != len(old.mirror)+added {
		return fmt.Errorf("the merge would leave %d mirrors where the host had %d", len(now.mirror), len(old.mirror))
	}
	isOwn := func(m mavenMirrorAt) bool {
		return slices.ContainsFunc(m.named("id"), func(l mavenLeaf) bool { return strings.TrimSpace(l.text) == id })
	}
	owned := 0
	for _, m := range now.mirror {
		if !isOwn(m) {
			continue
		}
		owned++
		for _, w := range want {
			if have := m.named(w.name); len(have) != 1 || strings.TrimSpace(have[0].text) != strings.TrimSpace(w.text) {
				return fmt.Errorf("the mirror %s would not read <%s> as the plan sets it", id, w.name)
			}
		}
		if slices.ContainsFunc(m.named("blocked"), func(l mavenLeaf) bool { return strings.TrimSpace(l.text) == "true" }) {
			return fmt.Errorf("the mirror %s would stay blocked", id)
		}
	}
	if owned != 1 {
		return fmt.Errorf("the mirror %s would be defined %d times", id, owned)
	}
	planned := func(name string) bool {
		return name == "blocked" || slices.ContainsFunc(want, func(w mavenLeaf) bool { return w.name == name })
	}
	for i, m := range old.mirror {
		// A mirror added by the merge leads the host's.
		after := now.mirror[i+added]
		for _, l := range m.leaves {
			if isOwn(m) && planned(l.name) {
				continue
			}
			if !slices.ContainsFunc(after.named(l.name), func(n mavenLeaf) bool { return n.text == l.text }) {
				return fmt.Errorf("the merge would not keep <%s>%s</%s> of the host's mirror %d", l.name, strings.TrimSpace(l.text), l.name, i+1)
			}
		}
	}
	return nil
}

// mirrorsBlock is the <mirrors>...</mirrors> element in a planned settings.xml.
func mirrorsBlock(plan string) (string, bool) {
	i := strings.Index(plan, mirrorsOpen)
	if i < 0 {
		return "", false
	}
	j := strings.Index(plan[i:], mirrorsClose)
	if j < 0 {
		return "", false
	}
	return plan[i : i+j+len(mirrorsClose)], true
}

// maskXMLComments returns s with every <!-- --> comment, delimiters included,
// replaced by as many spaces, so an index into the result is an index into s.
// An unterminated comment runs to the end.
func maskXMLComments(s string) string {
	var sb strings.Builder
	for {
		i := strings.Index(s, "<!--")
		if i < 0 {
			sb.WriteString(s)
			return sb.String()
		}
		sb.WriteString(s[:i])
		n := len(s) - i
		if j := strings.Index(s[i+4:], "-->"); j >= 0 {
			n = 4 + j + 3
		}
		sb.WriteString(strings.Repeat(" ", n))
		s = s[i+n:]
	}
}
