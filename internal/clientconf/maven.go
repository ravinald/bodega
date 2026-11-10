package clientconf

import (
	"fmt"
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

var (
	xmlLeaf     = regexp.MustCompile(`<([A-Za-z][\w.-]*)>([^<]*)</([A-Za-z][\w.-]*)>`)
	mirrorOpen  = "<mirror>"
	mirrorClose = "</mirror>"
)

// mirrorElements lists where each <mirror> element of masked stands, opening
// tag through closing tag.
func mirrorElements(masked string) [][2]int {
	var out [][2]int
	for at := 0; ; {
		i := strings.Index(masked[at:], mirrorOpen)
		if i < 0 {
			return out
		}
		j := strings.Index(masked[at+i:], mirrorClose)
		if j < 0 {
			return out
		}
		out = append(out, [2]int{at + i, at + i + j + len(mirrorClose)})
		at += i + j + len(mirrorClose)
	}
}

// mergeMavenMirror is MergeMavenSettings for a plan that edits the mirror
// named bodega and leaves the rest of <mirrors> alone: that mirror takes the
// plan's id, mirrorOf and url and keeps its other elements (mirrorOfLayouts,
// name), and the host's other mirrors stay, bodega's ahead of them when it is
// new, since Maven takes the first mirror that matches a repository. A
// <blocked>true</blocked> in bodega's mirror is removed on its own: Maven
// refuses every request through a blocked mirror. A bodega mirror written with
// CDATA or nested elements is replaced whole, the other mirrors still kept.
func mergeMavenMirror(existing, planned []byte) []byte {
	old, plan := string(existing), string(planned)
	block, ok := mirrorsBlock(plan)
	planMirrors := mirrorElements(block)
	masked := maskXMLComments(old)
	i := strings.Index(masked, mirrorsOpen)
	if !ok || len(planMirrors) != 1 || i < 0 {
		return MergeMavenSettings(existing, planned)
	}
	k := strings.Index(masked[i:], mirrorsClose)
	if k < 0 {
		return MergeMavenSettings(existing, planned)
	}
	inner := i + len(mirrorsOpen)
	// own is the plan's mirror with the whitespace leading it, as it stands
	// under <mirrors>.
	own := block[len(mirrorsOpen):planMirrors[0][1]]
	want := xmlLeaf.FindAllStringSubmatch(own, -1)
	id := ""
	for _, w := range want {
		if w[1] == "id" {
			id = strings.TrimSpace(w[2])
		}
	}
	for _, at := range mirrorElements(masked[inner : i+k]) {
		start, end := inner+at[0], inner+at[1]
		have := xmlLeaf.FindAllStringSubmatchIndex(masked[start:end], -1)
		isOwn := false
		for _, h := range have {
			tag, text := masked[start+h[2]:start+h[3]], strings.TrimSpace(masked[start+h[4]:start+h[5]])
			isOwn = isOwn || tag == "id" && text == id
		}
		if !isOwn {
			continue
		}
		elem := old[start:end]
		if strings.Count(masked[start:end], "<") != 2+2*len(have) {
			return []byte(old[:start] + strings.TrimSpace(own) + old[end:])
		}
		lead := elem[len(mirrorOpen) : len(mirrorOpen)+len(elem[len(mirrorOpen):])-len(strings.TrimLeft(elem[len(mirrorOpen):], " \t\r\n"))]
		last := len(mirrorOpen)
		var missing string
		type edit struct {
			from, to int
			text     string
		}
		var edits []edit
		for _, h := range have {
			last = h[1]
			if tag := elem[h[2]:h[3]]; tag == "blocked" && strings.TrimSpace(elem[h[4]:h[5]]) == "true" {
				from := h[0]
				for from > 0 && strings.ContainsRune(" \t", rune(elem[from-1])) {
					from--
				}
				if from > 0 && elem[from-1] == '\n' {
					from--
				}
				edits = append(edits, edit{from, h[1], ""})
			}
		}
		for _, w := range want {
			at := slices.IndexFunc(have, func(h []int) bool { return elem[h[2]:h[3]] == w[1] && elem[h[2]:h[3]] == elem[h[6]:h[7]] })
			if at < 0 {
				missing += lead + w[0]
				continue
			}
			edits = append(edits, edit{have[at][4], have[at][5], w[2]})
		}
		edits = append(edits, edit{last, last, missing})
		slices.SortStableFunc(edits, func(a, b edit) int { return b.from - a.from })
		for _, e := range edits {
			elem = elem[:e.from] + e.text + elem[e.to:]
		}
		return []byte(old[:start] + elem + old[end:])
	}
	return []byte(old[:inner] + own + old[inner:])
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
