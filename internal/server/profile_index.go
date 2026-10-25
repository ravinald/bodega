package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// The index filters. Each takes the document one ecosystem's resolver reads
// and returns it with the versions a profile does not permit removed.
//
// The request predicate is the control and these are not: a client that
// already holds a tarball URL fetches it without reading any index, so an
// implementation that only filtered here would enforce nothing. What they buy
// is a refusal the client's own resolver can act on. pip told "no matching
// distribution" picks another version; pip handed a 403 halfway through an
// install stops with a stack trace and leaves the environment half-built.
//
// permit is nil wherever the profile states no rule for the package, and every
// filter returns the document untouched for a nil predicate rather than
// running a pass that permits everything. That is what keeps an install with
// no profiles paying nothing.

// filterGomodList drops the versions a profile does not permit from a
// GOPROXY @v/list. The document is one version per line and nothing else, so
// the filter is the whole grammar.
func filterGomodList(body []byte, permit func(string) bool) []byte {
	if permit == nil {
		return body
	}
	var out bytes.Buffer
	for _, line := range strings.Split(string(body), "\n") {
		v := strings.TrimSpace(line)
		if v == "" || !permit(v) {
			continue
		}
		out.WriteString(v)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// filterCargoIndex drops the releases a profile does not permit from a sparse
// index document, which is one JSON object per line.
//
// A line that does not parse, or carries no vers, is passed through. cargo
// reads this document and bodega does not author it: dropping a line nothing
// here understood would refuse a crate on the strength of a field bodega
// failed to read, which is a refusal nobody decided.
func filterCargoIndex(body []byte, permit func(string) bool) []byte {
	if permit == nil {
		return body
	}
	var out bytes.Buffer
	for _, line := range bytes.Split(body, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec struct {
			Vers string `json:"vers"`
		}
		if err := json.Unmarshal(line, &rec); err == nil && rec.Vers != "" && !permit(rec.Vers) {
			continue
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// pypiAnchorElementPattern matches one whole anchor, tag through closing tag.
// A PEP 503 index is generated HTML with one anchor per file and nothing
// nested inside it, so an element can be dropped without a parser — and
// dropping the element rather than the opening tag is what keeps the filename
// text from being left behind as a bare word pip would render and nobody could
// click.
var pypiAnchorElementPattern = regexp.MustCompile(`(?s)<a\s[^>]*>.*?</a>`)

// filterPypiSimplePage drops the files a profile does not permit from a PEP
// 503 per-distribution index.
//
// The version comes off the filename through pypiPageVersion, which strips
// the page's own distribution name rather than guessing where the name ends.
// The wheel route makes the looser parse when the client comes back for the
// file, because a URL is all it has. The two have to agree on every name
// either can place: they are the index and the artifact for one file, so a
// page that lists what the route then refuses is the mid-install 403 this
// filter exists to prevent, and a page that hides what the route would serve
// loses a release nobody decided against.
//
// A file whose name yields no version is kept. What could not be read is not a
// version the profile refused, and dropping it would hide an artifact on the
// strength of a filename shape.
func filterPypiSimplePage(body []byte, pkg string, permit func(string) bool) []byte {
	if permit == nil {
		return body
	}
	return pypiAnchorElementPattern.ReplaceAllFunc(body, func(el []byte) []byte {
		m := pypiHrefPattern.FindSubmatch(el)
		if m == nil {
			return el
		}
		version := pypiPageVersion(pkg, pypiHrefFilename(string(m[1])))
		if version == "" || permit(version) {
			return el
		}
		return nil
	})
}

// filterPackumentVersions drops rejected versions from an npm packument,
// along with the time entries and dist-tags that point at them.
//
// It is the whole of what filterPackumentByManifest and the profile filter
// each do, differing only in what they reject. Two copies of this walk is how
// one of them would keep a dist-tag naming a version the other had removed,
// which npm resolves by installing the version bodega then refuses.
func filterPackumentVersions(body []byte, rejected func(string) bool) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	withholdPackumentVersions(doc, rejected)
	return json.Marshal(doc)
}

// withholdPackumentVersions is filterPackumentVersions on a document already
// parsed, for a caller that has more to do to it before it is serialized.
func withholdPackumentVersions(doc map[string]any, rejected func(string) bool) {
	if versions, ok := doc["versions"].(map[string]any); ok {
		for v := range versions {
			if rejected(v) {
				delete(versions, v)
			}
		}
	}
	if times, ok := doc["time"].(map[string]any); ok {
		for v := range times {
			if v == "created" || v == "modified" {
				continue
			}
			if rejected(v) {
				delete(times, v)
			}
		}
	}
	if tags, ok := doc["dist-tags"].(map[string]any); ok {
		for tag, v := range tags {
			s, ok := v.(string)
			if !ok {
				continue
			}
			if rejected(s) {
				delete(tags, tag)
			}
		}
	}
}

// filterPackumentByProfile drops the versions a profile does not permit.
func filterPackumentByProfile(body []byte, permit func(string) bool) ([]byte, error) {
	if permit == nil {
		return body, nil
	}
	return filterPackumentVersions(body, func(v string) bool { return !permit(v) })
}

// helmChartKeyPattern matches the chart name that opens one entry in a helm
// index: two spaces, a name, a colon, nothing else on the line.
var helmChartKeyPattern = regexp.MustCompile(`^  ([^\s:][^:]*):\s*$`)

// helmVersionPattern matches the version field of a chart release, at either
// of the two indents a helm index puts it at.
var helmVersionPattern = regexp.MustCompile(`^\s+-?\s*version:\s*"?([^"\s]+)"?\s*$`)

// filterHelmIndex drops the charts and releases a profile does not permit from
// an index.yaml.
//
// Line-based rather than parsed, because bodega carries no YAML library and
// pulling one in to filter one document is a dependency the whole binary then
// answers for. The grammar it needs is small and fixed: helm's own `repo
// index` and bodega's generator both write a two-space chart key followed by a
// list of releases, and a release's version is the only field read.
//
// Everything outside the entries block passes through untouched, including
// apiVersion and generated. A document whose shape this does not recognize
// comes back as it went in: a chart list nobody could parse is not a chart
// list a profile refused, and the request predicate is what stops the fetch
// either way.
func filterHelmIndex(body []byte, covers func(chart string) bool, permit func(chart, version string) bool) []byte {
	if covers == nil {
		return body
	}
	lines := strings.Split(string(body), "\n")
	var out []string

	// A group is one chart key line and the release blocks that follow it. The
	// key repeats per release in the document bodega's own builder writes and
	// appears once in helm's, so grouping rather than counting handles both.
	var chart, keyLine string
	var block []string
	var kept []string

	flushBlock := func() {
		if len(block) == 0 {
			return
		}
		version := ""
		for _, l := range block {
			if m := helmVersionPattern.FindStringSubmatch(l); m != nil {
				version = m[1]
				break
			}
		}
		if version == "" || permit == nil || permit(chart, version) {
			kept = append(kept, block...)
		}
		block = nil
	}
	flushGroup := func() {
		flushBlock()
		if keyLine != "" && len(kept) > 0 {
			out = append(out, keyLine)
			out = append(out, kept...)
		}
		keyLine, kept = "", nil
	}

	inEntries := false
	for _, line := range lines {
		if !inEntries {
			out = append(out, line)
			if strings.TrimRight(line, " \t") == "entries:" {
				inEntries = true
			}
			continue
		}
		// A key at the left margin ends the entries block. `helm repo index`
		// writes generated: there, and read as release content it is emitted
		// or dropped with whichever chart happened to come last.
		if line != "" && !strings.HasPrefix(line, " ") {
			flushGroup()
			inEntries = false
			out = append(out, line)
			continue
		}
		// The release check comes first because a release whose opening
		// field is a value-less mapping key ("  - annotations:") also
		// satisfies the chart-key pattern. `helm repo index` marshals through
		// sigs.k8s.io/yaml, which sorts keys, so every chart carrying Artifact
		// Hub annotations opens exactly that way and the other order read the
		// whole index as one empty chart.
		if strings.HasPrefix(line, "  - ") {
			flushBlock()
			block = append(block, line)
			continue
		}
		if m := helmChartKeyPattern.FindStringSubmatch(line); m != nil {
			flushGroup()
			chart = strings.TrimSpace(m[1])
			if covers(chart) {
				keyLine = line
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		block = append(block, line)
	}
	flushGroup()

	return []byte(strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n")
}

// indexFilterWriter buffers a proxied index so a profile filter runs over the
// whole document before the client sees it.
//
// Buffering rather than streaming, for the reason pypiIndexWriter and
// npmPackumentWriter each buffer: a version line, a JSON record or a YAML
// block cannot be dropped from a chunk that may have split it in half.
// proxyOrCache has already spooled the bytes and written them to the cache
// before the first Write lands here, so the cached object stays the document
// the upstream served and a cache hit filters identically to a miss.
//
// Over maxUpstreamBody the response is refused rather than relayed unfiltered.
// An index served past the filter is an index that lists what the profile
// refuses, which the client then fetches and is told 403 halfway through — the
// failure this whole path exists to avoid.
//
// It is not an http.Flusher and has no ReadFrom. Both would defeat the buffer.
type indexFilterWriter struct {
	http.ResponseWriter
	subject string // what the refusal names when the body is too large
	filter  func([]byte) []byte
	// parse replaces filter for a document that is decoded whole, where a
	// body bodega cannot read has no line to pass through and is refused like
	// one too large to buffer.
	parse  func([]byte) ([]byte, error)
	status int
	body   bytes.Buffer
	tooBig bool
}

func (p *indexFilterWriter) WriteHeader(code int) {
	if p.status == 0 {
		p.status = code
	}
}

func (p *indexFilterWriter) Write(b []byte) (int, error) {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	if int64(p.body.Len()+len(b)) > maxUpstreamBody {
		p.tooBig = true
		p.body.Reset()
		return 0, fmt.Errorf("index for %s exceeds bodega's %d-byte filter buffer", p.subject, maxUpstreamBody)
	}
	return p.body.Write(b)
}

// flush filters a successful index and writes the buffered response through. A
// refusal or an error passes untouched: those bodies list nothing, and a 403
// from the allow-list must reach the client as the handler wrote it.
func (p *indexFilterWriter) flush() error {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	body := p.body.Bytes()
	if p.status == http.StatusOK {
		if p.tooBig {
			err := fmt.Errorf("index for %s exceeds bodega's %d-byte filter buffer: serving it unfiltered would list versions this host is refused", p.subject, maxUpstreamBody)
			http.Error(p.ResponseWriter, err.Error(), http.StatusBadGateway)
			return err
		}
		if p.parse != nil {
			filtered, err := p.parse(body)
			if err != nil {
				err = fmt.Errorf("%s could not be filtered for this host's profile, and serving it unfiltered would list packages this host is refused: %w", p.subject, err)
				http.Error(p.ResponseWriter, err.Error(), http.StatusBadGateway)
				return err
			}
			body = filtered
		} else {
			body = p.filter(body)
		}
		// proxyS3 sets ETag from the stored object, which is the upstream
		// document rather than what is going out. Left on, it labels the
		// filtered body with a validator for different bytes.
		p.Header().Del("ETag")
	}
	p.Header().Set("Content-Length", strconv.Itoa(len(body)))
	p.ResponseWriter.WriteHeader(p.status)
	//nolint:gosec // G705: body is the filtered index; Content-Type is set by the handler or by proxyOrCache.
	_, err := p.ResponseWriter.Write(body)
	return err
}

// filterRubygemsInfo drops the versions a profile does not permit from a
// compact index info/<gem> file: a header, a "---" line, then one line per
// version and platform, opening with the version and a space.
//
// The version is compared with its platform suffix cut, as the gem route
// compares it, so a pin on 1.16.7 keeps 1.16.7-x86_64-linux. A line with no
// version on it passes through, for the reason filterCargoIndex gives.
func filterRubygemsInfo(body []byte, permit func(string) bool) []byte {
	if permit == nil {
		return body
	}
	var out bytes.Buffer
	inBody := false
	for _, line := range strings.SplitAfter(string(body), "\n") {
		if line == "" {
			continue
		}
		if !inBody {
			out.WriteString(line)
			inBody = strings.TrimRight(line, "\r\n") == "---"
			continue
		}
		if version, _, ok := strings.Cut(line, " "); ok && version != "" && !permit(rubygemsRelease(version)) {
			continue
		}
		out.WriteString(line)
	}
	return out.Bytes()
}

// rubygemsGemRule is one profile's reading of one gem: whether it appears at
// all, and the per-version predicate when its versions are filtered.
type rubygemsGemRule func(gem string) (listed bool, permit func(string) bool)

// rubygemsRuleFor binds a profile to the gem registry, and is nil when the
// profile states no rubygems rule, which is the signal to filter nothing.
func rubygemsRuleFor(p *entitle.Profile) rubygemsGemRule {
	if !p.Governs(manifest.TypeRubygems) {
		return nil
	}
	return func(gem string) (bool, func(string) bool) {
		if !p.Covers(manifest.TypeRubygems, gem).Permitted {
			return false, nil
		}
		return true, profileVersionFilter(p, manifest.TypeRubygems, gem)
	}
}

// filterRubygemsVersions rebuilds the compact index versions file for a
// profile: a header, "---", then "<gem> <v>[,<v>...] <md5 of info/<gem>>"
// lines, where a gem may appear on several lines as versions are appended and
// the last line's checksum is the current one.
//
// A gem the profile excludes loses every line. A gem whose versions it filters
// keeps the permitted versions, and every line it keeps carries the MD5 of the
// filtered info file infoSum returns: Bundler compares that checksum with the
// info file it holds and refuses one that disagrees, so the upstream's
// checksum next to a filtered info file fails every install of the gem. A gem
// whose listed versions all pass keeps its lines byte for byte, because its
// info file goes out unfiltered and the upstream checksum is still the true
// one; that is what keeps a profile pinning three gems from costing an info
// read for every gem in the registry.
//
// A gem whose filtered info file infoSum cannot checksum (its upstream info
// answers an error, or the allow-list has not approved it yet) loses every
// line rather than failing the document. The host could neither read that
// gem's info nor install it, so leaving it out is the answer Bundler would
// reach on its own; a 502 would turn one gem's outage into every install on
// every host bound to the profile.
//
// "-" before a version marks a yank, and the version is judged without it.
func filterRubygemsVersions(body []byte, rule rubygemsGemRule, infoSum func(gem string, permit func(string) bool) (string, error)) []byte {
	if rule == nil {
		return body
	}
	type gemLine struct {
		line, gem string
		versions  []string
	}
	var header []string
	var lines []gemLine
	inBody := false
	for _, line := range strings.SplitAfter(string(body), "\n") {
		if line == "" {
			continue
		}
		if !inBody {
			header = append(header, line)
			inBody = strings.TrimRight(line, "\r\n") == "---"
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			lines = append(lines, gemLine{line: line})
			continue
		}
		lines = append(lines, gemLine{line: line, gem: parts[0], versions: strings.Split(parts[1], ",")})
	}

	type gemView struct {
		listed bool
		permit func(string) bool
		cut    bool
		sum    string
		failed bool
	}
	views := map[string]*gemView{}
	for _, l := range lines {
		if l.gem == "" {
			continue
		}
		v, seen := views[l.gem]
		if !seen {
			v = &gemView{}
			v.listed, v.permit = rule(l.gem)
			views[l.gem] = v
		}
		if !v.listed || v.permit == nil {
			continue
		}
		for _, ver := range l.versions {
			if !v.permit(rubygemsRelease(strings.TrimPrefix(ver, "-"))) {
				v.cut = true
			}
		}
	}

	var out bytes.Buffer
	for _, h := range header {
		out.WriteString(h)
	}
	for _, l := range lines {
		v := views[l.gem]
		if l.gem == "" || (v.listed && !v.cut) {
			out.WriteString(l.line)
			continue
		}
		if !v.listed || v.failed {
			continue
		}
		var kept []string
		for _, ver := range l.versions {
			if v.permit(rubygemsRelease(strings.TrimPrefix(ver, "-"))) {
				kept = append(kept, ver)
			}
		}
		if len(kept) == 0 {
			continue
		}
		if v.sum == "" {
			sum, err := infoSum(l.gem, v.permit)
			if err != nil {
				v.failed = true
				continue
			}
			v.sum = sum
		}
		fmt.Fprintf(&out, "%s %s %s\n", l.gem, strings.Join(kept, ","), v.sum)
	}
	return out.Bytes()
}

// filterRubygemsSpecs drops the tuples a profile does not permit from a full
// index file (specs.4.8.gz and its latest_ and prerelease_ siblings): a gzipped
// Marshal array of [name, Gem::Version, platform]. A tuple bodega cannot read
// is kept, for the reason filterCargoIndex keeps a line.
func filterRubygemsSpecs(body []byte, rule rubygemsGemRule) ([]byte, error) {
	if rule == nil {
		return body, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, maxUpstreamBody+1))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	if int64(len(raw)) > maxUpstreamBody {
		return nil, fmt.Errorf("unpacks past bodega's %d-byte filter buffer", maxUpstreamBody)
	}
	filtered, err := filterRubygemsMarshalList(raw, func(el *rbValue) (string, string, bool) {
		if el.tag != '[' || len(el.items) != 3 {
			return "", "", false
		}
		name, ok := rbString(el.items[0])
		version, vok := rbGemVersion(el.items[1])
		return name, version, ok && vok
	}, rule)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(filtered); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// filterRubygemsDependencies drops the entries a profile does not permit from
// a dependency API answer: a Marshal array of hashes carrying :name and
// :number. An empty body is the upstream's answer to an empty gem list and
// passes as it came.
func filterRubygemsDependencies(body []byte, rule rubygemsGemRule) ([]byte, error) {
	if rule == nil || len(body) == 0 {
		return body, nil
	}
	return filterRubygemsMarshalList(body, func(el *rbValue) (string, string, bool) {
		name, ok := rbHashString(el, "name")
		number, nok := rbHashString(el, "number")
		return name, number, ok && nok
	}, rule)
}

// filterRubygemsMarshalList keeps the elements of a top-level Marshal array
// whose gem and version rule permits, as identify reads them.
func filterRubygemsMarshalList(raw []byte, identify func(*rbValue) (gem, version string, ok bool), rule rubygemsGemRule) ([]byte, error) {
	doc, err := rbUnmarshal(raw)
	if err != nil {
		return nil, err
	}
	if doc.tag != '[' {
		return nil, fmt.Errorf("%w: the top-level object is not an array", errRbShape)
	}
	kept := doc.items[:0:0]
	for _, el := range doc.items {
		gem, version, ok := identify(el)
		if ok {
			listed, permit := rule(gem)
			if !listed || (permit != nil && !permit(rubygemsRelease(version))) {
				continue
			}
		}
		kept = append(kept, el)
	}
	doc.items = kept
	return rbMarshal(doc), nil
}

// mavenVersionsBlock, mavenVersionElement and mavenLatestRelease read the
// three parts of a maven-metadata.xml a profile changes. The document is
// edited in place rather than decoded and re-encoded: it carries elements a
// filter has no reason to understand (plugins, snapshotVersions, lastUpdated),
// and encoding/xml would rewrite every one of them.
var (
	mavenVersionsBlock  = regexp.MustCompile(`(?s)<versions>.*?</versions>`)
	mavenVersionElement = regexp.MustCompile(`[ \t]*<version>\s*([^<]*?)\s*</version>[ \t]*(\r?\n)?`)
	mavenLatestRelease  = regexp.MustCompile(`([ \t]*)<(latest|release)>\s*([^<]*?)\s*</(?:latest|release)>([ \t]*\r?\n?)`)
)

// mavenMetadataVersions lists the versions a maven-metadata.xml names, in
// document order: its <versions> list, and <latest> and <release>, which
// filterMavenMetadata also judges when there is no list.
func mavenMetadataVersions(body []byte) []string {
	seen := map[string]bool{}
	var out []string
	note := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, block := range mavenVersionsBlock.FindAll(body, -1) {
		for _, m := range mavenVersionElement.FindAllSubmatch(block, -1) {
			note(string(m[1]))
		}
	}
	for _, m := range mavenLatestRelease.FindAllSubmatch(body, -1) {
		note(string(m[3]))
	}
	return out
}

// filterMavenMetadata drops the versions a profile does not permit from an
// artifact-level maven-metadata.xml and recomputes <latest> and <release>
// from what remains. Both are what a resolver asked for LATEST, RELEASE or a
// dynamic Gradle version reads first, so leaving the upstream's values would
// send it to a version this host is refused.
//
// Maven appends each deployed version to the list, so the last one left is
// latest and the last one left that is not a -SNAPSHOT is release. An element
// with nothing left to name is removed rather than emptied, which a resolver
// reads as metadata that names none, the same answer as no versions at all.
//
// A document with no <versions> list has nothing to recompute from, and its
// <latest> and <release> are dropped only when they name a refused version.
func filterMavenMetadata(body []byte, permit func(string) bool) []byte {
	if permit == nil {
		return body
	}
	var kept []string
	listed := false
	body = mavenVersionsBlock.ReplaceAllFunc(body, func(block []byte) []byte {
		listed = true
		return mavenVersionElement.ReplaceAllFunc(block, func(el []byte) []byte {
			v := string(mavenVersionElement.FindSubmatch(el)[1])
			if !permit(v) {
				return nil
			}
			kept = append(kept, v)
			return el
		})
	})
	latest, release := "", ""
	for _, v := range kept {
		latest = v
		if !strings.HasSuffix(v, "-SNAPSHOT") {
			release = v
		}
	}
	return mavenLatestRelease.ReplaceAllFunc(body, func(el []byte) []byte {
		m := mavenLatestRelease.FindSubmatch(el)
		tag, current := string(m[2]), string(m[3])
		want := release
		if tag == "latest" {
			want = latest
		}
		if !listed {
			if permit(current) {
				return el
			}
			want = ""
		}
		if want == "" {
			return nil
		}
		return fmt.Appendf(nil, "%s<%s>%s</%s>%s", m[1], tag, want, tag, m[4])
	})
}
