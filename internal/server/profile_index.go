package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
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
// The version comes off the filename through wheelIdentity, which is the same
// parse the wheel route makes when the client comes back for the file. A file
// whose name yields no version is kept: an sdist or a wheel bodega could not
// place is not a version the profile refused, and refusing what could not be
// read would hide artifacts on the strength of a filename shape.
func filterPypiSimplePage(body []byte, permit func(string) bool) []byte {
	if permit == nil {
		return body
	}
	return pypiAnchorElementPattern.ReplaceAllFunc(body, func(el []byte) []byte {
		m := pypiHrefPattern.FindSubmatch(el)
		if m == nil {
			return el
		}
		_, version := wheelIdentity(pypiHrefFilename(string(m[1])))
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

	return json.Marshal(doc)
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
		if m := helmChartKeyPattern.FindStringSubmatch(line); m != nil {
			flushGroup()
			chart = strings.TrimSpace(m[1])
			if covers(chart) {
				keyLine = line
			}
			continue
		}
		if strings.HasPrefix(line, "  - ") {
			flushBlock()
			block = append(block, line)
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		block = append(block, line)
	}
	flushGroup()

	return []byte(strings.Join(out, "\n") + "\n")
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
	status  int
	body    bytes.Buffer
	tooBig  bool
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
		body = p.filter(body)
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
