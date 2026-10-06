package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// The index filter: with `bodega policy filter set <type> on`, a proxied
// packument, simple page or @v/list goes out without the versions the age or
// OSV gate would block, so the client's resolver settles on the newest
// version that passes instead of the newest upstream and a refusal.
//
// The artifact route refuses the same versions on its own (refuseWithheld).
// An index is advice to a resolver, and a lockfile or a pasted URL never reads
// it, so the index must not be the only place the decision is enforced.

// filteredHeader names how many versions an index withheld and which gate
// withheld them, e.g. "3; age=2; osv=1". Absent when nothing was withheld.
const filteredHeader = "X-Bodega-Filtered"

// publishTimeFetchers bounds the upstream reads one index request makes to
// date versions it has not seen before. A gomod list carries no times, so a
// cold module costs a .info fetch per version; sixteen at a time keeps a list
// of a few hundred versions inside a client's patience without opening
// hundreds of connections to one host.
const publishTimeFetchers = 16

// maxPublishTimes caps the in-memory publish-time cache. A publish time never
// changes once a version exists, so entries never expire; the cap is there so
// a client walking every package on a registry cannot grow it without bound.
// Past it the cache starts over, which costs refetches and nothing else.
const maxPublishTimes = 200_000

// publishTimes caches upstream publish times by ecosystem, package and
// version. Caching is what keeps the filter from refetching a gomod .info per
// version per request: a version is fetched once, and from then on only the
// versions an upstream newly lists cost a read, which are the ones inside the
// age window.
type publishTimes struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func publishKey(eco, name, version string) string {
	return eco + "\x00" + name + "\x00" + version
}

func (p *publishTimes) get(eco, name, version string) (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.m[publishKey(eco, name, version)]
	return t, ok
}

func (p *publishTimes) put(eco, name, version string, t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil || len(p.m) >= maxPublishTimes {
		p.m = make(map[string]time.Time)
	}
	p.m[publishKey(eco, name, version)] = t
}

// guardedTransport runs the proxy's upstream guard on every request and every
// redirect hop. The age checker brings its own client, and pointed at the
// configured upstreams it would otherwise reach whatever a redirect named.
type guardedTransport struct{}

func (guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := upstreamGuard(req.URL.String()); err != nil {
		return nil, err
	}
	return http.DefaultTransport.RoundTrip(req)
}

// publishTimeClient holds every publish-time fetch to the rule the proxy
// fetches are held to.
var publishTimeClient = &http.Client{Timeout: 10 * time.Second, Transport: guardedTransport{}}

// publishClock is the age checker's own date sources, pointed at the
// upstreams this server proxies rather than at the public registries
// admission reads. The filter has to date the versions the client is shown,
// and those come from npm_upstream, pypi_upstream and gomod_upstream.
func (s *Server) publishClock() *policy.AgeChecker {
	c := policy.NewAgeChecker(nil)
	c.NpmRegistry = strings.TrimRight(s.cfg.NpmUpstream, "/")
	c.PypiBase = strings.TrimRight(s.cfg.PypiUpstream, "/")
	c.GoProxy = strings.TrimRight(s.cfg.GomodUpstream, "/")
	c.HTTP = publishTimeClient
	return c
}

// indexWithhold is one index response's pass through the gates. It counts
// what it withheld so the response can say so once, in a header and in one
// audit row, rather than once per version.
type indexWithhold struct {
	s       *Server
	r       *http.Request
	eco     string
	name    string
	gate    *policy.IndexGate
	counts  map[string]int
	undated int
}

// indexWithholdFor returns the filter pass for one proxied index, or nil when
// the filter is off for the type or neither gate blocks. A policy the server
// cannot read serves the index unfiltered and says so: the artifact route
// still decides, and failing the index closed would turn a database hiccup
// into every install on the type failing.
func (s *Server) indexWithholdFor(r *http.Request, eco, name string) *indexWithhold {
	if s.indexFilter == nil {
		return nil
	}
	gate, err := s.indexFilter.Gate(r.Context(), eco)
	if err != nil {
		s.logger.Warn("index filter policy unreadable; serving the index unfiltered",
			"type", eco, "package", name, "error", err)
		return nil
	}
	if gate == nil {
		return nil
	}
	return &indexWithhold{s: s, r: r, eco: eco, name: name, gate: gate, counts: map[string]int{}}
}

// decide returns the versions the gate withholds, each mapped to the gate
// that withholds it. A version with no publish time is kept and logged by
// name, never dropped quietly.
func (iw *indexWithhold) decide(versions []string, times map[string]time.Time) map[string]string {
	out := map[string]string{}
	for _, v := range versions {
		t, dated := times[v]
		if !dated && iw.gate.Dates() {
			iw.undated++
			iw.s.logger.Warn("publish time unreadable; the version stays in the filtered index",
				"type", iw.eco, "package", iw.name, "version", v)
		}
		if why := iw.gate.Withhold(iw.r.Context(), iw.name, v, t); why != "" {
			out[v] = why
			iw.counts[why]++
		}
	}
	return out
}

func (iw *indexWithhold) withheld() int {
	return iw.counts[policy.WithheldAge] + iw.counts[policy.WithheldOSV]
}

// finish labels the response and writes its one audit row. Called before the
// status line goes out, since it sets a header.
func (iw *indexWithhold) finish(h http.Header) {
	n := iw.withheld()
	if n == 0 {
		return
	}
	label := strconv.Itoa(n)
	for _, why := range []string{policy.WithheldAge, policy.WithheldOSV} {
		if c := iw.counts[why]; c > 0 {
			label += fmt.Sprintf("; %s=%d", why, c)
		}
	}
	h.Set(filteredHeader, label)

	db := iw.s.auditDB
	if db == nil || !db.ShouldRecord(audit.EventCache) {
		return
	}
	details, err := json.Marshal(map[string]any{
		"withheld": n,
		"age":      iw.counts[policy.WithheldAge],
		"osv":      iw.counts[policy.WithheldOSV],
		"undated":  iw.undated,
		"path":     truncateField(iw.r.URL.Path, maxDetailField),
	})
	if err != nil {
		details = []byte("{}")
	}
	ctx, cancel := auditContext(iw.r)
	defer cancel()
	if err := db.Record(ctx, audit.Event{
		EventType: audit.EventCache,
		PkgType:   iw.eco,
		PkgName:   iw.name,
		ClientIP:  ClientIP(iw.r),
		Identity:  Identity(iw.r),
		UserAgent: truncateField(iw.r.UserAgent(), maxDetailField),
		Status:    audit.CacheIndexFiltered,
		Details:   string(details),
	}); err != nil {
		iw.s.logger.Error("audit write failed, index filter outcome not recorded; still serving",
			"type", iw.eco, "package", iw.name, "error", err)
	}
}

// packument withholds from a proxied npm packument, dating each version by
// the packument's own time map. A withheld dist-tags.latest is repointed at
// the newest remaining release, because npm installs latest for a bare name
// and a document with no latest at all fails that install for want of a tag.
func (iw *indexWithhold) packument(body []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse packument for %s: %w", iw.name, err)
	}
	versions, _ := doc["versions"].(map[string]any)
	stamps, _ := doc["time"].(map[string]any)
	listed := make([]string, 0, len(versions))
	times := make(map[string]time.Time, len(versions))
	for v := range versions {
		listed = append(listed, v)
		s, _ := stamps[v].(string)
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			times[v] = t
			iw.s.publishTimes.put(iw.eco, iw.name, v, t)
		}
	}
	withheld := iw.decide(listed, times)
	if len(withheld) == 0 {
		return body, nil
	}

	latest, _ := doc["dist-tags"].(map[string]any)["latest"].(string)
	withholdPackumentVersions(doc, func(v string) bool { _, ok := withheld[v]; return ok })
	if _, gone := withheld[latest]; gone {
		if next := npmNewestRelease(doc["versions"]); next != "" {
			tags, ok := doc["dist-tags"].(map[string]any)
			if !ok {
				tags = map[string]any{}
				doc["dist-tags"] = tags
			}
			tags["latest"] = next
		}
	}
	return json.Marshal(doc)
}

// versionsMap withholds from the versions object of a packument bodega
// generated from a manifest entry. That document carries no time map, so the
// versions are dated from the upstream's.
func (iw *indexWithhold) versionsMap(versions map[string]any) {
	listed := make([]string, 0, len(versions))
	for v := range versions {
		listed = append(listed, v)
	}
	for v := range iw.decide(listed, iw.s.publishTimesFor(iw.r.Context(), iw.eco, iw.name, listed)) {
		delete(versions, v)
	}
}

// npmNewestRelease is the highest non-prerelease version in a packument's
// versions object. A prerelease is never promoted to latest: npm itself only
// moves latest there when a publisher says so.
func npmNewestRelease(versions any) string {
	m, _ := versions.(map[string]any)
	best := ""
	var bestSV builder.SemVer
	for v := range m {
		sv, ok := builder.ParseSemVer(v)
		if !ok || sv.Pre != "" {
			continue
		}
		if best == "" || bestSV.Less(sv) {
			best, bestSV = v, sv
		}
	}
	return best
}

// pypiPage withholds from a proxied PEP 503 simple page.
func (iw *indexWithhold) pypiPage(body []byte) []byte {
	seen := map[string]bool{}
	var listed []string
	for _, el := range pypiAnchorElementPattern.FindAll(body, -1) {
		m := pypiHrefPattern.FindSubmatch(el)
		if m == nil {
			continue
		}
		if v := pypiPageVersion(iw.name, pypiHrefFilename(string(m[1]))); v != "" && !seen[v] {
			seen[v] = true
			listed = append(listed, v)
		}
	}
	withheld := iw.decide(listed, iw.s.publishTimesFor(iw.r.Context(), iw.eco, iw.name, listed))
	if len(withheld) == 0 {
		return body
	}
	return filterPypiSimplePage(body, iw.name, func(v string) bool { _, ok := withheld[v]; return !ok })
}

// pypiJSON decides a proxied PEP 691 page, dating each version by the
// earliest upload-time the page itself carries and reading the rest the way
// the HTML page does.
func (iw *indexWithhold) pypiJSON(listed []string, uploaded map[string]time.Time) map[string]string {
	times := make(map[string]time.Time, len(listed))
	var undated []string
	for _, v := range listed {
		if t, ok := uploaded[v]; ok {
			times[v] = t
			iw.s.publishTimes.put(iw.eco, iw.name, v, t)
		} else {
			undated = append(undated, v)
		}
	}
	if len(undated) > 0 {
		for v, t := range iw.s.publishTimesFor(iw.r.Context(), iw.eco, iw.name, undated) {
			times[v] = t
		}
	}
	return iw.decide(listed, times)
}

// gomodList withholds from a proxied @v/list.
func (iw *indexWithhold) gomodList(body []byte) []byte {
	var listed []string
	for _, line := range strings.Split(string(body), "\n") {
		if v := strings.TrimSpace(line); v != "" {
			listed = append(listed, v)
		}
	}
	withheld := iw.decide(listed, iw.s.publishTimesFor(iw.r.Context(), iw.eco, iw.name, listed))
	if len(withheld) == 0 {
		return body
	}
	return filterGomodList(body, func(v string) bool { _, ok := withheld[v]; return !ok })
}

// refuseWithheld answers 403 for an artifact whose version the index filter
// withholds, and reports whether it did. It is the enforcement the filtered
// index advertises: a lockfile, a cached resolution or a hand-typed URL names
// the version without reading the index, and without this the filter would
// be the only thing standing between that request and the bytes.
//
// Called only where the index listing the artifact is a proxied one the
// filter rewrites, so an artifact this route refuses is never one a filtered
// index went on to list.
func (s *Server) refuseWithheld(w http.ResponseWriter, r *http.Request, eco, name, version string) bool {
	if version == "" {
		return false
	}
	iw := s.indexWithholdFor(r, eco, name)
	if iw == nil {
		return false
	}
	why := iw.decide([]string{version}, s.publishTimesFor(r.Context(), eco, name, []string{version}))[version]
	if why == "" {
		return false
	}
	reason := fmt.Sprintf("%s %s@%s has an OSV record and the %s OSV gate blocks it", eco, name, version, eco)
	if why == policy.WithheldAge {
		reason = fmt.Sprintf("%s %s@%s is newer than the %s minimum publish age the %s age gate blocks on",
			eco, name, version, policy.ShortDuration(iw.gate.MinAge), eco)
	}
	recordDenialFor(s.auditDB, r, eco, name, version, audit.DenialWithheldVersion,
		map[string]string{"check": why, "reason": reason})
	http.Error(w, reason+"; bodega's index for this package omits it, so resolve against the index or wait out the window", http.StatusForbidden)
	return true
}

// publishTimesFor dates versions of one package, from the cache where it can
// and from upstream where it cannot. A version missing from the result could
// not be dated, and the caller keeps it.
func (s *Server) publishTimesFor(ctx context.Context, eco, name string, versions []string) map[string]time.Time {
	out := make(map[string]time.Time, len(versions))
	var missing []string
	for _, v := range versions {
		if t, ok := s.publishTimes.get(eco, name, v); ok {
			out[v] = t
		} else {
			missing = append(missing, v)
		}
	}
	if len(missing) == 0 {
		return out
	}

	// One document dates every version where the ecosystem publishes one: the
	// packument's time map, and the PEP 700 upload-time on a JSON simple page.
	switch eco {
	case manifest.TypeNpm:
		s.npmPublishTimes(ctx, name)
	case manifest.TypePypi:
		s.pypiPublishTimes(ctx, name)
	}
	var still []string
	for _, v := range missing {
		if t, ok := s.publishTimes.get(eco, name, v); ok {
			out[v] = t
		} else {
			still = append(still, v)
		}
	}
	if eco == manifest.TypeNpm || len(still) == 0 {
		return out
	}

	// A version at a time: every gomod version, and the pypi versions a
	// simple page carried no upload-time for, through the same JSON API the
	// age gate reads.
	clock := s.publishClock()
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, publishTimeFetchers)
	for _, v := range still {
		wg.Add(1)
		slots <- struct{}{}
		go func(v string) {
			defer wg.Done()
			defer func() { <-slots }()
			t, err := clock.PublishedAt(ctx, eco, name, v)
			if err != nil {
				s.logger.Debug("publish time fetch failed", "type", eco, "package", name, "version", v, "error", err)
				return
			}
			s.publishTimes.put(eco, name, v, t)
			mu.Lock()
			out[v] = t
			mu.Unlock()
		}(v)
	}
	wg.Wait()
	return out
}

// npmPublishTimes caches every time in an upstream packument.
func (s *Server) npmPublishTimes(ctx context.Context, name string) {
	var doc struct {
		Time map[string]string `json:"time"`
	}
	url := strings.TrimRight(s.cfg.NpmUpstream, "/") + "/" + npmEscapeName(name)
	if err := s.upstreamJSON(ctx, url, "application/json", &doc); err != nil {
		s.logger.Debug("npm publish times unavailable", "package", name, "error", err)
		return
	}
	for v, ts := range doc.Time {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil && v != "created" && v != "modified" {
			s.publishTimes.put(manifest.TypeNpm, name, v, t)
		}
	}
}

// pypiJSONSimple is the PEP 691 media type, which carries PEP 700 upload-time
// per file where the HTML page carries none.
const pypiJSONSimple = "application/vnd.pypi.simple.v1+json"

// pypiPublishTimes caches the earliest upload-time of each version on the
// upstream's JSON simple page. Earliest because that is the moment the
// version became installable, which is the same reading the age gate takes
// off the JSON API.
func (s *Server) pypiPublishTimes(ctx context.Context, name string) {
	var doc struct {
		Files []struct {
			Filename   string `json:"filename"`
			UploadTime string `json:"upload-time"`
		} `json:"files"`
	}
	if err := s.upstreamJSON(ctx, s.pypiSimpleURL(manifest.CanonicalPypiName(name)), pypiJSONSimple, &doc); err != nil {
		s.logger.Debug("pypi JSON simple page unavailable", "package", name, "error", err)
		return
	}
	earliest := map[string]time.Time{}
	for _, f := range doc.Files {
		v := pypiPageVersion(name, f.Filename)
		t, err := time.Parse(time.RFC3339Nano, f.UploadTime)
		if v == "" || err != nil {
			continue
		}
		if e, ok := earliest[v]; !ok || t.Before(e) {
			earliest[v] = t
		}
	}
	for v, t := range earliest {
		s.publishTimes.put(manifest.TypePypi, name, v, t)
	}
}

// upstreamJSON fetches one JSON document through the guarded client.
func (s *Server) upstreamJSON(ctx context.Context, url, accept string, into any) error {
	//nolint:gosec // G704: publishTimeClient's transport runs upstreamGuard on this URL and on every redirect hop.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", accept)
	//nolint:gosec // G704: see above; guardedTransport refuses before any byte leaves.
	resp, err := publishTimeClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamBody+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxUpstreamBody {
		return fmt.Errorf("GET %s: body exceeds bodega's %d-byte buffer", url, maxUpstreamBody)
	}
	return json.Unmarshal(body, into)
}
