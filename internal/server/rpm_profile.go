package server

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- dnf repositories under a profile --------------------------------------
//
// A host whose profile governs rpm is served a repomd.xml of its own: primary,
// filelists and other point at copies holding only the packages the profile
// admits, and every other entry (updateinfo, group, modules, the *_db
// variants) is the upstream's, unchanged. bodega signs that document as it
// signs the unfiltered one, so the client's repo_gpgcheck covers the filter.
//
// The filtered files are built once per profile and upstream metadata, stored
// under their own checksum beside the upstream's files, and reached only
// through the repomd.xml of the profile that built them: a metadata request
// from a governed host is matched against its profile's repomd.xml, never the
// upstream's, so neither the unfiltered primary nor another profile's copy is
// listed for it. The filter is a listing control; the package route's
// entitleGate is what refuses a package by name, whatever href asks for it.

// rpmFilteredTypes are the repomd.xml entries a profile rewrites: the three
// that list packages. Their *_zck variants are left as the upstream's, and a
// dnf with zchunk on, its default, reads those instead where they exist.
var rpmFilteredTypes = []string{"primary", "filelists", "other"}

// rpmProfileBuildsKept is how many builds a profile keeps per repository tree.
// Two covers a host still holding the revision before the newest, which
// rpmServedRepomds lets it do for up to rpmRolloverGrace.
const rpmProfileBuildsKept = 2

// rpmFilters reports whether p rewrites rpm metadata at all.
func rpmFilters(p *entitle.Profile) bool { return p.Governs(manifest.TypeRpm) }

// rpmViewID is the key rpmServed holds a host's repomd.xml under. A governed
// host's view is its profile's as it stands now, so a filtered document and
// the upstream's are never two revisions of one tree, and neither are two
// versions of one profile. The fingerprint is what keeps a profile edit out
// of rpmServed's rollover grace: that grace lets a key keep the revision it
// holds while the upstream moves, and applied to an edit it would keep
// serving a listing the profile no longer grants.
func rpmViewID(t rpmTree, p *entitle.Profile) string {
	if !rpmFilters(p) {
		return t.id()
	}
	return rpmProfileView(t, p) + p.Fingerprint(manifest.TypeRpm)
}

// rpmProfileView is the part of rpmViewID every version of p shares.
func rpmProfileView(t rpmTree, p *entitle.Profile) string {
	return t.id() + "\x00profile\x00" + p.Name() + "\x00"
}

// rpmFilteredFile is one filtered metadata file as its repomd.xml entry
// describes it.
type rpmFilteredFile struct {
	typ, href      string
	sum, openSum   string
	size, openSize int64
	timestamp      int64
}

// rpmProfileBuild is one profile's filtered files over one set of upstream
// files, identified by the profile's fingerprint and the upstream checksums.
type rpmProfileBuild struct {
	key, fingerprint string
	files            map[string]rpmFilteredFile
}

// rpmProfileBuilds holds each profile view's recent builds and the builds
// running for it. built counts the builds made, which is what a test reads to
// show a second host on a profile reused the first host's.
type rpmProfileBuilds struct {
	mu    sync.Mutex
	views map[string]*rpmProfileSlot
	built int
	// timeout bounds one build, rpmProfileBuildTimeout when zero. wait is how
	// long a request waits on a running build before answering without it,
	// rpmProfileBuildWait when zero.
	timeout, wait time.Duration
	// running counts the build goroutines alive, so a test can let them end
	// before its store goes away.
	running sync.WaitGroup
}

// rpmProfileBuildWait is how long a request waits on a build before it is
// answered from the previous build or with a 503. It stays under 5 seconds so
// the client has a byte long before dnf's 30-second low-speed cutoff, and a
// build that small repositories finish inside it is answered in one request.
const rpmProfileBuildWait = 3 * time.Second

// rpmProfileRetryAfter is the Retry-After a 503 for a running build carries.
const rpmProfileRetryAfter = "10"

var rpmProfileBuildTimeout = func() time.Duration {
	d, _ := time.ParseDuration(config.DefaultRpmProfileBuildTimeout)
	return d
}()

type rpmProfileSlot struct {
	mu      sync.Mutex
	recent  []*rpmProfileBuild
	running map[string]*rpmProfileJob
}

// rpmProfileJob is one build in progress. b and err are set before done is
// closed and never written after.
type rpmProfileJob struct {
	done chan struct{}
	b    *rpmProfileBuild
	err  error
}

// errRpmProfileBuilding is a request that found its view's build running past
// rpmProfileBuildWait with no previous build to serve.
var errRpmProfileBuilding = errors.New("the profile's filtered metadata is still being built")

// rpmProfileBuildError is a build that failed. The build logged it, so the
// requests waiting on it answer without logging it again.
type rpmProfileBuildError struct {
	file string
	err  error
}

func (e *rpmProfileBuildError) Error() string {
	return fmt.Sprintf("building the filtered %s: %v", e.file, e.err)
}

func (e *rpmProfileBuildError) Unwrap() error { return e.err }

func (c *rpmProfileBuilds) slot(view string) *rpmProfileSlot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.views == nil {
		c.views = map[string]*rpmProfileSlot{}
	}
	sl := c.views[view]
	if sl == nil {
		sl = &rpmProfileSlot{running: map[string]*rpmProfileJob{}}
		c.views[view] = sl
	}
	return sl
}

func (c *rpmProfileBuilds) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.built
}

// rpmProfileRepomd is the repomd.xml a host on p is served in place of doc.
// A doc naming no primary lists no package, so it is served as it came.
func (s *Server) rpmProfileRepomd(r *http.Request, t rpmTree, p *entitle.Profile, doc []byte) ([]byte, error) {
	data, err := parseRpmRepomd(doc)
	if err != nil {
		return nil, err
	}
	b, err := s.rpmProfileFiles(r, t, p, data)
	if err != nil || b == nil {
		return doc, err
	}
	return rpmRewriteRepomd(doc, b)
}

// rpmProfileFiles is p's build over the upstream files data names, made when
// no build for this fingerprint and these checksums is held or one of its
// files has gone from the store.
func (s *Server) rpmProfileFiles(r *http.Request, t rpmTree, p *entitle.Profile, data []rpmRepomdData) (*rpmProfileBuild, error) {
	entries := map[string]rpmRepomdData{}
	for _, d := range data {
		for _, typ := range rpmFilteredTypes {
			if d.Type == typ {
				if _, dup := entries[typ]; !dup {
					entries[typ] = d
				}
			}
		}
	}
	if _, ok := entries["primary"]; !ok {
		return nil, nil
	}
	store := s.typeStore(manifest.TypeRpm)
	if store == nil {
		return nil, errors.New("no storage backend holds the rpm type, so a filtered metadata file has nowhere to live")
	}
	stamps := map[string]int64{}
	var latest int64
	for _, d := range data {
		if ts, ok := rpmTimestamp(d); ok && ts > latest {
			latest = ts
		}
	}
	key := p.Fingerprint(manifest.TypeRpm)
	for _, typ := range rpmFilteredTypes {
		if e, ok := entries[typ]; ok {
			ts, ok := rpmTimestamp(e)
			if !ok {
				ts = latest
			}
			stamps[typ] = ts
			key += "\x00" + typ + "=" + e.Checksum.Value + "@" + strconv.FormatInt(ts, 10)
		}
	}

	fingerprint := p.Fingerprint(manifest.TypeRpm)
	sl := s.rpmProfileBuilds.slot(rpmProfileView(t, p))
	sl.mu.Lock()
	recent := slices.Clone(sl.recent)
	sl.mu.Unlock()
	for _, b := range recent {
		if b.key == key && s.rpmProfileBuildStored(r, t, b) {
			return b, nil
		}
	}

	sl.mu.Lock()
	job := sl.running[key]
	if job == nil {
		job = &rpmProfileJob{done: make(chan struct{})}
		sl.running[key] = job
		timeout := s.rpmProfileBuilds.timeout
		if timeout <= 0 {
			timeout = rpmProfileBuildTimeout
		}
		// The build belongs to no request: dnf gives up on a repomd.xml after
		// 30 seconds without a byte, and a build of BaseOS's filelists takes
		// longer, so under the request's context it would be canceled and
		// started over by every retry. It keeps the request's values (who
		// asked, for the upstream fetch's records) and drops its cancellation.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), timeout)
		br := r.Clone(ctx)
		s.rpmProfileBuilds.running.Add(1)
		go func() {
			defer s.rpmProfileBuilds.running.Done()
			defer cancel()
			b, err := s.rpmBuildProfileFiles(br, t, p, key, fingerprint, entries, stamps)
			sl.mu.Lock()
			delete(sl.running, key)
			if err == nil {
				sl.recent = append([]*rpmProfileBuild{b}, sl.recent...)
				if len(sl.recent) > rpmProfileBuildsKept {
					sl.recent = sl.recent[:rpmProfileBuildsKept]
				}
			}
			job.b, job.err = b, err
			sl.mu.Unlock()
			close(job.done)
		}()
	}
	sl.mu.Unlock()

	wait := s.rpmProfileBuilds.wait
	if wait <= 0 {
		wait = rpmProfileBuildWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-job.done:
		return job.b, job.err
	case <-r.Context().Done():
		return nil, r.Context().Err()
	case <-timer.C:
	}
	// A previous build under this fingerprint lists what the profile grants
	// today over an older upstream; one under another fingerprint would list
	// what an edited profile no longer grants, so it is never served.
	sl.mu.Lock()
	recent = slices.Clone(sl.recent)
	sl.mu.Unlock()
	for _, b := range recent {
		if b.fingerprint == fingerprint && s.rpmProfileBuildStored(r, t, b) {
			return b, nil
		}
	}
	return nil, errRpmProfileBuilding
}

// rpmBuildProfileFiles reads, filters and stores the files entries names,
// under r's context, which is the build's own. A failure is logged here, once
// for every request waiting on it.
func (s *Server) rpmBuildProfileFiles(r *http.Request, t rpmTree, p *entitle.Profile, key, fingerprint string, entries map[string]rpmRepomdData, stamps map[string]int64) (b *rpmProfileBuild, err error) {
	file := "primary"
	defer func() {
		// A request's handler has net/http's recover behind it; this
		// goroutine has none, and a panic in a filter would stop the server.
		if v := recover(); v != nil {
			err = fmt.Errorf("panic: %v", v)
		}
		if err != nil {
			s.logger.Error("rpm metadata could not be filtered for a profile",
				"profile", p.Name(), "repository", t.id(), "file", file, "error", err)
			b, err = nil, &rpmProfileBuildError{file: file, err: err}
		}
	}()
	store := s.typeStore(manifest.TypeRpm)
	read := func(e rpmRepomdData) ([]byte, error) {
		if !rpmMetadataHrefServed(e.Location.Href) {
			return nil, fmt.Errorf("repomd.xml places %s at %q, outside repodata/, which bodega does not serve", e.Type, e.Location.Href)
		}
		return s.rpmRead(r, t, e.Type, func(w http.ResponseWriter, req *http.Request) { s.serveRpmMetadataEntry(w, req, t, e) })
	}
	primary := entries["primary"]
	raw, err := read(primary)
	if err != nil {
		return nil, err
	}
	ext := path.Ext(primary.Location.Href)
	kept, n, err := rpmAdmittedPkgids(raw, ext, p)
	if err != nil {
		return nil, fmt.Errorf("primary %s of %s: %w", primary.Location.Href, t.id(), err)
	}
	b = &rpmProfileBuild{key: key, fingerprint: fingerprint, files: map[string]rpmFilteredFile{}}
	for _, typ := range rpmFilteredTypes {
		e, ok := entries[typ]
		if !ok {
			continue
		}
		file = typ
		if typ != "primary" {
			if raw, err = read(e); err != nil {
				return nil, err
			}
			ext = path.Ext(e.Location.Href)
		}
		body, open, err := rpmFilterPackages(raw, ext, n, kept, typ == "primary")
		if err != nil {
			return nil, fmt.Errorf("filter %s %s of %s: %w", typ, e.Location.Href, t.id(), err)
		}
		sum := rpmSHA256Hex(body)
		f := rpmFilteredFile{typ: typ, sum: sum, openSum: open.sum, size: int64(len(body)), openSize: open.size, timestamp: stamps[typ],
			href: "repodata/" + sum + "-" + typ + ".xml.gz"}
		if err := store.Put(r.Context(), rpmFilteredKey(t, f), body); err != nil {
			return nil, fmt.Errorf("store the filtered %s of %s: %w", typ, t.id(), err)
		}
		b.files[typ] = f
	}
	s.rpmProfileBuilds.mu.Lock()
	s.rpmProfileBuilds.built++
	s.rpmProfileBuilds.mu.Unlock()
	s.logger.Info("filtered an rpm repository's metadata for a profile",
		"profile", p.Name(), "repository", t.id(), "primary", primary.Checksum.Value, "kept", len(kept))
	return b, nil
}

// rpmTimestamp is the timestamp an upstream entry gives its file. A filtered
// file carries its upstream file's, never the time it was built, because the
// filtered repomd.xml has to come out byte for byte the same wherever it is
// rebuilt: a .asc request reaching a restarted process, or another instance
// on the same store, signs a reconstruction, and a build-time timestamp makes
// that signature fail against the document the client already holds. An
// entry with none takes the newest any entry gives.
func rpmTimestamp(d rpmRepomdData) (int64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(d.Timestamp), 64)
	if err != nil || f <= 0 {
		return 0, false
	}
	return int64(f), true
}

func (s *Server) rpmProfileBuildStored(r *http.Request, t rpmTree, b *rpmProfileBuild) bool {
	store := s.typeStore(manifest.TypeRpm)
	for _, f := range b.files {
		if info, err := store.Head(r.Context(), rpmFilteredKey(t, f)); err != nil || info == nil || !info.Exists {
			return false
		}
	}
	return true
}

func rpmFilteredKey(t rpmTree, f rpmFilteredFile) string {
	return manifest.RpmMetadataKey(t.repo, t.releasever, t.basearch, f.sum, path.Base(f.href))
}

func rpmMetadataHrefServed(href string) bool {
	rest, ok := strings.CutPrefix(href, "repodata/")
	return ok && rest != "" && !strings.Contains(rest, "/")
}

func rpmSHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// handleRpmProfileMetadata serves a metadata file to a host on p, matched
// against the repomd.xml p serves it: the one it holds, or the one the
// current upstream document filters to. A filtered entry is read from the
// store under its own checksum; any other entry is the upstream's file.
func (s *Server) handleRpmProfileMetadata(w http.ResponseWriter, r *http.Request, t rpmTree, p *entitle.Profile, href string) {
	match := func(d rpmRepomdData) bool { return d.Location.Href == href }
	entry, err := s.rpmHeldEntry(r, t, match)
	if err != nil {
		var doc []byte
		doc, err = s.rpmRead(r, t, "repomd.xml", func(w http.ResponseWriter, req *http.Request) { s.handleRpmRepomd(w, req, t) })
		if err == nil {
			doc, err = s.rpmProfileRepomd(r, t, p, doc)
		}
		if err == nil {
			entry, err = rpmEntryIn(doc, match)
		}
	}
	if err != nil {
		var failed *rpmProfileBuildError
		switch {
		case errors.Is(err, errRpmNotListed):
			http.Error(w, fmt.Sprintf("the repomd.xml profile %q is served for %s names no %s.", p.Name(), t.id(), href), http.StatusNotFound)
		case errors.Is(err, errRpmProfileBuilding), errors.As(err, &failed):
			s.writeRpmProfileError(w, t, p, err)
		default:
			s.writeRpmReadError(w, r, t, "repomd.xml", err)
		}
		return
	}
	if !rpmFilteredType(entry.Type) {
		s.serveRpmMetadataEntry(w, r, t, entry)
		return
	}
	key := manifest.RpmMetadataKey(t.repo, t.releasever, t.basearch, entry.Checksum.Value, path.Base(entry.Location.Href))
	body, err := s.typeStore(manifest.TypeRpm).Get(r.Context(), key)
	if err != nil || len(body) == 0 {
		s.logger.Warn("a filtered rpm metadata file the profile's repomd.xml names is not in the store", "profile", p.Name(), "repository", t.id(), "key", key, "error", err)
		http.Error(w, fmt.Sprintf("bodega no longer holds the filtered %s of %s for profile %q; run `dnf makecache` to fetch a current repomd.xml, which rebuilds it.", entry.Type, t.id(), p.Name()), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	http.ServeContent(&cacheDirectiveWriter{ResponseWriter: w, directive: cachePrivateImmutable}, r, "", time.Time{}, bytes.NewReader(body))
}

// writeRpmProfileError answers a request whose profile's repomd.xml could not
// be made. It never falls back to the unfiltered document, which lists what
// the profile withholds.
func (s *Server) writeRpmProfileError(w http.ResponseWriter, t rpmTree, p *entitle.Profile, err error) {
	var failed *rpmProfileBuildError
	switch {
	case errors.Is(err, errRpmProfileBuilding):
		w.Header().Set("Retry-After", rpmProfileRetryAfter)
		http.Error(w, fmt.Sprintf("bodega is still building the metadata of %s for profile %q; dnf retries, and the build continues without it.", t.id(), p.Name()), http.StatusServiceUnavailable)
		return
	case errors.As(err, &failed):
	default:
		s.logger.Error("rpm repomd.xml could not be filtered for a profile", "profile", p.Name(), "repository", t.id(), "error", err)
	}
	http.Error(w, fmt.Sprintf("bodega could not filter the metadata of %s for profile %q, so it served no repomd.xml rather than the unfiltered one; the server log names the cause.", t.id(), p.Name()), http.StatusBadGateway)
}

func rpmFilteredType(typ string) bool {
	for _, t := range rpmFilteredTypes {
		if t == typ {
			return true
		}
	}
	return false
}

func rpmEntryIn(doc []byte, match func(rpmRepomdData) bool) (rpmRepomdData, error) {
	data, err := parseRpmRepomd(doc)
	if err != nil {
		return rpmRepomdData{}, err
	}
	for _, d := range data {
		if match(d) {
			return d, nil
		}
	}
	return rpmRepomdData{}, errRpmNotListed
}

// ---- rewriting repomd.xml --------------------------------------------------

// rpmRewriteRepomd replaces each <data> entry b filtered with one describing
// the filtered file, leaving every other byte of doc as the upstream wrote it.
func rpmRewriteRepomd(doc []byte, b *rpmProfileBuild) ([]byte, error) {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	var out bytes.Buffer
	last, depth := int64(0), 0
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("repomd.xml does not parse: %w", err)
		}
		switch se := tok.(type) {
		case xml.StartElement:
			if depth != 1 || se.Name.Local != "data" {
				depth++
				continue
			}
			if err := dec.Skip(); err != nil {
				return nil, fmt.Errorf("repomd.xml does not parse: %w", err)
			}
			f, ok := b.files[xmlAttr(se, "type")]
			if !ok {
				continue
			}
			out.Write(doc[last:start])
			out.WriteString(f.repomdData())
			last = dec.InputOffset()
		case xml.EndElement:
			depth--
		}
	}
	out.Write(doc[last:])
	return out.Bytes(), nil
}

func xmlAttr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (f rpmFilteredFile) repomdData() string {
	return fmt.Sprintf(`<data type="%s">
    <checksum type="sha256">%s</checksum>
    <open-checksum type="sha256">%s</open-checksum>
    <location href="%s"/>
    <timestamp>%d</timestamp>
    <size>%d</size>
    <open-size>%d</open-size>
  </data>`, f.typ, f.sum, f.openSum, f.href, f.timestamp, f.size, f.openSize)
}

// ---- filtering primary, filelists and other --------------------------------

// rpmAdmittedPkgids reads primary for the pkgid of every package p admits,
// by name and by the version primary gives it, and counts them. A package
// bodega would not serve at all is left out with the rest.
func rpmAdmittedPkgids(raw []byte, ext string, p *entitle.Profile) (map[string]bool, int, error) {
	r, closeFn, err := rpmDecompress(raw, ext)
	if err != nil {
		return nil, 0, fmt.Errorf("decompress: %w", err)
	}
	defer closeFn()
	lr := &io.LimitedReader{R: r, N: rpmMaxPrimary + 1}
	dec := xml.NewDecoder(lr)
	kept, n := map[string]bool{}, 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return kept, n, nil
		}
		if err != nil {
			if lr.N <= 0 {
				return nil, 0, fmt.Errorf("expands past %d bytes", int64(rpmMaxPrimary))
			}
			return nil, 0, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "package" {
			continue
		}
		var el rpmPrimaryElement
		if err := dec.DecodeElement(&el, &se); err != nil {
			return nil, 0, err
		}
		pkg, ok := el.servable()
		if !ok || !p.Permits(manifest.TypeRpm, pkg.name, pkg.evr()).Permitted {
			continue
		}
		kept[pkg.sum] = true
		n++
	}
}

// rpmOpen is the checksum and size of a filtered file's uncompressed content.
type rpmOpen struct {
	sum  string
	size int64
}

// rpmSetPackagesAttr sets the packages attribute of the start tag tag, the
// root element's package count in primary, filelists and other, to n, and
// leaves every other byte as written. It walks the tag attribute by
// attribute, as XML lays one out, rather than matching a pattern over it: a
// pattern either misses single quotes and spacing around "=", or also
// matches a prefixed x:packages and the same text inside another
// attribute's value. A tag with no unprefixed packages attribute comes back
// as it came.
func rpmSetPackagesAttr(tag []byte, n int) []byte {
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	nameEnd := func(c byte) bool { return space(c) || c == '=' || c == '>' || c == '/' }
	skip := func(i int) int {
		for i < len(tag) && space(tag[i]) {
			i++
		}
		return i
	}
	i := 1
	for i < len(tag) && !nameEnd(tag[i]) {
		i++
	}
	for {
		i = skip(i)
		start := i
		for i < len(tag) && !nameEnd(tag[i]) {
			i++
		}
		if i == start {
			return tag
		}
		name := string(tag[start:i])
		if i = skip(i); i >= len(tag) || tag[i] != '=' {
			return tag
		}
		if i = skip(i + 1); i >= len(tag) || (tag[i] != '"' && tag[i] != '\'') {
			return tag
		}
		end := bytes.IndexByte(tag[i+1:], tag[i])
		if end < 0 {
			return tag
		}
		end += i + 1
		if name == "packages" {
			out := append(bytes.Clone(tag[:i+1]), strconv.Itoa(n)...)
			return append(out, tag[end:]...)
		}
		i = end + 1
	}
}

// rpmFilterPackages copies one of primary, filelists or other through,
// keeping each top-level <package> whose pkgid kept holds and the whitespace
// before it, setting the root's packages attribute to n, and gzipping the
// result. Every byte it keeps is the upstream's: the decoder decides where an
// element starts and ends, and the bytes between those offsets are copied, so
// nothing the filter does not understand is lost by a re-encode.
//
// primary carries the pkgid in a child (<checksum pkgid="YES">); filelists
// and other carry it as the package's own attribute.
func rpmFilterPackages(raw []byte, ext string, n int, kept map[string]bool, primary bool) ([]byte, rpmOpen, error) {
	r, closeFn, err := rpmDecompress(raw, ext)
	if err != nil {
		return nil, rpmOpen{}, fmt.Errorf("decompress: %w", err)
	}
	defer closeFn()
	lr := &io.LimitedReader{R: r, N: rpmMaxPrimary + 1}
	rec := &rpmRecorder{r: bufio.NewReader(lr)}
	dec := xml.NewDecoder(rec)

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	open := sha256.New()
	var openSize int64
	write := func(b []byte) {
		_, _ = zw.Write(b)
		_, _ = open.Write(b)
		openSize += int64(len(b))
	}

	var held []byte
	depth := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if lr.N <= 0 {
				return nil, rpmOpen{}, fmt.Errorf("expands past %d bytes", int64(rpmMaxPrimary))
			}
			return nil, rpmOpen{}, err
		}
		switch tt := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				hdr := rec.take(dec.InputOffset())
				at := bytes.LastIndexByte(hdr, '<')
				write(hdr[:at])
				write(rpmSetPackagesAttr(hdr[at:], n))
				depth++
				continue
			}
			if depth == 1 && tt.Name.Local == "package" {
				id, err := rpmPkgid(dec, tt, primary)
				if err != nil {
					return nil, rpmOpen{}, err
				}
				el := rec.take(dec.InputOffset())
				if kept[id] {
					write(held)
					write(el)
				}
				held = nil
				continue
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 1 && len(bytes.TrimSpace(tt)) == 0 {
				held = append(held[:0], rec.take(dec.InputOffset())...)
				continue
			}
		}
		write(held)
		held = nil
		write(rec.take(dec.InputOffset()))
	}
	write(held)
	write(rec.rest())
	if err := zw.Close(); err != nil {
		return nil, rpmOpen{}, err
	}
	return gz.Bytes(), rpmOpen{sum: hex.EncodeToString(open.Sum(nil)), size: openSize}, nil
}

// rpmPkgid reads the pkgid of the <package> se opens, consuming the element.
func rpmPkgid(dec *xml.Decoder, se xml.StartElement, primary bool) (string, error) {
	if !primary {
		id := xmlAttr(se, "pkgid")
		return id, dec.Skip()
	}
	var el rpmPrimaryElement
	if err := dec.DecodeElement(&el, &se); err != nil {
		return "", err
	}
	pkg, _ := el.servable()
	return pkg.sum, nil
}

// rpmRecorder keeps every byte the decoder reads until take hands it out. The
// decoder reads one byte at a time from an io.ByteReader and does no buffering
// of its own, so its InputOffset names a position in what was recorded; the
// one byte it may read ahead and push back stays recorded past that offset.
type rpmRecorder struct {
	r    io.ByteReader
	buf  []byte
	base int64
}

func (rr *rpmRecorder) ReadByte() (byte, error) {
	b, err := rr.r.ReadByte()
	if err == nil {
		rr.buf = append(rr.buf, b)
	}
	return b, err
}

func (rr *rpmRecorder) Read(p []byte) (int, error) {
	for i := range p {
		b, err := rr.ReadByte()
		if err != nil {
			return i, err
		}
		p[i] = b
	}
	return len(p), nil
}

// take returns the bytes recorded up to offset off and forgets them.
func (rr *rpmRecorder) take(off int64) []byte {
	n := off - rr.base
	out := rr.buf[:n:n]
	rr.buf = rr.buf[n:]
	rr.base = off
	return out
}

func (rr *rpmRecorder) rest() []byte {
	out := rr.buf
	rr.buf = nil
	return out
}
