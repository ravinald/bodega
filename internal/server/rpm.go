package server

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/storage"
)

// ---- dnf repositories ------------------------------------------------------
//
// Bodega serves every repository in rpm_upstreams as a pull-through cache
// under /rpm/:
//
//   /rpm/bodega.gpg                                          — the signing key's public half
//   /rpm/<repo>/<releasever>/<basearch>/repodata/repomd.xml  — mutable, metadata_ttl
//   /rpm/<repo>/<releasever>/<basearch>/repodata/repomd.xml.asc — bodega's signature over it
//   /rpm/<repo>/<releasever>/<basearch>/repodata/<file>      — a file repomd.xml names, immutable
//   /rpm/<repo>/<releasever>/<basearch>/<href>               — a package primary lists, immutable
//
// repomd.xml is the one document bodega signs. It carries the checksum of
// every metadata file, and primary carries the checksum of every package, so
// a client that verifies repomd.xml against bodega's key and each file
// against the checksum above it trusts the whole tree through one signature.
// bodega verifies each file and package against those same checksums before
// it caches one, and never rewrites a package, so the vendor's header
// signature still verifies under gpgcheck.
//
// A path names its repository, release and architecture, and only the
// repository name reaches the upstream URL unvalidated by a pattern; it has
// to be a key of rpm_upstreams.

// rpmMaxPrimary bounds what a decompressed primary may expand to. EPEL's
// runs to about 150 MB; anything past this is a decompression bomb rather
// than a repository.
const rpmMaxPrimary = 2 << 30

// rpmTree is one repository at one release and architecture.
type rpmTree struct {
	repo, releasever, basearch string
	// base is the repository's URL with both variables substituted, ending
	// in "/". Hrefs in repomd.xml and primary are relative to it.
	base string
}

func (t rpmTree) id() string { return t.repo + "/" + t.releasever + "/" + t.basearch }

func (s *Server) handleRpm(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	if p == "bodega.gpg" {
		s.serveAptKey(w, r, s.aptSign.Load().pub())
		return
	}
	segs, ok := splitRpmPath(r.URL.EscapedPath())
	if !ok {
		http.NotFound(w, r)
		return
	}
	raw, ok := s.cfg.RpmUpstreams[segs[0]]
	if !ok {
		noSharedCache(w)
		http.Error(w, fmt.Sprintf("rpm repository %q is not in rpm_upstreams on this server; an operator names each repository bodega serves there.", segs[0]), http.StatusNotFound)
		return
	}
	if !manifest.RpmValidReleasever(segs[1]) {
		noSharedCache(w)
		http.Error(w, fmt.Sprintf("releasever %q is not a release number such as 9 or 9.4.", segs[1]), http.StatusBadRequest)
		return
	}
	if !manifest.RpmValidBasearch(segs[2]) {
		noSharedCache(w)
		http.Error(w, fmt.Sprintf("basearch %q is not one of %s.", segs[2], strings.Join(manifest.RpmBasearches, ", ")), http.StatusBadRequest)
		return
	}
	t := rpmTree{repo: segs[0], releasever: segs[1], basearch: segs[2],
		base: strings.NewReplacer("$releasever", segs[1], "$basearch", segs[2]).Replace(raw)}
	rest := segs[3]
	switch {
	case rest == "repodata/repomd.xml":
		s.handleRpmRepomd(w, r, t)
	case rest == "repodata/repomd.xml.asc":
		s.handleRpmRepomdSignature(w, r, t)
	case strings.HasPrefix(rest, "repodata/") && !strings.Contains(strings.TrimPrefix(rest, "repodata/"), "/"):
		s.handleRpmMetadata(w, r, t, rest)
	default:
		s.handleRpmPackage(w, r, t, rest)
	}
}

// splitRpmPath reads <repo>/<releasever>/<basearch>/<rest> from the escaped
// path, splitting before it unescapes, so an encoded "/" stays inside the
// segment the client put it in and fails that segment's check rather than
// shifting the rest into the next one.
func splitRpmPath(escaped string) ([]string, bool) {
	rest, ok := strings.CutPrefix(escaped, "/rpm/")
	if !ok {
		return nil, false
	}
	segs := strings.SplitN(rest, "/", 4)
	if len(segs) < 4 || segs[3] == "" {
		return nil, false
	}
	for i, seg := range segs {
		u, err := url.PathUnescape(seg)
		if err != nil || u == "" {
			return nil, false
		}
		segs[i] = u
	}
	return segs, true
}

// handleRpmRepomd serves the upstream's repomd.xml as it came. Its
// signature is a separate route, so the bytes here are the upstream's.
//
// A client's GET is answered through rpmServed, which decides the revision
// this client is handed, for the .asc request that follows. The cached object
// cannot answer that: stale_grace hands one client the old revision while a
// refresh lands the new one, and another client's request can refresh it
// between this client's two requests. The GET is always answered in full, so
// a client never keeps a revision through a 304 that bodega has no record of.
func (s *Server) handleRpmRepomd(w http.ResponseWriter, r *http.Request, t rpmTree) {
	noSharedCache(w)
	markIndexResponse(r)
	key := manifest.RpmRepomdKey(t.repo, t.releasever, t.basearch)
	serve := func(w http.ResponseWriter, r *http.Request) {
		s.proxyOrCache(w, r, s.typeStore(manifest.TypeRpm), key, t.base+"repodata/repomd.xml", manifest.TypeRpm, "", "", false, true)
	}
	if isOwnRead(r) || r.Method != http.MethodGet {
		serve(w, r)
		return
	}
	full := r.Clone(r.Context())
	for _, h := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
		full.Header.Del(h)
	}
	cw := &capturedResponse{header: http.Header{}}
	serve(cw, full)
	if cw.tooBig {
		s.logger.Error("rpm repomd.xml exceeds the response buffer", "repository", t.id(), "limit", maxUpstreamBody)
		http.Error(w, fmt.Sprintf("repomd.xml of %s exceeds bodega's %d-byte buffer; the upstream is not publishing a repository index.", t.id(), maxUpstreamBody), http.StatusBadGateway)
		return
	}
	for k, v := range cw.header {
		w.Header()[k] = v
	}
	status := cw.status
	if status == 0 {
		status = http.StatusOK
	}
	body := cw.body.Bytes()
	if status == http.StatusOK {
		if held := s.rpmServed.publish(t.id(), rpmClientKey(r), body, s.rpmServed.now()); !bytes.Equal(held, body) {
			body = held
			for _, h := range []string{"ETag", "Last-Modified"} {
				w.Header().Del(h)
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// handleRpmRepomdSignature signs the repomd.xml this client was handed, so
// the pair verifies whichever revision the cache holds by now. A client with
// no document on record within rpmServedWindow gets a signature over the
// cached copy, read without refreshing it.
func (s *Server) handleRpmRepomdSignature(w http.ResponseWriter, r *http.Request, t rpmTree) {
	noSharedCache(w)
	markIndexResponse(r)
	sign := s.aptSign.Load()
	if sign == nil {
		http.Error(w, "this server holds no signing key, so it serves repomd.xml unsigned; an operator runs `bodega apt key generate`, or a client sets repo_gpgcheck=0.", http.StatusNotFound)
		return
	}
	doc, ok := s.rpmServed.held(t.id(), rpmClientKey(r), s.rpmServed.now())
	if !ok {
		var err error
		if doc, err = s.rpmCachedRepomd(r, t); err != nil {
			s.writeRpmReadError(w, r, t, "repomd.xml", err)
			return
		}
	}
	sig, err := sign.signer.DetachSign(doc)
	if err != nil {
		s.logger.Error("rpm repomd.xml signing failed", "repository", t.id(), "error", err)
		http.Error(w, "signing repomd.xml failed; the server log names the key error.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pgp-signature")
	_, _ = w.Write(sig)
}

// rpmServedWindow is how long the repomd.xml a client was handed stays the
// one its .asc request is signed over, when nothing moved it since.
const rpmServedWindow = 10 * time.Minute

// rpmSignatureWait is how long after a client key was last handed a
// repomd.xml one of its readers may still ask for the signature. dnf asks for
// it right after the document, so this only has to outlast a slow link
// between the two. A key quiet for longer has no reader left to break, and
// moves to a newer revision on its next request.
const rpmSignatureWait = 30 * time.Second

// rpmRolloverGrace bounds how long a key that is never quiet (many hosts
// behind one NAT address) keeps the revision it holds once the cache has a
// newer one. It is the window the old repomd.xml and its signature stay
// served as a pair after a refresh. Ten minutes is a sixth of the default
// metadata_ttl, so a busy key trails the cache by less than the TTL already
// lets any client trail the upstream.
const rpmRolloverGrace = 10 * time.Minute

// rpmServedClients bounds the clients remembered per repository tree. A
// client past the bound is handed the cached copy and signed it, as one
// arriving after rpmServedWindow is.
const rpmServedClients = 1 << 16

// rpmClientKey is who a repomd.xml was served to: the address and the
// identity the request carried. Two hosts behind one address with no identity
// of their own share a key, and so share a revision; see rpmServedRepomds.
func rpmClientKey(r *http.Request) string {
	return ClientIP(r) + "\x00" + callerName(r)
}

// rpmServedRepomds is the repomd.xml each client key holds, per repository
// tree. In memory and per process: after a restart, or on a second bodega
// behind the same address, .asc is signed over the cached copy.
//
// The .asc request carries nothing that says which repomd.xml its reader got,
// so the signature is always over the revision the key holds, and only a
// repomd.xml request moves a key to a new revision: a signature request reads
// and never changes what is held. A key moves when it has been quiet for
// rpmSignatureWait, so no reader is left between its two requests, or when
// the cache has held a newer revision for rpmRolloverGrace. The second case
// is the race this design accepts: a reader whose two requests straddle that
// forced move gets a signature over the newer revision, fails repo_gpgcheck
// once, and its next dnf makecache verifies.
type rpmServedRepomds struct {
	mu    sync.Mutex
	trees map[string]*rpmServedTree
	// clock is time.Now outside tests.
	clock func() time.Time
}

func (c *rpmServedRepomds) now() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return time.Now()
}

type rpmServedTree struct {
	latest    []byte
	clients   map[string]*rpmServedClient
	lastPrune time.Time
}

// rpmServedClient is the revision one client key holds, when it was last
// handed out, and since when the cache has offered a newer one.
type rpmServedClient struct {
	doc        []byte
	at         time.Time
	newerSince time.Time
}

// publish records that client was served fetched and returns the revision
// to hand it: the one it holds, until rpmServedRepomds says it moves.
func (c *rpmServedRepomds) publish(tree, client string, fetched []byte, now time.Time) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.trees == nil {
		c.trees = map[string]*rpmServedTree{}
	}
	t := c.trees[tree]
	if t == nil {
		t = &rpmServedTree{clients: map[string]*rpmServedClient{}}
		c.trees[tree] = t
	}
	if now.Sub(t.lastPrune) > rpmServedWindow {
		for k, d := range t.clients {
			if now.Sub(d.at) > rpmServedWindow {
				delete(t.clients, k)
			}
		}
		t.lastPrune = now
	}
	// One copy per revision, however many clients hold it.
	if !bytes.Equal(t.latest, fetched) {
		t.latest = bytes.Clone(fetched)
	}
	cl := t.clients[client]
	if cl == nil || now.Sub(cl.at) > rpmServedWindow {
		if cl == nil && len(t.clients) >= rpmServedClients {
			return fetched
		}
		cl = &rpmServedClient{doc: t.latest}
		t.clients[client] = cl
	}
	switch {
	case bytes.Equal(cl.doc, t.latest):
		cl.newerSince = time.Time{}
	case now.Sub(cl.at) > rpmSignatureWait:
		cl.doc, cl.newerSince = t.latest, time.Time{}
	case cl.newerSince.IsZero():
		cl.newerSince = now
	case now.Sub(cl.newerSince) >= rpmRolloverGrace:
		cl.doc, cl.newerSince = t.latest, time.Time{}
	}
	cl.at = now
	return cl.doc
}

// held returns the revision client holds, changing nothing: the .asc route
// and the metadata routes both read it.
func (c *rpmServedRepomds) held(tree, client string, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.trees[tree]
	if t == nil {
		return nil, false
	}
	cl := t.clients[client]
	if cl == nil || now.Sub(cl.at) > rpmServedWindow {
		return nil, false
	}
	return cl.doc, true
}

// rpmCachedRepomd is the stored repomd.xml, fetched through the repomd route
// only when none is stored.
func (s *Server) rpmCachedRepomd(r *http.Request, t rpmTree) ([]byte, error) {
	if store := s.typeStore(manifest.TypeRpm); store != nil {
		if b, err := store.Get(r.Context(), manifest.RpmRepomdKey(t.repo, t.releasever, t.basearch)); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return s.rpmRead(r, t, "repomd.xml", func(w http.ResponseWriter, req *http.Request) { s.handleRpmRepomd(w, req, t) })
}

// rpmRead runs one of this file's own routes for bodega's own use and
// returns the body. The read is marked as bodega's own, so it writes no audit
// or discovery row in the client's name; the client's request has written
// its own. It gets a served-object slot of its own too: the metadata routes
// mark theirs as an index, and on the client's slot that would strip the
// object key from the package's serve_fetch row, which is where
// reconciliation reads the package's version.
func (s *Server) rpmRead(r *http.Request, t rpmTree, what string, serve func(http.ResponseWriter, *http.Request)) ([]byte, error) {
	ctx := context.WithValue(withOwnRead(r.Context()), servedObjectCtxKey{}, &servedObject{})
	req := r.Clone(ctx)
	for _, h := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
		req.Header.Del(h)
	}
	cw := &capturedResponse{header: http.Header{}}
	serve(cw, req)
	switch {
	case cw.tooBig:
		return nil, fmt.Errorf("%s of %s exceeds bodega's %d-byte buffer", what, t.id(), maxUpstreamBody)
	case cw.status == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s publishes no %s", errUpstreamNotFound, t.base, what)
	case cw.status != 0 && cw.status != http.StatusOK:
		return nil, &rpmReadStatus{what: what, status: cw.status, body: strings.TrimSpace(cw.body.String())}
	}
	return cw.body.Bytes(), nil
}

// rpmReadStatus is a non-200 answer from one of this file's own routes,
// relayed to the client whose request needed it.
type rpmReadStatus struct {
	what   string
	status int
	body   string
}

func (e *rpmReadStatus) Error() string {
	return fmt.Sprintf("reading %s answered HTTP %d: %s", e.what, e.status, e.body)
}

func (s *Server) writeRpmReadError(w http.ResponseWriter, r *http.Request, t rpmTree, what string, err error) {
	var st *rpmReadStatus
	switch {
	case errors.As(err, &st):
		http.Error(w, st.body, st.status)
	case errors.Is(err, errUpstreamNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		s.logger.Error("rpm metadata read failed", "repository", t.id(), "file", what, "error", err)
		http.Error(w, fmt.Sprintf("bodega could not read %s for %s; the server log names the cause.", what, t.id()), http.StatusBadGateway)
	}
}

// rpmRepomdData is one <data> entry of repomd.xml.
type rpmRepomdData struct {
	Type     string `xml:"type,attr"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
}

func parseRpmRepomd(doc []byte) ([]rpmRepomdData, error) {
	var md struct {
		Data []rpmRepomdData `xml:"data"`
	}
	if err := xml.Unmarshal(doc, &md); err != nil {
		return nil, fmt.Errorf("repomd.xml does not parse: %w", err)
	}
	for i := range md.Data {
		md.Data[i].Checksum.Value = strings.TrimSpace(md.Data[i].Checksum.Value)
	}
	return md.Data, nil
}

// errRpmNotListed is a file the current repomd.xml or primary does not name.
// It is kept apart from errUpstreamNotFound, which is the upstream answering
// 404 for repomd.xml itself.
var errRpmNotListed = errors.New("not listed")

// rpmMetadataEntry is the first entry of the current repomd.xml that match
// accepts, read through the repomd route so a stale copy is refreshed first.
func (s *Server) rpmMetadataEntry(r *http.Request, t rpmTree, match func(rpmRepomdData) bool) (rpmRepomdData, error) {
	doc, err := s.rpmRead(r, t, "repomd.xml", func(w http.ResponseWriter, req *http.Request) { s.handleRpmRepomd(w, req, t) })
	if err != nil {
		return rpmRepomdData{}, err
	}
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

// rpmHeldEntry is the first entry match accepts in the repomd.xml this
// client holds, or errRpmNotListed when it holds none or that one names none.
func (s *Server) rpmHeldEntry(r *http.Request, t rpmTree, match func(rpmRepomdData) bool) (rpmRepomdData, error) {
	doc, ok := s.rpmServed.held(t.id(), rpmClientKey(r), s.rpmServed.now())
	if !ok {
		return rpmRepomdData{}, errRpmNotListed
	}
	data, err := parseRpmRepomd(doc)
	if err != nil {
		return rpmRepomdData{}, errRpmNotListed
	}
	for _, d := range data {
		if match(d) {
			return d, nil
		}
	}
	return rpmRepomdData{}, errRpmNotListed
}

// handleRpmMetadata serves a file the current repomd.xml names, verified
// against the checksum it gives the file and cached under that checksum. The
// current repomd.xml for a client is the one rpmServed says it holds, which
// can trail the cache, so that entry is tried first: a repository naming its
// files without a checksum in the href gives the same name another checksum
// in the next revision, and the client verifies against its own.
func (s *Server) handleRpmMetadata(w http.ResponseWriter, r *http.Request, t rpmTree, href string) {
	markIndexResponse(r)
	match := func(d rpmRepomdData) bool { return d.Location.Href == href }
	entry, err := s.rpmHeldEntry(r, t, match)
	if err != nil {
		entry, err = s.rpmMetadataEntry(r, t, match)
	}
	if err != nil {
		if errors.Is(err, errRpmNotListed) {
			http.Error(w, fmt.Sprintf("the current repomd.xml of %s names no %s.", t.id(), href), http.StatusNotFound)
			return
		}
		s.writeRpmReadError(w, r, t, "repomd.xml", err)
		return
	}
	s.serveRpmMetadataEntry(w, r, t, entry)
}

// serveRpmMetadataEntry serves the file one repomd.xml entry names, cached
// under that entry's checksum and verified against it, so the bytes are the
// entry's whichever publication another caller holds.
func (s *Server) serveRpmMetadataEntry(w http.ResponseWriter, r *http.Request, t rpmTree, entry rpmRepomdData) {
	markIndexResponse(r)
	href := entry.Location.Href
	if !rpmChecksumUsable(entry.Checksum.Type, entry.Checksum.Value) {
		s.refuseRpmChecksumType(w, r, t, href, "", "", entry.Checksum.Type)
		return
	}
	file := path.Base(href)
	key := manifest.RpmMetadataKey(t.repo, t.releasever, t.basearch, entry.Checksum.Value, file)
	upstream := t.base + href
	verify := rpmVerifyingOpener(entry.Checksum.Type, entry.Checksum.Value, func(got string) error {
		return rpmMismatch(t, href, "", "", "repomd.xml", entry.Checksum.Type, entry.Checksum.Value, got)
	})
	req := r.WithContext(withUpstreamOpener(r.Context(), verify))
	resolve := func(context.Context) (string, error) { return upstream, nil }
	s.proxyOrResolve(&cacheDirectiveWriter{ResponseWriter: w, directive: cachePrivateImmutable}, req,
		s.typeStore(manifest.TypeRpm), key, resolve, upstream, nil, manifest.TypeRpm, "", "", true, true)
}

// handleRpmPackage serves a package at an href the current primary lists,
// judged under the name and version primary gives it. The gates run before
// any byte of the package is asked for, as a composer dist's do.
func (s *Server) handleRpmPackage(w http.ResponseWriter, r *http.Request, t rpmTree, href string) {
	ctx := r.Context()
	idx, err := s.rpmPrimary(r, t)
	if err != nil {
		if errors.Is(err, errRpmNotListed) {
			http.Error(w, fmt.Sprintf("the current repomd.xml of %s names no primary, so no package is served from it.", t.id()), http.StatusNotFound)
			return
		}
		s.writeRpmReadError(w, r, t, "primary", err)
		return
	}
	pkg, ok := idx.pkgs[href]
	if !ok {
		http.Error(w, fmt.Sprintf("the current primary of %s lists no package at %s.", t.id(), href), http.StatusNotFound)
		return
	}
	name, version := pkg.name, pkg.evr()

	pm, _ := s.store.GetPackage(ctx, manifest.TypeRpm, name)
	if pm != nil {
		if isPackageHidden(pm) {
			s.refuseHidden(w, r, manifest.TypeRpm, name, "")
			return
		}
		if isVersionHidden(pm, version) {
			s.refuseHidden(w, r, manifest.TypeRpm, name, version)
			return
		}
		vc, baseVer := packageVersionConstraint(pm)
		if vc != "" && vc != manifest.ConstraintAny && baseVer != "" {
			if ok, ordered := versionAllowed(manifest.TypeRpm, baseVer, version, vc); !ok {
				s.refuseVersionConstraint(w, r, manifest.TypeRpm, name, baseVer, version, vc, ordered)
				return
			}
		}
	}
	if !s.entitleGate(w, r, manifest.TypeRpm, name, version) {
		return
	}
	if !rpmChecksumUsable(pkg.sumType, pkg.sum) {
		s.refuseRpmChecksumType(w, r, t, href, name, version, pkg.sumType)
		return
	}

	store, err := s.versionStore(ctx, manifest.TypeRpm, name, version)
	if err != nil {
		s.logger.Error("storage backend recorded for artifact is not configured",
			"type", manifest.TypeRpm, "package", name, "version", version, "error", err)
		http.Error(w, "storage backend error", http.StatusBadGateway)
		return
	}
	key := manifest.RpmPackageKey(t.repo, t.releasever, t.basearch, name, version, path.Base(href))
	upstream := t.base + href
	candidate := policy.RpmCandidate(name, t.base)
	cw := &cacheDirectiveWriter{ResponseWriter: w, directive: cachePrivateImmutable}
	if st, err := store.Head(ctx, key); err == nil && st != nil && st.Exists {
		s.serveRpmCachedPackage(cw, r, t, store, key, upstream, candidate, href, pkg)
		return
	}
	verify := rpmVerifyingOpener(pkg.sumType, pkg.sum, func(got string) error {
		return rpmMismatch(t, href, name, version, "primary", pkg.sumType, pkg.sum, got)
	})
	req := r.WithContext(withUpstreamOpener(ctx, verify))
	resolve := func(context.Context) (string, error) { return upstream, nil }
	forceProxy := pm == nil || packageMode(pm) == manifest.ModeProxy
	s.proxyOrResolve(cw, req, rpmFillStore{store}, key,
		resolve, upstream, nil, manifest.TypeRpm, candidate, name, true, forceProxy)
}

// rpmFillStore is the package store with Head answering that nothing is
// there, so proxyOrResolve only ever fills. proxyOrResolve serves an
// immutable hit with no allow-list verdict and no digest check, which suits a
// key that names its bytes; an rpm key names a version, and the allow-list and
// the current primary both have to rule on every response. A copy landing
// between serveRpmCachedPackage's Head and this fill is fetched and verified
// again rather than served unjudged.
type rpmFillStore struct{ storage.ObjectStore }

func (rpmFillStore) Head(context.Context, string) (*storage.ObjectInfo, error) {
	return &storage.ObjectInfo{}, nil
}

// serveRpmCachedPackage answers from the cache once the allow-list admits the
// package and the cached bytes hash to the checksum the current primary gives
// it. One discovery row per request: the gate writes a refusal's, the hit or
// the mismatch writes the rest.
func (s *Server) serveRpmCachedPackage(w http.ResponseWriter, r *http.Request, t rpmTree, store storage.ObjectStore, key, upstream, candidate, href string, pkg rpmPackage) {
	ctx := r.Context()
	name, version := pkg.name, pkg.evr()
	baseline := s.baselineLookup(ctx, manifest.TypeRpm, name, key, true)
	override := s.allowListOverrideLookup(ctx, manifest.TypeRpm, name, key, true)
	admit := func(obj cachedObject) bool {
		if _, ok := s.upstreamPolicyGate(w, r, manifest.TypeRpm, upstream, candidate, name, key, true, baseline, override); !ok {
			return false
		}
		got, err := s.rpmCachedDigest(ctx, store, key, pkg, obj)
		if err != nil {
			s.logger.Error("rpm cached package could not be verified", "repository", t.id(), "key", key, "error", err)
			http.Error(w, fmt.Sprintf("bodega could not verify its cached copy of %s %s against the current primary of %s; the server log names the cause. Retry.", name, version, t.id()), http.StatusBadGateway)
			return false
		}
		if got != pkg.sum {
			s.recordCacheHitDiscovery(ctx, r, manifest.TypeRpm, upstream, candidate, name, key)
			f := newRefusal(checkChecksum, manifest.TypeRpm, name, version, http.StatusBadGateway)
			f.reason = fmt.Sprintf("bodega holds %s of %s with %s %s, and the current primary gives it %s, so bodega served nothing.", href, t.id(), pkg.sumType, got, pkg.sum)
			f.next = fmt.Sprintf("the repository republished %s %s with other bytes; an operator who trusts the new primary runs `bodega pkg remove rpm %s`, and the next request fetches and verifies the package again.", name, version, name)
			s.logger.Warn("rpm cached package disagrees with primary", "repository", t.id(), "key", key, "cached", got, "primary", pkg.sum, "incident", f.incident)
			f.write(w, r)
			return false
		}
		return true
	}
	s.serveCacheHitIf(w, r, store, key, true, admit, func(obj cachedObject) {
		s.recordCacheHit(ctx, r, manifest.TypeRpm, upstream, candidate, name, key, obj)
	})
}

// rpmCachedDigest is the digest, under the primary's checksum type, of the
// object serveCacheHitIf opened. The hash reads the object through a second
// handle, so it vouches for the served one only where both report the same
// identity; a writer landing between the two opens is an error to retry.
// A digest already taken for the same identity and checksum is reused, so a
// warm package is hashed once per process rather than once per request.
func (s *Server) rpmCachedDigest(ctx context.Context, store storage.ObjectStore, key string, pkg rpmPackage, obj cachedObject) (string, error) {
	if obj.id.Known() && s.rpmVerified.holds(key, pkg.sum, obj.id) {
		return pkg.sum, nil
	}
	res, err := store.GetStream(ctx, key)
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", fmt.Errorf("%s vanished while it was being verified", key)
	}
	defer func() { _ = res.Body.Close() }()
	h := rpmHash(pkg.sumType)
	if _, err := io.Copy(h, res.Body); err != nil {
		return "", err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !obj.id.Known() {
		return got, nil
	}
	if streamIdentity(store, res) != obj.id {
		return "", fmt.Errorf("%s was replaced while it was being verified", key)
	}
	if got == pkg.sum {
		s.rpmVerified.remember(key, pkg.sum, obj.id)
	}
	return got, nil
}

// rpmVerifiedObjects is which stored package objects already hashed to which
// primary checksum, by the identity the store reported for them.
type rpmVerifiedObjects struct {
	mu sync.Mutex
	m  map[string]rpmVerifiedObject
}

type rpmVerifiedObject struct {
	sum string
	id  audit.ObjectIdentity
}

func (c *rpmVerifiedObjects) holds(key, sum string, id audit.ObjectIdentity) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	return ok && v.sum == sum && v.id == id
}

func (c *rpmVerifiedObjects) remember(key, sum string, id audit.ObjectIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]rpmVerifiedObject{}
	}
	c.m[key] = rpmVerifiedObject{sum: sum, id: id}
}

// ---- checksums -------------------------------------------------------------

// rpmHash is the hash a repomd.xml or primary checksum type names. SHA-1 and
// MD5 are refused: a collision in either would let an upstream swap a file
// under a checksum bodega's signature then vouches for.
func rpmHash(typ string) hash.Hash {
	switch strings.ToLower(typ) {
	case "sha256":
		return sha256.New()
	case "sha224":
		return sha256.New224()
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	}
	return nil
}

func rpmChecksumUsable(typ, value string) bool {
	h := rpmHash(typ)
	if h == nil || len(value) != 2*h.Size() {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (s *Server) refuseRpmChecksumType(w http.ResponseWriter, r *http.Request, t rpmTree, href, name, version, typ string) {
	f := newRefusal(checkChecksum, manifest.TypeRpm, name, version, http.StatusBadGateway)
	f.reason = fmt.Sprintf("%s gives %s a %q checksum, and bodega verifies only well-formed SHA-2 checksums before it caches a file.", t.id(), href, typ)
	f.next = "an operator points this repository at a mirror that publishes SHA-256 metadata, which every current RHEL-family repository does."
	s.logger.Warn("rpm checksum type refused", "repository", t.id(), "href", href, "type", typ, "incident", f.incident)
	f.write(w, r)
}

// rpmMismatch is the refusal for bytes that do not hash to the checksum the
// document above them gives. It names both digests, since the next step is
// someone comparing them against the upstream by hand.
func rpmMismatch(t rpmTree, href, name, version, source, typ, want, got string) error {
	f := newRefusal(checkChecksum, manifest.TypeRpm, name, version, http.StatusBadGateway)
	f.reason = fmt.Sprintf("the upstream of %s sent %s with %s %s, and %s gives it %s, so bodega stored nothing.", t.id(), href, typ, got, source, want)
	f.next = "retry; if it repeats, the mirror is mid-sync or something between bodega and it is altering content, and an operator should look before trusting it."
	return &resolveRefusal{f: f}
}

// rpmVerifyingOpener opens an upstream file whose body fails the read at
// its end unless it hashes to want, so the spool reports the refusal and
// proxyOrResolve stores nothing.
func rpmVerifyingOpener(typ, want string, refuse func(got string) error) upstreamOpener {
	return func(ctx context.Context, rawURL string) (*upstreamStream, error) {
		up, err := openUpstream(ctx, rawURL, requiresIdentityEncoding(manifest.TypeRpm))
		if err != nil {
			return nil, err
		}
		up.body = &rpmVerifyingReader{r: up.body, h: rpmHash(typ), want: strings.ToLower(want), refuse: refuse}
		return up, nil
	}
}

type rpmVerifyingReader struct {
	r      io.ReadCloser
	h      hash.Hash
	want   string
	refuse func(got string) error
}

func (v *rpmVerifyingReader) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	v.h.Write(p[:n])
	if errors.Is(err, io.EOF) {
		if got := hex.EncodeToString(v.h.Sum(nil)); got != v.want {
			return n, v.refuse(got)
		}
	}
	return n, err
}

func (v *rpmVerifyingReader) Close() error { return v.r.Close() }

// ---- primary ---------------------------------------------------------------

// rpmPackage is what bodega keeps of one primary <package>: its identity and
// the checksum its bytes must match.
type rpmPackage struct {
	name, epoch, ver, rel string
	sumType, sum          string
}

func (p rpmPackage) evr() string { return manifest.RpmEVR(p.epoch, p.ver, p.rel) }

// rpmPrimaryIndex is one parsed primary, keyed by href.
type rpmPrimaryIndex struct {
	checksum string
	pkgs     map[string]rpmPackage
}

// rpmPrimaryCache holds the parsed primary of each repository tree until
// repomd.xml names a primary with another checksum. Parsing EPEL's takes
// seconds, so each tree has its own lock and a parse holds up only requests
// for that tree.
type rpmPrimaryCache struct {
	mu    sync.Mutex
	trees map[string]*rpmPrimarySlot
}

type rpmPrimarySlot struct {
	mu  sync.Mutex
	idx *rpmPrimaryIndex
}

func (c *rpmPrimaryCache) slot(id string) *rpmPrimarySlot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.trees == nil {
		c.trees = map[string]*rpmPrimarySlot{}
	}
	sl := c.trees[id]
	if sl == nil {
		sl = &rpmPrimarySlot{}
		c.trees[id] = sl
	}
	return sl
}

// rpmPrimary is the index of the primary the current repomd.xml names. A
// primary with a checksum the cache already holds is not read again.
func (s *Server) rpmPrimary(r *http.Request, t rpmTree) (*rpmPrimaryIndex, error) {
	entry, err := s.rpmMetadataEntry(r, t, func(d rpmRepomdData) bool { return d.Type == "primary" })
	if err != nil {
		return nil, err
	}
	sl := s.rpmPrimaries.slot(t.id())
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if sl.idx != nil && sl.idx.checksum == entry.Checksum.Value {
		return sl.idx, nil
	}
	href := entry.Location.Href
	if !strings.HasPrefix(href, "repodata/") || strings.Contains(strings.TrimPrefix(href, "repodata/"), "/") {
		return nil, fmt.Errorf("repomd.xml places primary at %q, outside repodata/, which bodega does not serve", href)
	}
	// Served from the entry selected above rather than resolved by href
	// again: a repository that reuses primary's filename across revisions
	// would otherwise hand back the bytes of a revision this caller holds,
	// and they would be indexed under this entry's checksum.
	raw, err := s.rpmRead(r, t, "primary", func(w http.ResponseWriter, req *http.Request) { s.serveRpmMetadataEntry(w, req, t, entry) })
	if err != nil {
		return nil, err
	}
	pkgs, err := parseRpmPrimary(raw, path.Ext(href))
	if err != nil {
		return nil, fmt.Errorf("primary %s of %s: %w", href, t.id(), err)
	}
	sl.idx = &rpmPrimaryIndex{checksum: entry.Checksum.Value, pkgs: pkgs}
	s.logger.Info("rpm primary indexed", "repository", t.id(), "checksum", entry.Checksum.Value, "packages", len(pkgs))
	return sl.idx, nil
}

// rpmDecompress reads a metadata file in whichever compression its
// extension names; anything else is read as it is.
func rpmDecompress(raw []byte, ext string) (io.Reader, func(), error) {
	in := bytes.NewReader(raw)
	switch ext {
	case ".gz":
		zr, err := gzip.NewReader(in)
		if err != nil {
			return nil, nil, err
		}
		return zr, func() { _ = zr.Close() }, nil
	case ".xz":
		xr, err := xz.NewReader(in)
		if err != nil {
			return nil, nil, err
		}
		return xr, func() {}, nil
	case ".zst":
		zr, err := zstd.NewReader(in)
		if err != nil {
			return nil, nil, err
		}
		return zr, zr.Close, nil
	case ".bz2":
		return bzip2.NewReader(in), func() {}, nil
	}
	return in, func() {}, nil
}

// parseRpmPrimary reads every <package> of a primary document, streaming,
// since EPEL's runs to hundreds of thousands of elements. A package whose
// location carries xml:base lives on another host and is left out: bodega
// fetches only under the repository's own base URL.
func parseRpmPrimary(raw []byte, ext string) (map[string]rpmPackage, error) {
	r, closeFn, err := rpmDecompress(raw, ext)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	defer closeFn()
	lr := &io.LimitedReader{R: r, N: rpmMaxPrimary + 1}
	dec := xml.NewDecoder(lr)
	out := map[string]rpmPackage{}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if lr.N <= 0 {
				return nil, fmt.Errorf("expands past %d bytes", int64(rpmMaxPrimary))
			}
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "package" {
			continue
		}
		var p struct {
			Name    string `xml:"name"`
			Version struct {
				Epoch string `xml:"epoch,attr"`
				Ver   string `xml:"ver,attr"`
				Rel   string `xml:"rel,attr"`
			} `xml:"version"`
			Checksum struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"checksum"`
			Location struct {
				Href  string     `xml:"href,attr"`
				Attrs []xml.Attr `xml:",any,attr"`
			} `xml:"location"`
		}
		if err := dec.DecodeElement(&p, &se); err != nil {
			return nil, err
		}
		if hasXMLBase(p.Location.Attrs) || p.Location.Href == "" ||
			!manifest.RpmValidName(p.Name) || !rpmSafeHref(p.Location.Href) {
			continue
		}
		pkg := rpmPackage{name: p.Name, epoch: p.Version.Epoch, ver: p.Version.Ver, rel: p.Version.Rel,
			sumType: p.Checksum.Type, sum: strings.ToLower(strings.TrimSpace(p.Checksum.Value))}
		if !manifest.RpmValidEVR(pkg.evr()) {
			continue
		}
		out[p.Location.Href] = pkg
	}
	return out, nil
}

func hasXMLBase(attrs []xml.Attr) bool {
	for _, a := range attrs {
		if a.Name.Local == "base" {
			return true
		}
	}
	return false
}

// rpmSafeHref reports whether an href stays inside the repository: relative,
// no empty, "." or ".." segment, ending in .rpm.
func rpmSafeHref(href string) bool {
	if !strings.HasSuffix(href, ".rpm") || strings.HasPrefix(href, "/") || strings.ContainsAny(href, "\\?#\x00") {
		return false
	}
	for _, seg := range strings.Split(href, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
