package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"strconv"
	"strings"
	"time"

	"net/http"

	modulepath "golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/provenance"
	"github.com/ravinald/bodega/internal/storage"
)

// ---- Go module proxy -------------------------------------------------------

func (s *Server) handleGomod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fullPath := r.PathValue("path")
	// No module path can begin "sumdb/": the first element of one carries a
	// dot, which is the rule that lets the protocol put the checksum database
	// under the same root.
	if rest, ok := strings.CutPrefix(fullPath, "sumdb/"); ok {
		s.handleGomodSumdb(w, r, rest)
		return
	}
	var escaped, file, upstream string
	if m, ok := strings.CutSuffix(fullPath, "/@latest"); ok && m != "" {
		// Stored beside @v/list under the name the handler's mutable checks
		// already recognize, so it is cached, refreshed and filtered as the
		// listing is.
		escaped, file = m, "@latest"
		upstream = s.cfg.GomodUpstream + "/" + escaped + "/@latest"
	} else {
		idx := strings.Index(fullPath, "/@v/")
		if idx < 0 {
			http.NotFound(w, r)
			return
		}
		escaped = fullPath[:idx]
		file = fullPath[idx+4:] // "list", "v1.30.0.info", etc.
		upstream = s.cfg.GomodUpstream + "/" + escaped + "/@v/" + file
	}
	// The wire carries an uppercase letter as "!" plus its lowercase; every
	// manifest, profile entry and discovery row names the module as go.mod
	// spells it. The upstream URL and the storage key keep the wire form,
	// which is what the upstream serves and what the cache already holds.
	module, err := modulepath.UnescapePath(escaped)
	if err != nil {
		http.Error(w, "module path "+escaped+" is not a valid escaped Go module path: "+err.Error(), http.StatusBadRequest)
		return
	}

	s3Key := manifest.GomodFileKey(module, file)
	immutable := file != "list" && !strings.HasSuffix(file, "latest")

	pm, _ := s.store.GetPackage(ctx, manifest.TypeGomod, module)
	if pm != nil && isPackageHidden(pm) {
		s.refuseHidden(w, r, manifest.TypeGomod, module, "")
		return
	}

	// list and @latest are the mutable documents a profile decides the content
	// of; everything else under @v/ is an artifact whose bytes a profile
	// decides the reachability of. Neither may be stored by a cache shared
	// across host classes.
	if immutable {
		w = cachePrivateOn200(w, file)
	} else {
		noSharedCache(w)
	}

	// The listing names no version, so it is decided at the membership level
	// and filtered below; every other file under @v/ names one.
	if !s.entitleGate(w, r, manifest.TypeGomod, module, gomodVersionFromFile(file)) {
		return
	}
	// The index filter rewrites only a list answered from upstream, and the
	// artifact gate refuses only what such a list would have withheld: a
	// hosted module's list names versions admitted on import, and refusing
	// their files would be the mid-install 403 the filter exists to prevent.
	proxied := (pm == nil && s.cacheEnabled()) || (pm != nil && packageMode(pm) == manifest.ModeProxy)
	if proxied && s.refuseWithheld(w, r, manifest.TypeGomod, module, gomodVersionFromFile(file)) {
		return
	}
	if file == "list" || file == "@latest" {
		permit := profileVersionFilter(s.profileFor(r), manifest.TypeGomod, module)
		var withhold *indexWithhold
		if proxied {
			withhold = s.indexWithholdFor(r, manifest.TypeGomod, module)
		}
		if permit != nil || withhold != nil {
			filterList := func(b []byte) []byte {
				b = filterGomodList(b, permit)
				if withhold != nil {
					b = withhold.gomodList(b)
					withhold.finish(w.Header())
				}
				return b
			}
			rw := &indexFilterWriter{ResponseWriter: w, subject: module + "/@v/list", filter: filterList}
			if file == "@latest" {
				rw.subject = module + "/@latest"
				rw.filter = func(b []byte) []byte { return b }
			}
			s.serveGomodFile(rw, r, pm, module, file, s3Key, upstream, immutable)
			if file == "@latest" && rw.status == http.StatusOK && !rw.tooBig {
				// @latest names one version and cannot be filtered down to
				// another, so a version the list would drop is a 404. The go
				// command reads @latest only when the list offers nothing
				// suitable, and a 404 there is the same answer the filtered
				// list already gave.
				if v := gomodLatestVersion(rw.body.Bytes()); v != "" && len(bytes.TrimSpace(filterList([]byte(v+"\n")))) == 0 {
					http.Error(w, module+"/@latest names "+v+", which this host may not fetch; no other version is offered in its place", http.StatusNotFound)
					return
				}
			}
			if err := rw.flush(); err != nil {
				s.logger.Error("gomod list response failed", "module", module, "error", err)
			}
			return
		}
	}

	s.serveGomodFile(w, r, pm, module, file, s3Key, upstream, immutable)
}

// serveGomodFile is the body of handleGomod once the profile has decided
// whether the response passes through a filter. Split so the filtered and
// unfiltered paths cannot answer a request differently for any reason other
// than the filter.
func (s *Server) serveGomodFile(w http.ResponseWriter, r *http.Request, pm *manifest.PackageManifest, module, file, s3Key, upstream string, immutable bool) {
	ctx := r.Context()
	if pm != nil && packageMode(pm) == manifest.ModeProxy {
		// Version constraint enforcement: check if the requested version is allowed.
		if immutable {
			vc, ver := packageVersionConstraint(pm)
			if vc != "" && vc != manifest.ConstraintAny {
				reqVersion := file
				if dot := strings.LastIndex(file, "."); dot > 0 {
					reqVersion = file[:dot] // "v1.30.0.info" → "v1.30.0"
				}
				if ok, ordered := versionAllowed(manifest.TypeGomod, ver, reqVersion, vc); !ok {
					s.refuseVersionConstraint(w, r, manifest.TypeGomod, module, ver, reqVersion, vc, ordered)
					return
				}
			}
		}
		s.proxyOrCache(w, r, s.typeStore(manifest.TypeGomod), s3Key, upstream, manifest.TypeGomod, module, module, immutable, true)
		return
	}

	// A module no manifest names is answered upstream when the proxy is on, as
	// the npm packument and the cargo sparse index already are. Left to
	// proxyVersion it 404s, which is a `go get` for anything not catalogued
	// here failing against a feature README.md advertises for this type.
	//
	// Every file under @v/ takes this path, not just the mutable ones. The
	// listing alone answers nothing a client can act on: `go get` reads list,
	// then .info, .mod and .zip, and proxying the first while 404ing the rest
	// is a module resolution that fails one step later.
	if pm == nil && s.cacheEnabled() {
		s.proxyOrCache(w, r, s.typeStore(manifest.TypeGomod), s3Key, upstream, manifest.TypeGomod, module, module, immutable, false)
		return
	}

	if pm == nil {
		s.recordNoManifest(ctx, r, manifest.TypeGomod, module, gomodVersionFromFile(file), upstream)
	}
	if published, ok := gomodRecordedTime(pm, file); ok {
		rw := &indexFilterWriter{
			ResponseWriter: w,
			subject:        module + "/@v/" + file,
			filter:         func(b []byte) []byte { return gomodInfoWithTime(b, published) },
		}
		s.proxyVersion(rw, r, manifest.TypeGomod, module, gomodVersionFromFile(file), s3Key)
		if err := rw.flush(); err != nil {
			s.logger.Error("gomod info response failed", "module", module, "error", err)
		}
		return
	}
	s.proxyVersion(w, r, manifest.TypeGomod, module, gomodVersionFromFile(file), s3Key)
}

// gomodLatestVersion reads Version from an @latest document. A document that
// does not parse names nothing, and is passed through for the go command to
// report.
func gomodLatestVersion(body []byte) string {
	var doc struct{ Version string }
	if json.Unmarshal(body, &doc) != nil {
		return ""
	}
	return doc.Version
}

// handleGomodSumdb proxies the checksum database under /go/sumdb/, the part of
// the GOPROXY protocol that lets a host reaching only bodega verify go.sum
// lines. The go command checks every tree head and record against the public
// key it already holds, so bodega relays bytes it cannot forge.
//
// Only sum.golang.org is served: gomod_sumdb_url is where its bytes come from,
// and answering for another database name would hand the client that host's
// records under a name its key does not cover.
func (s *Server) handleGomodSumdb(w http.ResponseWriter, r *http.Request, p string) {
	name, rest, _ := strings.Cut(p, "/")
	if name != gomodSumdbName || !isSafePath(rest) {
		http.NotFound(w, r)
		return
	}
	var immutable bool
	switch {
	case rest == "supported":
		// A 200 routes every lookup here; a 404 sends the go command to the
		// database directly. With the proxy off the lookups below cannot be
		// answered, so the honest answer is the 404.
		if !s.cacheEnabled() {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	case rest == "latest", strings.HasPrefix(rest, "lookup/"):
		immutable = false
	case strings.HasPrefix(rest, "tile/"):
		// A full tile never changes. A partial one (".p/<width>") is
		// rewritten as the log grows, under the same name.
		immutable = !strings.Contains(rest, ".p/")
	default:
		http.NotFound(w, r)
		return
	}
	store := s.typeStore(manifest.TypeGomod)
	key := manifest.GomodSumdbKey(gomodSumdbName, rest)
	upstream := s.cfg.GomodSumdbURL + "/" + rest
	// No allow-list candidate: the database is not a package, and refusing a
	// lookup under module rules would fail `go` for modules bodega serves.
	proxy := func(w http.ResponseWriter) {
		s.proxyOrCache(w, r, store, key, upstream, manifest.TypeGomod, "", "sumdb/"+gomodSumdbName, immutable, false)
	}
	tile, ok := sumdbPartialHashTile(rest)
	if !ok || store == nil {
		proxy(w)
		return
	}
	// The listing answers both whether the requested width is cached and
	// which wider ones are. A store that cannot list is treated as holding
	// no wider source, which is what the handler did before slicing existed.
	widths, err := sumdbCachedPartialWidths(r.Context(), store, tile)
	if err != nil || widths[tile.W] {
		proxy(w)
		return
	}
	if s.serveSumdbTilePrefix(w, r, store, tile, widths) {
		return
	}
	// Before the status line rather than after the body: proxyOrCache writes
	// the 200 once the tile is cached, and a client that goes on to ask for a
	// narrower width of the same tile must find the digest already there.
	proxy(&beforeOK{ResponseWriter: w, hook: func() { s.recordSumdbPartialDigest(r.Context(), store, tile) }})
}

// sumdbMaxTileHeight bounds the tiles bodega slices. sum.golang.org uses 8,
// and a full tile is 2^H hashes, so the bound is also what caps the read of a
// cached source at 8 KiB rather than whatever height a request names.
const sumdbMaxTileHeight = 8

// sumdbHashSize is the width of one entry in a hash tile.
const sumdbHashSize = 32

// sumdbPartialHashTile parses rest as a partial hash tile. Data tiles
// (tile/H/data/...) are excluded: their entries are records of varying
// length, so the first W of them is not the first W*32 bytes.
func sumdbPartialHashTile(rest string) (tlog.Tile, bool) {
	tile, err := tlog.ParseTilePath(rest)
	if err != nil || tile.L < 0 || tile.H > sumdbMaxTileHeight || tile.W >= 1<<tile.H {
		return tlog.Tile{}, false
	}
	return tile, true
}

// sumdbCachedPartialWidths lists the partial widths cached for tile's
// position, in one List of "<tile>.p/" whatever the requested width: probing
// each width above it would cost up to 2^H-1 reads per miss, a request each
// on S3, and a partial holds fewer than 2^H entries, so the listing fits one
// page. The store is the record rather than an index kept beside it, so a
// tile cached before this code existed is found, and two fills finishing in
// either order cannot leave a wider tile hidden behind a narrower entry.
func sumdbCachedPartialWidths(ctx context.Context, store storage.ObjectStore, tile tlog.Tile) (map[int]bool, error) {
	full := tile
	full.W = 1 << tile.H
	prefix := manifest.GomodSumdbKey(gomodSumdbName, full.Path()) + ".p/"
	keys, err := store.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	widths := make(map[int]bool, len(keys))
	for _, k := range keys {
		s := strings.TrimPrefix(k, prefix)
		w, err := strconv.Atoi(s)
		if err != nil || strconv.Itoa(w) != s || w <= 0 || w >= full.W {
			continue
		}
		widths[w] = true
	}
	return widths, nil
}

// sumdbPartialDigest is the SHA-256 of one cached partial tile, read back from
// the store when it was filled. Partial tiles are mutable objects, so the
// audit store pins no digest for them, and slicing bytes nothing vouches for
// would hand a client a corrupt tile it reports as a checksum-database
// security error.
type sumdbPartialDigest struct {
	Width  int    `json:"width"`
	SHA256 string `json:"sha256"`
}

// sumdbPartialDigestKey is where the sumdbPartialDigest for tile, at its own
// width, lives. One key per width: a fill writes only its own record, so
// fills of different widths never overwrite each other's. "digest/" is not a
// path the handler answers, so a client cannot read it.
func sumdbPartialDigestKey(tile tlog.Tile) string {
	return manifest.GomodSumdbKey(gomodSumdbName, "digest/"+tile.Path())
}

// serveSumdbTilePrefix answers a missing partial tile with the first W hashes
// of the same tile cached complete, or of the widest partial cached wider,
// as the go command slices its own cache (sumdb.Client.readTile in
// golang.org/x/mod). The client checks every hash against a tree head it
// already holds, so the slice is no less authenticated than the source; it is
// what lets `go` verify with the upstream unreachable. It reports false, having
// written nothing, when no verified source is cached.
//
// The slice is never stored under its own key: it would be a copy of bytes
// already held, and a write here is a write per request for every width.
func (s *Server) serveSumdbTilePrefix(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, tile tlog.Tile, widths map[int]bool) bool {
	ctx := r.Context()
	full := tile
	full.W = 1 << tile.H
	fullKey := manifest.GomodSumdbKey(gomodSumdbName, full.Path())
	src, obj, ok := s.readSumdbTile(ctx, store, fullKey, full.W, func(digest string, _ cachedObject) bool {
		if s.auditDB == nil {
			return false
		}
		stored, err := s.auditDB.GetChecksum(ctx, fullKey)
		return err == nil && stored != nil && stored.Value == digest
	})
	srcKey := fullKey
	if !ok {
		widest := 0
		for wd := range widths {
			widest = max(widest, wd)
		}
		if widest <= tile.W {
			return false
		}
		wide := tile
		wide.W = widest
		srcKey = manifest.GomodSumdbKey(gomodSumdbName, wide.Path())
		src, obj, ok = s.readSumdbTile(ctx, store, srcKey, wide.W, s.sumdbPartialVerifier(ctx, store, wide, srcKey))
		if !ok {
			return false
		}
	}
	s.logFor(ctx).Info("sumdb partial tile served from a wider cached tile",
		"key", manifest.GomodSumdbKey(gomodSumdbName, tile.Path()), "source", srcKey)
	s.recordCacheHit(ctx, r, manifest.TypeGomod, s.cfg.GomodSumdbURL+"/"+tile.Path(), "", "sumdb/"+gomodSumdbName, srcKey, obj)
	body := src[:tile.W*sumdbHashSize]
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		_ = failBodyTransfer(ctx, fmt.Errorf("write %s sliced from %s: %w", tile.Path(), srcKey, err))
	}
	return true
}

// sumdbPartialVerifier decides whether the cached partial at key may be
// sliced. Its sumdbPartialDigest decides when there is one. A partial cached
// before digests were kept has none, and falls back to the cache origin the
// fill recorded: that row binds the store's identity of the object (ETag, or
// size and modification time) to the fetch, so bytes rewritten since do not
// match it. A partial with neither is not sliced.
func (s *Server) sumdbPartialVerifier(ctx context.Context, store storage.ObjectStore, tile tlog.Tile, key string) func(string, cachedObject) bool {
	rec, found := readSumdbPartialDigest(ctx, store, tile)
	return func(digest string, obj cachedObject) bool {
		if found {
			return digest == rec.SHA256
		}
		if s.auditDB == nil {
			return false
		}
		origin, err := s.auditDB.CacheOrigin(ctx, key, obj.id)
		return err == nil && origin != ""
	}
}

// readSumdbTile reads the cached tile at key, which must hold exactly width
// hashes and pass verified on its sha256 and the store's identity of the
// object. A source that is absent, the wrong length or fails verified is not
// one to slice, and the caller falls through to the next source or the
// upstream.
func (s *Server) readSumdbTile(ctx context.Context, store storage.ObjectStore, key string, width int, verified func(digest string, obj cachedObject) bool) ([]byte, cachedObject, bool) {
	res, err := store.GetStream(ctx, key)
	if err != nil || res == nil {
		return nil, cachedObject{}, false
	}
	defer func() { _ = res.Body.Close() }()
	want := width * sumdbHashSize
	data, err := io.ReadAll(io.LimitReader(res.Body, int64(want)+1))
	if err != nil || len(data) != want {
		s.logFor(ctx).Warn("cached sumdb tile is not the length its width names, not slicing it",
			"key", key, "bytes", len(data), "want", want, "error", err)
		return nil, cachedObject{}, false
	}
	sum := sha256.Sum256(data)
	obj := cachedObject{store: store, id: streamIdentity(store, res)}
	if !verified(hex.EncodeToString(sum[:]), obj) {
		s.logFor(ctx).Warn("cached sumdb tile does not match its stored checksum, not slicing it; the request goes upstream",
			"key", key)
		return nil, cachedObject{}, false
	}
	return data, obj, true
}

// readSumdbPartialDigest reads tile's sumdbPartialDigest; found is false when
// there is none or it does not describe tile's width.
func readSumdbPartialDigest(ctx context.Context, store storage.ObjectStore, tile tlog.Tile) (sumdbPartialDigest, bool) {
	data, err := store.Get(ctx, sumdbPartialDigestKey(tile))
	if err != nil || data == nil {
		return sumdbPartialDigest{}, false
	}
	var rec sumdbPartialDigest
	if json.Unmarshal(data, &rec) != nil || rec.Width != tile.W || len(rec.SHA256) != sha256.Size*2 {
		return sumdbPartialDigest{}, false
	}
	return rec, true
}

// recordSumdbPartialDigest writes the sumdbPartialDigest of the partial just
// cached. It reads the cached object back rather than trusting the response,
// so the digest describes what a later slice will read. Two fills of one
// width write the same record, since a partial of a given width never
// changes; if the stored bytes nonetheless differ from the record, the slice
// is refused and the request goes upstream, never served wrong.
func (s *Server) recordSumdbPartialDigest(ctx context.Context, store storage.ObjectStore, tile tlog.Tile) {
	key := manifest.GomodSumdbKey(gomodSumdbName, tile.Path())
	data, err := store.Get(ctx, key)
	if err != nil || len(data) != tile.W*sumdbHashSize {
		return
	}
	sum := sha256.Sum256(data)
	rec, err := json.Marshal(sumdbPartialDigest{Width: tile.W, SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		return
	}
	if err := store.Put(ctx, sumdbPartialDigestKey(tile), rec); err != nil {
		s.logFor(ctx).Warn("could not record the digest of a cached sumdb partial; a narrower miss will fall back to its cache origin",
			"key", key, "error", err)
	}
}

// beforeOK runs hook once, ahead of a 200 status line, and passes everything
// else through.
type beforeOK struct {
	http.ResponseWriter
	hook    func()
	written bool
}

func (b *beforeOK) WriteHeader(code int) {
	if !b.written {
		b.written = true
		if code == http.StatusOK {
			b.hook()
		}
	}
	b.ResponseWriter.WriteHeader(code)
}

func (b *beforeOK) Write(p []byte) (int, error) {
	if !b.written {
		b.WriteHeader(http.StatusOK)
	}
	return b.ResponseWriter.Write(p)
}

func (b *beforeOK) Unwrap() http.ResponseWriter { return b.ResponseWriter }

// checksumDatabaseGate holds a Go module's .zip or .mod, spooled at path, to
// the hash the checksum database signed for it when the fill's admission
// recorded the version verified. It returns the refusal to answer on a
// disagreement, having written the policy_blocked row, and nil otherwise:
// for any other file, type or outcome there is no signed hash to compare. No
// policy or override applies.
func (s *Server) checksumDatabaseGate(ctx context.Context, r *http.Request, fill fillAdmission, s3Key, path string) *refusal {
	if fill.typ != manifest.TypeGomod {
		return nil
	}
	ext := pathpkg.Ext(s3Key)
	if ext != ".zip" && ext != ".mod" {
		return nil
	}
	entry := admit.ChecksumDatabaseEntry(fill.row)
	if entry == nil || entry.ChecksumDatabase.Outcome != audit.ProvenanceVerified {
		return nil
	}
	want := entry.ChecksumDatabase.ZipHash
	var (
		got string
		err error
	)
	if ext == ".zip" {
		got, err = dirhash.HashZip(path, dirhash.Hash1)
	} else {
		want = entry.ChecksumDatabase.ModHash
		got, err = dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) { return os.Open(path) }) //nolint:gosec // the spool file this fill wrote
	}
	if err != nil {
		got = "an error (" + err.Error() + ")"
	}
	if err == nil && got == want {
		return nil
	}
	file := pathpkg.Base(s3Key)
	_, incident := admit.RecordChecksumMismatch(ctx, s.auditDB, fill.row, file, got, admit.Who{Identity: Identity(r)})
	s.logFor(ctx).Error("checksum database mismatch", "module", fill.name, "version", fill.version, "file", file,
		"database_hash", want, "computed_hash", got, "incident", incident)
	return checksumDatabaseRefusal(fill.name, fill.version, incident)
}

// gomodUnpublished reports whether a gomod fill names a version the checksum
// database cannot confirm and the upstream does not publish. The go command
// resolves a package path by asking for the .info of each prefix and moves
// on at a 404 or 410, so a prefix that is no module has to get the
// upstream's not-found: the checksum_database refusal is a 403, which the go
// command treats as fatal. Only a .info fill is probed, because .mod and .zip
// are asked for once a module resolved. Only unknown leads to the upstream
// read, and only a 404 or 410 there skips the admission; any other answer
// leaves the refusal standing. A read that cannot reach the upstream is
// answered from the not-found record an earlier 404 left, as every fill is
// during an outage: the probe skips the fetch path that writes and reads that
// record, so this does both, or an outage turns every prefix of a command
// path the cache carries into a refusal. Any 2xx, served or not, proves the
// path exists and clears that record, as the ordinary fill does.
func (s *Server) gomodUnpublished(ctx context.Context, checkers []policy.VersionChecker, fill fillAdmission, s3Key string, ve manifest.VersionEntry) bool {
	if fill.typ != manifest.TypeGomod || fill.version == "" || pathpkg.Ext(s3Key) != ".info" {
		return false
	}
	var db *provenance.ChecksumDatabase
	for _, c := range checkers {
		if d, ok := c.(*provenance.ChecksumDatabase); ok {
			db = d
		}
	}
	if db == nil {
		return false
	}
	res := db.Check(ctx, &manifest.PackageManifest{Type: manifest.TypeGomod, Name: fill.name}, &ve)
	if res.ChecksumDatabase == nil || res.ChecksumDatabase.Outcome != audit.ProvenanceUnknown {
		return false
	}
	escaped, err := modulepath.EscapePath(fill.name)
	if err != nil {
		return false
	}
	ev, err := modulepath.EscapeVersion(fill.version)
	if err != nil {
		return false
	}
	info := strings.TrimRight(s.cfg.GomodUpstream, "/") + "/" + escaped + "/@v/" + ev + ".info"
	open := func(ctx context.Context, u string) (*upstreamStream, error) { return openUpstream(ctx, u, false) }
	if o, ok := ctx.Value(upstreamOpenerKey{}).(upstreamOpener); ok {
		open = o
	}
	store := s.typeStore(fill.typ)
	up, err := open(ctx, info)
	if err == nil {
		up.body.Close()
	}
	if err == nil || upstreamAnsweredIn(err) {
		if store != nil {
			s.clearNotFound(ctx, store, s3Key)
		}
		return false
	}
	var status *upstreamStatusError
	unpublished := errors.Is(err, errUpstreamNotFound) || (errors.As(err, &status) && status.status == http.StatusGone)
	if errors.Is(err, errUpstreamNotFound) {
		s.recordNotFound(ctx, store, fill.typ, s3Key)
	}
	if !unpublished && s.recordedNotFound(ctx, store, fill.typ, s3Key, err) {
		return true
	}
	if unpublished {
		s.logFor(ctx).Info("checksum database and upstream both lack this Go module version, answering not found",
			"module", fill.name, "version", fill.version, "url", info)
	}
	return unpublished
}

// gomodSumdbName is the checksum database the go command names by default.
const gomodSumdbName = "sum.golang.org"

// gomodRecordedTime returns the publish time recorded for the version a .info
// request names. Any other file, or a version with none recorded, is served
// as stored.
func gomodRecordedTime(pm *manifest.PackageManifest, file string) (time.Time, bool) {
	if pm == nil || !strings.HasSuffix(file, ".info") {
		return time.Time{}, false
	}
	version := strings.TrimSuffix(file, ".info")
	for _, ve := range pm.Versions {
		if ve.Version == version {
			return publishedTime(ve)
		}
	}
	return time.Time{}, false
}

// gomodInfoWithTime sets Time in a stored .info document to the recorded
// publish time, keeping every other field. The stored document is upstream's
// own, so the two normally agree; the manifest is what every hosted index
// answers from, and a .info disagreeing with the packument and the simple page
// would give one module two ages. A document that does not parse is passed
// through as it is, since the go command reports that better than this can.
func gomodInfoWithTime(body []byte, published time.Time) []byte {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil || doc == nil {
		return body
	}
	ts, err := json.Marshal(published.Format(time.RFC3339))
	if err != nil {
		return body
	}
	doc["Time"] = ts
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

// gomodVersionFromFile recovers the manifest version from a proxy filename.
// "list" and "@latest" name no version and return "", which routes them by
// type — correct, because both are regenerable listings rather than artifacts.
func gomodVersionFromFile(file string) string {
	for _, ext := range []string{".zip", ".info", ".mod"} {
		if strings.HasSuffix(file, ext) {
			return strings.TrimSuffix(file, ext)
		}
	}
	return ""
}

// versionAllowed reports whether reqVersion satisfies the constraint relative
// to entryVersion under typ's version ordering, and whether both versions
// could be ordered at all. An unorderable pair is refused under every
// constraint but any: a range nobody can place a version in admits nothing,
// and the second return lets the refusal say so rather than call the version
// out of range.
func versionAllowed(typ, entryVersion, reqVersion, constraint string) (allowed, ordered bool) {
	if constraint == manifest.ConstraintAny {
		return true, true
	}
	c, ok := policy.CompareVersions(typ, reqVersion, entryVersion)
	if !ok {
		return false, false
	}
	switch constraint {
	case manifest.ConstraintExact, "":
		return c == 0, true
	case manifest.ConstraintCompatible:
		return c >= 0 && sharesRelease(typ, entryVersion, reqVersion, 1), true
	case manifest.ConstraintPatch:
		return c >= 0 && sharesRelease(typ, entryVersion, reqVersion, 2), true
	}
	return false, true
}

// sharesRelease reports whether two versions agree on their first n release
// segments, a missing segment reading as 0 so that Maven's 2 is 2.0.
func sharesRelease(typ, a, b string, n int) bool {
	ra, oka := policy.ReleaseSegments(typ, a)
	rb, okb := policy.ReleaseSegments(typ, b)
	if !oka || !okb {
		return false
	}
	at := func(r []int, i int) int {
		if i < len(r) {
			return r[i]
		}
		return 0
	}
	for i := range n {
		if at(ra, i) != at(rb, i) {
			return false
		}
	}
	return true
}
