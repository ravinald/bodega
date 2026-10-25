package server

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"net/http"

	modulepath "golang.org/x/mod/module"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
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
	// No allow-list candidate: the database is not a package, and refusing a
	// lookup under module rules would fail `go` for modules bodega serves.
	s.proxyOrCache(w, r, s.typeStore(manifest.TypeGomod), manifest.GomodSumdbKey(gomodSumdbName, rest),
		s.cfg.GomodSumdbURL+"/"+rest, manifest.TypeGomod, "", "sumdb/"+gomodSumdbName, immutable, false)
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
