package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Composer repository ---------------------------------------------------
//
// Bodega serves a Composer v2 repository under /composer/, pulled through
// from composer_upstream (Packagist):
//
//   /composer/packages.json                                     — bodega's own root document
//   /composer/p2/<vendor>/<package>.json and ~dev.json          — metadata, mutable
//   /composer/dist/<vendor>/<package>/<version>/<reference>.<type> — archive, immutable
//
// Packagist serves metadata only. Each version's archive lives at the URL its
// dist names, almost always a GitHub zipball, so the metadata is rewritten on
// the way out to send every archive through the dist route, and the dist
// route reads the archive's upstream URL back out of the cached metadata. The
// request path names which archive; it never names where bodega fetches it.
//
// Anything else 404s here, before any upstream is composed.

// composerDistTypePattern is a dist type, which is the archive's extension.
var composerDistTypePattern = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// composerCodeloadBase is where GitHub's API redirects a zipball. A variable
// so a test can stand an archive host in for it.
var composerCodeloadBase = "https://codeload.github.com"

// composerRootDocument names the per-package metadata route and nothing else.
// With no providers-url, notify-batch or search key, Composer 2 has no other
// URL on this repository to read, and no other host to report installs to.
const composerRootDocument = `{"packages":[],"metadata-url":"/composer/p2/%package%.json"}` + "\n"

func (s *Server) handleComposer(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	switch {
	case p == "packages.json":
		noSharedCache(w)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(composerRootDocument))
	case strings.HasPrefix(p, "p2/"):
		file, ok := strings.CutSuffix(strings.TrimPrefix(p, "p2/"), ".json")
		name, dev := strings.CutSuffix(file, "~dev")
		if !ok || !manifest.ComposerValidName(name) {
			http.NotFound(w, r)
			return
		}
		s.handleComposerMetadata(w, r, name, dev)
	case strings.HasPrefix(p, "dist/"):
		d, ok := parseComposerDistPath(r.URL.EscapedPath())
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.handleComposerDist(w, r, d)
	default:
		http.NotFound(w, r)
	}
}

// composerDist is the archive a dist route names.
type composerDist struct {
	name, version, reference, typ string
}

func (d composerDist) file() string { return d.reference + "." + d.typ }

// parseComposerDistPath reads /composer/dist/<vendor>/<package>/<version>/<reference>.<type>
// from the escaped path, segment by segment, because a branch version holds a
// "/" that only its escaping keeps inside one segment.
func parseComposerDistPath(escaped string) (composerDist, bool) {
	rest, ok := strings.CutPrefix(escaped, "/composer/dist/")
	if !ok {
		return composerDist{}, false
	}
	segs := strings.Split(rest, "/")
	if len(segs) != 4 {
		return composerDist{}, false
	}
	for i, seg := range segs {
		u, err := url.PathUnescape(seg)
		if err != nil || u == "" {
			return composerDist{}, false
		}
		segs[i] = u
	}
	dot := strings.LastIndex(segs[3], ".")
	if dot <= 0 {
		return composerDist{}, false
	}
	d := composerDist{
		name:      segs[0] + "/" + segs[1],
		version:   segs[2],
		reference: segs[3][:dot],
		typ:       segs[3][dot+1:],
	}
	if !manifest.ComposerValidName(d.name) || !manifest.ComposerValidReference(d.reference) ||
		!composerDistTypePattern.MatchString(d.typ) || strings.ContainsAny(d.version, "\x00\r\n") {
		return composerDist{}, false
	}
	return d, true
}

// composerDevVersion reports whether a version is a branch, which Packagist
// lists in ~dev.json rather than beside the tagged releases.
func composerDevVersion(v string) bool {
	return strings.HasPrefix(v, "dev-") || strings.HasSuffix(v, "-dev")
}

func composerMetadataPath(name string, dev bool) string {
	if dev {
		return "/p2/" + name + "~dev.json"
	}
	return "/p2/" + name + ".json"
}

// handleComposerMetadata serves a package's p2 document with every dist URL
// rewritten onto this server. The cache holds the upstream's bytes, so the
// rewrite runs on every answer and follows this request's own base URL.
func (s *Server) handleComposerMetadata(w http.ResponseWriter, r *http.Request, name string, dev bool) {
	noSharedCache(w)
	pm, _ := s.store.GetPackage(r.Context(), manifest.TypeComposer, name)
	if pm != nil && isPackageHidden(pm) {
		s.refuseHidden(w, r, manifest.TypeComposer, name, "")
		return
	}
	if !s.entitleGateAnswering(w, r, manifest.TypeComposer, name, "", http.StatusNotFound) {
		return
	}
	base := s.publicBase(r) + "/composer/dist"
	rw := &indexFilterWriter{
		ResponseWriter: w,
		subject:        "the composer metadata for " + name,
		parse:          func(b []byte) ([]byte, error) { return rewriteComposerDists(b, base) },
		rewrite:        "dist URL rewrite",
		passThrough:    "hand the client the upstream's dist URLs and send its archive fetches around bodega",
	}
	s.proxyOrCache(rw, r, s.typeStore(manifest.TypeComposer), manifest.ComposerMetadataKey(name, dev),
		s.cfg.ComposerUpstream+composerMetadataPath(name, dev), manifest.TypeComposer, name, name, false, false)
	if err := rw.flush(); err != nil {
		s.logger.Error("composer metadata response failed", "package", name, "error", err)
	}
}

// handleComposerDist serves one version's archive. The gates are the ones a
// gem file passes, the manifest's version constraint included, and they run
// before the metadata is read for the archive's URL.
func (s *Server) handleComposerDist(w http.ResponseWriter, r *http.Request, d composerDist) {
	ctx := r.Context()
	pm, _ := s.store.GetPackage(ctx, manifest.TypeComposer, d.name)
	if pm != nil {
		if isPackageHidden(pm) {
			s.refuseHidden(w, r, manifest.TypeComposer, d.name, "")
			return
		}
		if isVersionHidden(pm, d.version) {
			s.refuseHidden(w, r, manifest.TypeComposer, d.name, d.version)
			return
		}
		vc, baseVer := packageVersionConstraint(pm)
		if vc != "" && vc != manifest.ConstraintAny && baseVer != "" {
			if ok, ordered := versionAllowed(manifest.TypeComposer, baseVer, d.version, vc); !ok {
				s.refuseVersionConstraint(w, r, manifest.TypeComposer, d.name, baseVer, d.version, vc, ordered)
				return
			}
		}
	}
	if !s.entitleGate(w, r, manifest.TypeComposer, d.name, d.version) {
		return
	}

	w = cachePrivateOn200(w, d.file())
	forceProxy := pm == nil || packageMode(pm) == manifest.ModeProxy
	store, err := s.versionStore(ctx, manifest.TypeComposer, d.name, d.version)
	if err != nil {
		s.logger.Error("storage backend recorded for artifact is not configured",
			"type", manifest.TypeComposer, "package", d.name, "version", d.version, "error", err)
		http.Error(w, "storage backend error", http.StatusBadGateway)
		return
	}
	resolve := func(context.Context) (string, error) { return s.composerDistUpstream(r, d) }
	s.proxyOrResolve(w, r, store, manifest.ComposerDistKey(d.name, d.version, d.reference), resolve, "", nil,
		manifest.TypeComposer, d.name, d.name, true, forceProxy)
}

// composerDistUpstream is the URL the metadata names for d's archive, read
// through the metadata route's own cache so a fresh copy costs no upstream
// read. A version or reference the metadata does not list is
// errUpstreamNotFound, and no archive host is contacted for it.
func (s *Server) composerDistUpstream(r *http.Request, d composerDist) (string, error) {
	dev := composerDevVersion(d.version)
	doc, err := s.composerMetadataDocument(r, d.name, dev)
	if err != nil {
		return "", err
	}
	named, err := composerDistURL(doc, d)
	if err != nil {
		return "", err
	}
	fetch, err := composerFetchURL(named)
	if err != nil {
		return "", err
	}
	for _, raw := range []string{named, fetch} {
		u, _ := url.Parse(raw)
		if host := u.Hostname(); !s.composerDistHostListed(host) {
			f := newRefusal(checkDistHost, manifest.TypeComposer, d.name, d.version, http.StatusForbidden)
			f.reason = fmt.Sprintf("its dist archive is on %s, which composer_dist_hosts does not list.", host)
			f.next = fmt.Sprintf("ask an operator to add %s to composer_dist_hosts if archives should be fetched from it.", host)
			return "", &resolveRefusal{f: f}
		}
	}
	return fetch, nil
}

func (s *Server) composerDistHostListed(host string) bool {
	host = config.CanonicalHost(host)
	for _, h := range s.cfg.ComposerDistHosts {
		if config.CanonicalHost(h) == host {
			return true
		}
	}
	return false
}

// composerMetadataDocument reads a package's p2 document as the metadata
// route would fetch it, unrewritten. The read is marked as bodega's own
// (withOwnRead), so it writes no audit or discovery row in the client's name;
// the dist request has written its own.
func (s *Server) composerMetadataDocument(r *http.Request, name string, dev bool) ([]byte, error) {
	req := r.Clone(withOwnRead(r.Context()))
	req.URL.Path = "/composer" + composerMetadataPath(name, dev)
	req.URL.RawPath = ""
	req.URL.RawQuery = ""
	for _, h := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
		req.Header.Del(h)
	}
	cw := &capturedResponse{header: http.Header{}}
	s.proxyOrCache(cw, req, s.typeStore(manifest.TypeComposer), manifest.ComposerMetadataKey(name, dev),
		s.cfg.ComposerUpstream+composerMetadataPath(name, dev), manifest.TypeComposer, name, name, false, false)
	switch {
	case cw.tooBig:
		return nil, fmt.Errorf("composer metadata for %s exceeds bodega's %d-byte buffer", name, maxUpstreamBody)
	case cw.status == http.StatusNotFound:
		return nil, fmt.Errorf("%w: Packagist lists no package %s", errUpstreamNotFound, name)
	case cw.status != 0 && cw.status != http.StatusOK:
		return nil, fmt.Errorf("composer metadata for %s answered HTTP %d", name, cw.status)
	}
	return cw.body.Bytes(), nil
}

// composerDistURL finds the dist URL the metadata names for d, matched on the
// version, the reference and the type together.
func composerDistURL(doc []byte, d composerDist) (string, error) {
	pkgs, err := parseComposerMetadata(doc)
	if err != nil {
		return "", fmt.Errorf("composer metadata for %s does not parse: %w", d.name, err)
	}
	for _, pkg := range pkgs {
		if pkg.name != d.name {
			continue
		}
		for _, v := range pkg.versions {
			if v.version != d.version || v.dist == nil {
				continue
			}
			var dist struct {
				URL       string `json:"url"`
				Reference string `json:"reference"`
				Type      string `json:"type"`
			}
			if json.Unmarshal(v.dist, &dist) != nil {
				continue
			}
			if dist.Reference == d.reference && dist.Type == d.typ && dist.URL != "" {
				return dist.URL, nil
			}
		}
	}
	return "", fmt.Errorf("%w: the metadata for %s lists no %s archive of %s at reference %s",
		errUpstreamNotFound, d.name, d.typ, d.version, d.reference)
}

// composerFetchURL is the URL an archive is fetched from. A GitHub API
// zipball is fetched from codeload, the address the API redirects it to:
// codeload carries no API rate limit, which an anonymous fetch from the API
// host exhausts at sixty archives an hour.
func composerFetchURL(named string) (string, error) {
	u, err := url.Parse(named)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("the dist URL %q does not parse as an absolute URL", named)
	}
	if !strings.EqualFold(u.Hostname(), "api.github.com") {
		return named, nil
	}
	segs := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	if len(segs) != 5 || segs[0] != "repos" || segs[3] != "zipball" || segs[1] == "" || segs[2] == "" || segs[4] == "" {
		return named, nil
	}
	return composerCodeloadBase + "/" + segs[1] + "/" + segs[2] + "/legacy.zip/" + segs[4], nil
}

// resolveRefusal is a resolver error that is a refusal on bodega's own
// authority rather than a failure to look, and is answered as that refusal.
type resolveRefusal struct{ f *refusal }

func (e *resolveRefusal) Error() string { return e.f.summary() }

// ---- minified metadata -----------------------------------------------------

// jsonSpan is the byte range of one JSON value inside a document.
type jsonSpan struct{ start, end int }

type jsonMember struct {
	key string
	val jsonSpan
}

// jsonObjectMembers lists an object's members with the span of each value,
// and the offset of the object's closing brace.
func jsonObjectMembers(doc []byte, obj jsonSpan) ([]jsonMember, int, error) {
	raw := doc[obj.start:obj.end]
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, 0, errors.New("want an object")
	}
	var out []jsonMember
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, 0, err
		}
		key, _ := tok.(string)
		off := int(dec.InputOffset())
		for off < len(raw) && strings.IndexByte(" \t\r\n:", raw[off]) >= 0 {
			off++
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, 0, err
		}
		out = append(out, jsonMember{key: key, val: jsonSpan{obj.start + off, obj.start + int(dec.InputOffset())}})
	}
	if _, err := dec.Token(); err != nil {
		return nil, 0, err
	}
	return out, obj.start + int(dec.InputOffset()) - 1, nil
}

// jsonArrayElements lists the span of each element of an array.
func jsonArrayElements(doc []byte, arr jsonSpan) ([]jsonSpan, error) {
	raw := doc[arr.start:arr.end]
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, errors.New("want an array")
	}
	var out []jsonSpan
	for dec.More() {
		off := int(dec.InputOffset())
		for off < len(raw) && strings.IndexByte(" \t\r\n,", raw[off]) >= 0 {
			off++
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, err
		}
		out = append(out, jsonSpan{arr.start + off, arr.start + int(dec.InputOffset())})
	}
	return out, nil
}

func memberSpan(ms []jsonMember, key string) (jsonSpan, bool) {
	for _, m := range ms {
		if m.key == key {
			return m.val, true
		}
	}
	return jsonSpan{}, false
}

// composerVersionEntry is one version of a package as Composer reads it,
// after the minified format's inheritance, with where its bytes sit.
type composerVersionEntry struct {
	version string
	// dist is the version's effective dist object, inherited or its own, and
	// nil when it has none.
	dist json.RawMessage
	// distSpan is the version's own dist value, absent when it inherits one.
	distSpan *jsonSpan
	// closeBrace is where a dist the version inherits is written in.
	closeBrace int
	empty      bool
}

type composerPackage struct {
	name     string
	versions []composerVersionEntry
}

// parseComposerMetadata reads a p2 document. Under "minified":"composer/2.0"
// each version lists only the keys that differ from the version before it,
// and "__unset" removes one, so a version with no dist key of its own carries
// the previous version's.
func parseComposerMetadata(doc []byte) ([]composerPackage, error) {
	top, _, err := jsonObjectMembers(doc, jsonSpan{0, len(doc)})
	if err != nil {
		return nil, err
	}
	minified := false
	if sp, ok := memberSpan(top, "minified"); ok {
		var m string
		_ = json.Unmarshal(doc[sp.start:sp.end], &m)
		minified = m == "composer/2.0"
	}
	sp, ok := memberSpan(top, "packages")
	if !ok {
		return nil, nil
	}
	pkgMembers, _, err := jsonObjectMembers(doc, sp)
	if err != nil {
		// Packagist answers an unknown package with an empty "packages" array.
		if bytes.Equal(bytes.TrimSpace(doc[sp.start:sp.end]), []byte("[]")) {
			return nil, nil
		}
		return nil, fmt.Errorf("packages: %w", err)
	}
	var out []composerPackage
	for _, pm := range pkgMembers {
		elems, err := jsonArrayElements(doc, pm.val)
		if err != nil {
			return nil, fmt.Errorf("packages[%q]: %w", pm.key, err)
		}
		pkg := composerPackage{name: pm.key}
		var version string
		var dist json.RawMessage
		for i, el := range elems {
			ms, closeBrace, err := jsonObjectMembers(doc, el)
			if err != nil {
				return nil, fmt.Errorf("packages[%q][%d]: %w", pm.key, i, err)
			}
			inherit := minified && i > 0
			if !inherit {
				version, dist = "", nil
			}
			if vs, ok := memberSpan(ms, "version"); ok {
				version = ""
				_ = json.Unmarshal(doc[vs.start:vs.end], &version)
			}
			e := composerVersionEntry{closeBrace: closeBrace, empty: len(ms) == 0}
			if ds, ok := memberSpan(ms, "dist"); ok {
				raw := bytes.TrimSpace(doc[ds.start:ds.end])
				if len(raw) > 0 && raw[0] == '{' {
					dist, e.distSpan = json.RawMessage(raw), &ds
				} else {
					// null, or "__unset" under minification: no dist.
					dist = nil
				}
			}
			e.version, e.dist = version, dist
			pkg.versions = append(pkg.versions, e)
		}
		out = append(out, pkg)
	}
	return out, nil
}

// rewriteComposerDists points every dist URL in a p2 document at
// <base>/<vendor>/<package>/<version>/<reference>.<type>, and changes no
// other byte. A version that inherits its dist under minification is given
// one of its own, since the inherited URL would name the previous version's
// archive. A version with no dist is left as it is: Composer installs it from
// source, around bodega.
func rewriteComposerDists(doc []byte, base string) ([]byte, error) {
	pkgs, err := parseComposerMetadata(doc)
	if err != nil {
		return nil, err
	}
	type edit struct {
		at, end int
		with    []byte
	}
	var edits []edit
	for _, pkg := range pkgs {
		for _, v := range pkg.versions {
			if v.dist == nil {
				continue
			}
			dist, err := rewriteComposerDist(v.dist, base, pkg.name, v.version)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", pkg.name, v.version, err)
			}
			if v.distSpan != nil {
				edits = append(edits, edit{v.distSpan.start, v.distSpan.end, dist})
				continue
			}
			ins := []byte(`"dist":`)
			if !v.empty {
				ins = []byte(`,"dist":`)
			}
			edits = append(edits, edit{v.closeBrace, v.closeBrace, append(ins, dist...)})
		}
	}
	var out bytes.Buffer
	out.Grow(len(doc))
	last := 0
	for _, e := range edits {
		out.Write(doc[last:e.at])
		out.Write(e.with)
		last = e.end
	}
	out.Write(doc[last:])
	return out.Bytes(), nil
}

// rewriteComposerDist replaces the url member of one dist object.
func rewriteComposerDist(dist json.RawMessage, base, name, version string) ([]byte, error) {
	ms, _, err := jsonObjectMembers(dist, jsonSpan{0, len(dist)})
	if err != nil {
		return nil, err
	}
	sp, ok := memberSpan(ms, "url")
	if !ok {
		return dist, nil
	}
	var fields struct {
		Reference string `json:"reference"`
		Type      string `json:"type"`
	}
	_ = json.Unmarshal(dist, &fields)
	vendor, pkg, _ := strings.Cut(name, "/")
	target := base + "/" + url.PathEscape(vendor) + "/" + url.PathEscape(pkg) + "/" + url.PathEscape(version) +
		"/" + url.PathEscape(fields.Reference) + "." + url.PathEscape(fields.Type)
	var enc bytes.Buffer
	e := json.NewEncoder(&enc)
	e.SetEscapeHTML(false)
	if err := e.Encode(target); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(dist)+len(target))
	out = append(out, dist[:sp.start]...)
	out = append(out, bytes.TrimRight(enc.Bytes(), "\n")...)
	out = append(out, dist[sp.end:]...)
	return out, nil
}
