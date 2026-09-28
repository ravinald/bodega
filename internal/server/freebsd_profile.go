package server

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgrepos"
	"github.com/ravinald/bodega/internal/storage"
)

// ---- pkg under a profile ---------------------------------------------------
//
// pkg decides what to fetch by reading a catalogue, exactly as apt does, so the
// catalogue is the control and the gate on the objects is the backstop. A
// profile that scopes freebsd (entitle.Profile.FreeBSDScope) is served, per
// repository and ABI, a packagesite.pkg and data.pkg holding only the records
// the profile permits, at pkgrepos.ProfilePath(<profile>)/<abi>/<repo>/. A host
// bound to that profile is refused the unfiltered catalogue, and a .pkg it
// composed by hand is refused by freeBSDObjectGate with the profile's own
// refusal text.
//
// Filtering discards whatever signature upstream put on the catalogue, so
// every filtered catalogue is signed by bodega's pkg key, proxied upstreams
// included, and the stanza a bound host installs trusts that key instead of
// /usr/share/keys/pkg. Nothing here verifies FreeBSD's signature before
// re-signing, which is the same limit docs/threat-model.md states for apt's
// filtered codenames: the chain of trust ends at the upstream's TLS
// certificate. With no pkg key loaded the view refuses rather than serving an
// unsigned catalogue, which would be a downgrade from FreeBSD's signature
// nobody asked for.
//
// The filter reads packagesite.yaml alone and derives data from the same kept
// records, which is how the generated catalogue is built: the two documents
// describe one record set, and deriving both from one read is what keeps them
// from disagreeing about what the host may install.

// freeBSDProfileCatalogCap bounds one packagesite.yaml line. It is the compact
// manifest cap, because a line is that document plus the repository's fields.
const freeBSDProfileCatalogCap = freeBSDManifestCap

// handleFreeBSDProfile serves one path under a profile's filtered view of a
// repository.
func (s *Server) handleFreeBSDProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("profile")
	abi, repo, rest, ok := splitFreeBSDPath(r.PathValue("path"))
	if !ok || name == "" {
		http.Error(w, "invalid freebsd repository path: expected "+pkgrepos.ProfilePath("<profile>")+"/<abi>/<repo>/<path>, for example "+pkgrepos.ProfilePath("web")+"/FreeBSD:14:amd64/latest/meta.conf", http.StatusBadRequest)
		return
	}
	view, reason := s.freeBSDProfileView(r.Context(), name)
	if view == nil {
		http.Error(w, reason, http.StatusNotFound)
		return
	}
	s.serveFreeBSD(w, r, abi, repo, rest, view)
}

// freeBSDProfileView resolves the profile a view URL names, or says why there
// is no view under that name.
//
// Read from the profile tables rather than the binding set, for the reason
// aptProfileViews is: an operator writes the profile, installs the stanza and
// binds the host, and the stanza's URL has to answer before the binding exists.
func (s *Server) freeBSDProfileView(ctx context.Context, name string) (*entitle.Profile, string) {
	if s.auditDB == nil {
		return nil, "no profile store is configured on this server, so no filtered pkg catalogue is served"
	}
	d, err := s.auditDB.GetProfile(ctx, name)
	if err != nil {
		return nil, fmt.Sprintf("no profile %q serves a filtered pkg catalogue here", name)
	}
	p := entitle.New(d)
	if scoped, refused := p.FreeBSDScope(); !scoped {
		if refused == "" {
			refused = "it states no freebsd rule"
		}
		return nil, fmt.Sprintf("profile %q has no filtered pkg catalogue: %s. Close it with block: bodega profile set %s freebsd --membership closed --expansion block",
			name, refused, name)
	}
	return p, ""
}

// freeBSDCatalogGate decides a repository-root file. It answers true when the
// handler should carry on.
//
// On the published path, a host whose profile scopes freebsd is refused the
// catalogue outright. Serving it would hand the host every record the profile
// refuses, which is the disclosure the filtered view exists to close, and a
// host still reading it is one whose stanza predates its binding: the refusal
// names the command that installs the right one.
//
// On a view, a host bound to a different scoped profile is refused the same
// way, and the fallback names are 404: the view serves its own three files
// and nothing a pkg client asks for when those fail would be filtered.
func (s *Server) freeBSDCatalogGate(w http.ResponseWriter, r *http.Request, abi, repo, rest string, view *entitle.Profile) bool {
	host := s.profileFor(r)
	scoped, _ := host.FreeBSDScope()
	if view != nil && slices.Contains(manifest.FreeBSDFallbackRootFiles, rest) {
		http.Error(w, rest+" is not served under a profile's filtered view: it serves meta.conf, data.pkg and packagesite.pkg, filtered and signed by bodega", http.StatusNotFound)
		return false
	}
	if !scoped || (view != nil && view.Name() == host.Name()) {
		return true
	}
	want := s.publicBase(r) + pkgrepos.ProfilePath(host.Name()) + "/" + abi + "/" + repo + "/"
	s.logger.Info("freebsd: refused a catalogue outside the filtered view the host's profile is served",
		"profile", host.Name(), "abi", abi, "repo", repo, "file", rest)
	http.Error(w, fmt.Sprintf("profile %q scopes freebsd, so this host reads the catalogue filtered for it at %s and not this one.\n"+
		"  Install that stanza:  bodega doctor --write-pkg-repo\n", host.Name(), want), http.StatusForbidden)
	return false
}

// freeBSDObjectGate is the backstop: a path under a repository that is not a
// root file is a package, and the host's profile decides it by the name and
// version its filename carries. It answers true when the handler should
// carry on.
//
// The filename rather than a catalogue lookup, because pkg names every object
// <name>-<version>[~<hash>].<ext> and the filter judges the record's own name
// and version with the same predicate, so the two agree on every object pkg
// published. An object a generated repository stores under some other name
// is judged by what its filename says, which refuses a package the catalogue
// lists rather than serving one it does not: the failure is a 403 naming the
// package, not a leak.
func (s *Server) freeBSDObjectGate(w http.ResponseWriter, r *http.Request, rest string) bool {
	name, version := freeBSDObjectIdentity(rest)
	return s.entitleGate(w, r, manifest.TypeFreeBSD, name, version)
}

// freeBSDObjectIdentity reads the package name and version out of a
// repository path. pkg joins them with the last hyphen, since a version holds
// none and a name may hold several; a hashed layout appends ~<hash>, and a
// signature beside a package names that package. A filename carrying no
// hyphen is a name with no version, which Covers decides on membership alone.
func freeBSDObjectIdentity(rest string) (name, version string) {
	base := strings.TrimSuffix(path.Base(rest), ".sig")
	for _, ext := range []string{".pkg", ".tzst", ".txz", ".tbz", ".tgz", ".tar"} {
		if trimmed, ok := strings.CutSuffix(base, ext); ok {
			base = trimmed
			break
		}
	}
	if i := strings.IndexByte(base, '~'); i >= 0 {
		base = base[:i]
	}
	i := strings.LastIndexByte(base, '-')
	if i <= 0 || i == len(base)-1 {
		return base, ""
	}
	return base[:i], base[i+1:]
}

// serveFreeBSDProfileCatalog answers one of the three root files under a
// profile's view: the published packagesite.pkg read the way the route would
// serve it, filtered, and re-signed.
func (s *Server) serveFreeBSDProfileCatalog(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, view *entitle.Profile, abi, repo, rest, key string, generated bool, ve manifest.VersionEntry, configured, proxied bool) {
	noSharedCache(w)
	var src []byte
	status, errBody := http.StatusOK, ""
	if rest != manifest.FreeBSDMetaFile {
		src, status, errBody = s.freeBSDPublishedCatalog(r, store, abi, repo, generated, ve, configured, proxied)
	}
	if status != http.StatusOK {
		// The published catalogue's own answer, passed through: a mirror that
		// has not finished is a 404 here for the reason it is there, and an
		// allow-list refusal reaches the client as the policy wrote it.
		http.Error(w, strings.TrimRight(errBody, "\n"), status)
		return
	}
	body, err := s.freeBSDProfileCatalog(r.Context(), view, abi, repo, rest, src)
	if err != nil {
		s.logger.Error("freebsd: the profile's filtered catalogue could not be built; the view serves nothing rather than the unfiltered one",
			"profile", view.Name(), "abi", abi, "repo", repo, "file", rest, "error", err)
		http.Error(w, freeBSDCatalogUnavailable, http.StatusInternalServerError)
		return
	}
	ct := contentTypeForKey(key)
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: the body is the archive this process just built; Content-Type is set above.
	_, _ = w.Write(body)
}

// freeBSDPublishedCatalog reads the repository's own packagesite.pkg through
// the same path a client of the published repository is served it by, so the
// view can never be built from bytes that route would not serve: a hosted
// mirror's catalogue from the store and never from upstream, a proxied one
// through the cache and the allow-list, a generated one from the build.
//
// The request is cloned without its validators. pkg sends If-Modified-Since,
// and a 304 for the published catalogue says nothing about a filtered one.
func (s *Server) freeBSDPublishedCatalog(r *http.Request, store storage.ObjectStore, abi, repo string, generated bool, ve manifest.VersionEntry, configured, proxied bool) ([]byte, int, string) {
	file := manifest.FreeBSDCatalogFile
	if generated {
		body, err := s.freeBSDGeneratedCatalog(r.Context(), store, abi, repo, file)
		if err != nil {
			s.logger.Error("freebsd: generating the catalogue a profile's view is filtered from failed",
				"abi", abi, "repo", repo, "error", err)
			return nil, http.StatusInternalServerError, freeBSDCatalogUnavailable
		}
		return body, http.StatusOK, ""
	}
	upstream := freeBSDUpstreamOf(ve, configured, file)
	if !proxied {
		upstream = ""
	}
	inner := r.Clone(r.Context())
	for _, h := range []string{"If-Modified-Since", "If-None-Match", "If-Range", "Range"} {
		inner.Header.Del(h)
	}
	capture := &freeBSDCapture{header: http.Header{}}
	s.proxyOrCache(capture, inner, store, manifest.FreeBSDKey(abi, repo, file), upstream,
		manifest.TypeFreeBSD, upstream, repo+"/"+file, false, proxied)
	if capture.status == 0 {
		capture.status = http.StatusOK
	}
	if capture.tooBig {
		return nil, http.StatusBadGateway, fmt.Sprintf("the published %s exceeds bodega's %d-byte filter buffer", file, maxUpstreamBody)
	}
	if capture.status != http.StatusOK {
		return nil, capture.status, capture.body.String()
	}
	return capture.body.Bytes(), http.StatusOK, ""
}

// freeBSDCapture buffers a response the view filters before anything reaches
// the client.
type freeBSDCapture struct {
	header http.Header
	status int
	body   bytes.Buffer
	tooBig bool
}

func (c *freeBSDCapture) Header() http.Header { return c.header }

func (c *freeBSDCapture) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
}

func (c *freeBSDCapture) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if int64(c.body.Len()+len(b)) > maxUpstreamBody {
		c.tooBig = true
		c.body.Reset()
		return 0, fmt.Errorf("the published catalogue exceeds bodega's %d-byte filter buffer", maxUpstreamBody)
	}
	return c.body.Write(b)
}

// freeBSDProfileCatalog returns one root file of the profile's view, building
// the set when the published catalogue, the profile or the signing key has
// moved since the last build.
func (s *Server) freeBSDProfileCatalog(ctx context.Context, view *entitle.Profile, abi, repo, file string, src []byte) ([]byte, error) {
	if file == manifest.FreeBSDMetaFile {
		return freeBSDMetaConf(), nil
	}
	sign := s.pkgSign.Load()
	switch {
	case sign != nil && sign.err != nil:
		return nil, fmt.Errorf("a pkg signing key is installed but cannot be loaded, and a filtered catalogue is never served unsigned: %w", sign.err)
	case sign == nil:
		return nil, errors.New("no pkg signing key is loaded, and a filtered catalogue carries bodega's signature or none: FreeBSD's cannot survive the filter. Run \"bodega freebsd key generate\" and reload the server")
	}
	digest := sha256.Sum256(src)
	objects := hex.EncodeToString(digest[:]) + "\x00" + view.Fingerprint(manifest.TypeFreeBSD)
	cacheKey := "profile\x00" + view.Name() + "\x00" + abi + "\x00" + repo

	if cat, ok := s.freeBSDCat.Load(cacheKey); ok {
		if built, ok := cat.(*freeBSDCatalog); ok && built.fresh(objects, sign.fingerprint, s.cache.MetadataTTL) {
			return built.file(file)
		}
	}
	unlock := s.freeBSDBuild.lock(cacheKey)
	defer unlock()
	if cat, ok := s.freeBSDCat.Load(cacheKey); ok {
		if built, ok := cat.(*freeBSDCatalog); ok && built.fresh(objects, sign.fingerprint, s.cache.MetadataTTL) {
			return built.file(file)
		}
	}

	records, kept, dropped, err := filterFreeBSDCatalog(src, view)
	if err != nil {
		return nil, fmt.Errorf("filter the published %s for %s@%s: %w", manifest.FreeBSDCatalogFile, repo, abi, err)
	}
	cat := &freeBSDCatalog{objects: objects, key: sign.fingerprint, builtAt: time.Now(), meta: freeBSDMetaConf()}
	if cat.catalogue, err = s.freeBSDArchive(freeBSDCatalogDoc, freeBSDPackagesiteDoc(records), sign); err != nil {
		return nil, fmt.Errorf("build %s: %w", manifest.FreeBSDCatalogFile, err)
	}
	data, err := freeBSDDataDocument(records)
	if err != nil {
		return nil, fmt.Errorf("build the data document: %w", err)
	}
	if cat.data, err = s.freeBSDArchive(freeBSDDataDoc, data, sign); err != nil {
		return nil, fmt.Errorf("build %s: %w", manifest.FreeBSDDataFile, err)
	}
	s.freeBSDCat.Store(cacheKey, cat)
	s.logger.Info("freebsd: filtered a pkg catalogue for a profile",
		"profile", view.Name(), "abi", abi, "repo", repo, "kept", kept, "dropped", dropped, "fingerprint", sign.fingerprint)
	return cat.file(file)
}

// filterFreeBSDCatalog keeps the packagesite.yaml records the profile permits,
// as the upstream's own bytes, and counts both halves.
//
// A record that does not parse, or names no package, fails the whole filter:
// the kept set up to that line is a catalogue bodega would sign and serve as
// if it were complete, and every package after the break would read to the
// host as one the profile refuses. The same reasoning is filterAptPackages'.
//
// An empty result is not a failure. A profile applies to every repository, and
// one that lists packages from latest/ correctly keeps nothing from kmods/.
func filterFreeBSDCatalog(src []byte, p *entitle.Profile) (records []json.RawMessage, kept, dropped int, err error) {
	dec, closeDec, err := freeBSDPkgDecompressor(bufio.NewReader(bytes.NewReader(src)))
	if err != nil {
		return nil, 0, 0, err
	}
	defer closeDec()
	tr := tar.NewReader(dec)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, 0, fmt.Errorf("read the catalogue archive: %w", err)
		}
		if strings.TrimPrefix(hdr.Name, "./") != freeBSDCatalogDoc {
			continue
		}
		sc := bufio.NewScanner(tr)
		sc.Buffer(make([]byte, 0, 64<<10), freeBSDProfileCatalogCap)
		line := 0
		for sc.Scan() {
			line++
			raw := bytes.TrimSpace(sc.Bytes())
			if len(raw) == 0 {
				continue
			}
			var rec struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if err := json.Unmarshal(raw, &rec); err != nil || rec.Name == "" || rec.Version == "" {
				return nil, kept, dropped, fmt.Errorf("record %d of %s names no package and version, and everything after it would be missing from a catalogue bodega signs", line, freeBSDCatalogDoc)
			}
			if !p.Permits(manifest.TypeFreeBSD, rec.Name, rec.Version).Permitted {
				dropped++
				continue
			}
			kept++
			records = append(records, json.RawMessage(bytes.Clone(raw)))
		}
		if err := sc.Err(); err != nil {
			return nil, kept, dropped, fmt.Errorf("read %s past record %d: %w", freeBSDCatalogDoc, line, err)
		}
		return records, kept, dropped, nil
	}
	return nil, 0, 0, fmt.Errorf("the catalogue archive carries no %s member", freeBSDCatalogDoc)
}
