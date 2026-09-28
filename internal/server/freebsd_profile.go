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
// profile that governs freebsd, whatever its membership and expansion, is
// served, per repository and ABI, a packagesite.pkg and data.pkg holding only
// the records entitle.Profile.Permits admits, at
// pkgrepos.ProfilePath(<profile>)/<abi>/<repo>/. A host bound to that profile
// is refused the unfiltered catalogue, and an object it composed by hand is
// decided by freeBSDObjectGate against the record that names it.
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
	if !p.Governs(manifest.TypeFreeBSD) {
		return nil, fmt.Sprintf("profile %q states no freebsd rule, so it has no filtered pkg catalogue. Give it one: bodega profile add %s freebsd <name>",
			name, name)
	}
	return p, ""
}

// freeBSDCatalogGate decides a repository-root file. It answers true when the
// handler should carry on.
//
// On the published path, a host whose profile governs freebsd is refused the
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
	scoped := host.Governs(manifest.TypeFreeBSD)
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
	http.Error(w, fmt.Sprintf("profile %q governs freebsd, so this host reads the catalogue filtered for it at %s and not this one.\n"+
		"  Install that stanza:  bodega doctor --write-pkg-repo\n", host.Name(), want), http.StatusForbidden)
	return false
}

// freeBSDObjectGate is the backstop: a path under a repository that is not a
// root file is a package, and the host's profile decides it by the name and
// version the catalogue record naming that path declares. It answers true
// when the handler should carry on.
//
// The record rather than the filename, because the two can disagree: a
// generated repository takes a record's identity from the package's own
// manifest and its repopath from wherever the operator stored it, so
// All/nginx-1.0.pkg may hold tree. The filter judges records, and the gate
// judging anything else is a gate that serves what the catalogue withheld.
// For the same reason an object no record names is refused outright, since
// nothing says what it is: that covers Latest/pkg.pkg and its .sig, which
// alias a package whose version the path does not carry, and any object an
// operator stored outside the catalogue.
//
// A host whose profile does not govern freebsd never reaches the catalogue
// read, so the published repository costs it nothing.
func (s *Server) freeBSDObjectGate(w http.ResponseWriter, r *http.Request, src freeBSDCatalogSource, rest string) bool {
	p := s.profileFor(r)
	if !p.Governs(manifest.TypeFreeBSD) {
		return true
	}
	id, listed, status, errBody := s.freeBSDObjectRecord(r, src, rest)
	if status != http.StatusOK {
		s.logger.Error("freebsd: the catalogue that decides a governed host's package fetch could not be read; refusing the fetch",
			"profile", p.Name(), "abi", src.abi, "repo", src.repo, "path", rest, "status", status, "error", strings.TrimSpace(errBody))
		http.Error(w, fmt.Sprintf("profile %q decides each package in %s@%s by the catalogue record that names it, and that catalogue could not be read (%d %s), "+
			"so no package there is served to this host until it can. The server log names the cause.",
			p.Name(), src.repo, src.abi, status, http.StatusText(status)), http.StatusServiceUnavailable)
		return false
	}
	if listed {
		return s.entitleGate(w, r, manifest.TypeFreeBSD, id.name, id.version)
	}
	d := entitle.Decision{
		Governed: true,
		Refusal:  entitle.RefusalMembership,
		Reason:   fmt.Sprintf("no record in the catalogue of %s@%s names %s", src.repo, src.abi, rest),
	}
	s.recordProfileRefusal(r, p, manifest.TypeFreeBSD, rest, "", d)
	http.Error(w, fmt.Sprintf("%s: profile %q is decided per package, and no record in the catalogue of %s@%s names %s, so nothing says which package it holds.\n"+
		"  pkg fetches the path a record names; an alias such as Latest/pkg.pkg, or an object stored outside the catalogue, is not one.\n"+
		"  See what the catalogue lists:  pkg search -r %s%s -x '.*'\n",
		entitle.RefusalMembership, p.Name(), src.repo, src.abi, rest, pkgrepos.TagPrefix, src.repo), http.StatusForbidden)
	return false
}

// freeBSDCatalogSource is what freeBSDPublishedCatalog needs to read one
// repository's catalogue the way the route serves it.
type freeBSDCatalogSource struct {
	store      storage.ObjectStore
	abi, repo  string
	generated  bool
	ve         manifest.VersionEntry
	configured bool
	proxied    bool
}

// freeBSDIdentity is the package a catalogue record declares.
type freeBSDIdentity struct{ name, version string }

// freeBSDCatalogIndex maps every repopath one published catalogue names to
// its record's identity, and is independent of any profile: Permits runs per
// request against whichever profile the host is bound to now.
type freeBSDCatalogIndex struct {
	digest  string
	builtAt time.Time
	objects map[string]freeBSDIdentity
}

// freeBSDObjectRecord finds the record naming rest, or the .pkg a .sig sits
// beside, in the repository's published catalogue.
//
// An index younger than the metadata TTL answers a hit without reading the
// catalogue: a repopath is content-addressed or version-named, so the record
// that named it still describes the object. A miss, or an older index, reads
// the catalogue and rebuilds when its digest moved, so a package published
// since the last build is found rather than refused until the TTL runs out.
func (s *Server) freeBSDObjectRecord(r *http.Request, src freeBSDCatalogSource, rest string) (freeBSDIdentity, bool, int, string) {
	cacheKey := "index\x00" + src.abi + "\x00" + src.repo
	lookup := func(idx *freeBSDCatalogIndex) (freeBSDIdentity, bool) {
		if id, ok := idx.objects[rest]; ok {
			return id, true
		}
		if pkg, ok := strings.CutSuffix(rest, ".sig"); ok {
			id, ok := idx.objects[pkg]
			return id, ok
		}
		return freeBSDIdentity{}, false
	}
	cached := func() *freeBSDCatalogIndex {
		if v, ok := s.freeBSDCat.Load(cacheKey); ok {
			if idx, ok := v.(*freeBSDCatalogIndex); ok {
				return idx
			}
		}
		return nil
	}
	if idx := cached(); idx != nil && s.cache.MetadataTTL > 0 && time.Since(idx.builtAt) < s.cache.MetadataTTL {
		if id, ok := lookup(idx); ok {
			return id, true, http.StatusOK, ""
		}
	}

	body, status, errBody := s.freeBSDPublishedCatalog(r, src.store, src.abi, src.repo, src.generated, src.ve, src.configured, src.proxied)
	if status != http.StatusOK {
		return freeBSDIdentity{}, false, status, errBody
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	unlock := s.freeBSDBuild.lock(cacheKey)
	defer unlock()
	idx := cached()
	if idx == nil || idx.digest != digest {
		objects := map[string]freeBSDIdentity{}
		err := walkFreeBSDCatalog(body, func(_ []byte, name, version, repopath string) {
			if repopath != "" {
				objects[repopath] = freeBSDIdentity{name: name, version: version}
			}
		})
		if err != nil {
			return freeBSDIdentity{}, false, http.StatusInternalServerError,
				fmt.Sprintf("index the published %s for %s@%s: %v", manifest.FreeBSDCatalogFile, src.repo, src.abi, err)
		}
		idx = &freeBSDCatalogIndex{digest: digest, objects: objects}
	}
	idx = &freeBSDCatalogIndex{digest: idx.digest, objects: idx.objects, builtAt: time.Now()}
	s.freeBSDCat.Store(cacheKey, idx)
	id, ok := lookup(idx)
	return id, ok, http.StatusOK, ""
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
// An empty result is not a failure. A profile applies to every repository, and
// one that lists packages from latest/ correctly keeps nothing from kmods/.
func filterFreeBSDCatalog(src []byte, p *entitle.Profile) (records []json.RawMessage, kept, dropped int, err error) {
	err = walkFreeBSDCatalog(src, func(raw []byte, name, version, _ string) {
		if !p.Permits(manifest.TypeFreeBSD, name, version).Permitted {
			dropped++
			return
		}
		kept++
		records = append(records, json.RawMessage(bytes.Clone(raw)))
	})
	if err != nil {
		return nil, kept, dropped, err
	}
	return records, kept, dropped, nil
}

// walkFreeBSDCatalog calls fn once per packagesite.yaml record in a catalogue
// archive, in order. The filter and the object gate both read records through
// it, so the two cannot disagree about which package a record declares.
//
// A record that does not parse, or names no package and version, fails the
// whole walk: a filtered catalogue built up to that line is one bodega would
// sign and serve as if it were complete, and every package after the break
// would read to the host as one the profile refuses. The same reasoning is
// filterAptPackages'.
func walkFreeBSDCatalog(src []byte, fn func(raw []byte, name, version, repopath string)) error {
	dec, closeDec, err := freeBSDPkgDecompressor(bufio.NewReader(bytes.NewReader(src)))
	if err != nil {
		return err
	}
	defer closeDec()
	tr := tar.NewReader(dec)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read the catalogue archive: %w", err)
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
				Name     string `json:"name"`
				Version  string `json:"version"`
				Repopath string `json:"repopath"`
			}
			if err := json.Unmarshal(raw, &rec); err != nil || rec.Name == "" || rec.Version == "" {
				return fmt.Errorf("record %d of %s names no package and version, and everything after it would be missing from a catalogue bodega signs", line, freeBSDCatalogDoc)
			}
			fn(raw, rec.Name, rec.Version, rec.Repopath)
		}
		if err := sc.Err(); err != nil {
			return fmt.Errorf("read %s past record %d: %w", freeBSDCatalogDoc, line, err)
		}
		return nil
	}
	return fmt.Errorf("the catalogue archive carries no %s member", freeBSDCatalogDoc)
}
