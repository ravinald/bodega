package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/distinfo"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// ---- Ports distfiles --------------------------------------------------------

// distinfoRefresh is how old the distinfo index may get before a request
// starts a background re-read, so a ports tree updated under a running server
// is picked up without a restart. A warm re-read of a full tree is about a
// second.
const distinfoRefresh = 10 * time.Minute

// distfilesGuard is upstreamGuard with plain http admitted, and it is the only
// upstream check in bodega that admits it.
//
// Every other type trusts the transport for the bytes it caches, because the
// digest it later checks is one bodega recorded from that same transport. A
// distfile's digest is pinned in the ports tree before bodega fetches anything,
// so TLS adds nothing to what gets admitted: an attacker on the path can make
// a fetch fail the check and nothing else. And the default upstream needs it.
// distcache.FreeBSD.org answers https with a certificate naming only
// pkg.freebsd.org and pkgmir.geo.freebsd.org, which is why bsd.port.mk's own
// MASTER_SITE_BACKUP spells it http://. The address check still applies, so a
// distfiles_upstream cannot be pointed at this host's own network.
//
// A variable, like upstreamGuard, so a test can serve a fixture from loopback.
var distfilesGuard = func(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("distfiles upstream URL must use http or https, got %q", u.Scheme)
	}
	return checkUpstreamHost(u.Hostname())
}

// distinfoLogf writes the tree's lines to logger at the level the tree gave
// each one, and adds hiddenTreeHint to a failed read of root.
func distinfoLogf(logger *slog.Logger, root string, getenv func(string) string) distinfo.Logf {
	return func(level slog.Level, readErr error, msg string) {
		if hint := hiddenTreeHint(root, readErr, getenv); hint != "" {
			msg += "; " + hint
		}
		logger.Log(context.Background(), level, msg)
	}
}

// hiddenTreeHint explains a ports tree the shipped bodega.service hides from
// the server. PrivateTmp=true gives the service its own empty /tmp and
// /var/tmp, and ProtectHome=true makes /home unreadable, so a tree the operator
// can list from a shell reads as missing (ENOENT) or forbidden (EACCES) here.
// Only a failure to open root itself counts: a file missing below a root the
// server did read is an incomplete tree, and no mount override fixes that.
// NOTIFY_SOCKET is the evidence of a systemd unit, the same signal sdNotify
// reads; without it, or for any other root or error, the hint is empty and the
// plain failure stands. For /home, BindReadOnlyPaths= alone is not enough: the
// bind lands beneath a mode-000 mount the service account cannot traverse, so
// the hint names ProtectHome=tmpfs as well.
func hiddenTreeHint(root string, err error, getenv func(string) string) string {
	if err == nil || getenv("NOTIFY_SOCKET") == "" || !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
		return ""
	}
	clean := filepath.Clean(root)
	var pe *fs.PathError
	if !errors.As(err, &pe) || filepath.Clean(pe.Path) != clean {
		return ""
	}
	under := func(dir string) bool { return clean == dir || strings.HasPrefix(clean, dir+"/") }
	move := "move the tree to /usr/ports or /srv and point distfiles_ports_tree at it"
	bind, ok := systemdBindSource(clean)
	var cause, extra string
	switch {
	case under("/tmp") || under("/var/tmp"):
		cause = fmt.Sprintf("the shipped bodega.service sets PrivateTmp=true, which gives the service its own empty /tmp and /var/tmp, so %s does not exist for it", root)
	case under("/home"):
		cause = fmt.Sprintf("the shipped bodega.service sets ProtectHome=true, which makes /home unreadable to the service, so %s cannot be read", root)
		extra = "ProtectHome=tmpfs and "
	default:
		return ""
	}
	if !ok {
		return fmt.Sprintf("%s: %s; a BindReadOnlyPaths= override cannot name this path, because systemd does not bind a source containing a quote or control character", cause, move)
	}
	return fmt.Sprintf("%s: %s, or run `systemctl edit bodega`, add %sBindReadOnlyPaths=%s under [Service], and restart bodega", cause, move, extra, bind)
}

// systemdBindSource renders path as one BindReadOnlyPaths= source. Double
// quotes keep whitespace and ':' inside the one source, and inside them a
// backslash must be doubled and '%' (a unit specifier) written as "%%". systemd
// 259 fails to bind a source holding a quote or a control character however it
// is escaped, so those report false rather than advice that cannot work.
func systemdBindSource(path string) (string, bool) {
	if !utf8.ValidString(path) || strings.ContainsFunc(path, func(r rune) bool { return r == '"' || r == '\'' || unicode.IsControl(r) }) {
		return "", false
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `%`, `%%`).Replace(path) + `"`, true
}

// rewindSpool returns a spooled distfile to its start before it is served. A
// variable so a test can make it fail: no real file on a working disk refuses
// a seek to 0.
var rewindSpool = func(f *os.File) error {
	_, err := f.Seek(0, io.SeekStart)
	return err
}

// distfilesUpstreamClient is upstreamClient with distfilesGuard on every
// redirect hop, and no overall timeout: a distfile can run to gigabytes, and
// the server's own write timeout bounds the request that caused the fetch.
var distfilesUpstreamClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxUpstreamRedirects {
			return fmt.Errorf("stopped after %d redirects", len(via))
		}
		return distfilesGuard(req.URL.String())
	},
}

// clientCheckPath is the name, under /distfiles/, of the make fragment a
// client includes to measure its environment. "@" starts no distinfo name a
// client of this route can request, so it cannot shadow a distfile.
const clientCheckPath = "@environment.mk"

// handleDistfiles serves GET /distfiles/@{environment}/{name...}: one distfile
// by its distinfo name, which is "[${DIST_SUBDIR}/]<file>", for a client whose
// check measured environment. This is the HTTP deployment: a client includes
// the fragment GET /distfiles/@environment.mk returns at the end of
// /etc/make.conf, sets
//
//	MASTER_SITE_OVERRIDE?=	https://<bodega>/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/
//
// and do-fetch.sh requests <override><file>, which is this route.
//
// The environment segment is what binds the admission to the client. The index
// was read against a declared client environment, and nothing on this side can
// see whether a client still holds it: a file the client adds under
// ${LOCALBASE}/etc can move a restricted port's DISTINFO_FILE onto another
// port's distfiles. The fragment measures those inputs in the make that reads
// the port and names the environment's digest only when all of them hold, so
// a request is answered only when its segment is the digest the index was
// admitted against. "unsupported", another digest, or no segment at all is
// refused before storage or upstream is touched.
//
// The HTTP deployment preempts the port's own sites; it does not enforce
// anything. do-fetch.sh tries the override, then the port's MASTER_SITES,
// then MASTER_SITE_BACKUP, so any answer here other than the bytes (a 404, a
// 451, a 502, an unreachable host) sends the client straight to the internet.
// Only the DISTDIR deployment, where 'bodega build fetch distfiles' writes
// into a directory the client already reads, stops a build reaching the
// network: do-fetch.sh skips every site list for a file already present.
//
// Pull-through is the default rather than a full copy. The complete set runs
// to roughly two terabytes, distcache.FreeBSD.org answers 403 to a directory
// listing, and there is no manifest of the universe short of walking every
// */*/distinfo in a ports tree. A miss is fetched from distfiles_upstream,
// held against the distinfo line, and only then cached and served.
//
// The digest check is the reason this is not a binary namespace. See
// internal/distinfo for why the two must stay apart.
func (s *Server) handleDistfiles(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	measured := ""
	if rest, ok := strings.CutPrefix(name, "@"); ok && name != clientCheckPath {
		measured, name, _ = strings.Cut(rest, "/")
	}
	if name != clientCheckPath {
		if err := manifest.DistfilesValidName(name); err != nil || !isSafePath(name) {
			http.Error(w, "invalid distfile path: expected /distfiles/@<environment>/[<DIST_SUBDIR>/]<file>, the name as a distinfo line spells it", http.StatusBadRequest)
			return
		}
	}
	if s.distinfo == nil {
		// 404 rather than 503: this is configuration, not an outage, and a
		// client configured against this host falls through to the port's
		// own sites on a 404 at once.
		http.Error(w, "this server has no distfiles_ports_tree configured, so it has no distinfo to admit a distfile against", http.StatusNotFound)
		return
	}
	if name == clientCheckPath {
		s.serveClientCheck(w)
		return
	}
	// A distfile whose manifest entry records a backend lives there, which is
	// what 'bodega pkg move' changes. Anything else, pulled through or not yet
	// uploaded, lives where storage_by_type sends new writes. pm.Name is
	// compared because GetPackage folds "/" to "--", so "a/b" and "a--b"
	// reach one manifest.
	ctx := r.Context()
	store := s.typeStore(manifest.TypeDistfiles)
	if pm, _ := s.store.GetPackage(ctx, manifest.TypeDistfiles, name); pm != nil && pm.Name == name {
		if isPackageHidden(pm) {
			http.NotFound(w, r)
			return
		}
		if s.stores != nil && len(pm.Versions) > 0 && pm.Versions[0].Storage != "" {
			recorded, err := s.stores.ByName(pm.Versions[0].Storage)
			if err != nil {
				s.logger.Error("storage backend recorded for distfile is not configured", "name", name, "error", err)
				http.Error(w, "storage backend error", http.StatusBadGateway)
				return
			}
			store = recorded
		}
	}
	if !s.requireStorage(w, store) {
		return
	}
	w = cachePrivateOn200(w, name)
	if !s.entitleGate(w, r, manifest.TypeDistfiles, name, "") {
		return
	}

	// The distinfo decides before the cache does. A file cached before its
	// port was marked RESTRICTED, or before a tree update repinned its name,
	// must not keep being served on the strength of having been admitted once.
	entry, err := s.distinfo.LookupIn(measured, name)
	switch {
	case errors.Is(err, distinfo.ErrEnvironment):
		s.logger.Info("distfiles: refusing a client that did not measure the admitted environment", "name", name, "environment", measured, "reason", err)
		recordDenialFor(s.auditDB, r, manifest.TypeDistfiles, name, "", audit.DenialDistfileClient, map[string]string{"environment": measured, "reason": err.Error()})
		// 451 for the reason a restricted file gets it: the terms this client
		// holds are not the ones admission read, so bodega cannot say it may
		// redistribute the file to it. The client moves on to the port's own
		// sites.
		msg := err.Error()
		switch measured {
		case "":
			msg += "; include /distfiles/" + clientCheckPath + " at the end of the client's /etc/make.conf and request /distfiles/@${BODEGA_DISTFILES_ENV}/<name>"
		case distinfo.ClientUnsupported:
		default:
			msg += "; fetch /distfiles/" + clientCheckPath + " to the client again"
		}
		http.Error(w, msg+"; until then fetch it from the port's own MASTER_SITES", http.StatusUnavailableForLegalReasons)
		return
	case errors.Is(err, distinfo.ErrRestricted):
		s.logger.Info("distfiles: refusing a distfile its port forbids redistributing", "name", name, "reason", err)
		recordDenialFor(s.auditDB, r, manifest.TypeDistfiles, name, "", audit.DenialDistfileLicense, map[string]string{"reason": entry.Restricted})
		// 451 names the reason a 404 would hide. The client moves on to the
		// port's own sites either way, which is where a restricted file has
		// to come from.
		http.Error(w, s.withoutTreeRoot(err.Error())+"; fetch it from the port's own MASTER_SITES", http.StatusUnavailableForLegalReasons)
		return
	case errors.Is(err, distinfo.ErrNotReady):
		// The error names the tree's path and, after a failed read, the cause.
		// Both are for the operator's log; a client can only retry.
		s.logger.Warn("distfiles: request arrived before the ports tree was indexed", "name", name, "error", err)
		w.Header().Set("Retry-After", "30")
		http.Error(w, "the distinfo index is not loaded yet: the server is still reading its ports tree, or its last read failed; retry after the Retry-After interval", http.StatusServiceUnavailable)
		return
	case err != nil:
		// Not listed, or listed ambiguously: either way there is no digest to
		// hold the bytes to, and pinning the first fetch is what binary does
		// and what this type exists not to do.
		s.logger.Info("distfiles: no distinfo digest to admit against", "name", name, "root", s.distinfo.Root(), "error", err)
		http.Error(w, s.withoutTreeRoot(err.Error())+"; update the server's ports tree to the client's revision", http.StatusNotFound)
		return
	}

	key := manifest.DistfilesKey(name)
	upstream := s.cfg.DistfilesUpstream + manifest.DistfilesURLPath(name)
	if info, _ := store.Head(ctx, key); info != nil && info.Exists && info.Size == entry.Size {
		if s.serveVerifiedDistfile(w, r, store, name, key, upstream, entry) {
			return
		}
	}

	// A digest says the bytes are right; it does not say the operator agreed
	// to contact the host that would supply them.
	if !s.enforceUpstreamPolicyRecording(w, r, manifest.TypeDistfiles, upstream, upstream, name, key, true) {
		return
	}
	s.logger.Info("distfiles: cache miss, fetching upstream", "name", name, "upstream", upstream)
	// Identity encoding, because the digest is over the file as distinfo
	// describes it and a transport that decoded a gzip-encoded response would
	// hand the check different bytes than the client's `make checksum` reads.
	up, err := openUpstreamVia(ctx, distfilesUpstreamClient, distfilesGuard, upstream, true)
	if err != nil {
		if errors.Is(err, errUpstreamNotFound) {
			http.Error(w, "distfiles_upstream does not carry "+name, http.StatusNotFound)
			return
		}
		s.logger.Error("distfiles: upstream fetch failed", "name", name, "upstream", upstream, "error", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	defer up.body.Close()

	// A declared length that disagrees with distinfo is refused before the
	// body is read, so a wrong file costs no spool.
	if up.contentLength >= 0 && up.contentLength != entry.Size {
		s.refuseDistfile(w, r, name, key, entry, "", up.contentLength, up.url)
		return
	}
	spool, err := s.spoolUpstream(up)
	if err != nil {
		if reason := spoolDenialReason(err); reason != "" {
			s.recordSpoolRefusal(r, manifest.TypeDistfiles, name, key, reason, err)
			w.Header().Set("Retry-After", spoolRetryAfter)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		s.logger.Error("distfiles: upstream read failed", "name", name, "error", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	defer spool.close()

	if spool.size != entry.Size || spool.sha256 != entry.SHA256 {
		s.refuseDistfile(w, r, name, key, entry, spool.sha256, spool.size, up.url)
		return
	}

	s.fillCache(ctx, store, key, spool.path(), up.url, spool.sha256, spool.size)
	s.recordCacheEvent(r, audit.CacheMiss, manifest.TypeDistfiles, up.url, name, name, key)

	if err := rewindSpool(spool.file); err != nil {
		s.logger.Error("distfiles: could not rewind the spooled distfile", "name", name, "error", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", spool.size))
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: the body is a distfile whose digest matched distinfo; Content-Type is set above.
	if _, err := io.Copy(w, spool.file); err != nil {
		s.logger.Warn("distfiles: client read was cut short", "name", name, "error", err)
	}
}

// withoutTreeRoot is msg with the server's ports tree path cut from every
// path under it. A restriction the reader could not resolve names the file it
// stopped in, and the client needs that file's place in its own tree, not
// where the server keeps its copy.
//
// Every spelling is cut, not only the configured one: the reader resolves the
// root's symlinks before expanding PORTSDIR, so an included file is named
// under the resolved path, and an index read before the symlink was
// retargeted names the path it resolved to then. Longest first, because one
// spelling can end another (/private/var/... against /var/... on macOS).
func (s *Server) withoutTreeRoot(msg string) string {
	roots := s.distinfo.RootSpellings()
	sort.Slice(roots, func(i, j int) bool { return len(roots[i]) > len(roots[j]) })
	for _, root := range roots {
		msg = strings.ReplaceAll(msg, root+"/", "")
	}
	for _, root := range roots {
		msg = strings.ReplaceAll(msg, root, "the server's ports tree")
	}
	return msg
}

// serveClientCheck answers /distfiles/@environment.mk with the fragment that
// measures the environment the index was admitted against. It names file paths
// and snapshot digests from the server's configuration, and nothing a client
// could not already read in its own make.conf.
func (s *Server) serveClientCheck(w http.ResponseWriter) {
	text, err := s.distinfo.ClientCheck()
	if err != nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(text)
}

// serveVerifiedDistfile serves a stored distfile only once the bytes it is
// about to send have matched entry, and reports whether it wrote a response.
// False means the caller should treat the request as a miss.
//
// A stored object is not evidence of admission. It may have been admitted
// under an older tree that has since repinned the name to other bytes of the
// same length, uploaded from a DISTDIR some other tool wrote, or copied in
// by 'pkg move' or by hand. So the object is spooled while it is hashed, and
// the spool is what gets served: hashing the object and then streaming it a
// second time would verify one read and serve another, which is a different
// object whenever a writer lands in between. The cost is one spool copy per
// hit; a distfile is fetched once per port build, and serving bytes the
// client's `make checksum` then refuses is what the digest exists to prevent.
//
// A mismatch is recorded and falls through to the miss path, whose verified
// fetch replaces the object. A spool bound, like a miss, answers 503.
func (s *Server) serveVerifiedDistfile(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, name, key, upstream string, entry distinfo.Entry) bool {
	res, err := store.GetStream(r.Context(), key)
	if err != nil || res == nil {
		// Gone since the Head, or unreadable: a miss fetches and replaces it.
		if err != nil {
			s.logger.Warn("distfiles: stored object could not be opened, fetching upstream instead", "name", name, "key", key, "error", err)
		}
		return false
	}
	obj := cachedObject{store: store, id: streamIdentity(store, res)}
	spool, err := s.spoolUpstream(&upstreamStream{url: store.Label() + ":" + key, body: res.Body, contentLength: res.ContentLength})
	_ = res.Body.Close()
	if err != nil {
		if reason := spoolDenialReason(err); reason != "" {
			s.recordSpoolRefusal(r, manifest.TypeDistfiles, name, key, reason, err)
			w.Header().Set("Retry-After", spoolRetryAfter)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return true
		}
		s.logger.Warn("distfiles: stored object could not be read, fetching upstream instead", "name", name, "key", key, "error", err)
		return false
	}
	defer spool.close()
	if spool.size != entry.Size || spool.sha256 != entry.SHA256 {
		s.logger.Error("distfiles: stored bytes disagree with distinfo, fetching upstream to replace them",
			"name", name, "key", key, "backend", store.Label(), "want_sha256", entry.SHA256, "want_size", entry.Size,
			"got_sha256", spool.sha256, "got_size", spool.size, "ports", strings.Join(entry.Ports, ","))
		s.recordDistfileMismatch(r, name, key, entry, spool.sha256, spool.size, store.Label()+":"+key)
		return false
	}
	if err := rewindSpool(spool.file); err != nil {
		s.logger.Error("distfiles: could not rewind the spooled distfile", "name", name, "error", err)
		http.Error(w, "storage read failed", http.StatusBadGateway)
		return true
	}
	s.recordCacheServed(r, manifest.TypeDistfiles, name, name, key, obj)
	// The miss path records discovery under the upstream URL and the audit row
	// under the name, so the two halves are called apart: recordCacheHit would
	// give both the same candidate and put the hit on a row the miss never wrote.
	s.recordCacheHitDiscovery(r.Context(), r, manifest.TypeDistfiles, upstream, upstream, name, key)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", spool.size))
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: the body is a distfile whose digest matched distinfo; Content-Type is set above.
	if _, err := io.Copy(w, spool.file); err != nil {
		s.logger.Warn("distfiles: client read was cut short", "name", name, "error", err)
	}
	return true
}

// refuseDistfile answers a fetch whose bytes disagree with distinfo. Nothing
// is cached. computed is empty when the refusal came off the declared length
// alone.
func (s *Server) refuseDistfile(w http.ResponseWriter, r *http.Request, name, key string, entry distinfo.Entry, computed string, size int64, from string) {
	s.logger.Error("distfiles: upstream bytes disagree with distinfo, refusing them",
		"name", name, "upstream", from, "want_sha256", entry.SHA256, "want_size", entry.Size,
		"got_sha256", computed, "got_size", size, "ports", strings.Join(entry.Ports, ","))
	s.recordDistfileMismatch(r, name, key, entry, computed, size, from)
	http.Error(w, "upstream bytes for "+name+" do not match the ports tree's distinfo, so they were not cached or served", http.StatusBadGateway)
}

// recordDistfileMismatch writes the checksum_mismatch cache row for bytes
// that disagree with distinfo. from is the upstream URL for a fetch, or
// "<backend>:<key>" for a stored object.
func (s *Server) recordDistfileMismatch(r *http.Request, name, key string, entry distinfo.Entry, computed string, size int64, from string) {
	if s.auditDB == nil {
		return
	}
	ctx, cancel := auditContext(r)
	defer cancel()
	details, _ := json.Marshal(map[string]string{
		"expected":      entry.SHA256,
		"computed":      computed,
		"expected_size": fmt.Sprintf("%d", entry.Size),
		"size":          fmt.Sprintf("%d", size),
		"object_key":    key,
		"upstream_url":  from,
		"ports":         strings.Join(entry.Ports, ","),
	})
	_ = s.auditDB.Record(ctx, audit.Event{
		EventType: audit.EventCache,
		PkgType:   manifest.TypeDistfiles,
		PkgName:   name,
		Status:    audit.CacheChecksumMismatch,
		Details:   string(details),
	})
}
