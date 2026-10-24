package server

import (
	"bytes"
	"crypto/md5" //nolint:gosec // G501: the compact index's own checksum, which Bundler compares; it guards nothing here.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- RubyGems registry -----------------------------------------------------
//
// Bodega serves a RubyGems registry under /rubygems/, pulled through from
// rubygems_upstream byte for byte. The paths are the ones gem and Bundler
// compose against a source URL:
//
//   /rubygems/versions                              — compact index, mutable
//   /rubygems/info/<gem>                            — compact index, mutable
//   /rubygems/gems/<name>-<version>[-<platform>].gem — gem file, immutable
//   /rubygems/quick/Marshal.4.8/<file>.gemspec.rz   — gemspec, immutable
//   /rubygems/specs.4.8.gz and its latest_/prerelease_ siblings — full index, mutable
//   /rubygems/api/v1/dependencies?gems=a,b          — dependency API, mutable
//
// Anything else 404s here, before any upstream is composed.

// rubygemsNamePattern is the character set rubygems.org accepts in a gem name.
// The leading character is held to a letter or digit so no name can be "." or
// "..", which is what keeps a name safe to place in a path.
var rubygemsNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// rubygemsFullIndexFiles are the legacy index documents `gem` reads when it
// has no compact index client. Each is regenerated on every push.
var rubygemsFullIndexFiles = map[string]bool{
	"specs.4.8.gz":            true,
	"latest_specs.4.8.gz":     true,
	"prerelease_specs.4.8.gz": true,
}

const rubygemsSpecDir = "quick/Marshal.4.8/"

func (s *Server) handleRubygems(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	switch {
	case p == "versions":
		s.handleRubygemsCompactIndex(w, r, p, "")
	case strings.HasPrefix(p, "info/"):
		gem := strings.TrimPrefix(p, "info/")
		if !rubygemsNamePattern.MatchString(gem) {
			http.NotFound(w, r)
			return
		}
		s.handleRubygemsCompactIndex(w, r, p, gem)
	case rubygemsFullIndexFiles[p]:
		s.handleRubygemsFullIndex(w, r, p)
	case p == "api/v1/dependencies":
		s.handleRubygemsDependencies(w, r)
	case strings.HasPrefix(p, "gems/"):
		file := strings.TrimPrefix(p, "gems/")
		name, version := manifest.RubygemsGemIdentity(file)
		if !rubygemsFileNames(file, name) {
			http.NotFound(w, r)
			return
		}
		s.handleRubygemsVersioned(w, r, name, version, manifest.RubygemsGemKey(name, version), p)
	case strings.HasPrefix(p, rubygemsSpecDir):
		file := strings.TrimPrefix(p, rubygemsSpecDir)
		base, ok := strings.CutSuffix(file, ".gemspec.rz")
		name, version := manifest.RubygemsGemIdentity(base + ".gem")
		if !ok || !rubygemsFileNames(file, name) {
			http.NotFound(w, r)
			return
		}
		s.handleRubygemsVersioned(w, r, name, version, manifest.RubygemsSpecKey(file), p)
	default:
		http.NotFound(w, r)
	}
}

// rubygemsFileNames reports whether a gem or gemspec file name parsed into a
// gem name the registry could have published, with nothing in the file name
// that would leave its directory.
func rubygemsFileNames(file, name string) bool {
	return name != "" && !strings.Contains(file, "/") && rubygemsNamePattern.MatchString(name)
}

// rubygemsRelease is the version a gem file names with its platform suffix
// cut off: "1.16.7" for "1.16.7-x86_64-linux". A manifest entry's constraint
// is a statement about releases, and every platform build of one is that
// release, so both the entry's version and the requested one pass through
// this before they are compared.
func rubygemsRelease(version string) string {
	release, _, _ := strings.Cut(version, "-")
	return release
}

// handleRubygemsVersioned serves a gem file or a gemspec, both of which name
// one version of one gem and never change under that name. The gates are the
// ones a crate download passes, plus the manifest's version constraint, which
// a crate download does not check.
func (s *Server) handleRubygemsVersioned(w http.ResponseWriter, r *http.Request, name, version, s3Key, p string) {
	ctx := r.Context()
	release := rubygemsRelease(version)
	pm, _ := s.store.GetPackage(ctx, manifest.TypeRubygems, name)
	if pm != nil {
		if isPackageHidden(pm) {
			s.refuseHidden(w, r, manifest.TypeRubygems, name, "")
			return
		}
		// An operator hides a release or one build of it, and either way the
		// build requested is withheld.
		if isVersionHidden(pm, version) || isVersionHidden(pm, release) {
			s.refuseHidden(w, r, manifest.TypeRubygems, name, version)
			return
		}
		vc, baseVer := packageVersionConstraint(pm)
		if vc != "" && vc != manifest.ConstraintAny && baseVer != "" && !versionAllowed(rubygemsRelease(baseVer), release, vc) {
			s.refuseVersionConstraint(w, r, manifest.TypeRubygems, name, baseVer, version, vc)
			return
		}
	}

	// The release, not the build: a profile pins 1.16.7, and every platform
	// build of 1.16.7 is that release, as it is to the constraint above.
	if !s.entitleGate(w, r, manifest.TypeRubygems, name, release) {
		return
	}

	w = cachePrivateOn200(w, p)
	upstream := s.cfg.RubygemsUpstream + "/" + p
	forceProxy := pm == nil || packageMode(pm) == manifest.ModeProxy
	store, err := s.versionStore(ctx, manifest.TypeRubygems, name, version)
	if err != nil {
		s.logger.Error("storage backend recorded for artifact is not configured",
			"type", manifest.TypeRubygems, "package", name, "version", version, "error", err)
		http.Error(w, "storage backend error", http.StatusBadGateway)
		return
	}
	s.proxyOrCache(w, r, store, s3Key, upstream, manifest.TypeRubygems, name, name, true, forceProxy)
}

// handleRubygemsCompactIndex serves versions or info/<gem>. gem is empty for
// versions, which lists every gem and so is no one gem's to refuse.
//
// Under a profile that governs rubygems both are filtered on the way out, as
// every profile filter is (see profileVersionFilter): the cache holds the
// upstream's document and each host class gets its own reading of it.
func (s *Server) handleRubygemsCompactIndex(w http.ResponseWriter, r *http.Request, p, gem string) {
	noSharedCache(w)
	prof := s.profileFor(r)
	rw := &compactIndexWriter{ResponseWriter: w, r: r, subject: p}
	if gem != "" {
		pm, _ := s.store.GetPackage(r.Context(), manifest.TypeRubygems, gem)
		if pm != nil && isPackageHidden(pm) {
			s.refuseHidden(w, r, manifest.TypeRubygems, gem, "")
			return
		}
		if !s.entitleGateAnswering(w, r, manifest.TypeRubygems, gem, "", http.StatusNotFound) {
			return
		}
		if permit := rubygemsReleaseFilter(prof, gem); permit != nil {
			rw.filter = func(b []byte) ([]byte, error) { return filterRubygemsInfo(b, permit), nil }
		}
	} else if rule := rubygemsRuleFor(prof); rule != nil {
		rw.filter = func(b []byte) ([]byte, error) {
			return filterRubygemsVersions(b, rule, func(gem string, permit func(string) bool) (string, error) {
				info, err := s.rubygemsInfo(r, gem)
				if err != nil {
					s.logger.Warn("rubygems versions: dropped a gem this host's profile filters, because its info file could not be read to checksum",
						"gem", gem, "profile", prof.Name(), "error", err)
					return "", err
				}
				//nolint:gosec // G401: MD5 is the compact index's own checksum, which Bundler compares; it guards nothing here.
				sum := md5.Sum(filterRubygemsInfo(info, permit))
				return hex.EncodeToString(sum[:]), nil
			}), nil
		}
	}
	s.proxyOrCache(rw, r, s.typeStore(manifest.TypeRubygems), manifest.RubygemsIndexKey(p),
		s.cfg.RubygemsUpstream+"/"+p, manifest.TypeRubygems, gem, gem, false, false)
	if err := rw.flush(); err != nil {
		s.logger.Error("rubygems compact index response failed", "path", p, "error", err)
	}
}

// rubygemsReleaseFilter is profileVersionFilter for a gem, judging each
// version with its platform suffix cut.
func rubygemsReleaseFilter(p *entitle.Profile, gem string) func(string) bool {
	permit := profileVersionFilter(p, manifest.TypeRubygems, gem)
	if permit == nil {
		return nil
	}
	return func(v string) bool { return permit(rubygemsRelease(v)) }
}

// rubygemsInfo reads info/<gem> as the info route would serve it to this
// request, through the same cache and with the same freshness rule, so the
// checksum the filtered versions file names is the one of the info file the
// client is handed next. The request's own conditional and range headers are
// dropped: they describe the versions file the client holds. The read is
// marked as bodega's own (withOwnRead), so it writes no audit or discovery row
// in the client's name.
func (s *Server) rubygemsInfo(r *http.Request, gem string) ([]byte, error) {
	p := "info/" + gem
	req := r.Clone(withOwnRead(r.Context()))
	req.URL.Path = "/rubygems/" + p
	req.URL.RawQuery = ""
	for _, h := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
		req.Header.Del(h)
	}
	cw := &capturedResponse{header: http.Header{}}
	s.proxyOrCache(cw, req, s.typeStore(manifest.TypeRubygems), manifest.RubygemsIndexKey(p),
		s.cfg.RubygemsUpstream+"/"+p, manifest.TypeRubygems, gem, gem, false, false)
	switch {
	case cw.tooBig:
		return nil, fmt.Errorf("info/%s exceeds bodega's %d-byte buffer", gem, maxUpstreamBody)
	case cw.status != 0 && cw.status != http.StatusOK:
		return nil, fmt.Errorf("info/%s answered HTTP %d", gem, cw.status)
	}
	return cw.body.Bytes(), nil
}

// capturedResponse is a ResponseWriter that keeps what it is handed, for a
// document the server reads on its own behalf.
type capturedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
	tooBig bool
}

func (c *capturedResponse) Header() http.Header { return c.header }

func (c *capturedResponse) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
}

func (c *capturedResponse) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if int64(c.body.Len()+len(b)) > maxUpstreamBody {
		c.tooBig = true
		return 0, fmt.Errorf("response exceeds bodega's %d-byte buffer", maxUpstreamBody)
	}
	return c.body.Write(b)
}

// handleRubygemsFullIndex serves specs.4.8.gz and its latest_ and prerelease_
// siblings, filtered for a host whose profile governs rubygems.
func (s *Server) handleRubygemsFullIndex(w http.ResponseWriter, r *http.Request, p string) {
	noSharedCache(w)
	store, key, upstream := s.typeStore(manifest.TypeRubygems), manifest.RubygemsIndexKey(p), s.cfg.RubygemsUpstream+"/"+p
	rule := rubygemsRuleFor(s.profileFor(r))
	if rule == nil {
		s.proxyOrCache(w, r, store, key, upstream, manifest.TypeRubygems, "", "", false, false)
		return
	}
	rw := &indexFilterWriter{
		ResponseWriter: w,
		subject:        "the rubygems " + p,
		parse:          func(b []byte) ([]byte, error) { return filterRubygemsSpecs(b, rule) },
	}
	s.proxyOrCache(rw, r, store, key, upstream, manifest.TypeRubygems, "", "", false, false)
	if err := rw.flush(); err != nil {
		s.logger.Error("rubygems full index response failed", "path", p, "error", err)
	}
}

// handleRubygemsDependencies serves the dependency API older clients query
// for a comma-separated list of gems. The answer is cached per list, under the
// list's digest: the list is client-chosen and has no length bound a storage
// key could hold.
func (s *Server) handleRubygemsDependencies(w http.ResponseWriter, r *http.Request) {
	gems := r.URL.Query().Get("gems")
	upstream := s.cfg.RubygemsUpstream + "/api/v1/dependencies"
	if gems != "" {
		for _, g := range strings.Split(gems, ",") {
			if !rubygemsNamePattern.MatchString(g) {
				http.Error(w, fmt.Sprintf("gems=%q holds a name that is not a gem name", g), http.StatusBadRequest)
				return
			}
		}
		upstream += "?gems=" + gems
	}
	sum := sha256.Sum256([]byte(gems))
	key := manifest.RubygemsIndexKey("api/v1/dependencies/" + hex.EncodeToString(sum[:]))
	noSharedCache(w)
	rule := rubygemsRuleFor(s.profileFor(r))
	if rule == nil {
		s.proxyOrCache(w, r, s.typeStore(manifest.TypeRubygems), key, upstream, manifest.TypeRubygems, "", "", false, false)
		return
	}
	rw := &indexFilterWriter{
		ResponseWriter: w,
		subject:        "the rubygems dependency API answer",
		parse:          func(b []byte) ([]byte, error) { return filterRubygemsDependencies(b, rule) },
	}
	s.proxyOrCache(rw, r, s.typeStore(manifest.TypeRubygems), key, upstream, manifest.TypeRubygems, "", "", false, false)
	if err := rw.flush(); err != nil {
		s.logger.Error("rubygems dependency API response failed", "gems", gems, "error", err)
	}
}

// compactIndexWriter holds a compact index document until it is whole, then
// answers it with the validators and range support Bundler relies on.
//
// Bundler updates versions by asking for the bytes past the copy it holds,
// with If-None-Match on the ETag it was last given, and checks the joined file
// against Repr-Digest. proxyOrCache fetches and caches the whole document, so
// both validators are computed over the bytes served: on a cache hit and on a
// miss they describe the same document, which an upstream ETag stored beside
// a cached copy would not once the copy is refreshed. The digest of an
// unmodified document is the upstream's own, since the bytes are.
//
// Over maxUpstreamBody the response is refused rather than relayed without
// validators, which would make Bundler discard and refetch it on every run.
type compactIndexWriter struct {
	http.ResponseWriter
	r       *http.Request
	subject string
	// filter is the profile's reading of the document, run before the
	// validators are computed so they describe the bytes the client gets.
	filter func([]byte) ([]byte, error)
	status int
	body   bytes.Buffer
	tooBig bool
}

func (c *compactIndexWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
}

func (c *compactIndexWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if int64(c.body.Len()+len(b)) > maxUpstreamBody {
		c.tooBig = true
		c.body.Reset()
		return 0, fmt.Errorf("rubygems %s exceeds bodega's %d-byte compact index buffer", c.subject, maxUpstreamBody)
	}
	return c.body.Write(b)
}

func (c *compactIndexWriter) flush() error {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if c.status != http.StatusOK {
		c.ResponseWriter.WriteHeader(c.status)
		_, err := c.ResponseWriter.Write(c.body.Bytes())
		return err
	}
	if c.tooBig {
		err := fmt.Errorf("rubygems %s exceeds bodega's %d-byte compact index buffer", c.subject, maxUpstreamBody)
		http.Error(c.ResponseWriter, err.Error(), http.StatusBadGateway)
		return err
	}
	body := c.body.Bytes()
	if c.filter != nil {
		filtered, err := c.filter(body)
		if err != nil {
			err = fmt.Errorf("rubygems %s could not be filtered for this host's profile, and serving it unfiltered would list gems this host is refused: %w", c.subject, err)
			http.Error(c.ResponseWriter, err.Error(), http.StatusBadGateway)
			return err
		}
		body = filtered
	}
	sum := sha256.Sum256(body)
	h := c.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	h.Set("Repr-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
	h.Set("Accept-Ranges", "bytes")
	// ServeContent writes the length of whatever part it serves.
	h.Del("Content-Length")
	http.ServeContent(c.ResponseWriter, c.r, "", time.Time{}, bytes.NewReader(body))
	return nil
}
