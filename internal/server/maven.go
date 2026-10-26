package server

import (
	"context"
	"crypto/md5"  //nolint:gosec // G501: the repository layout's own checksum, which Maven compares; it guards nothing here.
	"crypto/sha1" //nolint:gosec // G505: as above.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// handleMaven serves a Maven repository: Maven Central's layout, proxied byte
// for byte from maven_upstreams, so one URL (<base>/maven/) answers Maven,
// Gradle, sbt and every other JVM resolver. Each file comes from the first
// repository in the list that publishes it; the identity does not depend on
// which one that was.
//
// The identity is <groupId>:<artifactId> at the path's version directory.
// Every file of one version (jar, pom, module, classifiers and their
// checksums and signatures) is judged and recorded under that one identity,
// which is what keeps a resolver's ten requests per dependency on one
// discovery row. A maven-metadata.xml outside a SNAPSHOT also reads as
// groupId-level metadata, and mavenMetadataGate judges it under both.
func (s *Server) handleMaven(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	mp, ok := manifest.ParseMavenPath(p)
	if !ok {
		// Answered here rather than upstream: a path outside the layout names
		// no identity the allow-list could judge, so forwarding it would let
		// any request reach the upstream unvetted.
		http.NotFound(w, r)
		return
	}
	name := mp.Name()
	ctx := r.Context()
	if mp.Version != "" && !mp.Metadata {
		s.mavenArtifacts.add(name)
	}

	pm, _ := s.store.GetPackage(ctx, manifest.TypeMaven, name)
	if pm != nil {
		if isPackageHidden(pm) {
			s.refuseHidden(w, r, manifest.TypeMaven, name, "")
			return
		}
		if mp.Version != "" {
			if isVersionHidden(pm, mp.Version) {
				s.refuseHidden(w, r, manifest.TypeMaven, name, mp.Version)
				return
			}
			vc, baseVer := packageVersionConstraint(pm)
			if vc != "" && vc != manifest.ConstraintAny && baseVer != "" {
				if ok, ordered := versionAllowed(manifest.TypeMaven, baseVer, mp.Version, vc); !ok {
					s.refuseVersionConstraint(w, r, manifest.TypeMaven, name, baseVer, mp.Version, vc, ordered)
					return
				}
			}
		}
	}

	forceProxy := pm == nil || packageMode(pm) == manifest.ModeProxy
	// The index filter rewrites only metadata answered from upstream, and the
	// artifact route refuses only what such metadata would have withheld, as
	// the gomod route does.
	proxied := (pm == nil && s.cacheEnabled()) || (pm != nil && packageMode(pm) == manifest.ModeProxy)
	// A metadata path with a group-level reading is judged here under both
	// readings, so the proxy is handed no candidate to judge it again under
	// the artifact reading alone.
	candidate := name
	if mp.GroupLevelID != "" {
		candidate = ""
		artifact, ok := s.mavenMetadataGate(w, r, mp, p, pm != nil)
		if !ok {
			return
		}
		// The version rule decides each version listed in artifact-level
		// metadata. Group-level metadata lists plugin prefixes and no
		// versions, so a request admitted on that reading alone is served
		// as the upstream wrote it.
		if artifact {
			permit := profileVersionFilter(s.profileFor(r), manifest.TypeMaven, name)
			var withhold *indexWithhold
			if proxied {
				withhold = s.indexWithholdFor(r, manifest.TypeMaven, name)
			}
			if permit != nil || withhold != nil {
				s.serveFilteredMavenMetadata(w, r, mp, p, permit, withhold, forceProxy)
				return
			}
		}
	} else {
		if !s.entitleGate(w, r, manifest.TypeMaven, name, mp.Version) {
			return
		}
		if proxied && s.refuseWithheld(w, r, manifest.TypeMaven, name, mp.Version) {
			return
		}
	}

	immutable := mp.Immutable()
	directive := cachePrivate
	if immutable {
		directive = cachePrivateImmutable
	}
	w = &cacheDirectiveWriter{ResponseWriter: w, directive: directive}

	upstreams, served := s.mavenUpstreamOrder(mp, p)
	s3Key := manifest.MavenKey(p)
	store := s.typeStore(manifest.TypeMaven)
	if mp.Version != "" && !mp.Metadata {
		var err error
		if store, err = s.versionStore(ctx, manifest.TypeMaven, name, mp.Version); err != nil {
			s.logger.Error("storage backend recorded for artifact is not configured",
				"type", manifest.TypeMaven, "package", name, "version", mp.Version, "error", err)
			http.Error(w, "storage backend error", http.StatusBadGateway)
			return
		}
	}
	s.proxyOrCacheOrdered(w, r, store, s3Key, upstreams, served, manifest.TypeMaven, candidate, name, immutable, forceProxy)
}

// mavenUpstreamURLs are the URLs repository path p is fetched from, one per
// maven_upstreams root in its order.
func (s *Server) mavenUpstreamURLs(p string) []string {
	urls := make([]string, 0, len(s.cfg.MavenUpstreams))
	for _, root := range s.cfg.MavenUpstreams {
		urls = append(urls, strings.TrimRight(root, "/")+"/"+p)
	}
	return urls
}

// mavenFirstUpstreamURL is the URL a row or a log line names for p before
// anything is fetched: the first repository the fetch would ask.
func (s *Server) mavenFirstUpstreamURL(p string) string {
	if urls := s.mavenUpstreamURLs(p); len(urls) > 0 {
		return urls[0]
	}
	return ""
}

// mavenUpstreamOrder is what a miss for p asks, and what it remembers once
// one has answered. A companion (a checksum or a signature) is asked only of
// the repository that served the file it describes, when this process
// fetched that file: two repositories publishing one coordinate need not
// publish the same bytes, and a .sha1 taken from the other would fail the
// client's check of the jar it was handed. A companion whose file this
// process never fetched walks the list like any other file.
func (s *Server) mavenUpstreamOrder(mp manifest.MavenPath, p string) ([]string, func(int)) {
	if mp.Companion != "" {
		if root, ok := s.mavenOrigins.get(strings.TrimSuffix(p, "."+mp.Companion)); ok {
			return []string{root + "/" + p}, nil
		}
		return s.mavenUpstreamURLs(p), nil
	}
	roots := s.cfg.MavenUpstreams
	return s.mavenUpstreamURLs(p), func(i int) {
		if i < len(roots) {
			s.mavenOrigins.put(p, strings.TrimRight(roots[i], "/"))
		}
	}
}

// mavenOriginCap bounds mavenOriginSet for the reason mavenArtifactSetCap
// bounds its set. A path it forgot sends its companion through the list.
const mavenOriginCap = 8192

// mavenOriginSet is the repository root each file fetched through /maven/ in
// this process came from, keyed by its repository path. The zero value is
// ready to use.
type mavenOriginSet struct {
	mu    sync.Mutex
	roots map[string]string
}

func (m *mavenOriginSet) put(p, root string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.roots == nil || len(m.roots) >= mavenOriginCap {
		m.roots = make(map[string]string)
	}
	m.roots[p] = root
}

func (m *mavenOriginSet) get(p string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	root, ok := m.roots[p]
	return root, ok
}

// serveFilteredMavenMetadata answers an artifact-level maven-metadata.xml, or
// one of its companions, filtered for a profile that rules on the artifact's
// versions, by the index filter, or both; either may be nil. The cache keeps
// the upstream's document and every host class filters its own copy on the
// way out, so one profile's reading is never stored where another's request
// can be answered from it. Its reads carry no allow-list candidate, because
// mavenMetadataGate has already judged the request under both readings.
//
// The checksum companions are computed from the filtered bytes. The upstream's
// describe a document this host is not handed, and Maven and Gradle both
// refuse metadata whose checksum disagrees. The .asc signature cannot be
// recomputed, so it is answered 404: Maven does not ask for one on metadata,
// and a signature over other bytes would be a false claim.
func (s *Server) serveFilteredMavenMetadata(w http.ResponseWriter, r *http.Request, mp manifest.MavenPath, p string, permit func(string) bool, withhold *indexWithhold, forceProxy bool) {
	noSharedCache(w)
	name := mp.Name()
	metaPath := strings.TrimSuffix(p, "."+mp.Companion)
	store := s.typeStore(manifest.TypeMaven)
	filter := func(b []byte) []byte {
		b = filterMavenMetadata(b, permit)
		if withhold != nil {
			b = withhold.mavenMetadata(b)
		}
		return b
	}

	if mp.Companion == "" {
		rw := &indexFilterWriter{
			ResponseWriter: w,
			subject:        "the maven-metadata.xml for " + name,
			filter: func(b []byte) []byte {
				b = filter(b)
				if withhold != nil {
					withhold.finish(w.Header())
				}
				return b
			},
		}
		upstreams, served := s.mavenUpstreamOrder(mp, p)
		s.proxyOrCacheOrdered(rw, r, store, manifest.MavenKey(p), upstreams, served, manifest.TypeMaven, "", name, false, forceProxy)
		if err := rw.flush(); err != nil {
			s.logger.Error("maven metadata response failed", "artifact", name, "error", err)
		}
		return
	}

	newHash, ok := mavenChecksums[mp.Companion]
	if !ok {
		http.Error(w, fmt.Sprintf("%s: this host is served a filtered list of the versions of %s, so the upstream's %s signature covers a different document and is not served",
			p, name, mp.Companion), http.StatusNotFound)
		return
	}
	body, status, err := s.mavenMetadataRead(r, metaPath, name, forceProxy)
	if err != nil {
		s.logger.Warn("maven metadata checksum: the metadata it describes could not be read",
			"artifact", name, "companion", mp.Companion, "error", err)
		if status < 400 || status >= 500 {
			status = http.StatusBadGateway
		}
		http.Error(w, fmt.Sprintf("%s: %v", p, err), status)
		return
	}
	h := newHash()
	h.Write(filter(body))
	sum := hex.EncodeToString(h.Sum(nil))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(sum)))
	_, _ = io.WriteString(w, sum)
}

// mavenChecksums are the companions a filtered metadata file's checksum can be
// recomputed for.
var mavenChecksums = map[string]func() hash.Hash{
	"md5":    md5.New,  //nolint:gosec // G401: the repository layout's own checksum, which Maven compares; it guards nothing here.
	"sha1":   sha1.New, //nolint:gosec // G401: as above.
	"sha256": sha256.New,
	"sha512": sha512.New,
}

// mavenMetadataRead reads a maven-metadata.xml as the metadata route would
// serve it to this request, through the same cache, so the checksum computed
// from it describes the document the client was handed. The read is bodega's
// own (withOwnRead): the client's metadata request already wrote its rows.
func (s *Server) mavenMetadataRead(r *http.Request, metaPath, name string, forceProxy bool) ([]byte, int, error) {
	req := r.Clone(withOwnRead(r.Context()))
	req.URL.Path = "/maven/" + metaPath
	req.URL.RawQuery = ""
	for _, h := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
		req.Header.Del(h)
	}
	cw := &capturedResponse{header: http.Header{}}
	upstreams, served := s.mavenUpstreamOrder(manifest.MavenPath{}, metaPath)
	s.proxyOrCacheOrdered(cw, req, s.typeStore(manifest.TypeMaven), manifest.MavenKey(metaPath), upstreams, served,
		manifest.TypeMaven, "", name, false, forceProxy)
	switch {
	case cw.tooBig:
		return nil, http.StatusBadGateway, fmt.Errorf("%s exceeds bodega's %d-byte buffer", metaPath, maxUpstreamBody)
	case cw.status != 0 && cw.status != http.StatusOK:
		return nil, cw.status, fmt.Errorf("%s answered HTTP %d, so there is no document to checksum", metaPath, cw.status)
	}
	return cw.body.Bytes(), http.StatusOK, nil
}

// mavenMetadataGate judges a maven-metadata.xml that has a group-level
// reading, before anything is fetched. The path reads as <groupId>:<artifactId>
// or as a groupId whose plugin prefixes it lists, and the content that would
// tell them apart is the upstream's, so both are judged and the request is
// admitted when either passes the profile and the allow-list. Either reading
// exposes a listing and nothing a resolver can install. artifact reports that
// the artifact reading was the one admitted, which is the one whose versions a
// profile filters.
//
// Discovery, the refusal queue and the profile reach row record one reading,
// so a promote or an approval proposes a rule for something that exists: the
// one reading that was admitted, and otherwise (both admitted, as in open
// mode, or neither) the artifact reading when that artifact is known from a
// request for one of its versions, and the group-level reading,
// <GroupLevelID>:*, when it is not. Recording the group reading for a real
// artifact's metadata would put a groupId nothing depends on beside the
// artifact's own row; recording the artifact reading for a plugin prefix
// lookup would propose org.apache.maven:plugins.
//
// The refusal answers 404 for a profile, as Maven and Gradle read a 404 on
// metadata as an artifact with no versions and a 403 as a broken repository,
// and 403 for the allow-list, as every route answers it.
func (s *Server) mavenMetadataGate(w http.ResponseWriter, r *http.Request, mp manifest.MavenPath, p string, known bool) (artifact, ok bool) {
	name, group := mp.Name(), mp.GroupLevelName()
	prof := s.profileFor(r)
	artProf, grpProf := prof.Covers(manifest.TypeMaven, name), prof.CoversMavenGroup(mp.GroupLevelID)
	recordArtifact := func(artAdmitted, grpAdmitted bool) bool {
		if artAdmitted != grpAdmitted {
			return artAdmitted
		}
		return known || s.mavenArtifactKnown(r, name)
	}

	if !artProf.Permitted && !grpProf.Permitted {
		rec, cov := group, grpProf
		if recordArtifact(false, false) {
			rec, cov = name, artProf
		}
		if cov.Reportable() {
			s.recordProfileReach(r, prof, manifest.TypeMaven, rec, "")
		}
		f := profileRefusal(prof, manifest.TypeMaven, rec, "", cov)
		f.status = http.StatusNotFound
		f.reason = fmt.Sprintf("%s: profile %q admits neither reading of %s: the artifact %s, nor any artifact of the groupId %s.",
			entitle.RefusalMembership, prof.Name(), p, name, mp.GroupLevelID)
		f.next = fmt.Sprintf("ask an operator to add one with `bodega profile add %s %s %s` or `bodega profile add %s %s %s`.",
			prof.Name(), manifest.TypeMaven, group, prof.Name(), manifest.TypeMaven, name)
		s.recordProfileRefusal(r, prof, manifest.TypeMaven, rec, "", cov, f.incident)
		s.queueRefusal(r, audit.QueueRefusal{PkgType: manifest.TypeMaven, PkgName: rec, Check: admit.QueueProfile,
			Profile: prof.Name(), Detail: f.reason, Incident: f.incident})
		f.write(w, r)
		return false, false
	}

	// artRule and grpRule are each reading's rule verdict alone, which is what
	// a discovery row's decision reports; artPolicy and grpPolicy also count an
	// override or a baseline, which admit the request but match no rule.
	artPolicy, grpPolicy, artRule, grpRule, listed := true, true, true, true, false
	if s.policy != nil {
		ctx, cancel := auditContext(r)
		defer cancel()
		var err error
		if listed, err = s.policy.Listed(ctx, manifest.TypeMaven); err != nil {
			s.logger.Error("policy rules lookup failed", "error", err)
		}
		key := manifest.MavenKey(p)
		artErr, grpErr := s.policy.Check(ctx, manifest.TypeMaven, name), s.policy.CheckMavenGroup(ctx, mp.GroupLevelID)
		artRule, grpRule = artErr == nil, grpErr == nil
		if artPolicy, err = s.mavenReadingAllowed(ctx, name, key, artErr); err == nil {
			grpPolicy, err = s.mavenReadingAllowed(ctx, group, key, grpErr)
		}
		if err != nil {
			s.logger.Error("policy check failed", "error", err)
			http.Error(w, "policy check failed", http.StatusInternalServerError)
			return false, false
		}
	}
	artOK, grpOK := artProf.Permitted && artPolicy, grpProf.Permitted && grpPolicy
	upstream := s.mavenFirstUpstreamURL(p)
	rec, cov, rule := group, grpProf, grpRule
	if recordArtifact(artOK, grpOK) {
		rec, cov, rule = name, artProf, artRule
	}

	if !artOK && !grpOK {
		f := allowListRefusal(manifest.TypeMaven, rec, rec, "")
		f.reason = fmt.Sprintf("%s reads as the artifact %s (%s) or as the groupId %s (%s), and neither reading is admitted.",
			p, name, mavenReadingVerdict(prof, artProf.Permitted, artPolicy), mp.GroupLevelID, mavenReadingVerdict(prof, grpProf.Permitted, grpPolicy))
		f.next = fmt.Sprintf("ask an operator to run `bodega policy add %s %s` or `bodega policy add %s %s` if it should be.",
			manifest.TypeMaven, group, manifest.TypeMaven, name)
		s.logger.Warn("upstream blocked by policy", "type", manifest.TypeMaven, "path", p,
			"artifact", name, "group", group, "url", upstream, "incident", f.incident)
		ctx, cancel := auditContext(r)
		defer cancel()
		s.recordDiscovery(ctx, r, manifest.TypeMaven, upstream, rec, rec, manifest.MavenKey(p), audit.DecisionDenied)
		s.recordPolicyViolation(r, manifest.TypeMaven, rec, upstream, f.incident)
		s.queueRefusal(r, audit.QueueRefusal{PkgType: manifest.TypeMaven, PkgName: rec,
			Check: admit.QueueAllowList, Pattern: rec, Detail: f.reason, Incident: f.incident})
		f.write(w, r)
		return false, false
	}

	if cov.Reportable() {
		s.recordProfileReach(r, prof, manifest.TypeMaven, rec, "")
	}
	if s.policy != nil {
		ctx, cancel := auditContext(r)
		defer cancel()
		s.recordDiscovery(ctx, r, manifest.TypeMaven, upstream, rec, rec, manifest.MavenKey(p), classifyDecision(listed, !rule))
	}
	return artOK, true
}

// mavenReadingAllowed reads one reading's allow-list verdict, err being what
// the check returned, and lets an active override or a baseline version admit
// a reading the rules refuse, as the proxy's own gate does.
func (s *Server) mavenReadingAllowed(ctx context.Context, name, key string, err error) (bool, error) {
	switch {
	case err == nil:
		return true, nil
	case !policy.IsViolation(err):
		return false, err
	}
	if o, ok := s.allowListOverrideLookup(ctx, manifest.TypeMaven, name, key, false)(); ok {
		s.logger.Warn("upstream admitted past the allow-list by override", "type", manifest.TypeMaven,
			"candidate", name, "key", key, "override", o.ID)
		return true, nil
	}
	if _, marked := s.baselineLookup(ctx, manifest.TypeMaven, name, key, false)(); marked {
		s.logger.Warn("upstream admitted past the allow-list as baseline", "type", manifest.TypeMaven,
			"candidate", name, "key", key)
		return true, nil
	}
	return false, nil
}

// mavenArtifactSetCap bounds mavenArtifactSet. Any client can name any
// coordinate, so an unbounded set is memory a scanner decides; a set that
// forgets falls back to the discovery table, which is the record it caches.
const mavenArtifactSetCap = 8192

// mavenArtifactSet is the Maven artifacts this process has seen a version's
// own file requested for. It answers the request that follows within the
// discovery recorder's batch window, before the row naming the artifact has
// reached the table. The zero value is ready to use.
type mavenArtifactSet struct {
	mu    sync.Mutex
	names map[string]struct{}
}

func (m *mavenArtifactSet) add(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.names == nil || len(m.names) >= mavenArtifactSetCap {
		m.names = make(map[string]struct{})
	}
	m.names[name] = struct{}{}
}

func (m *mavenArtifactSet) has(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.names[name]
	return ok
}

// mavenArtifactKnown reports whether name is an artifact something asked for
// a version of: in this process, or in a discovery row hinted with name that
// carries a version, which only a version's own file (pom, jar, module,
// classifier) writes. A sink that cannot be read answers no, and the caller
// records the group-level reading as it would for an artifact nobody named.
func (s *Server) mavenArtifactKnown(r *http.Request, name string) bool {
	if s.mavenArtifacts.has(name) {
		return true
	}
	if s.auditDB == nil {
		return false
	}
	ctx, cancel := auditContext(r)
	defer cancel()
	rows, err := s.auditDB.ListDiscovery(ctx, audit.DiscoveryFilter{RegistryType: manifest.TypeMaven, PatternHint: name, Limit: 64})
	if err != nil {
		s.logger.Debug("maven metadata: discovery unreadable, artifact treated as unknown", "artifact", name, "error", err)
		return false
	}
	for _, row := range rows {
		if row.PkgName == name && row.PkgVersion != "" {
			s.mavenArtifacts.add(name)
			return true
		}
	}
	return false
}

// mavenReadingVerdict says which check refused one reading of a metadata path.
func mavenReadingVerdict(prof *entitle.Profile, profileOK, policyOK bool) string {
	switch {
	case !profileOK:
		return fmt.Sprintf("profile %q does not list it", prof.Name())
	case !policyOK:
		return "not on this server's upstream allow-list"
	}
	return "admitted"
}
