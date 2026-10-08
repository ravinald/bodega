package server

import (
	"net/http"
	"sort"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Binaries --------------------------------------------------------------

// handleBinary resolves /binaries/{path...} two ways: through a configured
// namespaced upstream, or from the storage tree the uploader wrote.
//
// The namespaced form wins when the first path segment names a binary_upstreams
// key, even over a hosted entry of the same name (warnShadowedBinaries says so
// at startup and reload). When it names none and binary_upstreams holds at
// least one entry, the request reaches the storage read only if a hosted
// manifest names exactly the package the path resolves to; anything else 404s
// and is recorded as no_namespace.
//
// A plain fall-through to storage was rejected: an operator who opted into
// binary_upstreams and mistyped a namespace would get a storage read that also
// misses, so the 404 arrives either way and the discovery log holds nothing
// naming the key they meant to type. A typo matches no manifest, so gating on
// one keeps that row. Refusing hosted binaries once a namespace exists was
// rejected too: it strands every existing hosted entry the day the first
// namespace is added, and no namespace can point back at the storage tree.
//
// An install with no binary_upstreams block reaches the storage read on every
// path, which is what every existing install does today.
func (s *Server) handleBinary(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	if !isSafePath(p) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	if ns, rest, ok := splitNamespace(p); ok && len(s.cfg.BinaryUpstreams) > 0 {
		bu, configured := s.cfg.BinaryUpstreams[ns]
		if configured {
			s.handleBinaryUpstream(w, r, ns, rest, bu)
			return
		}
		if !s.hostsBinary(r, p) {
			// pattern_hint and pkg_name are both the namespace, matching the
			// git namespace miss: the actionable unit is the key an operator
			// would add to binary_upstreams, and keying the row on the full
			// request path would let any client grow the table one row per URL
			// it invents.
			s.recordDiscoveryRaw(r.Context(), r, manifest.TypeBinary, "", ns, ns, "", audit.DecisionNoNamespace, "")
			http.NotFound(w, r)
			return
		}
	}

	// Storage first, shape second. An install whose backend never came up owes
	// the operator a 503 naming that; a 404 would send them looking for a
	// package that is sitting right there.
	if !s.requireStorage(w, s.typeStore(manifest.TypeBinary)) {
		return
	}
	pkg, version, filename := manifest.BinaryPathIdentity(p)
	if pkg == "" {
		// Not a shape the uploader writes, so no key can be derived for it.
		http.NotFound(w, r)
		return
	}
	// No binary extension reaches isImmutableArtifact and none should: an
	// uploader names these files whatever it likes, so there is no filename
	// shape bodega can read a year-long freshness promise off. The shared-cache
	// grant is a separate question, and a profile answers it no.
	w = cachePrivateOn200(w, filename)
	if !s.entitleGate(w, r, manifest.TypeBinary, pkg, version) {
		return
	}
	pm, _ := s.store.GetPackage(r.Context(), manifest.TypeBinary, pkg)
	filename, entry, ok := pm.BinaryStoredFilename([]byte(s.pepper), version, filename)
	if !ok {
		http.NotFound(w, r)
		return
	}
	key := manifest.BinaryKey(pkg, version, filename)
	if entry == nil {
		s.proxyVersion(w, r, manifest.TypeBinary, pkg, version, key)
		return
	}
	// An alias names one entry, and another entry of the same version may
	// hold the same key on a different backend, so the backend comes from the
	// entry the alias resolved to rather than from a second lookup by version.
	store, err := s.stores.ByName(entry.Storage)
	if err != nil {
		s.logger.Error("storage backend recorded for artifact is not configured",
			"type", manifest.TypeBinary, "package", pkg, "version", version, "key", key, "error", err)
		http.Error(w, "storage backend error", http.StatusBadGateway)
		return
	}
	s.serveArtifact(w, r, store, key, "")
}

// hostsBinary reports whether a hosted binary manifest names exactly the
// package p resolves to. The name is compared rather than trusting the lookup,
// because GetPackage folds "/" to "--" and would answer for a different entry.
func (s *Server) hostsBinary(r *http.Request, p string) bool {
	pkg, _, _ := manifest.BinaryPathIdentity(p)
	if pkg == "" {
		return false
	}
	pm, _ := s.store.GetPackage(r.Context(), manifest.TypeBinary, pkg)
	return pm != nil && pm.Name == pkg
}

// warnShadowedBinaries logs the hosted binary entries a binary_upstreams key of
// the same name hides. The namespace wins the route, so those entries answer
// with the upstream's bytes or a 404 while the package API still lists them.
func (s *Server) warnShadowedBinaries() {
	var shadowed []string
	for _, name := range s.store.ListPackages(manifest.TypeBinary) {
		if _, ok := s.cfg.BinaryUpstreams[name]; ok {
			shadowed = append(shadowed, name)
		}
	}
	if len(shadowed) == 0 {
		return
	}
	sort.Strings(shadowed)
	s.logger.Warn("binary_upstreams keys shadow hosted binary entries of the same name; /binaries/<name>/... routes to the namespace, so those entries are unreachable until the key or the entry is renamed",
		"entries", shadowed, "namespaces", shadowed)
}

// handleBinaryUpstream serves one request against a configured namespace.
//
// catalog mode runs its manifest lookup here, before proxyOrCache, because the
// point of catalog is that an unvetted upstream is never reached: a check made
// after the fetch has already made the request it was meant to prevent.
//
// The key and the upstream URL are both composed from the split path rather
// than from manifest.BinaryKey, which folds a name through SafeName. A
// namespaced path is a path, not a package name, and rewriting it would put
// the cached object under a key the next request cannot compose.
func (s *Server) handleBinaryUpstream(w http.ResponseWriter, r *http.Request, ns, rest string, bu config.BinaryUpstream) {
	ctx := r.Context()
	if rest == "" {
		// The namespace alone names no artifact, so there is nothing to fetch
		// and nothing an operator could promote from a row about it.
		http.NotFound(w, r)
		return
	}

	pkgName := ns + "/" + rest
	upstream := bu.URL + rest
	key := manifest.BinaryPrefix + pkgName

	// <namespace>/<rest> is the name a manifest entry carries for a namespaced
	// binary, so it is what a profile lists. The path names no version bodega
	// can parse, which leaves membership as the whole decision here.
	w = cachePrivateOn200(w, rest)
	if !s.entitleGate(w, r, manifest.TypeBinary, pkgName, "") {
		return
	}

	// Anything that is not an explicit "open" is catalog. The default is
	// applied at config load, but a Server built in code carries whatever mode
	// it was handed, and the branch that fetches on demand is the one that has
	// to be opted into by name.
	//
	// The verdict is the manifest's own recorded name, not the lookup
	// succeeding. GetPackage addresses a manifest through SafeName, which maps
	// "/" to "--" and is therefore not injective: "vendor/tool--2.0/tool.tar.gz"
	// and "vendor/tool/2.0/tool.tar.gz" fold to one stored name, so cataloging
	// either would authorize both — and the client controls every byte of
	// <rest>. Comparing pm.Name is injective where the path is not, and needs
	// no encoding change under the manifests already written. Refusing a
	// "--" in <rest> was the alternative; it would also refuse the legitimate
	// upstream paths that contain one.
	if bu.Mode != config.UpstreamModeOpen {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeBinary, pkgName)
		if pm == nil || pm.Name != pkgName {
			s.recordNoManifest(ctx, r, manifest.TypeBinary, pkgName, "", upstream)
			http.NotFound(w, r)
			return
		}
	}

	// One store for the cache read and the cache write. Resolving it twice is
	// how an object cached on a miss lands in a backend the next Head never
	// looks at.
	store := s.typeStore(manifest.TypeBinary)
	// policyCandidate is the upstream URL: binary is a URL-scoped type, so the
	// allow-list matches a URL prefix. discoveryPkgName is <namespace>/<rest>,
	// which is what 'discover promote --as manifest' writes the entry under.
	s.proxyOrCache(w, r, store, key, upstream, manifest.TypeBinary, upstream, pkgName, true, true)
}
