package server

import (
	"net/http"
	"strings"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Binaries --------------------------------------------------------------

// handleBinary resolves /binaries/{path...} two ways: through a configured
// namespaced upstream, or from the storage tree the uploader wrote.
//
// The namespaced form wins when the first path segment names a binary_upstreams
// key. When it names none and binary_upstreams holds at least one entry, the
// request 404s and is recorded as no_namespace rather than falling through to
// the storage read.
//
// Plan 06 left that choice open and offered the fall-through as the
// alternative. The fall-through is worse: an operator who opted into
// binary_upstreams and mistyped a namespace would get a storage read that also
// misses, so the 404 arrives either way and the discovery log holds nothing
// naming the key they meant to type. A loud miss costs the same status code
// and answers the question.
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
		if !configured {
			// pattern_hint and pkg_name are both the namespace, matching the
			// git namespace miss: the actionable unit is the key an operator
			// would add to binary_upstreams, and keying the row on the full
			// request path would let any client grow the table one row per URL
			// it invents.
			s.recordDiscoveryRaw(r.Context(), r, manifest.TypeBinary, "", ns, ns, "", audit.DecisionNoNamespace, "")
			http.NotFound(w, r)
			return
		}
		s.handleBinaryUpstream(w, r, ns, rest, bu)
		return
	}

	// Storage first, shape second. An install whose backend never came up owes
	// the operator a 503 naming that; a 404 would send them looking for a
	// package that is sitting right there.
	if !s.requireStorage(w, s.typeStore(manifest.TypeBinary)) {
		return
	}
	pkg, version, filename := binaryPathIdentity(p)
	if pkg == "" {
		// Not a shape the uploader writes, so no key can be derived for it.
		http.NotFound(w, r)
		return
	}
	s.proxyVersion(w, r, manifest.TypeBinary, pkg, version, manifest.BinaryKey(pkg, version, filename))
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

	// Anything that is not an explicit "open" is catalog. The default is
	// applied at config load, but a Server built in code carries whatever mode
	// it was handed, and the branch that fetches on demand is the one that has
	// to be opted into by name.
	if bu.Mode != config.UpstreamModeOpen {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeBinary, pkgName)
		if pm == nil {
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

// binaryPathIdentity recovers the manifest entry that owns a binaries/ key.
// The uploader writes <name>/<version>/<file>, dropping the version segment
// for an entry that has none, so a two-segment path yields an empty version
// rather than mistaking the filename for one. Any other segment count names
// nothing and returns an empty package.
func binaryPathIdentity(p string) (pkg, version, filename string) {
	parts := strings.Split(p, "/")
	switch len(parts) {
	case 2:
		return parts[0], "", parts[1]
	case 3:
		return parts[0], parts[1], parts[2]
	}
	return "", "", ""
}
