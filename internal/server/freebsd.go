package server

import (
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// ---- FreeBSD pkg repository mirror -----------------------------------------
//
// One route serves a whole mirrored repository: GET /freebsd/{abi}/{repo}/{rest...},
// which is the path a pkg client composes from its configured URL and ${ABI}.
// The package name is the repository ("latest", "base_latest"), the version is
// the ABI ("FreeBSD:14:amd64"), and rest is either a repository-root file or a
// catalogue record's own repopath.
//
// Nothing here transforms a byte. packagesite.pkg and data.pkg are zstd
// tarballs, each carrying its own signature and public key as members —
// packagesite.yaml.sig and .pub in one, data.sig and data.pub in the other —
// so the archive is its own attestation: copied intact it validates against
// the stock fingerprint every FreeBSD host already ships, and bodega
// configures no key and asks the client to trust none. Recompressing,
// re-tarring or negotiating a content encoding over these would break that
// signature, and the client would report the failure against bytes bodega
// changed on purpose — with nothing on this side calling it a bodega fault.
//
// This is the opposite of apt, where internal/server/apt.go generates and
// re-signs Debian metadata because it must. Generating a pkg catalogue is a
// separate job and applies only to packages an operator built themselves.

// The paths pkg asks for on an old repository and no current one answers are
// manifest.FreeBSDLegacyRootFiles, refused below by name.
//
// digests.pkg was a meta.conf key whose own source comment at pkg 1.12 reads
// "Leave digests here so pkg will not complain"; it is gone from pkg 2.x.
// packagesite.txz and repo.txz are the pre-1.17 spellings. All of them 404 on
// every current FreeBSD repository, so they are refused rather than proxied:
// proxying would spend a round trip per client per update to cache somebody
// else's 404, and mirroring them would mean generating files upstream does not
// publish. The list is in manifest because the catalogue reader refuses a
// repopath landing on one, and a name refused here and mirrored there is an
// object no request reaches.

// handleFreeBSD serves one path under a mirrored repository.
func (s *Server) handleFreeBSD(w http.ResponseWriter, r *http.Request) {
	abi, repo, rest, ok := splitFreeBSDPath(r.PathValue("path"))
	if !ok {
		http.Error(w, "invalid freebsd repository path: expected /freebsd/<abi>/<repo>/<path>, for example /freebsd/FreeBSD:14:amd64/latest/meta.conf", http.StatusBadRequest)
		return
	}
	if slices.Contains(manifest.FreeBSDLegacyRootFiles, rest) {
		// Named in the log because the answer is a fact about pkg rather than
		// about this repository: a client asking for one of these is old
		// enough that the repository it wants has not existed for years.
		s.logger.Debug("freebsd: refusing a path no current repository publishes",
			"abi", abi, "repo", repo, "file", rest)
		http.Error(w, rest+" is not published by any current FreeBSD pkg repository; pkg 1.17 and later read meta.conf, data.pkg and packagesite.pkg", http.StatusNotFound)
		return
	}

	ctx := r.Context()
	pm, _ := s.store.GetPackage(ctx, manifest.TypeFreeBSD, repo)
	ve, configured := freeBSDVersion(pm, abi)
	// One entry decides everything about this request, and it is the entry
	// for the ABI that was asked for. A repository carries one per ABI and
	// they are configured apart: reading the mode off the first would serve
	// FreeBSD:13's proxy decision to a FreeBSD:14 client whose objects were
	// mirrored, and hiding one ABI would leave it readable as long as
	// another stayed visible.
	if pm != nil && (isPackageHidden(pm) || ve.Hidden) {
		// Before the cache read and before any upstream contact. hide is the
		// quarantine control, and an ABI that still answers from the store or
		// still warms a proxy cache is not quarantined.
		http.NotFound(w, r)
		return
	}
	if !s.entitleGate(w, r, manifest.TypeFreeBSD, repo, abi) {
		return
	}

	key := manifest.FreeBSDKey(abi, repo, rest)
	catalog := slices.Contains(manifest.FreeBSDCatalogFiles, rest)
	proxied := !configured || ve.EffectiveMode() == manifest.ModeProxy

	store, err := s.versionStore(ctx, manifest.TypeFreeBSD, repo, abi)
	if err != nil {
		s.logger.Error("storage backend recorded for artifact is not configured",
			"type", manifest.TypeFreeBSD, "package", repo, "version", abi, "error", err)
		http.Error(w, "storage backend error", http.StatusBadGateway)
		return
	}

	upstream := freeBSDUpstreamOf(ve, configured, rest)
	if catalog && !proxied {
		// A mirrored repository's catalogue is never fetched from upstream on
		// a miss. Upstream's catalogue is by construction newer than this
		// mirror's objects and names packages this store has never held, so
		// serving it would resolve an install that 404s partway through —
		// which is the one skew a mirror must not produce. A miss here means
		// the mirror has not finished, and the honest answer to that is 404:
		// pkg reports the repository as unavailable and installs nothing.
		if upstream != "" {
			s.logger.Warn("freebsd: catalogue miss on a mirrored repository; refusing to proxy it",
				"abi", abi, "repo", repo, "file", rest, "key", key)
		}
		upstream = ""
	}

	// Content-addressed by construction everywhere but the repository root:
	// latest/ publishes at All/Hashed/<name>-<version>~<hash>.pkg and
	// base_latest/ carries the version in the filename, so an object at a
	// given repopath never changes. The three root files are republished in
	// place and refetch after metadata_ttl.
	immutable := !catalog
	if catalog {
		noSharedCache(w)
	} else {
		w = cachePrivateOn200(w, path.Base(rest))
	}

	s.proxyOrCache(w, r, store, key, upstream, manifest.TypeFreeBSD, upstream, repo+"/"+rest, immutable, proxied)
}

// freeBSDVersion is the entry configured for one ABI.
//
// A freebsd package is a repository and its versions are the ABI directories
// under it, each with its own mode, URL, storage backend and hidden flag. The
// route resolves the ABI from the request path, so every one of those has to
// be read off the entry that ABI names rather than off whichever entry the
// manifest happens to list first.
func freeBSDVersion(pm *manifest.PackageManifest, abi string) (manifest.VersionEntry, bool) {
	if pm == nil {
		return manifest.VersionEntry{}, false
	}
	for _, ve := range pm.Versions {
		if ve.Version == abi {
			return ve, true
		}
	}
	return manifest.VersionEntry{}, false
}

// freeBSDUpstreamOf composes the upstream URL for one path, or "" when no
// entry names a repository root to compose it from.
//
// The entry's URL is the repository root as a pkg client would be pointed at
// it, ${ABI} already substituted. It is not composed from abi and repo here
// for the reason it is not composed in the builder: a private repository need
// not nest its ABIs, and nothing in a URL says which convention it follows.
func freeBSDUpstreamOf(ve manifest.VersionEntry, configured bool, rest string) string {
	if !configured || ve.URL == "" {
		return ""
	}
	return strings.TrimRight(ve.URL, "/") + "/" + rest
}

// splitFreeBSDPath validates a request path and splits it into the ABI, the
// repository and the repository-relative path.
//
// The relative half is validated as strictly as the catalogue's own repopath
// is at mirror time, and for the same reason: it composes an object key, and
// a key that walked out of FreeBSDRepoPrefix would read one repository's
// bytes under another's name. http.ServeMux already refuses a request whose
// raw path holds a "..", but this route also composes a key for the proxy
// fetch, so the check belongs where the key is built rather than upstream of
// it.
func splitFreeBSDPath(p string) (abi, repo, rest string, ok bool) {
	segs := strings.SplitN(p, "/", 3)
	if len(segs) != 3 {
		return "", "", "", false
	}
	abi, repo, rest = segs[0], segs[1], segs[2]
	if !manifest.FreeBSDValidABI(abi) || !manifest.FreeBSDValidRepo(repo) {
		return "", "", "", false
	}
	if rest == "" || strings.HasPrefix(rest, "/") || strings.Contains(rest, `\`) {
		return "", "", "", false
	}
	for _, seg := range strings.Split(rest, "/") {
		switch seg {
		case "", ".", "..":
			return "", "", "", false
		}
	}
	for _, r := range rest {
		if r < 0x20 || r == 0x7f {
			return "", "", "", false
		}
	}
	return abi, repo, rest, true
}
