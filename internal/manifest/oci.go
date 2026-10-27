package manifest

import (
	"regexp"
	"strings"
)

// OCI storage keys. A repository name holds any number of segments, so every
// key that follows one puts a marker segment after it: a repository component
// cannot start with "_", which keeps the tag "v1" of library/x apart from the
// repository library/x/v1. The registry's own storage driver separates
// _manifests and _layers from the repository the same way.
const (
	ociBlobPrefix     = "oci/blobs/"
	ociManifestPrefix = "oci/manifests/"
	ociTagPrefix      = "oci/tags/"

	ociDigestsMarker  = "/_digests/sha256/"
	ociTagsMarker     = "/_tags/"
	ociResolvedMarker = "/_resolved/sha256/"
	ociListSuffix     = "/_list"
)

// OCIDigestPrefix is the one digest algorithm bodega serves. sha512 is legal
// in the spec and no public registry publishes it.
const OCIDigestPrefix = "sha256:"

var (
	ociComponent      = `[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*`
	ociRepositoryRE   = regexp.MustCompile(`^` + ociComponent + `(?:/` + ociComponent + `)*$`)
	ociTagRE          = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	ociDigestRE       = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	ociRegistryNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// OCIValidRepository reports whether repo is a repository name the
// distribution spec accepts: lowercase components joined by "/", none of
// them "." or "..", so it is safe as key segments.
func OCIValidRepository(repo string) bool {
	return len(repo) <= 255 && ociRepositoryRE.MatchString(repo)
}

// OCIValidTag reports whether tag is a tag the distribution spec accepts.
func OCIValidTag(tag string) bool { return ociTagRE.MatchString(tag) }

// OCIValidDigest reports whether d is a sha256 digest in the spec's form.
func OCIValidDigest(d string) bool { return ociDigestRE.MatchString(d) }

// OCIValidRegistryName reports whether name can be a key of oci_upstreams: a
// lowercase hostname with at least one dot, which is what tells a registry
// apart from a Docker Hub namespace in the first segment of a path.
func OCIValidRegistryName(name string) bool {
	return len(name) <= 253 && ociRegistryNameRE.MatchString(name)
}

// OCIBlobKey is a blob's key. One per digest, shared by every repository and
// registry, since the digest is the whole identity of the bytes.
func OCIBlobKey(digest string) string {
	return ociBlobPrefix + "sha256/" + strings.TrimPrefix(digest, OCIDigestPrefix)
}

// OCIManifestKey is a manifest's key by digest. Immutable.
func OCIManifestKey(registry, repo, digest string) string {
	return ociManifestPrefix + registry + "/" + repo + ociDigestsMarker + strings.TrimPrefix(digest, OCIDigestPrefix)
}

// OCITagKey is a tag's key: the digest and media type it resolved to, not the
// manifest bytes. Regenerable.
func OCITagKey(registry, repo, tag string) string {
	return ociTagPrefix + registry + "/" + repo + ociTagsMarker + tag
}

// OCITagListKey is a repository's tags/list document. Regenerable.
func OCITagListKey(registry, repo string) string {
	return ociTagPrefix + registry + "/" + repo + ociListSuffix
}

// OCIResolvedKey holds the tag bodega last resolved to digest in a
// repository, which is what a request by digest is judged under.
func OCIResolvedKey(registry, repo, digest string) string {
	return ociTagPrefix + registry + "/" + repo + ociResolvedMarker + strings.TrimPrefix(digest, OCIDigestPrefix)
}

// parseOCIKey is ParseKey for the oci tree. The name is <registry>/<repository>
// and the version a tag or a digest; a blob names no repository.
func parseOCIKey(key string) (name, version string) {
	switch {
	case strings.HasPrefix(key, ociBlobPrefix):
		hex, ok := strings.CutPrefix(strings.TrimPrefix(key, ociBlobPrefix), "sha256/")
		if !ok || !OCIValidDigest(OCIDigestPrefix+hex) {
			return "", ""
		}
		return "", OCIDigestPrefix + hex
	case strings.HasPrefix(key, ociManifestPrefix):
		rest := strings.TrimPrefix(key, ociManifestPrefix)
		if i := strings.LastIndex(rest, ociDigestsMarker); i > 0 {
			return ociNameVersion(rest[:i], ociDigestVersion(rest[i+len(ociDigestsMarker):]))
		}
	case strings.HasPrefix(key, ociTagPrefix):
		rest := strings.TrimPrefix(key, ociTagPrefix)
		if i := strings.LastIndex(rest, ociTagsMarker); i > 0 && OCIValidTag(rest[i+len(ociTagsMarker):]) {
			return ociNameVersion(rest[:i], rest[i+len(ociTagsMarker):])
		}
		if i := strings.LastIndex(rest, ociResolvedMarker); i > 0 {
			return ociNameVersion(rest[:i], ociDigestVersion(rest[i+len(ociResolvedMarker):]))
		}
		if n, ok := strings.CutSuffix(rest, ociListSuffix); ok {
			return ociName(n), ""
		}
	}
	return "", ""
}

// ociName checks <registry>/<repository> as a key carries it.
func ociName(n string) string {
	registry, repo, ok := strings.Cut(n, "/")
	if !ok || !OCIValidRegistryName(registry) || !OCIValidRepository(repo) {
		return ""
	}
	return n
}

// ociNameVersion answers both or neither, so a key with a malformed
// repository never yields a version under no name.
func ociNameVersion(n, version string) (string, string) {
	if n = ociName(n); n == "" || version == "" {
		return "", ""
	}
	return n, version
}

func ociDigestVersion(hex string) string {
	if !OCIValidDigest(OCIDigestPrefix + hex) {
		return ""
	}
	return OCIDigestPrefix + hex
}
