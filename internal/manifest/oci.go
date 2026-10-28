package manifest

import (
	"fmt"
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

	ociDigestsMarker   = "/_digests/sha256/"
	ociTypesMarker     = "/_types/sha256/"
	ociTagsMarker      = "/_tags/"
	ociResolvedMarker  = "/_resolved/sha256/"
	ociResolvedBy      = "/_resolvedby/sha256/"
	ociChartsMarker    = "/_charts/sha256/"
	ociUnsettledMarker = "/_unsettled/"
	ociListSuffix      = "/_list"
)

// OCIDigestPrefix is the one digest algorithm bodega serves. sha512 is legal
// in the spec and no public registry publishes it.
const OCIDigestPrefix = "sha256:"

var (
	ociComponent      = `[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*`
	ociComponentRE    = regexp.MustCompile(`^` + ociComponent + `$`)
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

// HelmOCIConfigMediaType is the config media type of a chart pushed to an OCI
// registry, which is what tells a chart manifest from an image's.
const HelmOCIConfigMediaType = "application/vnd.cncf.helm.config.v1+json"

var helmChartNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidateHelmName refuses a helm entry in neither form the gate compares: a
// chart name from a classic repository (redis), or the <registry>/<repository>
// identity of a chart served under /v2/ (docker.io/bitnamicharts/redis).
func ValidateHelmName(name string) error {
	if helmChartNameRE.MatchString(name) {
		return nil
	}
	if registry, repo, ok := strings.Cut(name, "/"); ok && OCIValidRegistryName(registry) && OCIValidRepository(repo) {
		return nil
	}
	return fmt.Errorf("helm %q is neither a chart name from a classic repository (redis) nor an OCI chart as <registry>/<repository> in lowercase (docker.io/bitnamicharts/redis)", name)
}

// OCINamespaceWildcard is the last segment of a <registry>/<namespace>/*
// profile entry: every repository under that namespace of that registry.
const OCINamespaceWildcard = "*"

// ValidateOCIName refuses a profile entry that is neither a package identity
// a request resolves to nor <registry>/<namespace>/*, so no entry is stored
// that the gate could never match. Docker Hub's official images are always
// identified under library/, so docker.io/postgres is refused rather than
// stored as an entry no request carries.
func ValidateOCIName(name string) error {
	const form = "write <registry>/<repository> as bodega identifies an image (docker.io/library/postgres, ghcr.io/acme-labs/widget), " +
		"or <registry>/<namespace>/* for every repository of one namespace (ghcr.io/acme-labs/*)"
	registry, repo, ok := strings.Cut(name, "/")
	if !ok || !OCIValidRegistryName(registry) {
		return fmt.Errorf("oci %q does not start with a registry name such as docker.io or ghcr.io; %s", name, form)
	}
	if ns, ok := strings.CutSuffix(repo, "/"+OCINamespaceWildcard); ok && ociComponentRE.MatchString(ns) {
		return nil
	}
	if !OCIValidRepository(repo) {
		return fmt.Errorf("oci %q is not a repository; %s", name, form)
	}
	if registry == "docker.io" && !strings.Contains(repo, "/") {
		return fmt.Errorf("oci %q names a Docker Hub official image without its namespace; write docker.io/library/%s", name, repo)
	}
	return nil
}

// OCINamespaceEntry is the <registry>/<namespace>/* entry that covers name,
// and false when name's repository has no namespace. The namespace is the
// repository's first segment, so ghcr.io/a/* covers ghcr.io/a/b/c as well.
func OCINamespaceEntry(name string) (string, bool) {
	registry, repo, ok := strings.Cut(name, "/")
	if !ok {
		return "", false
	}
	ns, _, ok := strings.Cut(repo, "/")
	if !ok || ns == "" {
		return "", false
	}
	return registry + "/" + ns + "/" + OCINamespaceWildcard, true
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

// OCIManifestTypeKey holds the media type the registry served a manifest
// under, beside its bytes and in the same backend. Docker manifests need not
// repeat their type in the body, so the bytes alone cannot say it, and the
// bytes cannot be rewritten to carry it without changing their digest.
func OCIManifestTypeKey(registry, repo, digest string) string {
	return ociManifestPrefix + registry + "/" + repo + ociTypesMarker + strings.TrimPrefix(digest, OCIDigestPrefix)
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
// repository, which is what the allow-list judges a request by digest under.
func OCIResolvedKey(registry, repo, digest string) string {
	return ociTagPrefix + registry + "/" + repo + ociResolvedMarker + strings.TrimPrefix(digest, OCIDigestPrefix)
}

// OCIChartBlobKey records that the chart manifest manifestDigest names blob
// in a repository, and holds the tag the manifest was reached under. A blob
// request names no manifest, so this is what judges a chart's config and
// layer under the chart's verdict. Regenerable from the manifests.
func OCIChartBlobKey(registry, repo, blob, manifestDigest string) string {
	return OCIChartBlobPrefix(registry, repo, blob) + strings.TrimPrefix(manifestDigest, OCIDigestPrefix)
}

// OCIChartBlobPrefix lists every chart manifest of a repository naming blob.
func OCIChartBlobPrefix(registry, repo, blob string) string {
	return OCIChartsPrefix(registry, repo) + strings.TrimPrefix(blob, OCIDigestPrefix) + "/"
}

// OCIChartsPrefix lists every chart blob record of a repository, so a
// repository holds charts exactly when something is listed under it.
func OCIChartsPrefix(registry, repo string) string {
	return ociTagPrefix + registry + "/" + repo + ociChartsMarker
}

// OCIUnsettledPrefix is the prefix of a repository's OCIUnsettledKey records.
func OCIUnsettledPrefix(registry, repo string) string {
	return ociTagPrefix + registry + "/" + repo + ociUnsettledMarker
}

// OCIUnsettledKey marks the image an index root dated by its platform
// manifest child as one whose member digests are not all recorded under a
// verdict: its checks are running, or it was refused without every platform
// read.
func OCIUnsettledKey(registry, repo, root, child string) string {
	return OCIUnsettledPrefix(registry, repo) + strings.TrimPrefix(root, OCIDigestPrefix) + "." + strings.TrimPrefix(child, OCIDigestPrefix)
}

// OCIResolvedByKey marks that tag resolved to digest in a repository, which
// is what a profile judges a request by digest under. One key per tag rather
// than a list under one key, so recording a tag never rewrites, and never
// loses, a tag another request recorded.
func OCIResolvedByKey(registry, repo, digest, tag string) string {
	return OCIResolvedByPrefix(registry, repo, digest) + tag
}

// OCIResolvedByPrefix lists the OCIResolvedByKey markers of one digest.
func OCIResolvedByPrefix(registry, repo, digest string) string {
	return ociTagPrefix + registry + "/" + repo + ociResolvedBy + strings.TrimPrefix(digest, OCIDigestPrefix) + "/"
}

// OCIResolvedByTag is the tag an OCIResolvedByKey under prefix names, and
// false for a key that is not one.
func OCIResolvedByTag(prefix, key string) (string, bool) {
	tag, ok := strings.CutPrefix(key, prefix)
	return tag, ok && OCIValidTag(tag)
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
		// A sibling of the manifest, not a second copy of its version.
		if i := strings.LastIndex(rest, ociTypesMarker); i > 0 && ociDigestVersion(rest[i+len(ociTypesMarker):]) != "" {
			return ociName(rest[:i]), ""
		}
	case strings.HasPrefix(key, ociTagPrefix):
		rest := strings.TrimPrefix(key, ociTagPrefix)
		if i := strings.LastIndex(rest, ociResolvedBy); i > 0 {
			hex, tag, ok := strings.Cut(rest[i+len(ociResolvedBy):], "/")
			if !ok || !OCIValidTag(tag) {
				return "", ""
			}
			return ociNameVersion(rest[:i], ociDigestVersion(hex))
		}
		if i := strings.LastIndex(rest, ociTagsMarker); i > 0 && OCIValidTag(rest[i+len(ociTagsMarker):]) {
			return ociNameVersion(rest[:i], rest[i+len(ociTagsMarker):])
		}
		if i := strings.LastIndex(rest, ociResolvedMarker); i > 0 {
			return ociNameVersion(rest[:i], ociDigestVersion(rest[i+len(ociResolvedMarker):]))
		}
		if i := strings.LastIndex(rest, ociChartsMarker); i > 0 {
			if blob, m, ok := strings.Cut(rest[i+len(ociChartsMarker):], "/"); ok && ociDigestVersion(blob) != "" && ociDigestVersion(m) != "" {
				return ociName(rest[:i]), ""
			}
			return "", ""
		}
		// A record about the repository's images, not a version of it.
		if i := strings.LastIndex(rest, ociUnsettledMarker); i > 0 {
			root, child, ok := strings.Cut(rest[i+len(ociUnsettledMarker):], ".")
			if ok && ociDigestVersion(root) != "" && ociDigestVersion(child) != "" {
				return ociName(rest[:i]), ""
			}
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
