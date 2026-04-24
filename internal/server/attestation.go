package server

import (
	"net/http"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// Reserved VersionEntry.Metadata keys for SLSA-style attestation passthrough.
// The sync service (per DECISION_golden-vs-bodega) populates these when
// promoting a version from an external authority; bodega exposes the
// envelope as a sidecar URL alongside the package.
const (
	MetaAttestationURI   = "attestation_uri"
	MetaAttestationAlg   = "attestation_alg"
	MetaAttestationKeyID = "attestation_keyid"
)

// handleAttestation returns the DSSE envelope (or a redirect to it) for a
// given version. 404 when the VersionEntry has no attestation_uri set.
//
// http(s) URIs become a 302 redirect so the client fetches them directly.
// s3:// URIs fall back to the server's own object store — the bodega host
// already has the bucket credentials, the client doesn't.
func (s *Server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := r.PathValue("type")
	name := r.PathValue("name")
	version := r.PathValue("version")

	pm, err := s.store.GetPackage(ctx, t, name)
	if err != nil || pm == nil {
		http.NotFound(w, r)
		return
	}
	var ve *manifest.VersionEntry
	for i := range pm.Versions {
		if pm.Versions[i].Version == version || pm.Versions[i].Ref == version {
			ve = &pm.Versions[i]
			break
		}
	}
	if ve == nil || ve.Metadata == nil {
		http.NotFound(w, r)
		return
	}
	uri := ve.Metadata[MetaAttestationURI]
	if uri == "" {
		http.NotFound(w, r)
		return
	}

	switch {
	case strings.HasPrefix(uri, "http://"), strings.HasPrefix(uri, "https://"):
		http.Redirect(w, r, uri, http.StatusFound)
	case strings.HasPrefix(uri, "s3://"):
		// Strip scheme + bucket to derive the key. Expected shape: s3://bucket/key...
		rest := strings.TrimPrefix(uri, "s3://")
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			http.Error(w, "attestation_uri missing key", http.StatusBadGateway)
			return
		}
		// We don't cross-bucket-fetch; the bodega host's configured bucket is
		// the only storage we know how to read. Ignore the bucket prefix and
		// serve from our own objects using the key remainder.
		s.proxyS3(w, r, rest[slash+1:])
	default:
		http.Error(w, "unsupported attestation_uri scheme", http.StatusBadGateway)
	}
}
