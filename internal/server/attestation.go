package server

import (
	"net/http"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
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
// s3:// URIs are read by the bodega host, which already has the bucket
// credentials the client does not.
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
		//nolint:gosec // G710: uri comes from operator-controlled manifest, not from request input.
		http.Redirect(w, r, uri, http.StatusFound)
	case strings.HasPrefix(uri, "s3://"):
		bucket, key, ok := strings.Cut(strings.TrimPrefix(uri, "s3://"), "/")
		if !ok || key == "" {
			http.Error(w, "attestation_uri missing key", http.StatusBadGateway)
			return
		}
		store, key, backend := s.attestationStore(t, bucket, key)
		if backend == "" {
			s.logger.Warn("attestation_uri names a bucket no configured backend answers to; reading it from the type rule instead",
				"type", t, "package", name, "version", version, "uri", uri)
		}
		s.proxyS3(w, r, store, key)
	default:
		http.Error(w, "unsupported attestation_uri scheme", http.StatusBadGateway)
	}
}

// attestationStore resolves the bucket in an s3:// attestation_uri to the
// backend that holds it, returning the key rebased onto that backend and the
// backend's name ("" when nothing matched and the type rule answered).
//
// The URI is the only record of where the envelope is. Nothing in bodega
// writes the blob — an external authority puts it there — and 'pkg move' does
// not carry it, so VersionEntry.Storage describes where the artifact went and
// says nothing about where the envelope stayed. Resolving by record would 404
// an envelope sitting exactly where it was left; resolving by type rule alone
// broke retrieval for artifacts nobody touched, every time storage_by_type
// changed. Matching the bucket uses information already in the manifest and
// needs no new field.
//
// A backend rooted at a key prefix inside that bucket matches only when the
// URI's key sits under that prefix, because prefixed re-adds the prefix to
// every key it is handed.
//
// No match is a fallback, not a refusal: the type rule is what answered before
// named backends existed, so an envelope in a bucket bodega does not configure
// keeps whatever chance of resolving it had. The WARN is where an operator
// learns which of the two happened.
func (s *Server) attestationStore(typ, bucket, key string) (storage.ObjectStore, string, string) {
	if s.stores == nil {
		return nil, key, ""
	}
	want := "s3://" + bucket
	for _, ns := range s.stores.All() {
		label := ns.Store.Label()
		if label == want {
			return ns.Store, key, ns.Name
		}
		if prefix, rooted := strings.CutPrefix(label, want+"/"); rooted {
			if rel, under := strings.CutPrefix(key, prefix+"/"); under {
				return ns.Store, rel, ns.Name
			}
		}
	}
	return s.typeStore(typ), key, ""
}
