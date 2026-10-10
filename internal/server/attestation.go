package server

import (
	"context"
	"errors"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/attestsign"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// Reserved VersionEntry.Metadata keys for an attestation somebody other than
// this bodega wrote: the version entry records where the envelope is, and the
// route passes it through.
const (
	MetaAttestationURI   = manifest.MetaAttestationURI
	MetaAttestationAlg   = "attestation_alg"
	MetaAttestationKeyID = "attestation_keyid"
)

// handleAttestation answers with an attestation for one version: the newest
// envelope this bodega signed for it, or, when there is none, the one its
// attestation_uri names. ?source=upstream skips bodega's own and goes straight
// to attestation_uri. 404 when neither exists.
//
// Bodega's own comes first because it is the statement this server can stand
// behind: signed by the key /api/v1/attestation/keys publishes, over the bytes
// this server pinned. An attestation_uri is somebody else's statement, served
// as found.
//
// For the passthrough, http(s) URIs become a 302 redirect so the client
// fetches them directly, unless the uri carries a part the read routes
// withhold: the Location would publish it, so that answer is a 502 instead.
// s3:// URIs are read by the bodega host, which already has the bucket
// credentials the client does not.
func (s *Server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := r.PathValue("type")
	name := r.PathValue("name")
	version := r.PathValue("version")

	pm, err := s.store.GetPackage(ctx, t, name)
	if err != nil || (pm == nil && !slices.Contains(manifest.AllTypes, t)) {
		http.NotFound(w, r)
		return
	}
	var ve *manifest.VersionEntry
	if pm != nil {
		for i := range pm.Versions {
			if pm.Versions[i].Version == version || pm.Versions[i].Ref == version {
				ve = &pm.Versions[i]
				break
			}
		}
	}

	if r.URL.Query().Get("source") != "upstream" && s.serveOwnAttestation(w, r, t, name, version, pm, ve) {
		return
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
	case manifest.AttestationURIWithheld(uri):
		s.logger.Warn("attestation_uri carries userinfo, a query or a fragment, and a redirect would hand it to the caller; rewrite it without them or serve the envelope from s3://",
			"type", t, "package", name, "version", version)
		http.Error(w, "attestation_uri is not redirectable: it carries userinfo, a query or a fragment", http.StatusBadGateway)
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

// serveOwnAttestation writes the newest envelope bodega signed for the
// version and reports whether it did. A version with no manifest entry, which
// is a proxy fill of something never cataloged, is looked up by the keys its
// type and version derive and in the backend the type rule names, which is
// where the fill cached it.
//
// A storage failure is answered here as a 502 rather than falling through to
// attestation_uri: that would serve a different party's statement because
// this server could not read its own.
func (s *Server) serveOwnAttestation(w http.ResponseWriter, r *http.Request, typ, name, version string, pm *manifest.PackageManifest, ve *manifest.VersionEntry) bool {
	ctx := r.Context()
	store, err := s.versionStore(ctx, typ, name, version)
	if err != nil || store == nil {
		return false
	}
	keys, err := s.attestationObjectKeys(ctx, store, typ, name, version, pm, ve)
	if err != nil || len(keys) == 0 {
		return false
	}
	ek, err := attest.Newest(ctx, store, keys)
	if err == nil && ek == "" {
		return false
	}
	var body []byte
	if err == nil {
		body, err = store.Get(ctx, ek)
	}
	if err != nil || body == nil {
		s.logger.Error("could not read this server's attestation", "type", typ, "package", name, "version", version, "key", ek, "error", err)
		http.Error(w, "attestation storage read failed", http.StatusBadGateway)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	//nolint:gosec // G705: an envelope this server signed and stored, served as application/json.
	_, _ = w.Write(body)
	return true
}

// attestationObjectKeys returns the object keys a version's envelopes are
// filed under. pypi has no per-version key, so its envelopes are found by
// listing the pypi prefix and reading each wheel's own name.
func (s *Server) attestationObjectKeys(ctx context.Context, store storage.ObjectStore, typ, name, version string, pm *manifest.PackageManifest, ve *manifest.VersionEntry) ([]string, error) {
	if typ == manifest.TypePypi {
		listed, err := store.List(ctx, manifest.AttestationPrefix+manifest.PypiWheelPrefix)
		if err != nil {
			return nil, err
		}
		want := manifest.CanonicalPypiName(name)
		seen := map[string]bool{}
		var keys []string
		for _, ek := range listed {
			obj, ok := attest.ObjectKeyOf(ek)
			if !ok || seen[obj] {
				continue
			}
			seen[obj] = true
			if dist, v, ok := builder.ParsePypiArtifactName(path.Base(obj)); ok && dist == want && v == version {
				keys = append(keys, obj)
			}
		}
		return keys, nil
	}
	if pm == nil {
		pm = &manifest.PackageManifest{Type: typ, Name: name}
	}
	entry := manifest.VersionEntry{Version: version}
	if ve != nil {
		entry = *ve
	}
	return inventory.ArtifactKeys(ctx, store, pm, entry)
}

// setupAttestation builds the emitter proxy pins sign through, or says once
// why there is none. A sink that keeps no admissions table leaves nothing to
// re-read before signing, so every pin under it would be signed on the
// caller's word; one WARN here replaces an ERROR on every pin.
func (s *Server) setupAttestation() {
	switch {
	case s.auditDB == nil:
		s.logger.Warn("attestations are off: no audit store is open, so no admission is recorded for an attestation to cite")
		return
	case s.auditDB.ReadOnly() || !s.auditDB.EventsQueryable():
		s.logger.Warn("attestations are off: the audit store keeps no admissions table this process can re-read before signing; use the sqlite or postgres audit_sink",
			"sink", s.auditDB.SinkName(), "read_only", s.auditDB.ReadOnly())
		return
	}
	s.attest = &attest.Emitter{
		Signer: func() attestsign.Signer {
			if a := s.attestSign.Load(); a != nil {
				return a.signer
			}
			return nil
		},
		Admissions: s.auditDB,
		PlatformID: s.cfg.ResolveAttestationPlatformID(),
	}
}

// emitAttestation signs the envelope for one pin into store. A refusal goes
// to the journal at ERROR naming the pin: those bytes are now served with no
// signed statement behind them.
func (s *Server) emitAttestation(ctx context.Context, store storage.ObjectStore, p attest.Pin) {
	if s.attest == nil {
		return
	}
	ek, err := s.attest.Emit(ctx, store, p)
	if err != nil {
		s.logger.Error("attestation not signed", "type", p.Type, "package", p.Name, "version", p.Version,
			"key", p.ObjectKey, "error", err)
		return
	}
	if ek != "" {
		s.logger.Debug("attestation signed", "key", p.ObjectKey, "envelope", ek)
	}
}

// requiredBy is the RequiredBy of the version's manifest entry, when it has
// one.
func (s *Server) requiredBy(ctx context.Context, typ, name, version string) []string {
	pm, err := s.store.GetPackage(ctx, typ, name)
	if err != nil || pm == nil {
		return nil
	}
	for _, ve := range pm.Versions {
		if ve.Version == version || ve.Ref == version {
			return ve.RequiredBy
		}
	}
	return nil
}

// attestationStore resolves the bucket in an s3:// attestation_uri to the
// backend that holds it, returning the key rebased onto that backend and the
// backend's name ("" when nothing matched and the type rule answered).
//
// The URI is the only record of where that envelope is. Bodega does not write
// it (an external authority puts it there; bodega's own envelopes live under
// manifest.AttestationPrefix and serveOwnAttestation reads those) and 'pkg
// move' does not carry it, so VersionEntry.Storage describes where the
// artifact went and says nothing about where the envelope stayed. Resolving by
// record would 404 an envelope sitting exactly where it was left; resolving by
// type rule alone broke retrieval for artifacts nobody touched, every time
// storage_by_type changed. Matching the bucket uses information already in
// the manifest and needs no new field.
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

// attestSigning is the attestation key ring as the server holds it: the key
// that signs and the published set, swapped whole on reload so the keys route
// never lists a set the signer is not part of.
type attestSigning struct {
	signer attestsign.Signer
	keys   []attestationKey
}

// attestationKey is one element of GET /api/v1/attestation/keys.
type attestationKey struct {
	KeyID        string     `json:"keyid"`
	Alg          string     `json:"alg"`
	PublicKeyPEM string     `json:"public_key_pem"`
	CreatedAt    *time.Time `json:"created_at"`
	Retired      bool       `json:"retired"`
}

// loadAttestSigner installs the attestation key ring, if one is present. It
// runs at startup and on every SIGHUP.
//
// A reload never takes the signer away: a file that has gone missing or
// become unusable leaves the loaded ring signing and publishing, and the
// fault goes to the journal naming the file. A verifier pinned to the current
// key ID would otherwise see attestations stop, or start arriving under no
// key at all, because of a chmod. Dropping the key is a restart.
//
// No key at all is a supported configuration, warned about once per process
// rather than on every reload.
func (s *Server) loadAttestSigner() {
	prev := s.attestSign.Load()
	paths := attestsign.DefaultKeyPaths(s.cfg.StoragePath)
	kr, err := attestsign.Load(paths)
	switch {
	case errors.Is(err, attestsign.ErrNoKey) && prev != nil:
		s.logger.Warn("attestation signing key is gone from every search path; the loaded key keeps signing until a restart",
			"keyid", prev.signer.KeyID(), "searched", strings.Join(paths, ", "))
		return
	case errors.Is(err, attestsign.ErrNoKey):
		if s.attestNoKeyWarned.CompareAndSwap(false, true) {
			s.logger.Warn("no attestation signing key installed; bodega signs no attestations until one is generated and the server reloaded",
				"searched", strings.Join(paths, ", "))
		}
		return
	case err != nil:
		if prev != nil {
			s.logger.Error("attestation signing key present but unusable; the previously loaded key keeps signing until a restart",
				"error", err, "keyid", prev.signer.KeyID())
			return
		}
		s.logger.Error("attestation signing key present but unusable; bodega signs no attestations until it loads",
			"error", err)
		return
	}
	signer := kr.Signer()
	infos := kr.Keys()
	keys := make([]attestationKey, 0, len(infos))
	for _, k := range infos {
		ak := attestationKey{
			KeyID:        k.KeyID,
			Alg:          k.Algorithm,
			PublicKeyPEM: string(k.PublicKeyPEM),
			Retired:      !k.Retired.IsZero(),
		}
		if !k.Created.IsZero() {
			created := k.Created
			ak.CreatedAt = &created
		}
		keys = append(keys, ak)
	}
	s.attestSign.Store(&attestSigning{signer: signer, keys: keys})
	s.logger.Info("attestation signing key loaded",
		"path", kr.Path(), "keyid", signer.KeyID(), "published", len(keys))
}

// handleAttestationKeys lists every published attestation key. Unauthenticated
// like the apt keyring: a public key is what a verifier needs before it holds
// anything else. The key ID a verifier pins comes from a separate channel;
// this route only supplies the key that ID names.
func (s *Server) handleAttestationKeys(w http.ResponseWriter, _ *http.Request) {
	keys := []attestationKey{}
	if a := s.attestSign.Load(); a != nil {
		keys = a.keys
	}
	w.Header().Set("Cache-Control", "no-cache")
	writeJSON(w, http.StatusOK, keys)
}
