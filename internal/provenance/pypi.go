package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// PyPIPublishV1 is the predicate type of the publish attestation PyPI accepts
// from a Trusted Publisher: a statement with a null predicate whose only
// content is the subject and the certificate it is signed with.
const PyPIPublishV1 = "https://docs.pypi.org/attestations/publish/v1"

const (
	pypiSimpleJSON    = "application/vnd.pypi.simple.v1+json"
	pypiIntegrityJSON = "application/vnd.pypi.integrity.v1+json"
)

// pypiPublishers maps the Trusted Publisher kinds bodega verifies to the OIDC
// issuer their certificates carry and the forge their repository names live
// under.
var pypiPublishers = map[string]struct{ issuer, forge string }{
	"GitHub": {issuerGitHubActions, "https://github.com/"},
	"GitLab": {issuerGitLab, "https://gitlab.com/"},
}

var pypiSdistSuffixes = []string{".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz"}

// pypiPage is the part of a PEP 691 project page the check reads.
// Provenance is PEP 740's key: absent and null both mean the file was
// uploaded without an attestation.
type pypiPage struct {
	Files []struct {
		Filename   string            `json:"filename"`
		Hashes     map[string]string `json:"hashes"`
		Provenance *string           `json:"provenance"`
	} `json:"files"`
}

// pypiProvenance is PEP 740's provenance object.
type pypiProvenance struct {
	Version            int `json:"version"`
	AttestationBundles []struct {
		Publisher struct {
			Kind             string `json:"kind"`
			Repository       string `json:"repository"`
			Workflow         string `json:"workflow"`
			WorkflowFilepath string `json:"workflow_filepath"`
		} `json:"publisher"`
		Attestations []pypiAttestation `json:"attestations"`
	} `json:"attestation_bundles"`
}

type pypiAttestation struct {
	Version              int `json:"version"`
	VerificationMaterial struct {
		Certificate         string            `json:"certificate"`
		TransparencyEntries []json.RawMessage `json:"transparency_entries"`
	} `json:"verification_material"`
	Envelope struct {
		Statement string `json:"statement"`
		Signature string `json:"signature"`
	} `json:"envelope"`
}

type pypiFileEvidence struct {
	filename string
	ev       Evidence
	// signers is every identity a verified attestation of the file names, in
	// bundle order. ev carries the first; a file whose bundles name two must
	// not read as agreeing with whichever one sorted first.
	signers []audit.UpstreamProvenance
}

func (f pypiFileEvidence) identities() []audit.UpstreamProvenance {
	if len(f.signers) == 0 {
		return []audit.UpstreamProvenance{f.ev.UpstreamProvenance}
	}
	return f.signers
}

// Pypi verifies the PEP 740 attestations PyPI publishes for every file of
// name at version, read from the index root index (the verifier's own when
// empty).
//
// The JSON simple page says which files are of the version, their sha256, and
// where each one's provenance lives. Only a page that was read, parsed and
// lists the version with no provenance on any file is unavailable. A
// provenance object that could not be had, or a publisher kind bodega does not
// verify, is unknown. An attestation that was checked and failed, or one
// whose certificate binds a repository or workflow other than the publisher
// PyPI recorded at upload, is invalid. Files of one version that disagree
// with each other, some attested and some not or attested by different
// identities, are a mismatch.
func (v *Verifier) Pypi(ctx context.Context, index, name, version string) Evidence {
	index = strings.TrimRight(strings.TrimSpace(index), "/")
	if index == "" {
		index = strings.TrimRight(v.PypiIndex, "/")
	}
	indexRoot, err := url.Parse(index)
	if err != nil || indexRoot.Host == "" {
		return unknown("the pypi index root %q is not a URL, so whether %s %s publishes provenance is unknown", manifest.PublicURL(index), name, version)
	}
	page := indexRoot.JoinPath("simple", manifest.CanonicalPypiName(name)) // JoinPath drops the trailing slash PEP 503 wants.
	page.Path += "/"
	public := manifest.PublicURL(page.String())
	body, served, err := v.getWithin(ctx, page.String(), http.Header{"Accept": {pypiSimpleJSON}}, 32<<20, onIndex(indexRoot, indexRoot.Scheme == "https"))
	var off *offIndexError
	if errors.As(err, &off) {
		return unknown("the index page %s redirected to %s, which is not the index host %s; bodega reads pypi provenance from the configured index only, so it was not requested, and whether %s %s publishes provenance is unknown",
			public, off.where(), indexRoot.Host, name, version)
	}
	if err != nil {
		return unknown("the index page %s could not be read, so whether %s %s publishes provenance is unknown: %v", public, name, version, err)
	}
	var doc pypiPage
	if err := json.Unmarshal(body, &doc); err != nil {
		return unknown("the index page %s is not a PEP 691 JSON page, so whether %s %s publishes provenance is unknown: %v", public, name, version, err)
	}

	var withProvenance []int
	var without []string
	for i, f := range doc.Files {
		if !pypiSameVersion(pypiFileVersion(name, f.Filename), version) {
			continue
		}
		if f.Provenance == nil {
			without = append(without, f.Filename)
			continue
		}
		withProvenance = append(withProvenance, i)
	}
	if len(withProvenance) == 0 && len(without) == 0 {
		return unknown("the index page %s lists no file of %s %s, so whether it publishes provenance is unknown", public, name, version)
	}
	if len(withProvenance) == 0 {
		return unavailable("%s lists %d file(s) of %s %s, and PyPI publishes no attestation for any file of the version", public, len(without), name, version)
	}
	slices.SortFunc(withProvenance, func(a, b int) int { return strings.Compare(doc.Files[a].Filename, doc.Files[b].Filename) })
	slices.Sort(without)

	var tm root.TrustedMaterial
	var rootErr error
	trusted := func() (root.TrustedMaterial, error) {
		if tm == nil && rootErr == nil {
			tm, rootErr = v.Root(ctx)
		}
		return tm, rootErr
	}
	files := make([]pypiFileEvidence, 0, len(withProvenance))
	for _, i := range withProvenance {
		f := doc.Files[i]
		ev, signers := v.pypiFile(ctx, indexRoot, served, f.Filename, *f.Provenance, f.Hashes["sha256"], name, version, trusted)
		files = append(files, pypiFileEvidence{filename: f.Filename, ev: ev, signers: signers})
	}
	return pypiVersion(files, without, name, version)
}

// pypiVersion combines the files of one version: invalid over unknown over
// mismatch over verified, the first file in filename order deciding the
// detail.
func pypiVersion(files []pypiFileEvidence, without []string, name, version string) Evidence {
	for _, outcome := range []string{audit.ProvenanceInvalid, audit.ProvenanceUnknown} {
		for _, f := range files {
			if f.ev.Outcome == outcome {
				return f.ev
			}
		}
	}
	first := files[0].ev
	if len(without) > 0 {
		first.Outcome = audit.ProvenanceMismatch
		first.Detail = fmt.Sprintf("%s %s publishes provenance for %s, built by %s from %s, but not for %s; every file of a release built by the publisher's CI carries an attestation, so one without it was uploaded some other way",
			name, version, pypiFileNames(files), first.BuilderID, first.SourceRepositoryURI, strings.Join(without, ", "))
		return first
	}
	identities := map[string]bool{}
	var named []string
	for _, f := range files {
		for _, s := range f.identities() {
			id := PinnedBuilder(s.BuilderID) + " from " + s.SourceRepositoryURI
			if !identities[id] {
				identities[id] = true
				named = append(named, f.filename+": "+id)
			}
		}
	}
	if len(identities) > 1 {
		first.Outcome = audit.ProvenanceMismatch
		first.Detail = fmt.Sprintf("the files of %s %s were built by different identities: %s", name, version, strings.Join(named, "; "))
		return first
	}
	if len(files) > 1 {
		first.Detail += fmt.Sprintf(", for all %d files of the version", len(files))
	}
	return first
}

func pypiFileNames(files []pypiFileEvidence) string {
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = f.filename
	}
	return strings.Join(names, ", ")
}

// pypiFile verifies one file's provenance object. Alongside a verified
// file's evidence it returns the identity of every attestation in it.
func (v *Verifier) pypiFile(ctx context.Context, index, page *url.URL, filename, provenanceRef, sha256hex, name, version string,
	trusted func() (root.TrustedMaterial, error)) (Evidence, []audit.UpstreamProvenance) {
	ref, err := url.Parse(strings.TrimSpace(provenanceRef))
	if err != nil || strings.TrimSpace(provenanceRef) == "" {
		return unknown("%s names a provenance URL %q that does not parse, so whether it is attested is unknown", filename, manifest.PublicURL(provenanceRef)), nil
	}
	at := page.ResolveReference(ref)
	if at.Scheme != "https" || !sameHostPort(at, index) {
		return unknown("%s names its provenance at %s://%s, which is not the index host %s over https; bodega reads provenance from the configured index only, so it was not requested",
			filename, at.Scheme, at.Host, index.Host), nil
	}
	if at.User == nil {
		at.User = index.User
	}
	publicAt := manifest.PublicURL(at.String())
	digest, err := hex.DecodeString(strings.ToLower(sha256hex))
	if err != nil || len(digest) != sha256.Size {
		return unknown("%s publishes provenance, but the index page gives no sha256 for it, so the attestation subject cannot be checked", filename), nil
	}
	body, _, err := v.getWithin(ctx, at.String(), http.Header{"Accept": {pypiIntegrityJSON}}, 8<<20, onIndex(index, true))
	var off *offIndexError
	if errors.As(err, &off) {
		return unknown("%s publishes provenance at %s, which redirected to %s, not the index host %s over https; bodega reads provenance from the configured index only, so it was not requested",
			filename, publicAt, off.where(), index.Host), nil
	}
	if err != nil {
		return unknown("%s publishes provenance at %s, but it could not be read: %v", filename, publicAt, err), nil
	}
	var prov pypiProvenance
	if err := json.Unmarshal(body, &prov); err != nil {
		return unknown("%s publishes provenance at %s, but it is not a PEP 740 provenance object: %v", filename, publicAt, err), nil
	}
	if prov.Version != 1 {
		return unknown("%s's provenance object is version %d, and bodega reads version 1 only", filename, prov.Version), nil
	}
	if len(prov.AttestationBundles) == 0 {
		return unknown("%s's provenance object at %s holds no attestation bundle", filename, publicAt), nil
	}
	for _, b := range prov.AttestationBundles {
		for j, a := range b.Attestations {
			if a.Version != 1 {
				return unknown("%s attestation %d is version %d, and bodega reads version 1 only", filename, j, a.Version), nil
			}
		}
	}
	tm, err := trusted()
	if err != nil {
		return noRoot(err, "%s publishes provenance", filename), nil
	}

	sum := sha256.Sum256(body)
	var verified *Evidence
	var signers []audit.UpstreamProvenance
	var unknownKind *Evidence
	for i, b := range prov.AttestationBundles {
		pub := b.Publisher
		want, ok := pypiPublishers[pub.Kind]
		if !ok {
			if unknownKind == nil {
				ev := unknown("%s's attestation bundle %d names publisher kind %q, which bodega does not verify (it verifies GitHub and GitLab)", filename, i, pub.Kind)
				unknownKind = &ev
			}
			continue
		}
		workflow := ".github/workflows/" + pub.Workflow
		if pub.Kind == "GitLab" {
			workflow = "/" + pub.WorkflowFilepath
		}
		repo := want.forge + pub.Repository
		issuer := "^" + strings.ReplaceAll(want.issuer, ".", `\.`) + "$"
		if len(b.Attestations) == 0 {
			return invalid("%s's attestation bundle %d holds no attestation of predicate type %s or %s", filename, i, PyPIPublishV1, SLSAProvenanceV1), nil
		}
		for j, a := range b.Attestations {
			raw, err := pypiSigstoreBundle(a)
			if err != nil {
				return invalid("%s attestation %d is not a Sigstore attestation: %v", filename, j, err), nil
			}
			id, st, err := verifyBundle(tm, raw, issuer, "sha256", digest, builderFromSigner)
			if err != nil {
				return invalid("%s attestation %d did not verify: %v", filename, j, err), nil
			}
			if st.PredicateType != PyPIPublishV1 && st.PredicateType != SLSAProvenanceV1 {
				return invalid("%s attestation %d is of predicate type %q, not %s or %s", filename, j, st.PredicateType, PyPIPublishV1, SLSAProvenanceV1), nil
			}
			if len(st.Subject) != 1 || st.Subject[0].Name != filename || !strings.EqualFold(st.Subject[0].Digest["sha256"], sha256hex) {
				return invalid("%s attestation %d is a statement about something other than %s at sha256:%s", filename, j, filename, strings.ToLower(sha256hex)), nil
			}
			if !strings.EqualFold(id.SourceRepositoryURI, repo) || !signerNames(id.WorkflowRef, repo, workflow) {
				return invalid("%s attestation %d is signed by %s (%s), but PyPI names its %s publisher as %s workflow %s",
					filename, j, id.SourceRepositoryURI, id.WorkflowRef, pub.Kind, pub.Repository, strings.TrimPrefix(workflow, "/")), nil
			}
			id.Outcome = audit.ProvenanceVerified
			id.BundleDigest = "sha256:" + hex.EncodeToString(sum[:])
			signers = append(signers, id)
			if verified == nil {
				verified = &Evidence{UpstreamProvenance: id,
					Detail: "built by " + id.BuilderID + " from " + id.SourceRepositoryURI + ", as the " + pub.Kind + " publisher PyPI names"}
			}
		}
	}
	if unknownKind != nil {
		return *unknownKind, nil
	}
	return *verified, signers
}

// pypiSigstoreBundle assembles a Sigstore v0.3 bundle from a PEP 740
// attestation, which carries the same parts under its own names.
func pypiSigstoreBundle(a pypiAttestation) ([]byte, error) {
	if _, err := base64.StdEncoding.DecodeString(a.Envelope.Statement); err != nil {
		return nil, fmt.Errorf("the envelope's statement is not base64: %w", err)
	}
	entries := a.VerificationMaterial.TransparencyEntries
	if entries == nil {
		entries = []json.RawMessage{}
	}
	return json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate": map[string]string{"rawBytes": a.VerificationMaterial.Certificate},
			"tlogEntries": entries,
		},
		"dsseEnvelope": map[string]any{
			"payload":     a.Envelope.Statement,
			"payloadType": "application/vnd.in-toto+json",
			"signatures":  []map[string]string{{"sig": a.Envelope.Signature}},
		},
	})
}

// offIndexError is a redirect a pypi read refused to follow.
type offIndexError struct{ to *url.URL }

func (e *offIndexError) Error() string {
	return "refused a redirect to " + e.where() + ", off the index host"
}

func (e *offIndexError) where() string { return e.to.Scheme + "://" + e.to.Host }

// onIndex allows a redirect hop only to index's host and port, and only over
// https when httpsOnly is set, so a redirect can
// neither leave the index nor downgrade to plain http.
func onIndex(index *url.URL, httpsOnly bool) func(*url.URL) error {
	return func(to *url.URL) error {
		if (httpsOnly && to.Scheme != "https") || !sameHostPort(to, index) {
			return &offIndexError{to: to}
		}
		return nil
	}
}

// signerNames reports whether a build signer URI names workflow in repo, at
// whatever ref ran it. The repository compares case-insensitively, as forges
// resolve it; the workflow path does not.
func signerNames(signer, repo, workflow string) bool {
	want := repo + "/" + workflow + "@"
	if len(signer) <= len(want) {
		return false
	}
	return strings.EqualFold(signer[:len(repo)], repo) && signer[len(repo):len(want)] == "/"+workflow+"@"
}

// sameHostPort compares two URLs' hosts case-insensitively and their ports
// with the scheme's default filled in, so pypi.org and pypi.org:443 match.
func sameHostPort(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "http" {
			return "80"
		}
		return "443"
	}
	return strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

// pypiFileVersion places a file's version, knowing the project it is listed
// for: the name is stripped off the front under PEP 503 comparison, which
// splits a hyphenated project name a filename alone does not. A wheel's
// build and compatibility tags follow the version and are dropped. A file
// that is neither a wheel nor an sdist has no version here.
func pypiFileVersion(project, filename string) string {
	base, wheel := strings.CutSuffix(filename, ".whl")
	if !wheel {
		var ok bool
		for _, ext := range pypiSdistSuffixes {
			if base, ok = strings.CutSuffix(filename, ext); ok {
				break
			}
		}
		if !ok {
			return ""
		}
	}
	want := manifest.CanonicalPypiName(project)
	for i := 0; i < len(base); i++ {
		if base[i] != '-' || manifest.CanonicalPypiName(base[:i]) != want {
			continue
		}
		v := base[i+1:]
		if wheel {
			v, _, _ = strings.Cut(v, "-")
		}
		return v
	}
	return ""
}

// pypiSameVersion is PEP 440 equality, so 1.0 and 1.0.0 are one release.
func pypiSameVersion(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	av, aOK := manifest.ParsePyVersion(a)
	bv, bOK := manifest.ParsePyVersion(b)
	return aOK && bOK && av.Equal(bv)
}
