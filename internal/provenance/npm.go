package provenance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
)

// npmIssuers are the CI identities npm accepts provenance from.
var npmIssuers = "^(" + strings.ReplaceAll(issuerGitHubActions, ".", `\.`) + "|" + strings.ReplaceAll(issuerGitLab, ".", `\.`) + ")$"

// Npm verifies the provenance npm publishes for name@version, read from the
// registry root registry (the verifier's own when empty).
//
// The packument says whether provenance exists (dist.attestations) and what
// the tarball's sha512 is (dist.integrity). Only a packument that was read,
// parsed and lists the version without dist.attestations is unavailable.
// Every other failure is invalid: a packument that could not be read cannot
// say provenance is absent, and a version that publishes provenance never
// passes because the bundle could not be fetched or there was no trusted root
// to check it against.
//
// The attestations document also carries npm's own publish attestation,
// signed by the registry's key rather than a CI identity. It says the
// registry accepted an upload, not who built it, and is not read here.
func (v *Verifier) Npm(ctx context.Context, registry, name, version string) Evidence {
	registry = strings.TrimRight(strings.TrimSpace(registry), "/")
	if registry == "" {
		registry = v.NpmRegistry
	}
	body, err := v.get(ctx, registry+"/"+name, nil, 32<<20)
	if err != nil {
		return invalid("the packument lookup for %s failed, so whether %s@%s publishes provenance is unknown: %v", name, name, version, err)
	}
	var doc packument
	if err := json.Unmarshal(body, &doc); err != nil {
		return invalid("the packument lookup for %s failed: the answer is not JSON, so whether %s@%s publishes provenance is unknown: %v", name, name, version, err)
	}
	ev := v.npmVersion(ctx, registry, name, version, &doc)
	ev.Published = make(map[string]time.Time, len(doc.Time))
	for ver, at := range doc.Time {
		if t, err := time.Parse(time.RFC3339Nano, at); err == nil {
			ev.Published[ver] = t
		}
	}
	if t, ok := ev.Published[version]; ok {
		ev.PublishedAt = &t
	}
	return ev
}

// packument is the part of an npm packument the check reads. Time maps each
// version to when it was published, beside the "created" and "modified" keys,
// and keeps a version's time after the version itself is unpublished.
type packument struct {
	Versions map[string]struct {
		Dist struct {
			Integrity    string `json:"integrity"`
			Attestations *struct {
				URL        string `json:"url"`
				Provenance *struct {
					PredicateType string `json:"predicateType"`
				} `json:"provenance"`
			} `json:"attestations"`
		} `json:"dist"`
	} `json:"versions"`
	Time map[string]string `json:"time"`
}

func (v *Verifier) npmVersion(ctx context.Context, registry, name, version string, doc *packument) Evidence {
	ver, ok := doc.Versions[version]
	if !ok {
		return invalid("the packument for %s lists no version %s, so whether it publishes provenance is unknown", name, version)
	}
	att := ver.Dist.Attestations
	if att == nil || att.Provenance == nil {
		return unavailable("%s@%s publishes no provenance (no dist.attestations.provenance in the packument)", name, version)
	}
	integrity, err := sha512Integrity(ver.Dist.Integrity)
	if err != nil {
		return invalid("%s@%s publishes provenance, but %v, so its subject cannot be checked", name, version, err)
	}
	if strings.HasPrefix(att.URL, "/") {
		att.URL = registry + att.URL
	}
	body, err := v.get(ctx, att.URL, nil, 8<<20)
	if err != nil {
		return invalid("%s@%s publishes provenance, but its bundles could not be read: %v", name, version, err)
	}
	var bundles struct {
		Attestations []struct {
			PredicateType string          `json:"predicateType"`
			Bundle        json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(body, &bundles); err != nil {
		return invalid("%s@%s publishes provenance, but %s is not an attestations document: %v", name, version, att.URL, err)
	}
	tm, err := v.Root(ctx)
	if err != nil {
		return invalid("%s@%s publishes provenance, and it was not verified: %v", name, version, err)
	}

	var verified *Evidence
	for i, a := range bundles.Attestations {
		if a.PredicateType != SLSAProvenanceV1 && a.PredicateType != SLSAProvenanceV02 {
			continue
		}
		id, st, err := verifyBundle(tm, a.Bundle, npmIssuers, "sha512", integrity)
		if err != nil {
			return invalid("%s@%s provenance bundle %d did not verify: %v", name, version, i, err)
		}
		want := npmPURL(name, version)
		if !subjectNamed(st, want) {
			return invalid("%s@%s provenance bundle %d names a subject other than %s", name, version, i, want)
		}
		if verified == nil {
			id.Outcome = audit.ProvenanceVerified
			verified = &Evidence{UpstreamProvenance: id,
				Detail: "built by " + id.BuilderID + " from " + id.SourceRepositoryURI + " (" + id.WorkflowRef + ")"}
		}
	}
	if verified == nil {
		return invalid("%s@%s declares %s provenance, but %s holds no SLSA provenance bundle", name, version, att.Provenance.PredicateType, att.URL)
	}
	return *verified
}

// sha512Integrity decodes a Subresource Integrity string's sha512 digest.
// npm's integrity may list several algorithms; the provenance subject is
// sha512, so that is the one compared.
func sha512Integrity(sri string) ([]byte, error) {
	for _, f := range strings.Fields(sri) {
		b64, ok := strings.CutPrefix(f, "sha512-")
		if !ok {
			continue
		}
		if i := strings.IndexByte(b64, '?'); i >= 0 {
			b64 = b64[:i]
		}
		d, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(d) != 64 {
			return nil, errors.New("dist.integrity's sha512 is malformed")
		}
		return d, nil
	}
	return nil, errors.New("the packument carries no sha512 dist.integrity")
}

// npmPURL is the subject name npm's provenance gives a version, with the
// scope's "@" percent-encoded as the purl spec requires.
func npmPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		name = "%40" + name[1:]
	}
	return "pkg:npm/" + name + "@" + version
}

func subjectNamed(st *statement, want string) bool {
	norm := func(s string) string {
		if u, err := url.PathUnescape(s); err == nil {
			return u
		}
		return s
	}
	for _, s := range st.Subject {
		if norm(s.Name) == norm(want) {
			return true
		}
	}
	return false
}
