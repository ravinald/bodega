package provenance

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/klauspost/compress/snappy"

	"github.com/ravinald/bodega/internal/audit"
)

var githubIssuer = "^" + strings.ReplaceAll(issuerGitHubActions, ".", `\.`) + "$"

// GitHubRelease is a release asset on GitHub: the repository, the tag and
// the asset's file name.
type GitHubRelease struct {
	Owner, Repo, Tag, Asset string
}

// ParseReleaseAsset reads a release download URL under the verifier's GitHub
// host: <web>/<owner>/<repo>/releases/download/<tag>/<asset>.
func (v *Verifier) ParseReleaseAsset(raw string) (GitHubRelease, bool) {
	rest, ok := v.underGitHub(raw)
	if !ok {
		return GitHubRelease{}, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 6 || parts[2] != "releases" || parts[3] != "download" {
		return GitHubRelease{}, false
	}
	for _, p := range parts {
		if p == "" {
			return GitHubRelease{}, false
		}
	}
	return GitHubRelease{Owner: parts[0], Repo: parts[1], Tag: parts[4], Asset: parts[5]}, true
}

// ParseRepo reads a repository URL under the verifier's GitHub host:
// <web>/<owner>/<repo>, with or without ".git".
func (v *Verifier) ParseRepo(raw string) (owner, repo string, ok bool) {
	rest, ok := v.underGitHub(raw)
	if !ok {
		return "", "", false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimRight(rest, "/"), ".git"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (v *Verifier) underGitHub(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	web, err := url.Parse(v.GitHubWeb)
	if err != nil || !strings.EqualFold(u.Host, web.Host) || u.Scheme != web.Scheme {
		return "", false
	}
	return strings.TrimPrefix(u.Path, "/"), true
}

// ReleaseAssetDigest asks the release API for the sha256 GitHub recorded for
// an asset. Empty when the release lists the asset with no digest, as assets
// uploaded before GitHub began recording them are, or does not list it. An
// error is a lookup that failed, a missing release included: the asset's
// download comes from the same release, so a 404 here says the API could not
// be asked, not that the asset carries nothing.
func (v *Verifier) ReleaseAssetDigest(ctx context.Context, rel GitHubRelease) (string, error) {
	body, err := v.get(ctx, v.apiURL("repos", rel.Owner, rel.Repo, "releases", "tags", rel.Tag), githubHeaders(), 4<<20)
	if err != nil {
		return "", err
	}
	var doc struct {
		Assets []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("release %s/%s@%s is not JSON: %w", rel.Owner, rel.Repo, rel.Tag, err)
	}
	for _, a := range doc.Assets {
		if a.Name == rel.Asset {
			hexDigest, _ := strings.CutPrefix(a.Digest, "sha256:")
			return strings.ToLower(hexDigest), nil
		}
	}
	return "", nil
}

// PublishedSHA256 reads the SHA256SUMS a release publishes beside its assets
// and returns the line naming asset, or "" when the release publishes no such
// file (a 404) or none of its lines names asset. Any other failure to read
// one is an error, because "" would claim the release publishes nothing.
func (v *Verifier) PublishedSHA256(ctx context.Context, owner, repo, tag, asset string) (string, error) {
	for _, name := range []string{"SHA256SUMS", "sha256sums.txt"} {
		body, err := v.get(ctx, strings.TrimRight(v.GitHubWeb, "/")+"/"+owner+"/"+repo+"/releases/download/"+url.PathEscape(tag)+"/"+name, nil, 1<<20)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(body), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && len(f[0]) == 64 && path.Base(strings.TrimPrefix(f[1], "*")) == asset {
				return strings.ToLower(f[0]), nil
			}
		}
	}
	return "", nil
}

// GitHubAttestations verifies the SLSA provenance GitHub holds for an asset
// digest in owner/repo: what actions/attest records. A digest GitHub answers
// it holds no provenance for is unavailable. One whose provenance does not
// verify is invalid. A lookup that got no answer is unknown: a rate limit, an
// outage or a body that does not parse says nothing about whether the asset
// publishes provenance.
//
// GitHub's own release attestation (initiator "github") is a statement that
// the release is immutable, signed by GitHub rather than by the workflow that
// built the asset, and is not provenance; it is filtered out by predicate
// type.
func (v *Verifier) GitHubAttestations(ctx context.Context, owner, repo, sha256hex string) Evidence {
	digest, err := hex.DecodeString(sha256hex)
	if err != nil || len(digest) != 32 {
		return unknown("%q is not a sha256 digest, so the attestation lookup for %s/%s could not be made", sha256hex, owner, repo)
	}
	q := v.apiURL("repos", owner, repo, "attestations", "sha256:"+strings.ToLower(sha256hex)) + "?predicate_type=provenance"
	body, err := v.get(ctx, q, githubHeaders(), 8<<20)
	if errors.Is(err, errNotFound) {
		return unavailable("%s/%s publishes no attestation for sha256:%s", owner, repo, sha256hex)
	}
	if err != nil {
		return unknown("the attestation lookup for sha256:%s in %s/%s failed, so whether it carries provenance is unknown: %v", sha256hex, owner, repo, err)
	}
	var doc struct {
		Attestations []struct {
			Bundle    json.RawMessage `json:"bundle"`
			BundleURL string          `json:"bundle_url"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return unknown("the attestation lookup for sha256:%s in %s/%s failed: the answer is not JSON: %v", sha256hex, owner, repo, err)
	}
	var raws [][]byte
	for i, a := range doc.Attestations {
		raw, err := v.attestationBundle(ctx, a.Bundle, a.BundleURL)
		if err != nil {
			return unknown("%s/%s publishes attestation %d for sha256:%s, but it could not be read: %v", owner, repo, i, sha256hex, err)
		}
		if predicateTypeOf(raw) == SLSAProvenanceV1 {
			raws = append(raws, raw)
		}
	}
	if len(raws) == 0 {
		return unavailable("%s/%s publishes no SLSA provenance for sha256:%s", owner, repo, sha256hex)
	}
	tm, err := v.Root(ctx)
	if err != nil {
		return invalid("%s/%s publishes provenance for sha256:%s, and it was not verified: %v", owner, repo, sha256hex, err)
	}
	var verified *Evidence
	for i, raw := range raws {
		id, _, err := verifyBundle(tm, raw, githubIssuer, "sha256", digest)
		if err != nil {
			return invalid("%s/%s provenance bundle %d for sha256:%s did not verify: %v", owner, repo, i, sha256hex, err)
		}
		if verified == nil {
			id.Outcome = audit.ProvenanceVerified
			verified = &Evidence{UpstreamProvenance: id,
				Detail: "built by " + id.BuilderID + " from " + id.SourceRepositoryURI}
		}
	}
	return *verified
}

// attestationBundle is an attestation's bundle, inline or behind bundle_url.
// GitHub serves the second snappy-compressed.
func (v *Verifier) attestationBundle(ctx context.Context, inline json.RawMessage, bundleURL string) ([]byte, error) {
	if len(inline) > 0 && string(inline) != "null" {
		return inline, nil
	}
	if bundleURL == "" {
		return nil, errors.New("neither a bundle nor a bundle_url")
	}
	body, err := v.get(ctx, bundleURL, nil, 8<<20)
	if err != nil {
		return nil, err
	}
	if json.Valid(body) {
		return body, nil
	}
	return snappy.Decode(nil, body)
}

func (v *Verifier) apiURL(segments ...string) string {
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return strings.TrimRight(v.GitHubAPI, "/") + "/" + strings.Join(segments, "/")
}

func githubHeaders() http.Header {
	return http.Header{
		"Accept":               {"application/vnd.github+json"},
		"X-Github-Api-Version": {"2022-11-28"},
	}
}
