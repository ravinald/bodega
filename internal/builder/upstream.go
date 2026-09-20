package builder

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"
)

var upstreamClient = &http.Client{Timeout: 30 * time.Second}

// DiscoverPyPIVersions queries PyPI for all available versions of a package.
func DiscoverPyPIVersions(name string) ([]string, error) {
	return pypiVersionsAt(defaultPypiIndex, name)
}

// pypiResponseMax caps how much of a distribution's JSON document the resolver
// will read. Every explicit pin now depends on this call, so the cap has to
// clear a real package history rather than a discovery-sized sample: numpy's
// response measured 3,672,920 bytes and pandas' 2,130,480 bytes on 2026-09-15.
// Memory stays flat regardless, because the document is decoded as a stream.
const pypiResponseMax = 64 << 20

// jsonMaxDepth bounds the recursion of skipJSONValue. An index that answers
// with a million-deep array is not a document worth a stack overflow.
const jsonMaxDepth = 64

// pypiVersionsAt reads a distribution's releases from the JSON API under root,
// sorted ascending, keeping only the releases that still offer a file to
// download.
//
// The JSON API rather than the PEP 503 document under /simple/: a constraint is
// resolved against versions, and the simple index names files, so reading it
// means parsing a version back out of every wheel and sdist filename.
func pypiVersionsAt(root, name string) ([]string, error) {
	normalized := strings.ReplaceAll(strings.ToLower(name), "_", "-")
	url := strings.TrimRight(root, "/") + "/pypi/" + normalized + "/json"
	resp, err := upstreamClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("query pypi: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("pypi returned %d for %s", resp.StatusCode, name)
	}

	limited := &io.LimitedReader{R: resp.Body, N: pypiResponseMax + 1}
	versions, err := decodePypiReleases(json.NewDecoder(limited))
	if err != nil {
		// Reading past the cap truncates mid-document, and the decoder reports
		// that as malformed JSON. Say which it was: one is an index to fix, the
		// other is a limit to raise.
		if limited.N <= 0 {
			return nil, fmt.Errorf("pypi response for %s exceeds %d bytes", name, int64(pypiResponseMax))
		}
		return nil, fmt.Errorf("parse pypi response: %w", err)
	}
	SortPyVersions(versions)
	return versions, nil
}

// decodePypiReleases walks the JSON API document for one distribution and
// returns the versions that offer at least one downloadable file.
//
// Streamed rather than unmarshaled: the "info" block and the per-file metadata
// of a large distribution run to megabytes, and the resolver needs one string
// per release out of all of it.
func decodePypiReleases(dec *json.Decoder) ([]string, error) {
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if key != "releases" {
			if err := skipJSONValue(dec, 0); err != nil {
				return nil, err
			}
			continue
		}
		return decodePypiReleaseMap(dec)
	}
	return nil, nil
}

// decodePypiReleaseMap reads the "releases" object, dropping every release
// whose file list is empty. PyPI keeps the key of a deleted release and empties
// its array, so accepting the key alone resolves a pin to something pip cannot
// download and pushes the failure into the wheel build minutes later.
func decodePypiReleaseMap(dec *json.Decoder) ([]string, error) {
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	var versions []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		version, _ := t.(string)
		files, err := countPypiReleaseFiles(dec)
		if err != nil {
			return nil, err
		}
		if files > 0 {
			versions = append(versions, version)
		}
	}
	_, err := dec.Token()
	return versions, err
}

// countPypiReleaseFiles counts the entries of one release's file array without
// materializing any of them.
func countPypiReleaseFiles(dec *json.Decoder) (int, error) {
	t, err := dec.Token()
	if err != nil {
		return 0, err
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return 0, skipAfterToken(dec, t, 0)
	}
	count := 0
	for dec.More() {
		if err := skipJSONValue(dec, 1); err != nil {
			return 0, err
		}
		count++
	}
	_, err = dec.Token()
	return count, err
}

// skipJSONValue consumes one value from dec without materializing it.
// json.RawMessage would buffer the whole value, which for a popular
// distribution's "info" block is the thing being avoided.
func skipJSONValue(dec *json.Decoder, depth int) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	return skipAfterToken(dec, t, depth)
}

// skipAfterToken finishes skipping a value whose opening token is already read.
func skipAfterToken(dec *json.Decoder, t json.Token, depth int) error {
	d, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= jsonMaxDepth {
		return fmt.Errorf("json nested deeper than %d levels", jsonMaxDepth)
	}
	for dec.More() {
		if d == '{' {
			if _, err := dec.Token(); err != nil {
				return err
			}
		}
		if err := skipJSONValue(dec, depth+1); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != want {
		return fmt.Errorf("want %q at the start of the document, got %v", want, t)
	}
	return nil
}

// DiscoverGomodVersions queries the Go module proxy for available versions.
func DiscoverGomodVersions(name string) ([]string, error) {
	url := "https://proxy.golang.org/" + name + "/@v/list"
	resp, err := upstreamClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("query goproxy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("goproxy returned %d for %s", resp.StatusCode, name)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	var versions []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			versions = append(versions, line)
		}
	}
	sortVersions(versions)
	return versions, nil
}

// DiscoverNpmVersions queries the npm registry for available versions.
func DiscoverNpmVersions(name string) ([]string, error) {
	url := "https://registry.npmjs.org/" + name
	resp, err := upstreamClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("query npm: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("npm returned %d for %s", resp.StatusCode, name)
	}

	var result struct {
		Versions map[string]interface{} `json:"versions"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse npm response: %w", err)
	}

	versions := make([]string, 0, len(result.Versions))
	for v := range result.Versions {
		versions = append(versions, v)
	}
	sortVersions(versions)
	return versions, nil
}

// DiscoverHelmVersions parses a Helm chart repo's index.yaml for available versions.
func DiscoverHelmVersions(name, repoURL string) ([]string, error) {
	indexURL := strings.TrimSuffix(repoURL, "/") + "/index.yaml"
	resp, err := upstreamClient.Get(indexURL)
	if err != nil {
		return nil, fmt.Errorf("fetch helm index: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("helm repo returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	// Simple YAML parsing: look for "version:" lines under the chart name entry.
	// Full YAML parsing would require a dependency; this handles the common format.
	var versions []string
	inChart := false
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, name+":") {
			inChart = true
			continue
		}
		if inChart && strings.HasPrefix(trimmed, "- version:") {
			ver := strings.TrimSpace(strings.TrimPrefix(trimmed, "- version:"))
			ver = strings.Trim(ver, "\"'")
			if ver != "" {
				versions = append(versions, ver)
			}
		}
		if inChart && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && trimmed != "" {
			inChart = false
		}
	}
	sortVersions(versions)
	return versions, nil
}

// DiscoverGitRefs queries a git remote for available tags/refs.
func DiscoverGitRefs(url string) ([]string, error) {
	out, err := exec.Command("git", "ls-remote", "--tags", "--refs", url).Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-remote: %w", err)
	}

	var refs []string
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		ref := parts[1]
		ref = strings.TrimPrefix(ref, "refs/tags/")
		refs = append(refs, ref)
	}
	sortVersions(refs)
	return refs, nil
}

// sortVersions sorts version strings by semver when possible, falling back to lexicographic.
func sortVersions(versions []string) {
	sort.Slice(versions, func(i, j int) bool {
		a, aOK := ParseSemVer(versions[i])
		b, bOK := ParseSemVer(versions[j])
		if aOK && bOK {
			return a.Less(b)
		}
		return versions[i] < versions[j]
	})
}
