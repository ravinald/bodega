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
	normalized := strings.ReplaceAll(strings.ToLower(name), "_", "-")
	url := "https://pypi.org/pypi/" + normalized + "/json"
	resp, err := upstreamClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("query pypi: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("pypi returned %d for %s", resp.StatusCode, name)
	}

	var result struct {
		Releases map[string]interface{} `json:"releases"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse pypi response: %w", err)
	}

	versions := make([]string, 0, len(result.Releases))
	for v := range result.Releases {
		versions = append(versions, v)
	}
	sortVersions(versions)
	return versions, nil
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
