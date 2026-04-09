package builder

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/scaleapi/bodega/internal/manifest"
)

var descClient = &http.Client{Timeout: 10 * time.Second}

// FetchDescription tries to discover a short description for a package
// from its upstream registry. Returns empty string on failure.
func FetchDescription(entryType, name, url string) string {
	switch entryType {
	case manifest.TypeGit:
		return fetchGitHubDescription(name, url)
	case manifest.TypePypi:
		return fetchPyPIDescription(name)
	case manifest.TypeNpm:
		return fetchNpmDescription(name)
	case manifest.TypeGomod:
		return fetchGomodDescription(name)
	case manifest.TypeHelm:
		return fetchHelmDescription(name, url)
	}
	return ""
}

// fetchGitHubDescription queries the GitHub API for a repo description.
// Expects name as "owner/repo" or url as "https://github.com/owner/repo.git".
func fetchGitHubDescription(name, repoURL string) string {
	// Try to extract owner/repo from name or URL.
	ownerRepo := name
	if strings.Contains(repoURL, "github.com") {
		u := strings.TrimSuffix(repoURL, ".git")
		parts := strings.Split(u, "github.com/")
		if len(parts) == 2 {
			ownerRepo = strings.TrimSuffix(parts[1], "/")
		}
	}
	if ownerRepo == "" || !strings.Contains(ownerRepo, "/") {
		return ""
	}

	apiURL := "https://api.github.com/repos/" + ownerRepo
	resp, err := descClient.Get(apiURL)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	var result struct {
		Description string `json:"description"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if json.Unmarshal(body, &result) == nil {
		return result.Description
	}
	return ""
}

// fetchPyPIDescription queries the PyPI JSON API.
func fetchPyPIDescription(name string) string {
	// Normalize name: pip uses hyphens, PyPI API uses hyphens.
	normalized := strings.ReplaceAll(strings.ToLower(name), "_", "-")
	apiURL := "https://pypi.org/pypi/" + normalized + "/json"
	resp, err := descClient.Get(apiURL)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	var result struct {
		Info struct {
			Summary string `json:"summary"`
		} `json:"info"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if json.Unmarshal(body, &result) == nil {
		return result.Info.Summary
	}
	return ""
}

// fetchNpmDescription queries the npm registry.
func fetchNpmDescription(name string) string {
	apiURL := "https://registry.npmjs.org/" + name
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	resp, err := descClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	var result struct {
		Description string `json:"description"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if json.Unmarshal(body, &result) == nil {
		return result.Description
	}
	return ""
}

// fetchGomodDescription tries to get description from the Go module's source repo.
// Go proxy doesn't serve descriptions, so we check if it's a GitHub module.
func fetchGomodDescription(name string) string {
	if strings.HasPrefix(name, "github.com/") {
		parts := strings.SplitN(strings.TrimPrefix(name, "github.com/"), "/", 3)
		if len(parts) >= 2 {
			return fetchGitHubDescription(parts[0]+"/"+parts[1], "")
		}
	}
	return ""
}

// fetchHelmDescription tries the chart repo's index or the source URL.
func fetchHelmDescription(name, url string) string {
	// If URL points to GitHub, try the repo description.
	if strings.Contains(url, "github.com") {
		return fetchGitHubDescription("", url)
	}
	return ""
}

// DiscoverDescriptions fetches descriptions for all entries that don't have one yet.
// Called after fetch or on demand. Logs progress to out.
func DiscoverDescriptions(store *manifest.Store, out io.Writer) {
	for i := range store.Git {
		e := &store.Git[i]
		if e.Description == "" {
			if desc := FetchDescription(manifest.TypeGit, e.Name, e.URL); desc != "" {
				e.Description = desc
				fmt.Fprintf(out, "  [describe] git/%s: %s\n", e.Name, desc)
			}
		}
	}
	_ = store.SaveGit()

	for i := range store.Pypi.Packages {
		p := &store.Pypi.Packages[i]
		if p.Description == "" {
			if desc := FetchDescription(manifest.TypePypi, p.Name, ""); desc != "" {
				p.Description = desc
				fmt.Fprintf(out, "  [describe] pypi/%s: %s\n", p.Name, desc)
			}
		}
	}
	_ = store.SavePypi()

	for i := range store.Binary {
		e := &store.Binary[i]
		if e.Description == "" {
			if desc := FetchDescription(manifest.TypeBinary, e.Name, e.URL); desc != "" {
				e.Description = desc
				fmt.Fprintf(out, "  [describe] binary/%s: %s\n", e.Name, desc)
			}
		}
	}
	_ = store.SaveBinary()

	for i := range store.Gomod {
		e := &store.Gomod[i]
		if e.Description == "" {
			if desc := FetchDescription(manifest.TypeGomod, e.Name, e.URL); desc != "" {
				e.Description = desc
				fmt.Fprintf(out, "  [describe] gomod/%s: %s\n", e.Name, desc)
			}
		}
	}
	_ = store.SaveGomod()

	for i := range store.Helm {
		e := &store.Helm[i]
		if e.Description == "" {
			if desc := FetchDescription(manifest.TypeHelm, e.Name, e.URL); desc != "" {
				e.Description = desc
				fmt.Fprintf(out, "  [describe] helm/%s: %s\n", e.Name, desc)
			}
		}
	}
	_ = store.SaveHelm()

	for i := range store.Npm {
		e := &store.Npm[i]
		if e.Description == "" {
			if desc := FetchDescription(manifest.TypeNpm, e.Name, e.URL); desc != "" {
				e.Description = desc
				fmt.Fprintf(out, "  [describe] npm/%s: %s\n", e.Name, desc)
			}
		}
	}
	_ = store.SaveNpm()
}
