package builder

import (
	"context"
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
	case manifest.TypeApt:
		return fetchAptDescription(name)
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

// DiscoverDescriptions fetches descriptions for all packages that don't have
// one yet. Called after fetch or on demand.
func DiscoverDescriptions(store *manifest.Store, out io.Writer) {
	ctx := context.Background()

	for _, typ := range manifest.AllTypes {
		for _, name := range store.ListPackages(typ) {
			pm, err := store.GetPackage(ctx, typ, name)
			if err != nil || pm == nil || pm.Description != "" {
				continue
			}

			// Find a URL from the first version entry to pass to FetchDescription.
			url := ""
			for _, ve := range pm.Versions {
				if ve.URL != "" {
					url = ve.URL
					break
				}
			}

			desc := FetchDescription(typ, name, url)
			if desc != "" {
				pm.Description = desc
				if err := store.SavePackage(ctx, pm); err == nil {
					fmt.Fprintf(out, "  [describe] %s/%s: %s\n", typ, name, desc)
				}
			}
		}
	}
}

// fetchAptDescription extracts the short description from `apt-cache show`.
func fetchAptDescription(name string) string {
	ve := FetchAptMetadata(name)
	if ve == nil {
		return ""
	}
	return ve.Description
}
