package hostpkg

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/ravinald/bodega/internal/manifest"
)

// ParseHelm converts 'helm list -o json'.
//
// It is the one importer that cannot produce a complete entry. A helm release
// records the chart it was installed from ("nginx-18.2.4") but not the
// repository that chart came from, and bodega's helm entries resolve upstream
// per version rather than from a flat registry key. So the chart name and
// version are recovered and the URL is left empty for an operator to fill in,
// with a warning naming the command that answers it. Guessing a repository
// would put a URL nothing verified into a supply-chain catalog.
func ParseHelm(r io.Reader) (Result, error) {
	var releases []struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Chart     string `json:"chart"`
	}
	if err := json.NewDecoder(r).Decode(&releases); err != nil {
		return Result{}, fmt.Errorf("parse helm list: %w\nexpected JSON: helm list -o json", err)
	}
	var res Result
	seen := map[string]bool{}
	for _, rel := range releases {
		name, version := splitChart(rel.Chart)
		if name == "" {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"release %q names chart %q, which has no recoverable name and version", rel.Name, rel.Chart))
			continue
		}
		if seen[name+"@"+version] {
			continue
		}
		seen[name+"@"+version] = true
		res.Packages = append(res.Packages, pkg(manifest.TypeHelm, name, version, "", registryMode))
	}
	if len(res.Packages) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%d helm entr(ies) have no url: a release does not record which repository its chart came from. "+
				"Fill each url in before importing, or run 'helm search repo <chart> -o json' to resolve them",
			len(res.Packages)))
	}
	sortPackages(res.Packages)
	return res, nil
}

// splitChart recovers a chart's name and version from the single field helm
// reports them in. The separator is the last hyphen whose right side starts
// with a digit, because chart names contain hyphens too:
// "kube-prometheus-stack-62.7.0" is one name and one version, not four.
func splitChart(chart string) (name, version string) {
	for i := len(chart) - 1; i > 0; i-- {
		if chart[i] != '-' {
			continue
		}
		rest := chart[i+1:]
		if rest != "" && unicode.IsDigit(rune(rest[0])) {
			return chart[:i], rest
		}
	}
	if strings.TrimSpace(chart) == "" {
		return "", ""
	}
	return chart, ""
}
