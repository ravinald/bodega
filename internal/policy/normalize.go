package policy

import (
	"net/url"
	"strings"
)

// normalizePyPI normalizes a PyPI package name per PEP 503: lowercase and
// collapse `_` to `-`. Enough for allow-list equality checks; does not handle
// the full PEP 503 regex (repeated `.`, `-`, `_` runs).
func normalizePyPI(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

// stripScheme returns the URL without any `://` prefix. Handles `https://`,
// `http://`, `git+https://`, `ssh://` etc. Inputs with no scheme are returned
// unchanged, which lets users write patterns like `github.com/org/`.
func stripScheme(u string) string {
	if idx := strings.Index(u, "://"); idx >= 0 {
		return u[idx+3:]
	}
	return u
}

// hostFromURL returns the hostname component of a URL. If the input isn't a
// parseable URL-with-host, the input is returned unchanged — this lets the
// caller still do a direct equality check when the rule pattern is itself a
// bare host (e.g. `archive.ubuntu.com`).
func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Hostname()
}
