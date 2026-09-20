package policy

import (
	"net/url"
	"strings"
)

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
