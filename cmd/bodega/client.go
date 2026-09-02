package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
)

// Client talks to a running bodega over its mutation API.
//
// It exists so a catalog can be pushed from the host it was read on. bodega's
// verbs otherwise write the manifest store in-process, which requires the
// store: the host being cataloged has no bucket, no manifest directory and no
// audit database, and demanding them there would defeat the workflow.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// NewClient validates the target and refuses one that would leak credentials.
//
// A bearer token over plaintext http is readable by anything on the path, so
// the combination is refused rather than warned about. allowPlaintext is the
// deliberate override, matching what the server itself demands to serve
// without TLS.
func NewClient(rawURL, token string, allowPlaintext bool) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("--server %q does not parse as a URL: %w", rawURL, err)
	}
	switch {
	case u.Host == "":
		return nil, fmt.Errorf("--server %q names no host; write it as https://bodega.example:8080", rawURL)
	case u.Scheme == "https":
	case u.Scheme == "http":
		if token != "" && !allowPlaintext {
			return nil, fmt.Errorf("refusing to send a bearer token to %s over plaintext http: "+
				"anything on the path can read it. Use https, or pass --allow-plaintext if this is a trusted link", u.Host)
		}
		if !allowPlaintext {
			return nil, fmt.Errorf("refusing plaintext http to %s: use https, or pass --allow-plaintext", u.Host)
		}
	default:
		return nil, fmt.Errorf("--server scheme %q is not http or https", u.Scheme)
	}

	return &Client{
		BaseURL: strings.TrimRight(rawURL, "/"),
		Token:   token,
		// A host catalog is thousands of packages and the server admits each
		// one through the policy checks, so the ceiling is generous.
		HTTP: &http.Client{Timeout: 10 * time.Minute},
	}, nil
}

// Import pushes manifests to POST /api/v1/packages/import and returns what the
// server did with each one.
func (c *Client) Import(pms []manifest.PackageManifest, merge bool) (*server.ImportResponse, error) {
	body, err := json.Marshal(pms)
	if err != nil {
		return nil, fmt.Errorf("encode manifests: %w", err)
	}

	endpoint := c.BaseURL + "/api/v1/packages/import"
	if merge {
		endpoint += "?merge=true"
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w\nCheck the server is running and reachable from this host", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server refused the import: %s\n%s", resp.Status, serverError(payload))
	}

	var out server.ImportResponse
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &out, nil
}

// serverError pulls the message out of bodega's error envelope, falling back
// to the raw body so a proxy's HTML error page is still readable.
func serverError(payload []byte) string {
	var envelope struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(payload, &envelope); err == nil && envelope.Error != "" {
		return envelope.Error
	}
	text := strings.TrimSpace(string(payload))
	if len(text) > 500 {
		text = text[:500] + "..."
	}
	return text
}
