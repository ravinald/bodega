package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// The topology these tests exist for: a client speaks TLS to a proxy, the
// proxy speaks plaintext to bodega on loopback. r.TLS is nil on every request
// bodega sees and tls_cert/tls_key are empty, which is the state that made
// three separate sites report http:// for a deployment that is https
// everywhere a client can see.
//
// Fabricating X-Forwarded-Proto against a plain listener is what let the two
// earlier sweeps pass while leaving these open: the header is the symptom, the
// terminated connection is the condition. Here the header is set by a real
// httputil.ReverseProxy and the test client never writes it.

// terminatingProxy stands a TLS listener in front of a plaintext bodega and
// returns the client-facing base URL plus a client that trusts the proxy's
// certificate. Nothing in the test writes a forwarded header.
func terminatingProxy(t *testing.T, cfg *config.Config) (string, *http.Client) {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	backend := httptest.NewServer(
		server.New(cfg, store, storage.NewSingle(memStore(nil)), ":0", nil).Handler())
	t.Cleanup(backend.Close)

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			pr.Out.Header.Set("X-Real-IP", clientHost(pr.In.RemoteAddr))
		},
	}
	front := httptest.NewTLSServer(rp)
	t.Cleanup(front.Close)
	return front.URL, front.Client()
}

func clientHost(remoteAddr string) string {
	if i := strings.LastIndex(remoteAddr, ":"); i > 0 {
		return remoteAddr[:i]
	}
	return remoteAddr
}

type cargoConfigBody struct {
	DL  string `json:"dl"`
	API string `json:"api"`
}

func fetchCargoConfig(t *testing.T, base string, c *http.Client) (cargoConfigBody, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/cargo/config.json", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET /cargo/config.json: %v", err)
	}
	defer resp.Body.Close()
	var body cargoConfigBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode cargo config: %v", err)
	}
	return body, resp.Header
}

// TestTerminatingProxyCargoConfig is the defect in its own topology: cargo
// consumes these URLs rather than showing them, so a plaintext dl means every
// crate download leaves TLS on a deployment the operator believes is https.
func TestTerminatingProxyCargoConfig(t *testing.T) {
	base, client := terminatingProxy(t, &config.Config{})
	body, _ := fetchCargoConfig(t, base, client)
	for name, got := range map[string]string{"dl": body.DL, "api": body.API} {
		if !strings.HasPrefix(got, "https://") {
			t.Errorf("cargo %s = %q, want an https:// URL behind a terminating proxy", name, got)
		}
	}
	if !strings.HasSuffix(body.DL, "/cargo/{crate}/{version}/download") {
		t.Errorf("cargo dl = %q, want the download template preserved", body.DL)
	}
}

// TestTerminatingProxyPublicURLOutranks pins the requirement-1 chain: only the
// operator knows the hostname the proxy publishes, so public_url beats both
// the forwarded header and the request's own Host.
func TestTerminatingProxyPublicURLOutranks(t *testing.T) {
	base, client := terminatingProxy(t, &config.Config{PublicURL: "https://bodega.example.com/"})
	body, _ := fetchCargoConfig(t, base, client)
	want := "https://bodega.example.com/cargo/{crate}/{version}/download"
	if body.DL != want {
		t.Errorf("cargo dl = %q, want %q", body.DL, want)
	}
	if body.API != "https://bodega.example.com/cargo" {
		t.Errorf("cargo api = %q, want the public_url origin", body.API)
	}
}

// TestTerminatingProxyHSTS covers requirement 2. The documented deployment is
// https to every client, so it gets the header the docs promise; gating on
// r.TLS sent it to nobody there.
func TestTerminatingProxyHSTS(t *testing.T) {
	base, client := terminatingProxy(t, &config.Config{})
	_, hdr := fetchCargoConfig(t, base, client)
	hsts := hdr.Get("Strict-Transport-Security")
	if hsts == "" {
		t.Fatal("no Strict-Transport-Security behind a TLS-terminating proxy")
	}
	if !strings.Contains(hsts, "max-age=") {
		t.Errorf("HSTS missing max-age: %q", hsts)
	}
}

// TestUntrustedPeerCannotForgeScheme is the assertion the header must not cost
// us: X-Forwarded-Proto from a peer outside trusted_proxies decides nothing.
// The test client writes the header itself here, which is the point — that is
// what an untrusted client does.
func TestUntrustedPeerCannotForgeScheme(t *testing.T) {
	cfg := &config.Config{TrustedProxies: []string{"192.0.2.0/24"}}
	store := manifest.NewLocalStore(t.TempDir())
	ts := httptest.NewServer(
		server.New(cfg, store, storage.NewSingle(memStore(nil)), ":0", nil).Handler())
	t.Cleanup(ts.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/cargo/config.json", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /cargo/config.json: %v", err)
	}
	defer resp.Body.Close()
	var body cargoConfigBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode cargo config: %v", err)
	}
	if !strings.HasPrefix(body.DL, "http://") {
		t.Errorf("cargo dl = %q, want http:// for a forged header from an untrusted peer", body.DL)
	}
	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS = %q from an untrusted peer's forged X-Forwarded-Proto, want none", hsts)
	}
}

// TestLocalTLSStillSendsHSTS keeps the case that already worked: bodega
// terminating TLS itself is still https to the client.
func TestLocalTLSStillSendsHSTS(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ts := httptest.NewTLSServer(
		server.New(&config.Config{}, store, storage.NewSingle(memStore(nil)), ":0", nil).Handler())
	t.Cleanup(ts.Close)
	client := ts.Client()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/cargo/config.json", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /cargo/config.json: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS on a listener terminating TLS itself")
	}
	var body cargoConfigBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode cargo config: %v", err)
	}
	if !strings.HasPrefix(body.DL, "https://") {
		t.Errorf("cargo dl = %q, want https:// on a TLS listener", body.DL)
	}
}
