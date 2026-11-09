package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// allowLoopbackHost lets the guard pass any URL whose host is 127.0.0.1,
// userinfo included, which allowLoopbackUpstreams' prefix match refuses.
func allowLoopbackHost(t *testing.T) {
	t.Helper()
	saved := upstreamGuard
	upstreamGuard = func(rawURL string) error {
		if u, err := url.Parse(rawURL); err == nil && u.Hostname() == "127.0.0.1" {
			return nil
		}
		return saved(rawURL)
	}
	t.Cleanup(func() { upstreamGuard = saved })
}

// blackholeDials makes every upstream connect wait out upstream_connect_timeout
// and fail as net.Dialer does then. A SYN nobody answers is the real case, and
// no address drops one on every host the suite runs on.
func blackholeDials(t *testing.T, timeout time.Duration) {
	t.Helper()
	savedTimeout := upstreamConnectTimeout.Load()
	savedDial := upstreamTransport.DialContext
	upstreamConnectTimeout.Store(int64(timeout))
	upstreamTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		timer := time.NewTimer(time.Duration(upstreamConnectTimeout.Load()))
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil, &net.OpError{Op: "dial", Net: network, Err: os.ErrDeadlineExceeded}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	t.Cleanup(func() {
		upstreamConnectTimeout.Store(savedTimeout)
		upstreamTransport.DialContext = savedDial
	})
}

func closedLoopbackURL(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.NotFoundHandler())
	ts.Close()
	return ts.URL
}

// TestUnreachableUpstreamBodyNamesHostAndCause is B192: the 502 for an
// upstream bodega could not read names the host and the cause class, and
// carries nothing from the error text or the URL past host and port.
func TestUnreachableUpstreamBodyNamesHostAndCause(t *testing.T) {
	answering503 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down for maintenance", http.StatusServiceUnavailable)
	}))
	t.Cleanup(answering503.Close)
	host503 := strings.TrimPrefix(answering503.URL, "http://")

	closed := closedLoopbackURL(t)
	closedHost := strings.TrimPrefix(closed, "http://")
	secretURL := "http://user:secret@" + closedHost + "/maven2/private/path.jar?token=tok123"

	for _, c := range []struct {
		name      string
		resolve   upstreamResolver
		prep      func(*testing.T)
		wantHead  string
		wantHost  string
		wantClass string
		absent    []string
	}{
		{
			name: "resolver DNS failure",
			resolve: func(context.Context) (string, error) {
				dns := &net.DNSError{Err: "no such host", Name: "pypi.org", IsNotFound: true}
				return "", fmt.Errorf("cannot resolve upstream host %q: %w", "pypi.org", dns)
			},
			wantHead: "upstream resolution failed", wantHost: "pypi.org", wantClass: "DNS lookup failed",
			absent: []string{"no such host"},
		},
		{
			name:     "closed port",
			resolve:  func(context.Context) (string, error) { return closed + "/maven2/a.jar", nil },
			wantHead: "upstream fetch failed", wantHost: closedHost, wantClass: "connection refused",
			absent: []string{"/maven2/a.jar", "dial tcp"},
		},
		{
			name:     "past the connect timeout",
			resolve:  func(context.Context) (string, error) { return answering503.URL + "/maven2/a.jar", nil },
			prep:     func(t *testing.T) { blackholeDials(t, 50*time.Millisecond) },
			wantHead: "upstream fetch failed", wantHost: host503, wantClass: "timed out",
			absent: []string{"i/o timeout", "/maven2/a.jar"},
		},
		{
			name:     "upstream answers 503",
			resolve:  func(context.Context) (string, error) { return answering503.URL + "/maven2/a.jar", nil },
			wantHead: "upstream fetch failed", wantHost: host503, wantClass: "upstream answered HTTP 503 Service Unavailable",
			absent: []string{"down for maintenance", "/maven2/a.jar"},
		},
		{
			name:     "userinfo in the upstream URL",
			resolve:  func(context.Context) (string, error) { return secretURL, nil },
			wantHead: "upstream fetch failed", wantHost: closedHost, wantClass: "connection refused",
			absent: []string{"secret", "user", "token", "tok123", "/maven2/private"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := notFoundServer(t, storage.NewMemory(), "http://127.0.0.1:1")
			allowLoopbackHost(t)
			if c.prep != nil {
				c.prep(t)
			}
			var logs bytes.Buffer
			s.logger = slog.New(slog.NewTextHandler(&logs, nil))

			store := s.typeStore(manifest.TypeMaven)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/maven/"+markerJar, nil)
			s.proxyOrResolve(rec, req, store, manifest.MavenKey(markerJar), c.resolve, "", nil, manifest.TypeMaven, "", "", true, false)

			body := rec.Body.String()
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502 (body %q)", rec.Code, body)
			}
			if !strings.HasPrefix(body, c.wantHead+": "+c.wantHost+": "+c.wantClass+". ") {
				t.Errorf("body = %q, want it to open %q", body, c.wantHead+": "+c.wantHost+": "+c.wantClass+".")
			}
			if !strings.Contains(body, "retry once it is back") {
				t.Errorf("body = %q, want it to end on the next step", body)
			}
			for _, a := range c.absent {
				if strings.Contains(body, a) {
					t.Errorf("body = %q carries %q", body, a)
				}
			}
			if !strings.Contains(logs.String(), "error=") {
				t.Errorf("log carries no error field: %s", logs.String())
			}
		})
	}
}

func TestHostPortFillsTheSchemePort(t *testing.T) {
	for raw, want := range map[string]string{
		"https://u:p@pypi.org/simple/x/?q=1": "pypi.org:443",
		"http://mirror.example/a":            "mirror.example:80",
		"https://[2001:db8::1]:8443/a":       "[2001:db8::1]:8443",
		"":                                   "",
	} {
		if got := hostPort(raw); got != want {
			t.Errorf("hostPort(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestB192ReviewPypiIndexReadFailureNamesHost(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("short"))
	}))
	t.Cleanup(up.Close)
	s := proxyingServer(t)
	s.cfg.PypiUpstream = up.URL
	seedProxyPypi(t, s, "six", up.URL)
	status, body := getStatusAndBody(t, s, "/pypi/wheels/"+testWheel)
	if status != http.StatusBadGateway || !strings.Contains(body, hostPort(up.URL)+": unreachable.") {
		t.Fatalf("status=%d body=%q; want index host and unreachable", status, body)
	}
}

func TestB192ReviewFallbackGuardFailureNamesHost(t *testing.T) {
	up := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(up.Close)
	s := notFoundServer(t, storage.NewMemory(), up.URL)
	saved := upstreamLookupHost
	upstreamLookupHost = func(host string) ([]string, error) {
		if host == "mirror.example" {
			return nil, &net.DNSError{Name: host, Err: "no such host", IsNotFound: true}
		}
		return saved(host)
	}
	t.Cleanup(func() { upstreamLookupHost = saved })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/maven/"+markerJar, nil)
	resolve := func(context.Context) (string, error) { return up.URL + "/a.jar", nil }
	order := &upstreamOrder{fallbacks: []string{"https://mirror.example:8443/a.jar"}}
	s.proxyOrResolve(rec, req, s.typeStore(manifest.TypeMaven), manifest.MavenKey(markerJar), resolve, "", order, manifest.TypeMaven, "", "", true, false)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "mirror.example:8443: DNS lookup failed.") {
		t.Fatalf("status=%d body=%q; want mirror.example:8443 and DNS lookup failed", rec.Code, rec.Body.String())
	}
}

func TestB192ReviewRedirectStatusNamesAnsweringHost(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(target.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/a.jar", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
	s := notFoundServer(t, storage.NewMemory(), redirector.URL)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/maven/"+markerJar, nil)
	resolve := func(context.Context) (string, error) { return redirector.URL + "/a.jar", nil }
	s.proxyOrResolve(rec, req, s.typeStore(manifest.TypeMaven), manifest.MavenKey(markerJar), resolve, "", nil, manifest.TypeMaven, "", "", true, false)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(target.URL)+": upstream answered HTTP 503 Service Unavailable.") {
		t.Fatalf("status=%d body=%q; want answering host %s and HTTP 503", rec.Code, rec.Body.String(), hostPort(target.URL))
	}
}

func TestB192ReviewPypiDNSFailurePreservesPort(t *testing.T) {
	s := proxyingServer(t)
	s.cfg.PypiUpstream = "https://pypi.example:8443"
	seedProxyPypi(t, s, "six", s.cfg.PypiUpstream)
	saved := upstreamLookupHost
	upstreamLookupHost = func(host string) ([]string, error) {
		if host == "pypi.example" {
			return nil, &net.DNSError{Name: host, Err: "no such host", IsNotFound: true}
		}
		return saved(host)
	}
	t.Cleanup(func() { upstreamLookupHost = saved })
	status, body := getStatusAndBody(t, s, "/pypi/wheels/"+testWheel)
	if status != http.StatusBadGateway || !strings.Contains(body, "pypi.example:8443: DNS lookup failed.") {
		t.Fatalf("status=%d body=%q; want pypi.example:8443 and DNS lookup failed", status, body)
	}
}

func TestB192ReviewTLSProtocolFailure(t *testing.T) {
	up := httptest.NewUnstartedServer(http.NotFoundHandler())
	up.TLS = &tls.Config{MaxVersion: tls.VersionTLS12} //nolint:gosec // G402: the fixture is a server capped below what the client accepts
	up.StartTLS()
	t.Cleanup(up.Close)
	s := notFoundServer(t, storage.NewMemory(), up.URL)
	allowLoopbackHost(t)
	saved := upstreamClient
	transport := upstreamTransport.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	client := *saved
	client.Transport = transport
	upstreamClient = &client
	t.Cleanup(func() { upstreamClient = saved; transport.CloseIdleConnections() })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/maven/"+markerJar, nil)
	resolve := func(context.Context) (string, error) { return up.URL + "/a.jar", nil }
	s.proxyOrResolve(rec, req, s.typeStore(manifest.TypeMaven), manifest.MavenKey(markerJar), resolve, "", nil, manifest.TypeMaven, "", "", true, false)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(up.URL)+": TLS handshake failed.") {
		t.Fatalf("status=%d body=%q; want host and TLS handshake failed", rec.Code, rec.Body.String())
	}
}

func TestB192AuditArtifactReadFailureNamesHost(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("fallback=%v", fallback), func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "100")
				_, _ = w.Write([]byte("short"))
			}))
			t.Cleanup(target.Close)
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if fallback {
					http.NotFound(w, r)
					return
				}
				http.Redirect(w, r, target.URL+"/a.jar", http.StatusFound)
			}))
			t.Cleanup(first.Close)
			s := notFoundServer(t, storage.NewMemory(), first.URL)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/maven/"+markerJar, nil)
			resolve := func(context.Context) (string, error) { return first.URL + "/a.jar", nil }
			var order *upstreamOrder
			if fallback {
				order = &upstreamOrder{fallbacks: []string{target.URL + "/a.jar"}}
			}
			s.proxyOrResolve(rec, req, s.typeStore(manifest.TypeMaven), manifest.MavenKey(markerJar), resolve, "", order, manifest.TypeMaven, "", "", true, false)
			if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(target.URL)+": unreachable.") {
				t.Fatalf("status=%d body=%q; want failing body host %s and unreachable", rec.Code, rec.Body.String(), hostPort(target.URL))
			}
		})
	}
}

func TestB192AuditOCITokenFailureNamesHostAndCause(t *testing.T) {
	for _, kind := range []string{"status", "dns", "tls"} {
		t.Run(kind, func(t *testing.T) {
			token := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			if kind == "tls" {
				token.TLS = &tls.Config{MaxVersion: tls.VersionTLS12} //nolint:gosec // G402: the fixture rejects the client's TLS version
				token.StartTLS()
			} else {
				token.Start()
			}
			t.Cleanup(token.Close)
			realm := token.URL + "/token"
			wantClass := "upstream answered HTTP 503 Service Unavailable"
			//nolint:staticcheck // QF1003: the review's test, committed as written.
			if kind == "dns" {
				realm = "https://auth.example:8443/token"
				wantClass = "DNS lookup failed"
			} else if kind == "tls" {
				wantClass = "TLS handshake failed"
			}
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="registry.test",scope="repository:test:pull"`, realm))
				w.WriteHeader(http.StatusUnauthorized)
			}))
			t.Cleanup(registry.Close)
			s := notFoundServer(t, storage.NewMemory(), registry.URL)
			s.cfg.OCITokenHosts = []string{"127.0.0.1", "auth.example"}
			allowLoopbackHost(t)
			//nolint:staticcheck // QF1003: the review's test, committed as written.
			if kind == "dns" {
				saved := upstreamLookupHost
				upstreamLookupHost = func(host string) ([]string, error) {
					if host == "auth.example" {
						return nil, &net.DNSError{Name: host, Err: "no such host", IsNotFound: true}
					}
					return saved(host)
				}
				t.Cleanup(func() { upstreamLookupHost = saved })
			} else if kind == "tls" {
				saved := ociTokenClient
				transport := upstreamTransport.Clone()
				transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
				client := *saved
				client.Transport = transport
				ociTokenClient = &client
				t.Cleanup(func() { ociTokenClient = saved; transport.CloseIdleConnections() })
			}
			target := ociTarget{registry: "registry.test", repo: "test", upstream: registry.URL, kind: ociBlobs, ref: "sha256:" + strings.Repeat("0", 64)}
			rawURL := target.url("blobs/" + target.ref)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/v2/registry.test/test/blobs/"+target.ref, nil)
			req = req.WithContext(withUpstreamOpener(req.Context(), s.ociDigestOpener(target)))
			resolve := func(context.Context) (string, error) { return rawURL, nil }
			s.proxyOrResolve(rec, req, s.typeStore(manifest.TypeOCI), manifest.OCIBlobKey(target.ref), resolve, rawURL, nil, manifest.TypeOCI, target.name(), target.name(), true, true)
			if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(realm)+": "+wantClass+".") {
				t.Fatalf("status=%d body=%q; want token host %s and %s", rec.Code, rec.Body.String(), hostPort(realm), wantClass)
			}
		})
	}
}

func TestB192AuditOCIReadFailureNamesHostAndCause(t *testing.T) {
	for _, kind := range []string{"manifest", "tags", "referrers", "later status", "unauthorized"} {
		t.Run(kind, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "unauthorized" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if kind == "later status" {
					if r.URL.Path == "/second" {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.Header().Set("Link", `</second>; rel="next"`)
					_, _ = w.Write([]byte(`{"schemaVersion":2,"manifests":[]}`))
					return
				}
				w.Header().Set("Content-Length", "100")
				_, _ = w.Write([]byte("short"))
			}))
			t.Cleanup(target.Close)
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				//nolint:gosec // G710: the destination is this test's own fixture; only the path comes from the request.
				http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
			}))
			t.Cleanup(first.Close)
			rawURL := first.URL + "/object"
			wantClass := "unreachable"
			//nolint:staticcheck // QF1003: the review's test, committed as written.
			if kind == "later status" {
				rawURL = target.URL + "/object"
				wantClass = "upstream answered HTTP 503 Service Unavailable"
			} else if kind == "unauthorized" {
				wantClass = "upstream answered HTTP 401 Unauthorized"
			}
			s := notFoundServer(t, storage.NewMemory(), first.URL)
			targetInfo := ociTarget{registry: "registry.test", repo: "test", upstream: first.URL, ref: "sha256:" + strings.Repeat("0", 64)}
			store := s.typeStore(manifest.TypeOCI)
			var open upstreamOpener
			switch kind {
			case "manifest", "unauthorized":
				open = s.ociManifestOpener(targetInfo, store, manifest.TypeOCI, nil)
			case "tags":
				open = s.ociTagListOpener(targetInfo)
			default:
				open = s.ociReferrersOpener(targetInfo)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/v2/registry.test/test/manifests/"+targetInfo.ref, nil)
			req = req.WithContext(withUpstreamOpener(req.Context(), open))
			resolve := func(context.Context) (string, error) { return rawURL, nil }
			s.proxyOrResolve(rec, req, store, manifest.OCIManifestKey(targetInfo.registry, targetInfo.repo, targetInfo.ref), resolve, rawURL, nil, manifest.TypeOCI, targetInfo.name(), targetInfo.name(), true, true)
			if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(target.URL)+": "+wantClass+".") {
				t.Fatalf("status=%d body=%q; want answering host %s and %s", rec.Code, rec.Body.String(), hostPort(target.URL), wantClass)
			}
		})
	}
}

func TestB192ReauditOCIResponseBoundaries(t *testing.T) {
	for _, kind := range []string{"later 404", "tags JSON", "referrers JSON", "manifest limit"} {
		t.Run(kind, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "later 404":
					if r.URL.Path == "/second" {
						http.NotFound(w, r)
						return
					}
					w.Header().Set("Link", `</second>; rel="next"`)
					_, _ = w.Write([]byte(`{"schemaVersion":2,"manifests":[]}`))
				case "manifest limit":
					_, _ = w.Write([]byte(strings.Repeat(" ", ociMaxManifest+1)))
				default:
					_, _ = w.Write([]byte("invalid JSON"))
				}
			}))
			t.Cleanup(target.Close)
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				//nolint:gosec // G710: the destination is the local fixture; only the path comes from the request.
				http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
			}))
			t.Cleanup(first.Close)
			s := notFoundServer(t, storage.NewMemory(), first.URL)
			targetInfo := ociTarget{registry: "registry.test", repo: "test", upstream: first.URL, ref: "sha256:" + strings.Repeat("0", 64)}
			store := s.typeStore(manifest.TypeOCI)
			var open upstreamOpener
			switch kind {
			case "manifest limit":
				open = s.ociManifestOpener(targetInfo, store, manifest.TypeOCI, nil)
			case "tags JSON":
				open = s.ociTagListOpener(targetInfo)
			default:
				open = s.ociReferrersOpener(targetInfo)
			}
			rawURL := first.URL + "/object"
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/v2/registry.test/test/referrers/"+targetInfo.ref, nil)
			req = req.WithContext(withUpstreamOpener(req.Context(), open))
			resolve := func(context.Context) (string, error) { return rawURL, nil }
			s.proxyOrResolve(rec, req, store, manifest.OCIManifestKey(targetInfo.registry, targetInfo.repo, targetInfo.ref), resolve, rawURL, nil, manifest.TypeOCI, targetInfo.name(), targetInfo.name(), true, true)
			wantClass := "unreachable"
			if kind == "later 404" {
				wantClass = "upstream answered HTTP 404 Not Found"
			}
			if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(target.URL)+": "+wantClass+".") {
				t.Fatalf("status=%d body=%q; want answering host %s and %s", rec.Code, rec.Body.String(), hostPort(target.URL), wantClass)
			}
		})
	}
}

func TestB192ReauditUnusedTLSFailureDoesNotClassifyReusedConnection(t *testing.T) {
	started, release, failed, serving := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releases sync.Once
	unblock := func() { releases.Do(func() { close(release) }) }
	var handshakes atomic.Int32
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			w.Header().Set("Content-Length", "4")
			_, _ = w.Write([]byte("warm"))
			w.(http.Flusher).Flush()
			return
		}
		close(serving)
		<-r.Context().Done()
	}))
	up.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		if handshakes.Add(1) == 2 {
			close(started)
			<-release
			return nil, fmt.Errorf("fixture rejects the unused connection")
		}
		return nil, nil
	}}
	up.StartTLS()
	t.Cleanup(up.Close)
	t.Cleanup(unblock)
	s := notFoundServer(t, storage.NewMemory(), up.URL)
	allowLoopbackHost(t)
	transport := up.Client().Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	transport.ResponseHeaderTimeout = time.Second
	client := *upstreamClient
	client.Transport = transport
	saved := upstreamClient
	upstreamClient = &client
	t.Cleanup(func() { upstreamClient = saved; transport.CloseIdleConnections() })
	warm, err := client.Get(up.URL + "/warm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = warm.Body.Close() })
	wait := func(c <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-c:
		case <-time.After(5 * time.Second):
			t.Fatalf("waiting for %s", what)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
		if err != nil {
			close(failed)
		}
	}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/maven/"+markerJar, nil).WithContext(ctx)
	resolve := func(context.Context) (string, error) { return up.URL + "/artifact", nil }
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.proxyOrResolve(rec, req, s.typeStore(manifest.TypeMaven), manifest.MavenKey(markerJar), resolve, "", nil, manifest.TypeMaven, "", "", true, false)
	}()
	wait(started, "second connection's TLS handshake")
	if _, err := io.ReadAll(warm.Body); err != nil {
		t.Fatal(err)
	}
	_ = warm.Body.Close()
	wait(serving, "artifact request on the reused connection")
	unblock()
	wait(failed, "unused connection's failed TLS handshake")
	wait(done, "proxy timeout")
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(up.URL)+": timed out.") {
		t.Fatalf("status=%d body=%q; want reused connection's response timeout, not the unused dial's TLS failure", rec.Code, rec.Body.String())
	}
}

func TestB192ReauditComposerResolutionRetainsDiagnosis(t *testing.T) {
	for _, kind := range []string{"closed port", "redirected 503"} {
		t.Run(kind, func(t *testing.T) {
			f := newPackagistFixture(t)
			s := composerServer(t, f)
			upstream := closedLoopbackURL(t)
			wantHost, wantClass := hostPort(upstream), "connection refused"
			if kind == "redirected 503" {
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				t.Cleanup(target.Close)
				first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, target.URL+"/metadata", http.StatusFound)
				}))
				t.Cleanup(first.Close)
				upstream = first.URL
				wantHost, wantClass = hostPort(target.URL), "upstream answered HTTP 503 Service Unavailable"
			}
			s.cfg.ComposerUpstream = upstream
			rec := doRequest(s, http.MethodGet, consoleDistPath("v7.1.5", consoleRef515), nil)
			if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), wantHost+": "+wantClass+".") {
				t.Fatalf("status=%d body=%q; want metadata host %s and %s", rec.Code, rec.Body.String(), wantHost, wantClass)
			}
		})
	}
}

func TestB192FourthRedirectedInvalidRealm(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="relative-token",service="registry.test",scope="repository:test:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(target.Close)
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/object", http.StatusFound)
	}))
	t.Cleanup(first.Close)
	s := notFoundServer(t, storage.NewMemory(), first.URL)
	targetInfo := ociTarget{registry: "registry.test", repo: "test", upstream: first.URL, ref: "sha256:" + strings.Repeat("0", 64)}
	rawURL := first.URL + "/object"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v2/registry.test/test/blobs/"+targetInfo.ref, nil)
	req = req.WithContext(withUpstreamOpener(req.Context(), s.ociDigestOpener(targetInfo)))
	resolve := func(context.Context) (string, error) { return rawURL, nil }
	s.proxyOrResolve(rec, req, s.typeStore(manifest.TypeOCI), manifest.OCIBlobKey(targetInfo.ref), resolve, rawURL, nil, manifest.TypeOCI, targetInfo.name(), targetInfo.name(), true, true)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(target.URL)+": upstream answered HTTP 401 Unauthorized.") {
		t.Fatalf("status=%d body=%q; want respondent %s and HTTP 401", rec.Code, rec.Body.String(), hostPort(target.URL))
	}
}

func TestB192FourthComposerInvalidMetadata(t *testing.T) {
	for _, kind := range []string{"invalid JSON", "relative dist URL", "capture limit"} {
		t.Run(kind, func(t *testing.T) {
			f := newPackagistFixture(t)
			s := composerServer(t, f)
			body := "invalid JSON"
			switch kind {
			case "relative dist URL":
				body = `{"packages":{"symfony/console":[{"name":"symfony/console","version":"v7.1.5","dist":{"url":"relative.zip","type":"zip","reference":"` + consoleRef515 + `"}}]}}`
			case "capture limit":
				saved := maxUpstreamBody
				maxUpstreamBody = 64
				t.Cleanup(func() { maxUpstreamBody = saved })
				body = strings.Repeat(" ", 128)
			}
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(target.Close)
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/metadata", http.StatusFound)
			}))
			t.Cleanup(first.Close)
			s.cfg.ComposerUpstream = first.URL
			rec := doRequest(s, http.MethodGet, consoleDistPath("v7.1.5", consoleRef515), nil)
			if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(target.URL)+": unreachable.") {
				t.Fatalf("status=%d body=%q; want metadata respondent %s and unreachable", rec.Code, rec.Body.String(), hostPort(target.URL))
			}
		})
	}
}

func TestB192FourthUnusedTLSFailureAfterRedirect(t *testing.T) {
	started, release, failed, redirected := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releases sync.Once
	unblock := func() { releases.Do(func() { close(release) }) }
	var handshakes atomic.Int32
	busy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4")
		_, _ = w.Write([]byte("busy"))
		w.(http.Flusher).Flush()
	}))
	t.Cleanup(busy.Close)
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			w.Header().Set("Content-Length", "4")
			_, _ = w.Write([]byte("warm"))
			w.(http.Flusher).Flush()
			return
		}
		http.Redirect(w, r, busy.URL+"/artifact", http.StatusFound)
	}))
	up.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		if handshakes.Add(1) == 2 {
			close(started)
			<-release
			return nil, fmt.Errorf("fixture rejects the unused connection")
		}
		return nil, nil
	}}
	up.StartTLS()
	t.Cleanup(up.Close)
	t.Cleanup(unblock)
	s := notFoundServer(t, storage.NewMemory(), up.URL)
	allowLoopbackHost(t)
	transport := up.Client().Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	transport.MaxConnsPerHost = 2
	client := *upstreamClient
	client.Transport = transport
	saved := upstreamClient
	upstreamClient = &client
	t.Cleanup(func() { upstreamClient = saved; transport.CloseIdleConnections() })
	for i := 0; i < 2; i++ {
		resp, err := client.Get(busy.URL + "/held")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
	}
	warm, err := client.Get(up.URL + "/warm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = warm.Body.Close() })
	wait := func(c <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-c:
		case <-time.After(5 * time.Second):
			t.Fatalf("waiting for %s", what)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GetConn: func(host string) {
			if host == hostPort(busy.URL) {
				close(redirected)
			}
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err != nil {
				close(failed)
			}
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/maven/"+markerJar, nil).WithContext(ctx)
	resolve := func(context.Context) (string, error) { return up.URL + "/artifact", nil }
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.proxyOrResolve(rec, req, s.typeStore(manifest.TypeMaven), manifest.MavenKey(markerJar), resolve, "", nil, manifest.TypeMaven, "", "", true, false)
	}()
	wait(started, "unused TLS dial")
	if _, err := io.ReadAll(warm.Body); err != nil {
		t.Fatal(err)
	}
	_ = warm.Body.Close()
	wait(redirected, "redirect waiting for a connection to the HTTP origin")
	unblock()
	wait(failed, "the old origin's unused TLS failure")
	wait(done, "timeout waiting for the redirected connection")
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(busy.URL)+": timed out.") {
		t.Fatalf("status=%d body=%q; want HTTP origin %s and timed out", rec.Code, rec.Body.String(), hostPort(busy.URL))
	}
}

func TestB192FifthRelativeRedirectFailureNamesLastHost(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	t.Cleanup(target.Close)
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/loop", http.StatusFound)
	}))
	t.Cleanup(first.Close)
	s := notFoundServer(t, storage.NewMemory(), first.URL)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/maven/"+markerJar, nil)
	resolve := func(context.Context) (string, error) { return first.URL + "/artifact", nil }
	s.proxyOrResolve(rec, req, s.typeStore(manifest.TypeMaven), manifest.MavenKey(markerJar), resolve, "", nil, manifest.TypeMaven, "", "", true, false)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(target.URL)+": unreachable.") {
		t.Fatalf("status=%d body=%q; want redirecting host %s and unreachable", rec.Code, rec.Body.String(), hostPort(target.URL))
	}
}

func TestB192FifthUnusedTLSFailureMatchesHTTPEOF(t *testing.T) {
	started, release, failed, serving := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releases sync.Once
	unblock := func() { releases.Do(func() { close(release) }) }
	var handshakes atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(serving)
		select {
		case <-failed:
		case <-r.Context().Done():
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(target.Close)
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			w.Header().Set("Content-Length", "4")
			_, _ = w.Write([]byte("warm"))
			w.(http.Flusher).Flush()
			return
		}
		http.Redirect(w, r, target.URL+"/artifact", http.StatusFound)
	}))
	up.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if handshakes.Add(1) == 2 {
			close(started)
			<-release
			_ = hello.Conn.Close()
			return nil, fmt.Errorf("fixture closes the unused TLS connection")
		}
		return nil, nil
	}}
	up.StartTLS()
	t.Cleanup(up.Close)
	t.Cleanup(unblock)
	s := notFoundServer(t, storage.NewMemory(), up.URL)
	allowLoopbackHost(t)
	transport := up.Client().Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	client := *upstreamClient
	client.Transport = transport
	saved := upstreamClient
	upstreamClient = &client
	t.Cleanup(func() { upstreamClient = saved; transport.CloseIdleConnections() })
	warm, err := client.Get(up.URL + "/warm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = warm.Body.Close() })
	wait := func(c <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-c:
		case <-time.After(5 * time.Second):
			t.Fatalf("waiting for %s", what)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
		if err != nil {
			if err != io.EOF {
				t.Errorf("unused handshake error=%v; want EOF", err)
			}
			close(failed)
		}
	}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/maven/"+markerJar, nil).WithContext(ctx)
	resolve := func(context.Context) (string, error) { return up.URL + "/artifact", nil }
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.proxyOrResolve(rec, req, s.typeStore(manifest.TypeMaven), manifest.MavenKey(markerJar), resolve, "", nil, manifest.TypeMaven, "", "", true, false)
	}()
	wait(started, "unused TLS dial")
	if _, err := io.ReadAll(warm.Body); err != nil {
		t.Fatal(err)
	}
	_ = warm.Body.Close()
	wait(serving, "artifact request at the HTTP origin")
	unblock()
	wait(failed, "unused TLS EOF")
	wait(done, "HTTP origin's EOF")
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), hostPort(target.URL)+": unreachable.") {
		t.Fatalf("status=%d body=%q; want HTTP origin %s and unreachable", rec.Code, rec.Body.String(), hostPort(target.URL))
	}
}
