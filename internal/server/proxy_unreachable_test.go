package server

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
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
