package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// A Gradle plugin marker publishes a .pom and no .jar, and Gradle asks for
// both: the .jar is the path every outage case below requests.
const (
	markerDir = "/maven2/io/spring/dependency-management/io.spring.dependency-management.gradle.plugin/1.1.7/"
	markerPom = "io/spring/dependency-management/io.spring.dependency-management.gradle.plugin/1.1.7/io.spring.dependency-management.gradle.plugin-1.1.7.pom"
	markerJar = "io/spring/dependency-management/io.spring.dependency-management.gradle.plugin/1.1.7/io.spring.dependency-management.gradle.plugin-1.1.7.jar"
)

// outageUpstream is a Maven repository publishing the marker's .pom whose
// failure mode a test chooses: answering, answering 500 to everything, or
// gone, with its listener closed.
type outageUpstream struct {
	ts      *httptest.Server
	failing atomic.Bool
	jar     atomic.Pointer[string]
}

func newOutageUpstream(t *testing.T) *outageUpstream {
	t.Helper()
	u := &outageUpstream{}
	u.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case u.failing.Load():
			http.Error(w, "upstream down", http.StatusInternalServerError)
		case r.URL.Path == markerDir+filepath.Base(markerPom):
			_, _ = w.Write([]byte("<project>marker</project>"))
		case r.URL.Path == markerDir+filepath.Base(markerJar) && u.jar.Load() != nil:
			_, _ = w.Write([]byte(*u.jar.Load()))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(u.ts.Close)
	return u
}

// notFoundServer is a proxying server over store, so two of them built over
// one store are the same bodega before and after a restart.
func notFoundServer(t *testing.T, store storage.ObjectStore, upstream string) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		LogDir:         dir,
		AuditDB:        filepath.Join(dir, "audit.db"),
		StoragePath:    dir,
		DiscoverMode:   "observe",
		AllowPlaintext: true,
		MavenUpstreams: []string{upstream + "/maven2"},
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), storage.NewSingle(store),
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.discovery != nil {
		ctx, cancel := context.WithCancel(context.Background())
		go s.discovery.Start(ctx)
		t.Cleanup(cancel)
	}
	t.Cleanup(func() { _ = s.auditDB.Close() })
	s.cache = CacheConfig{Enabled: true, MetadataTTL: time.Hour}
	allowLoopbackUpstreams(t)
	return s
}

func wantMaven(t *testing.T, s *Server, p string, want int) {
	t.Helper()
	if code, body, _ := getMaven(t, s, p); code != want {
		t.Fatalf("GET /maven/%s = %d, want %d (body %q)", p, code, want, body)
	}
}

func notFoundRecords(t *testing.T, s *Server) []string {
	t.Helper()
	keys, err := s.typeStore(manifest.TypeMaven).List(t.Context(), notFoundPrefix)
	if err != nil {
		t.Fatalf("list records: %v", err)
	}
	return keys
}

// TestOutageAnswersARecorded404 is B185: online, the marker's .jar is a 404
// and the .pom is cached; cut off, the .pom is served from the cache and the
// .jar has to stay a 404, or Gradle reads the repository as broken.
func TestOutageAnswersARecorded404(t *testing.T) {
	for _, outage := range []struct {
		name string
		cut  func(*outageUpstream)
	}{
		{"connection refused", func(u *outageUpstream) { u.ts.Close() }},
		{"5xx", func(u *outageUpstream) { u.failing.Store(true) }},
	} {
		t.Run(outage.name, func(t *testing.T) {
			up := newOutageUpstream(t)
			s := notFoundServer(t, storage.NewMemory(), up.ts.URL)
			wantMaven(t, s, markerPom, http.StatusOK)
			wantMaven(t, s, markerJar, http.StatusNotFound)
			if got := notFoundRecords(t, s); len(got) != 1 {
				t.Fatalf("records after the upstream's 404 = %v, want one", got)
			}

			outage.cut(up)
			wantMaven(t, s, markerPom, http.StatusOK)
			wantMaven(t, s, markerJar, http.StatusNotFound)

			// Past the window the record no longer speaks for the upstream.
			s.cache.NotFoundTTL = map[string]time.Duration{manifest.TypeMaven: time.Nanosecond}
			wantMaven(t, s, markerJar, http.StatusBadGateway)
		})
	}
}

func TestOutageNeverInventsA404(t *testing.T) {
	up := newOutageUpstream(t)
	s := notFoundServer(t, storage.NewMemory(), up.ts.URL)
	up.ts.Close()
	wantMaven(t, s, markerJar, http.StatusBadGateway)
}

// Only an upstream that gave no usable answer lets a record speak for it. A
// 403, a 429 or a URL the guard refused is an answer, or bodega's own policy,
// and is reported as before even with a record standing.
func TestRecordAnswersOnlyAnUnreachableUpstream(t *testing.T) {
	dnsTimeout := &net.DNSError{Err: "i/o timeout", Name: "repo.example", IsTimeout: true}
	refusal := errors.New("upstream resolves to non-routable IP 10.0.0.1")
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"403", &upstreamStatusError{url: "u", status: http.StatusForbidden}, false},
		{"502", &upstreamStatusError{url: "u", status: http.StatusBadGateway}, true},
		{"201", &upstreamStatusError{url: "u", status: http.StatusCreated}, false},
		{"429", &upstreamRateLimited{url: "u", status: http.StatusTooManyRequests, retryAfter: "60"}, false},
		{"503 with Retry-After", &upstreamRateLimited{url: "u", status: http.StatusServiceUnavailable, retryAfter: "60"}, true},
		{"404", fmt.Errorf("%w: u returned 404", errUpstreamNotFound), false},
		{"DNS timeout", dnsTimeout, true},
		{"DNS timeout from the guard", fmt.Errorf("cannot resolve upstream host %q: %w", "repo.example", dnsTimeout), true},
		{"DNS no such host", fmt.Errorf("cannot resolve: %w", &net.DNSError{Err: "no such host", Name: "repo.example", IsNotFound: true}), true},
		{"guard refusal", refusal, false},
		{"redirect the guard refused", &url.Error{Op: "Get", URL: "u", Err: refusal}, false},
		{"connection refused", &url.Error{Op: "Get", URL: "u", Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}}, true},
		{"redirect to an unresolvable host", &url.Error{Op: "Get", URL: "u", Err: fmt.Errorf("cannot resolve: %w", dnsTimeout)}, true},
	} {
		if got := upstreamUnreachable(c.err); got != c.want {
			t.Errorf("%s: upstreamUnreachable = %v, want %v", c.name, got, c.want)
		}
	}
}

// guardDNS points the production URL guard at a resolver the test answers
// for, and the server's Maven upstream at a name only that resolver knows.
func guardDNS(t *testing.T, s *Server, lookup func(string) ([]string, error)) {
	t.Helper()
	oldGuard, oldLookup := upstreamGuard, upstreamLookupHost
	t.Cleanup(func() { upstreamGuard, upstreamLookupHost = oldGuard, oldLookup })
	upstreamGuard = validateUpstreamURL
	upstreamLookupHost = lookup
	s.cfg.MavenUpstreams = []string{"https://repo.example/maven2"}
}

func dnsTimeoutLookup(string) ([]string, error) {
	return nil, &net.DNSError{Err: "i/o timeout", Name: "repo.example", IsTimeout: true}
}

// A DNS failure is the guard's, before any HTTP: it has to count as the
// outage it is, and a private address the guard refuses must not.
func TestDNSOutageAnswersARecorded404(t *testing.T) {
	t.Run("recorded", func(t *testing.T) {
		up := newOutageUpstream(t)
		s := notFoundServer(t, storage.NewMemory(), up.ts.URL)
		wantMaven(t, s, markerJar, http.StatusNotFound)
		guardDNS(t, s, dnsTimeoutLookup)
		wantMaven(t, s, markerJar, http.StatusNotFound)

		s.cache.NotFoundTTL = map[string]time.Duration{manifest.TypeMaven: time.Nanosecond}
		wantMaven(t, s, markerJar, http.StatusBadGateway)
	})
	t.Run("never recorded", func(t *testing.T) {
		up := newOutageUpstream(t)
		s := notFoundServer(t, storage.NewMemory(), up.ts.URL)
		guardDNS(t, s, dnsTimeoutLookup)
		wantMaven(t, s, markerJar, http.StatusBadGateway)
	})
	t.Run("guard refusal", func(t *testing.T) {
		up := newOutageUpstream(t)
		s := notFoundServer(t, storage.NewMemory(), up.ts.URL)
		wantMaven(t, s, markerJar, http.StatusNotFound)
		guardDNS(t, s, func(string) ([]string, error) { return []string{"10.0.0.1"}, nil })
		wantMaven(t, s, markerJar, http.StatusBadGateway)
	})
}

// statusUpstream answers 404 until a test stores another status, with the
// headers and body that status carries.
type statusUpstream struct {
	ts         *httptest.Server
	code       atomic.Int64
	retryAfter atomic.Pointer[string]
}

func newStatusUpstream(t *testing.T) *statusUpstream {
	t.Helper()
	u := &statusUpstream{}
	u.code.Store(http.StatusNotFound)
	u.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ra := u.retryAfter.Load(); ra != nil {
			w.Header().Set("Retry-After", *ra)
		}
		w.WriteHeader(int(u.code.Load()))
		_, _ = w.Write([]byte("artifact"))
	}))
	t.Cleanup(u.ts.Close)
	return u
}

// A 503 carrying Retry-After is still the upstream failing; a 429 is the
// upstream answering, and keeps its rate-limit response.
func TestRetryAfterOutageAnswersARecorded404(t *testing.T) {
	sixty := "60"
	for _, c := range []struct {
		name     string
		status   int
		recorded bool
		want     int
	}{
		{"503 recorded", http.StatusServiceUnavailable, true, http.StatusNotFound},
		{"503 never recorded", http.StatusServiceUnavailable, false, http.StatusServiceUnavailable},
		{"429 recorded", http.StatusTooManyRequests, true, http.StatusServiceUnavailable},
	} {
		t.Run(c.name, func(t *testing.T) {
			up := newStatusUpstream(t)
			s := notFoundServer(t, storage.NewMemory(), up.ts.URL)
			if c.recorded {
				wantMaven(t, s, markerJar, http.StatusNotFound)
			}
			up.retryAfter.Store(&sixty)
			up.code.Store(int64(c.status))
			wantMaven(t, s, markerJar, c.want)
		})
	}
}

// The resolver path consults the record before its rate-limit and 502
// answers, as the fetch path does.
func TestResolverOutageAnswersARecorded404(t *testing.T) {
	dnsTimeout := &net.DNSError{Err: "i/o timeout", Name: "repo.example", IsTimeout: true}
	for _, c := range []struct {
		name    string
		outage  error
		wantOut int
	}{
		{"503 with Retry-After", &upstreamRateLimited{url: "u", status: http.StatusServiceUnavailable, retryAfter: "60"}, http.StatusNotFound},
		{"DNS timeout", fmt.Errorf("cannot resolve upstream host: %w", dnsTimeout), http.StatusNotFound},
		{"429", &upstreamRateLimited{url: "u", status: http.StatusTooManyRequests, retryAfter: "60"}, http.StatusServiceUnavailable},
		{"guard refusal", errors.New("upstream resolves to non-routable IP 10.0.0.1"), http.StatusBadGateway},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := notFoundServer(t, storage.NewMemory(), "http://127.0.0.1:1")
			store := s.typeStore(manifest.TypeMaven)
			key := manifest.MavenKey(markerJar)
			var resolveErr atomic.Pointer[error]
			notFound := fmt.Errorf("%w: index lists no such file", errUpstreamNotFound)
			resolveErr.Store(&notFound)
			resolve := func(context.Context) (string, error) { return "", *resolveErr.Load() }
			get := func() int {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/maven/"+markerJar, nil)
				s.proxyOrResolve(rec, req, store, key, resolve, "", nil, manifest.TypeMaven, "", "", true, false)
				return rec.Code
			}
			if got := get(); got != http.StatusNotFound {
				t.Fatalf("resolver 404 = %d, want 404", got)
			}
			resolveErr.Store(&c.outage)
			if got := get(); got != c.wantOut {
				t.Fatalf("resolver %s with a record = %d, want %d", c.name, got, c.wantOut)
			}
		})
	}
}

func TestPublishedAfterA404LeavesNoRecord(t *testing.T) {
	up := newOutageUpstream(t)
	s := notFoundServer(t, storage.NewMemory(), up.ts.URL)
	wantMaven(t, s, markerJar, http.StatusNotFound)
	if got := notFoundRecords(t, s); len(got) != 1 {
		t.Fatalf("records after the upstream's 404 = %v, want one", got)
	}

	body := "now published"
	up.jar.Store(&body)
	wantMaven(t, s, markerJar, http.StatusOK)
	if got := notFoundRecords(t, s); len(got) != 0 {
		t.Fatalf("records after the upstream's 200 = %v, want none", got)
	}
}

// Every 2xx says the upstream has the path, including one bodega does not
// serve and a 200 whose body breaks off: none may leave the record to answer
// a later outage.
func TestAnySuccessAfterA404LeavesNoRecord(t *testing.T) {
	for _, code := range []int{http.StatusCreated, http.StatusNoContent, http.StatusPartialContent} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			up := newStatusUpstream(t)
			s := notFoundServer(t, storage.NewMemory(), up.ts.URL)
			wantMaven(t, s, markerJar, http.StatusNotFound)
			up.code.Store(int64(code))
			getMaven(t, s, markerJar)
			if got := notFoundRecords(t, s); len(got) != 0 {
				t.Fatalf("records after the upstream's %d = %v, want none", code, got)
			}
		})
	}
	t.Run("200 cut off mid-body", func(t *testing.T) {
		var broken atomic.Bool
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !broken.Load() {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write([]byte("partial"))
		}))
		t.Cleanup(up.Close)
		s := notFoundServer(t, storage.NewMemory(), up.URL)
		wantMaven(t, s, markerJar, http.StatusNotFound)
		broken.Store(true)
		wantMaven(t, s, markerJar, http.StatusBadGateway)
		if got := notFoundRecords(t, s); len(got) != 0 {
			t.Fatalf("records after a 200 that broke off = %v, want none", got)
		}
	})
}

func TestNotFoundRecordSurvivesARestart(t *testing.T) {
	root := t.TempDir()
	up := newOutageUpstream(t)
	before := notFoundServer(t, storage.NewLocal(root), up.ts.URL)
	wantMaven(t, before, markerJar, http.StatusNotFound)

	up.ts.Close()
	after := notFoundServer(t, storage.NewLocal(root), up.ts.URL)
	wantMaven(t, after, markerJar, http.StatusNotFound)
}
