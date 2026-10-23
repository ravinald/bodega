package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

const staleGraceForTest = 500 * time.Millisecond

// silentUpstream accepts every connection and answers nothing until answer is
// closed, which is what an upstream behind a dropping firewall looks like once
// the connect has been made. hits counts the requests that reached it.
type silentUpstream struct {
	url    string
	hits   atomic.Int32
	answer chan struct{}
}

func newSilentUpstream(t *testing.T) *silentUpstream {
	t.Helper()
	u := &silentUpstream{answer: make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		select {
		case <-u.answer:
			_, _ = w.Write([]byte("fresh"))
		case <-r.Context().Done():
		}
	}))
	u.url = srv.URL + "/simple/colorama/"
	saved := upstreamGuard
	upstreamGuard = func(string) error { return nil }
	t.Cleanup(func() {
		upstreamGuard = saved
		u.release()
		srv.Close()
	})
	return u
}

func (u *silentUpstream) release() {
	select {
	case <-u.answer:
	default:
		close(u.answer)
	}
}

// newStaleGraceServer seeds key with a copy that is already past
// metadata_ttl, so every request for it takes the stale branch.
func newStaleGraceServer(t *testing.T, key string, seed bool) (*Server, *storage.Memory) {
	t.Helper()
	s := newDiscoveryServer(t)
	s.cache = CacheConfig{Enabled: true, MetadataTTL: time.Nanosecond, StaleGrace: staleGraceForTest}
	store := storage.NewMemory()
	if seed {
		store.Seed(key, "stale")
	}
	return s, store
}

func serveStale(s *Server, ctx context.Context, store storage.ObjectStore, key, upstream string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/pypi/simple/colorama/", nil).WithContext(ctx)
	req.RemoteAddr = "127.0.0.1:33333"
	rec := httptest.NewRecorder()
	resolve := func(context.Context) (string, error) { return upstream, nil }
	s.proxyOrResolve(rec, req, store, key, resolve, upstream, manifest.TypeNpm, "colorama", "colorama", false, true)
	return rec
}

func cachedBody(t *testing.T, store *storage.Memory, key string) string {
	t.Helper()
	b, err := store.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("read cached %s: %v", key, err)
	}
	return string(b)
}

func refreshIdle(s *Server, key string) func() bool {
	return func() bool {
		_, running := s.staleRefreshes.Load(key)
		return !running
	}
}

// B156: pip gives up at 15s and the stale fallback arrived only after the
// upstream fetch failed, which a dropped packet takes longer than that to do.
func TestStaleCopyServedWithinGraceFromSilentUpstream(t *testing.T) {
	const key = "pypi/simple/colorama/index"
	up := newSilentUpstream(t)
	s, store := newStaleGraceServer(t, key, true)

	ctx, hangUp := context.WithCancel(t.Context())
	start := time.Now()
	rec := serveStale(s, ctx, store, key, up.url)
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK || rec.Body.String() != "stale" {
		t.Fatalf("got %d %q, want 200 and the stale cached copy", rec.Code, rec.Body.String())
	}
	if elapsed > staleGraceForTest+time.Second {
		t.Fatalf("stale copy took %s, want within stale_grace (%s) plus 1s", elapsed, staleGraceForTest)
	}

	// The client is gone; the refresh it started must not be.
	hangUp()
	waitFor(t, func() bool { return up.hits.Load() == 1 })
	up.release()
	waitFor(t, func() bool { return cachedBody(t, store, key) == "fresh" })
	waitFor(t, refreshIdle(s, key))
	if got := up.hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1", got)
	}
}

func TestStaleRefreshRunsOncePerKey(t *testing.T) {
	const key = "pypi/simple/colorama/index"
	up := newSilentUpstream(t)
	s, store := newStaleGraceServer(t, key, true)

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- serveStale(s, t.Context(), store, key, up.url) }()
	waitFor(t, func() bool { return up.hits.Load() == 1 })

	start := time.Now()
	rec := serveStale(s, t.Context(), store, key, up.url)
	if elapsed := time.Since(start); elapsed >= staleGraceForTest {
		t.Errorf("second request took %s, want the stale copy at once rather than a second grace wait", elapsed)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "stale" {
		t.Fatalf("second request got %d %q, want 200 and the stale cached copy", rec.Code, rec.Body.String())
	}
	if r := <-first; r.Body.String() != "stale" {
		t.Fatalf("first request got %q, want the stale cached copy", r.Body.String())
	}
	if got := up.hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1: a refresh was already running", got)
	}

	up.release()
	waitFor(t, func() bool { return cachedBody(t, store, key) == "fresh" })
	waitFor(t, refreshIdle(s, key))
}

func TestStaleCopyReplacedWhenUpstreamAnswersWithinGrace(t *testing.T) {
	const key = "pypi/simple/colorama/index"
	up := newSilentUpstream(t)
	up.release()
	s, store := newStaleGraceServer(t, key, true)

	rec := serveStale(s, t.Context(), store, key, up.url)
	if rec.Code != http.StatusOK || rec.Body.String() != "fresh" {
		t.Fatalf("got %d %q, want 200 and the fresh upstream copy", rec.Code, rec.Body.String())
	}
	if got := cachedBody(t, store, key); got != "fresh" {
		t.Errorf("cache holds %q, want the fresh copy", got)
	}
	if !refreshIdle(s, key)() {
		t.Error("a foreground refresh left its claim held")
	}
}

// A miss has nothing to fall back to, so the grace does not apply and the
// client waits on the upstream until it gives up.
func TestMissFromSilentUpstreamStillFails(t *testing.T) {
	const key = "pypi/simple/colorama/index"
	up := newSilentUpstream(t)
	s, store := newStaleGraceServer(t, key, false)

	clientTimeout := staleGraceForTest + time.Second
	ctx, cancel := context.WithTimeout(t.Context(), clientTimeout)
	defer cancel()
	start := time.Now()
	rec := serveStale(s, ctx, store, key, up.url)
	elapsed := time.Since(start)

	if rec.Code != http.StatusBadGateway || rec.Body.String() != "upstream fetch failed\n" {
		t.Fatalf("got %d %q, want the existing 502 upstream fetch failed", rec.Code, rec.Body.String())
	}
	if elapsed < clientTimeout {
		t.Errorf("miss answered after %s, before the client gave up at %s", elapsed, clientTimeout)
	}
	if b, _ := store.Get(t.Context(), key); b != nil {
		t.Errorf("a failed miss cached %q", b)
	}
}

func TestUpstreamConnectTimeoutBoundsADroppedSYN(t *testing.T) {
	saved := upstreamConnectTimeout.Load()
	t.Cleanup(func() { upstreamConnectTimeout.Store(saved) })

	// Wired from the config key, so the bound below is the one serve applies.
	newACLServer(t, &config.Config{UpstreamConnectTimeout: "1s", StaleGrace: "2s"})
	if got := time.Duration(upstreamConnectTimeout.Load()); got != time.Second {
		t.Fatalf("connect timeout = %s, want the configured 1s", got)
	}

	start := time.Now()
	resp, err := upstreamClient.Get("http://10.255.255.1/")
	elapsed := time.Since(start)
	if err == nil {
		resp.Body.Close()
		t.Skip("10.255.255.1 answered from this host; nothing here drops SYNs")
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		t.Skipf("no route to 10.255.255.1 from this sandbox: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("connect failed after %s, want within upstream_connect_timeout (1s) plus 1s: %v", elapsed, err)
	}
}

func TestNewServerReadsStaleGrace(t *testing.T) {
	saved := upstreamConnectTimeout.Load()
	t.Cleanup(func() { upstreamConnectTimeout.Store(saved) })

	s := newACLServer(t, &config.Config{UpstreamConnectTimeout: "1s", StaleGrace: "2s"})
	if s.cache.StaleGrace != 2*time.Second {
		t.Errorf("stale grace = %s, want the configured 2s", s.cache.StaleGrace)
	}
	s = newACLServer(t, &config.Config{})
	if s.cache.StaleGrace != 3*time.Second {
		t.Errorf("stale grace = %s, want the 3s default for a Config built in code", s.cache.StaleGrace)
	}
}
