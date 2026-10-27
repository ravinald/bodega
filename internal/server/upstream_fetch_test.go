package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// shrinkUpstreamCap lowers the buffer ceiling for one test so the over-limit
// path is driven with a few bytes instead of a few hundred megabytes.
func shrinkUpstreamCap(t *testing.T, n int64) {
	t.Helper()
	saved := maxUpstreamBody
	maxUpstreamBody = n
	t.Cleanup(func() { maxUpstreamBody = saved })
}

// allowLoopbackUpstream lifts the SSRF guard for a fixture served from
// 127.0.0.1, which the real guard refuses by design.
func allowLoopbackUpstream(t *testing.T) {
	t.Helper()
	saved := upstreamGuard
	upstreamGuard = func(rawURL string) error {
		if strings.HasPrefix(rawURL, "http://127.0.0.1:") || strings.HasPrefix(rawURL, "http://[::1]:") {
			return nil
		}
		return saved(rawURL)
	}
	t.Cleanup(func() { upstreamGuard = saved })
}

// An artifact past the buffer ceiling has to fail. io.LimitReader signals EOF
// at its limit and io.ReadAll reports that as a complete body with a nil
// error, so the short bytes were checksummed as authoritative, cached under
// that digest and served to every client afterwards — corruption that every
// layer below reported as success.
func TestOversizeUpstreamBodyFailsInsteadOfTruncating(t *testing.T) {
	allowLoopbackUpstream(t)
	shrinkUpstreamCap(t, 64)

	const body = "this artifact is deliberately longer than the shrunken buffer ceiling"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Chunked, so Content-Length cannot short-circuit the check: the
		// length-unknown case is the one the read has to catch on its own.
		w.Header().Set("Transfer-Encoding", "chunked")
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	data, _, err := fetchUpstream(t.Context(), ts.URL)
	if err == nil {
		t.Fatalf("fetchUpstream returned %d bytes and no error for a body over the cap", len(data))
	}
	if data != nil {
		t.Errorf("data = %d bytes on the error path, want none", len(data))
	}
	if !strings.Contains(err.Error(), "exceeds") || !strings.Contains(err.Error(), "nothing was cached") {
		t.Errorf("error = %q, want it to name the limit and say nothing was cached", err)
	}
}

// A declared length over the ceiling is refusable before a byte moves, which
// is the cheap check ahead of the expensive one.
func TestDeclaredLengthOverCapIsRefusedBeforeReading(t *testing.T) {
	allowLoopbackUpstream(t)
	shrinkUpstreamCap(t, 8)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("far more than eight bytes"))
	}))
	defer ts.Close()

	_, _, err := fetchUpstream(t.Context(), ts.URL)
	if err == nil {
		t.Fatal("fetchUpstream accepted a body whose declared length is over the cap")
	}
	if !strings.Contains(err.Error(), "declares") {
		t.Errorf("error = %q, want it to name the declared length", err)
	}
}

// A cut transfer that still returns cleanly is the same class of failure as a
// truncation: short bytes with no error anywhere.
func TestShortBodyAgainstContentLengthFails(t *testing.T) {
	allowLoopbackUpstream(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("only twenty bytes!!!"))
	}))
	defer ts.Close()

	_, _, err := fetchUpstream(t.Context(), ts.URL)
	if err == nil {
		t.Fatal("fetchUpstream accepted a body shorter than the declared Content-Length")
	}
}

// The ceiling is inclusive: an artifact exactly at it is whole, and refusing
// it would be a second bug in the other direction.
func TestBodyExactlyAtTheCapSucceeds(t *testing.T) {
	allowLoopbackUpstream(t)
	const body = "exactly-thirty-two-bytes-here!!!"
	shrinkUpstreamCap(t, int64(len(body)))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	data, _, err := fetchUpstream(t.Context(), ts.URL)
	if err != nil {
		t.Fatalf("fetchUpstream refused a body exactly at the cap: %v", err)
	}
	if string(data) != body {
		t.Errorf("data = %q, want the whole body", data)
	}
}

// End to end through the handler: an artifact past the in-memory ceiling is
// served and cached whole, because the artifact path no longer buffers. The
// ceiling still governs the metadata fetches above, which is why the cap is
// shrunk here rather than removed.
func TestArtifactOverTheBufferCapIsStreamed(t *testing.T) {
	body := strings.Repeat("x", 4096)
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: body})
	s := mirrorServer(t, archive)
	shrinkUpstreamCap(t, 512)

	code, got := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusOK {
		t.Fatalf("pool fetch = %d, want 200", code)
	}
	if string(got) != body {
		t.Fatalf("served %d bytes, want %d", len(got), len(body))
	}

	key := "packages/apt/" + fixtureDeb
	cached, err := s.typeStore("apt").Get(t.Context(), key)
	if err != nil {
		t.Fatalf("read cached object: %v", err)
	}
	if string(cached) != body {
		t.Errorf("cached %d bytes, want %d", len(cached), len(body))
	}

	sum := sha256.Sum256([]byte(body))
	stored, err := s.auditDB.GetChecksum(t.Context(), key)
	if err != nil {
		t.Fatalf("GetChecksum: %v", err)
	}
	if stored == nil || stored.Value != hex.EncodeToString(sum[:]) {
		t.Errorf("stored checksum = %+v, want the digest of the streamed body", stored)
	}
}

// A cut transfer still fails, and still caches nothing. That was the half of
// #128 that made every later fetch of the real artifact fail verification
// against the digest of a truncated one, and streaming does not retire it.
func TestCutTransferIsNeitherCachedNorChecksummed(t *testing.T) {
	allowLoopbackUpstream(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer ts.Close()

	up, err := openUpstream(t.Context(), ts.URL, false)
	if err != nil {
		t.Fatalf("openUpstream: %v", err)
	}
	defer up.body.Close()

	spool, err := spoolTestServer(t, 0, 0).spoolUpstream(up)
	if err == nil {
		spool.close()
		t.Fatal("spoolUpstream accepted a body shorter than the declared Content-Length")
	}
	if !strings.Contains(err.Error(), "nothing was cached") {
		t.Errorf("error = %q, want it to say nothing was cached", err)
	}
}

// The spool file does not outlive the request. A proxy that leaves one behind
// per fetch fills the spool filesystem, which is the resource the streaming
// path traded process memory for.
func TestSpoolFileIsRemoved(t *testing.T) {
	allowLoopbackUpstream(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("artifact bytes"))
	}))
	defer ts.Close()

	up, err := openUpstream(t.Context(), ts.URL, false)
	if err != nil {
		t.Fatalf("openUpstream: %v", err)
	}
	defer up.body.Close()

	s := spoolTestServer(t, 0, 0)
	spool, err := s.spoolUpstream(up)
	if err != nil {
		t.Fatalf("spoolUpstream: %v", err)
	}
	name := spool.path()
	spool.close()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Errorf("spool file %s survived close (stat err = %v)", name, err)
	}
	// close returns the bytes as well as the file. A spool that frees the
	// inode and keeps its claim on the budget starves the next fetch of a
	// resource nothing is using.
	if st := s.spool.stats(); st.UsedBytes != 0 || st.InFlight != 0 {
		t.Errorf("stats = %+v after close, want the budget returned", st)
	}
}

// Maven Central's CDN throttles by User-Agent, and Go's default agent shares a
// bucket with every Go program behind the same address. B179.
func TestUpstreamFetchNamesBodega(t *testing.T) {
	allowLoopbackUpstream(t)
	got := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("pom"))
	}))
	defer ts.Close()

	if _, _, err := fetchUpstream(t.Context(), ts.URL); err != nil {
		t.Fatal(err)
	}
	if ua := <-got; !strings.HasPrefix(ua, "bodega/") {
		t.Errorf("User-Agent = %q, want bodega/<version>", ua)
	}
}

// An upstream rate limit is not an outage: a 502 tells Maven and Gradle the
// repository is down, a 503 with Retry-After tells them to wait.
func TestUpstreamRateLimitReachesTheClientAs503(t *testing.T) {
	const pkg = "leftpad"
	key := manifest.NpmTarballKey(pkg, "1.2.0")

	for _, tc := range []struct {
		name       string
		status     int
		retryAfter string
		cached     bool
		wantCode   int
		wantRetry  string
		wantWait   string
	}{
		{"429 with Retry-After", http.StatusTooManyRequests, "120", false, http.StatusServiceUnavailable, "120", "120 seconds"},
		{"429 with no Retry-After", http.StatusTooManyRequests, "", false, http.StatusServiceUnavailable, "60", "60 seconds"},
		{"503 with Retry-After", http.StatusServiceUnavailable, "30", false, http.StatusServiceUnavailable, "30", "30 seconds"},
		{"429 with zero-padded seconds", http.StatusTooManyRequests, "00000000120", false, http.StatusServiceUnavailable, "00000000120", "00000000120 seconds"},
		{"429 with an HTTP-date", http.StatusTooManyRequests, "Wed, 28 Oct 2026 07:28:00 GMT", false, http.StatusServiceUnavailable, "Wed, 28 Oct 2026 07:28:00 GMT", "Wed, 28 Oct 2026 07:28:00 GMT"},
		// Relayed as sent, but kept out of the body: upstream text there could
		// name a host.
		{"429 with a nonstandard Retry-After", http.StatusTooManyRequests, "see https://127.0.0.1/", false, http.StatusServiceUnavailable, "see https://127.0.0.1/", "Retry-After header"},
		{"500 stays an outage", http.StatusInternalServerError, "", false, http.StatusBadGateway, "", ""},
		{"503 with no Retry-After stays an outage", http.StatusServiceUnavailable, "", false, http.StatusBadGateway, "", ""},
		{"429 over a cached copy serves it", http.StatusTooManyRequests, "120", true, http.StatusOK, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allowLoopbackUpstream(t)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
			}))
			defer ts.Close()

			s := newDiscoveryServer(t)
			s.cache = CacheConfig{MetadataTTL: time.Nanosecond}
			store := storage.NewMemory()
			if tc.cached {
				store.Seed(key, "cached-tarball")
			}
			req := httptest.NewRequest(http.MethodGet, "/npm/"+pkg+"/-/"+pkg+"-1.2.0.tgz", nil)
			rec := httptest.NewRecorder()
			s.proxyOrCache(rec, req, store, key, ts.URL+"/leftpad-1.2.0.tgz", manifest.TypeNpm, pkg, pkg, false, true)

			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if got := rec.Header().Get("Retry-After"); got != tc.wantRetry {
				t.Errorf("Retry-After = %q, want %q", got, tc.wantRetry)
			}
			body := rec.Body.String()
			switch {
			case tc.cached:
				if body != "cached-tarball" {
					t.Errorf("body = %q, want the cached copy", body)
				}
			case tc.wantCode == http.StatusServiceUnavailable:
				if !strings.Contains(body, "rate-limiting") || !strings.Contains(body, tc.wantWait) {
					t.Errorf("body = %q, want it to say the upstream is rate-limiting and when to retry", body)
				}
				if strings.Contains(body, "127.0.0.1") {
					t.Errorf("body = %q names the upstream host", body)
				}
			}
		})
	}
}

// A CDN that gzips its rate-limit page is still saying "wait". The identity
// check guards artifact bodies, and a 429 carries none, so it must not turn
// the answer into an encoding refusal.
func TestEncodedRateLimitIsStillARateLimit(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "120")
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(status)
		}))
		_, err := openUpstreamVia(t.Context(), ts.Client(), func(string) error { return nil }, ts.URL, true)
		ts.Close()
		var limited *upstreamRateLimited
		if !errors.As(err, &limited) {
			t.Errorf("status %d: err = %v, want *upstreamRateLimited", status, err)
			continue
		}
		if limited.status != status || limited.retryAfter != "120" {
			t.Errorf("status %d: got status %d Retry-After %q", status, limited.status, limited.retryAfter)
		}
	}
}
