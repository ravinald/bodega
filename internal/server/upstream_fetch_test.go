package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

// End to end through the handler: an oversize artifact is a 502, and neither
// the object nor a checksum for it survives. Caching it was the half of #128
// that made every later fetch of the real artifact fail verification.
func TestOversizeArtifactIsNeitherCachedNorChecksummed(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{
		fixtureDeb: strings.Repeat("x", 4096),
	})
	s := mirrorServer(t, archive)
	shrinkUpstreamCap(t, 512)

	code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb)
	if code != http.StatusBadGateway {
		t.Fatalf("oversize pool fetch = %d, want 502", code)
	}

	key := "packages/apt/" + fixtureDeb
	store := s.typeStore("apt")
	if status, err := store.Head(t.Context(), key); err == nil && status != nil && status.Exists {
		t.Error("the truncated artifact was cached")
	}
	stored, err := s.auditDB.GetChecksum(t.Context(), key)
	if err != nil {
		t.Fatalf("GetChecksum: %v", err)
	}
	if stored != nil {
		t.Errorf("a checksum was stored for an artifact that never arrived whole: %+v", stored)
	}
}
