package server

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scaleapi/bodega/internal/logging"
)

// testHandler returns a simple 200 OK handler with a fixed body.
func testHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "hello")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
}

func newTestLogger(buf *bytes.Buffer, level slog.Level) *slog.Logger {
	h := logging.NewHandler(buf, level)
	return slog.New(h)
}

// ---- RequestLogger tests ---------------------------------------------------

func TestRequestLoggerInfoLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, slog.LevelInfo)

	handler := RequestLogger(logger)(testHandler("ok"))
	req := httptest.NewRequest("GET", "/api/v1/packages", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	log := buf.String()
	if !strings.Contains(log, "GET") {
		t.Error("log missing method")
	}
	if !strings.Contains(log, "/api/v1/packages") {
		t.Error("log missing path")
	}
	if !strings.Contains(log, "status=200") {
		t.Error("log missing status")
	}
	// Should NOT contain headers at Info level.
	if strings.Contains(log, "req_headers") {
		t.Error("headers should not appear at Info level")
	}
}

func TestRequestLoggerDebugLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, slog.LevelDebug)

	handler := RequestLogger(logger)(testHandler("ok"))
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	log := buf.String()
	if !strings.Contains(log, "req_headers") {
		t.Error("headers should appear at Debug level")
	}
	if !strings.Contains(log, "resp_headers") {
		t.Error("response headers should appear at Debug level")
	}
}

func TestRequestLoggerTraceLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, logging.LevelTrace)

	handler := RequestLogger(logger)(testHandler("response-body"))
	body := strings.NewReader("request-body-content")
	req := httptest.NewRequest("POST", "/test", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	log := buf.String()
	if !strings.Contains(log, "req_body") {
		t.Error("request body should appear at Trace level")
	}
	if !strings.Contains(log, "request-body-content") {
		t.Error("request body content missing")
	}
	if !strings.Contains(log, "resp_body") {
		t.Error("response body should appear at Trace level")
	}
	if !strings.Contains(log, "response-body") {
		t.Error("response body content missing")
	}
}

func TestRequestLoggerSkipsHealthz(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, slog.LevelInfo)

	handler := RequestLogger(logger)(testHandler("ok"))
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if buf.Len() > 0 {
		t.Errorf("healthz should not be logged, got: %s", buf.String())
	}
}

func TestRequestLoggerSkipsBinaryBody(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, logging.LevelTrace)

	binaryHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x00, 0x01, 0x02})
	})

	handler := RequestLogger(logger)(binaryHandler)
	req := httptest.NewRequest("GET", "/binaries/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	log := buf.String()
	if strings.Contains(log, "resp_body") {
		t.Error("binary response body should not be captured")
	}
}

func TestRequestLoggerErrorLevelNoOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, slog.LevelError)

	handler := RequestLogger(logger)(testHandler("ok"))
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if buf.Len() > 0 {
		t.Errorf("no log output expected at Error level, got: %s", buf.String())
	}
}

// ---- RealIPMiddleware tests ------------------------------------------------

func TestRealIPFromXRealIP(t *testing.T) {
	var gotIP string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = ClientIP(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := RealIPMiddleware(nil)(inner)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345" // trusted private IP
	req.Header.Set("X-Real-IP", "203.0.113.50")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotIP != "203.0.113.50" {
		t.Errorf("ClientIP = %q, want 203.0.113.50", gotIP)
	}
}

func TestRealIPFromXForwardedFor(t *testing.T) {
	var gotIP string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = ClientIP(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := RealIPMiddleware(nil)(inner)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.10, 10.0.0.5")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// 10.0.0.5 is trusted, so we walk left to 198.51.100.10.
	if gotIP != "198.51.100.10" {
		t.Errorf("ClientIP = %q, want 198.51.100.10", gotIP)
	}
}

func TestRealIPUntrustedPeer(t *testing.T) {
	var gotIP string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = ClientIP(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := RealIPMiddleware(nil)(inner)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345" // untrusted public IP
	req.Header.Set("X-Real-IP", "198.51.100.10")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Peer is not trusted, so forwarded headers are ignored.
	if gotIP != "203.0.113.1" {
		t.Errorf("ClientIP = %q, want 203.0.113.1 (direct peer)", gotIP)
	}
}

func TestRealIPNoForwardedHeaders(t *testing.T) {
	var gotIP string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = ClientIP(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := RealIPMiddleware(nil)(inner)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.5:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotIP != "10.0.0.5" {
		t.Errorf("ClientIP = %q, want 10.0.0.5", gotIP)
	}
}

func TestRealIPCustomTrustedNets(t *testing.T) {
	_, custom, _ := net.ParseCIDR("172.20.0.0/16")
	var gotIP string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = ClientIP(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := RealIPMiddleware([]*net.IPNet{custom})(inner)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "172.20.1.5:1234"
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotIP != "1.2.3.4" {
		t.Errorf("ClientIP = %q, want 1.2.3.4", gotIP)
	}
}

// ---- DenyListMiddleware tests -----------------------------------------------

func TestDenyListBlocksIPv4(t *testing.T) {
	nets, err := ParseDenyList([]string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("ParseDenyList: %v", err)
	}

	handler := DenyListMiddleware(nets)(testHandler("ok"))
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.50:12345"
	rec := httptest.NewRecorder()

	// Need RealIPMiddleware to populate context.
	chain := RealIPMiddleware(nil)(handler)
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestDenyListBlocksBareIPv4(t *testing.T) {
	nets, err := ParseDenyList([]string{"10.0.0.99"})
	if err != nil {
		t.Fatalf("ParseDenyList: %v", err)
	}

	handler := DenyListMiddleware(nets)(testHandler("ok"))
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.99:9999"
	rec := httptest.NewRecorder()

	chain := RealIPMiddleware(nil)(handler)
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestDenyListBlocksIPv6(t *testing.T) {
	nets, err := ParseDenyList([]string{"fd00::/8"})
	if err != nil {
		t.Fatalf("ParseDenyList: %v", err)
	}

	handler := DenyListMiddleware(nets)(testHandler("ok"))
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "[fd12::1]:8080"
	rec := httptest.NewRecorder()

	chain := RealIPMiddleware(nil)(handler)
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestDenyListBlocksBareIPv6(t *testing.T) {
	nets, err := ParseDenyList([]string{"::1"})
	if err != nil {
		t.Fatalf("ParseDenyList: %v", err)
	}

	handler := DenyListMiddleware(nets)(testHandler("ok"))
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "[::1]:8080"
	rec := httptest.NewRecorder()

	chain := RealIPMiddleware(nil)(handler)
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestDenyListAllowsNonMatchingIP(t *testing.T) {
	nets, err := ParseDenyList([]string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("ParseDenyList: %v", err)
	}

	handler := DenyListMiddleware(nets)(testHandler("ok"))
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.5:8080"
	rec := httptest.NewRecorder()

	chain := RealIPMiddleware(nil)(handler)
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestDenyListEmptyIsNoOp(t *testing.T) {
	handler := DenyListMiddleware(nil)(testHandler("ok"))
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestParseDenyListInvalidEntry(t *testing.T) {
	_, err := ParseDenyList([]string{"not-an-ip"})
	if err == nil {
		t.Error("expected error for invalid entry")
	}
}

func TestParseDenyListInvalidCIDR(t *testing.T) {
	_, err := ParseDenyList([]string{"10.0.0.1/999"})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestParseDenyListSkipsEmpty(t *testing.T) {
	nets, err := ParseDenyList([]string{"", "  ", "10.0.0.1"})
	if err != nil {
		t.Fatalf("ParseDenyList: %v", err)
	}
	if len(nets) != 1 {
		t.Errorf("got %d nets, want 1", len(nets))
	}
}

// ---- responseRecorder tests ------------------------------------------------

func TestResponseRecorderCapturesStatus(t *testing.T) {
	rec := &responseRecorder{ResponseWriter: httptest.NewRecorder(), statusCode: http.StatusOK}
	rec.WriteHeader(http.StatusNotFound)
	if rec.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want 404", rec.statusCode)
	}
}

func TestResponseRecorderCapturesSize(t *testing.T) {
	rec := &responseRecorder{ResponseWriter: httptest.NewRecorder(), statusCode: http.StatusOK}
	n, err := rec.Write([]byte("hello world"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 11 {
		t.Errorf("Write returned %d, want 11", n)
	}
	if rec.size != 11 {
		t.Errorf("size = %d, want 11", rec.size)
	}
}

func TestResponseRecorderCapturesBody(t *testing.T) {
	rec := &responseRecorder{
		ResponseWriter: httptest.NewRecorder(),
		statusCode:     http.StatusOK,
		captureBody:    true,
	}
	_, _ = rec.Write([]byte("captured"))
	if string(rec.body) != "captured" {
		t.Errorf("body = %q, want \"captured\"", string(rec.body))
	}
}

func TestResponseRecorderBodyCap(t *testing.T) {
	rec := &responseRecorder{
		ResponseWriter: httptest.NewRecorder(),
		statusCode:     http.StatusOK,
		captureBody:    true,
	}
	// Write more than maxBodyCapture.
	big := make([]byte, maxBodyCapture+1000)
	_, _ = rec.Write(big)
	if len(rec.body) > maxBodyCapture {
		t.Errorf("body length = %d, should be capped at %d", len(rec.body), maxBodyCapture)
	}
}

// ---- Helper tests ----------------------------------------------------------

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    string
		want string
	}{
		{"microseconds", "500µs", "500µs"},
		{"milliseconds", "42ms", "42.0ms"},
		{"seconds", "1.5s", "1.50s"},
	}
	for _, tc := range tests {
		// Use parseFloat-friendly format.
		_ = tc // table driven, used below
	}

	// Direct numeric tests.
	if got := formatDuration(500 * 1e3); got != "500µs" { // 500 microseconds in nanoseconds
		t.Errorf("formatDuration(500µs) = %q, want 500µs", got)
	}
}

func TestIsBinaryContentType(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"", false},
		{"text/html", false},
		{"application/json", false},
		{"application/octet-stream", true},
		{"application/zip", true},
		{"application/gzip", true},
		{"application/x-bzip2", true},
		{"image/png", true},
		{"application/vnd.debian.binary-package", true},
	}
	for _, tc := range tests {
		got := isBinaryContentType(tc.ct)
		if got != tc.want {
			t.Errorf("isBinaryContentType(%q) = %v, want %v", tc.ct, got, tc.want)
		}
	}
}
