package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// newDenialServer builds a Server whose real middleware chain is what the test
// drives. A unit test on the recorder would pass against the broken tree this
// replaces: the defect was that no chain position called Record at all, so
// every assertion here goes through Handler().
func newDenialServer(t *testing.T, adminCIDR, denyList []string) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		AptCodename:     "noble",
		LogDir:          dir,
		AuditDB:         filepath.Join(dir, "audit.db"),
		AdminPermitCIDR: adminCIDR,
		DenyList:        denyList,
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB == nil {
		t.Fatal("audit DB not opened; the test would assert nothing")
	}
	t.Cleanup(func() { _ = s.auditDB.Close() })
	return s
}

// denials returns every EventDenied row, newest first.
func denials(t *testing.T, s *Server) []audit.StoredEvent {
	t.Helper()
	rows, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventDenied})
	if err != nil {
		t.Fatalf("query audit db: %v", err)
	}
	return rows
}

// wantOneDenial asserts exactly one denial row with the given reason and
// client, and returns its decoded details.
func wantOneDenial(t *testing.T, s *Server, reason, clientIP string) map[string]string {
	t.Helper()
	rows := denials(t, s)
	if len(rows) != 1 {
		t.Fatalf("denial rows = %d, want 1 (%+v)", len(rows), rows)
	}
	row := rows[0]
	if row.Status != reason {
		t.Errorf("status = %q, want %q", row.Status, reason)
	}
	if row.ClientIP != clientIP {
		t.Errorf("client_ip = %q, want %q", row.ClientIP, clientIP)
	}
	if row.Timestamp.IsZero() {
		t.Error("timestamp is zero")
	}
	details := map[string]string{}
	if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
		t.Fatalf("details %q is not JSON: %v", row.Details, err)
	}
	return details
}

func doRequest(s *Server, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:33333"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	return rec
}

func TestDenyListDenialRecorded(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, []string{"203.0.113.0/24"})

	rec := doRequest(s, "GET", "/apt/dists/noble/Release", map[string]string{"X-Real-IP": "203.0.113.9"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	details := wantOneDenial(t, s, audit.DenialDenyList, "203.0.113.9")
	if details["path"] != "/apt/dists/noble/Release" || details["method"] != "GET" {
		t.Errorf("details = %v, want the method and path", details)
	}
}

func TestMutationDenialUnparseableIP(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)

	rec := doRequest(s, "DELETE", "/api/v1/packages/apt/hello", map[string]string{"X-Real-IP": "not-an-ip"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	details := wantOneDenial(t, s, audit.DenialUnparseableIP, "not-an-ip")
	if details["method"] != "DELETE" {
		t.Errorf("details = %v, want method DELETE", details)
	}
	rows := denials(t, s)
	if rows[0].PkgType != "apt" || rows[0].PkgName != "hello" {
		t.Errorf("pkg = %q/%q, want apt/hello", rows[0].PkgType, rows[0].PkgName)
	}
}

func TestMutationDenialIPNotPermitted(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)

	rec := doRequest(s, "DELETE", "/api/v1/packages/apt/hello", map[string]string{
		"X-Real-IP":  "203.0.113.9",
		"User-Agent": "curl/8.5.0",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	wantOneDenial(t, s, audit.DenialIPNotPermitted, "203.0.113.9")
	if ua := denials(t, s)[0].UserAgent; ua != "curl/8.5.0" {
		t.Errorf("user_agent = %q, want curl/8.5.0", ua)
	}
}

func TestMutationDenialNoTokensConfigured(t *testing.T) {
	s := newDenialServer(t, []string{"10.0.0.0/8"}, nil)

	rec := doRequest(s, "POST", "/api/v1/packages/apt", map[string]string{"X-Real-IP": "10.0.0.5"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	wantOneDenial(t, s, audit.DenialNoTokens, "10.0.0.5")
}

func TestMutationDenialTokenMissing(t *testing.T) {
	s := newDenialServer(t, []string{"10.0.0.0/8"}, nil)
	insertToken(t, s, "tok-present", "secret-token", nil)

	rec := doRequest(s, "POST", "/api/v1/packages/apt", map[string]string{"X-Real-IP": "10.0.0.5"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	wantOneDenial(t, s, audit.DenialTokenMissing, "10.0.0.5")
}

func TestMutationDenialTokenInvalid(t *testing.T) {
	s := newDenialServer(t, []string{"10.0.0.0/8"}, nil)
	insertToken(t, s, "tok-present", "secret-token", nil)

	rec := doRequest(s, "POST", "/api/v1/packages/apt", map[string]string{
		"X-Real-IP":     "10.0.0.5",
		"Authorization": "Bearer wrong-token",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	details := wantOneDenial(t, s, audit.DenialTokenInvalid, "10.0.0.5")
	prefix := details["hash_prefix"]
	if len(prefix) != 12 {
		t.Errorf("hash_prefix = %q, want 12 hex chars", prefix)
	}
	full := audit.HashToken("wrong-token", s.pepper)
	if !strings.HasPrefix(full, prefix) {
		t.Errorf("hash_prefix %q is not a prefix of the peppered hash", prefix)
	}
	assertNoSecret(t, s, "wrong-token", full)
}

func TestMutationDenialTokenExpired(t *testing.T) {
	s := newDenialServer(t, []string{"10.0.0.0/8"}, nil)
	expired := time.Now().Add(-time.Hour)
	insertToken(t, s, "tok-stale", "secret-token", &expired)

	rec := doRequest(s, "POST", "/api/v1/packages/apt", map[string]string{
		"X-Real-IP":     "10.0.0.5",
		"Authorization": "Bearer secret-token",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	details := wantOneDenial(t, s, audit.DenialTokenExpired, "10.0.0.5")
	if details["token_id"] != "tok-stale" {
		t.Errorf("token_id = %q, want tok-stale", details["token_id"])
	}
	assertNoSecret(t, s, "secret-token", audit.HashToken("secret-token", s.pepper))
}

// TestAdminReadDenialRecorded covers the gate the walk turned up: the
// admin-only read endpoints sit behind the mutation middleware, so a refused
// read of the audit trail was itself absent from the audit trail.
func TestAdminReadDenialRecorded(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)

	rec := doRequest(s, "GET", "/api/v1/audit", map[string]string{"X-Real-IP": "203.0.113.9"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	details := wantOneDenial(t, s, audit.DenialAdminOnly, "203.0.113.9")
	if details["path"] != "/api/v1/audit" {
		t.Errorf("details = %v, want path /api/v1/audit", details)
	}
}

// TestDenialFieldsAreCapped: the row is written before any handler has
// validated the request, so an unauthenticated caller must not choose how many
// bytes each 403 costs.
func TestDenialFieldsAreCapped(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)

	long := strings.Repeat("a", 4096)
	rec := doRequest(s, "DELETE", "/api/v1/packages/apt/"+long, map[string]string{
		"X-Real-IP":  "203.0.113.9",
		"User-Agent": long,
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	row := denials(t, s)[0]
	for name, v := range map[string]string{
		"pkg_name":   row.PkgName,
		"user_agent": row.UserAgent,
		"details":    row.Details,
	} {
		if len(v) > 1024 {
			t.Errorf("%s is %d bytes, want capped", name, len(v))
		}
	}
}

// TestServeLifecycleRecorded pairs with the denial rows: a reader has to be
// able to tell "nobody was turned away" from "the server was not running".
func TestServeLifecycleRecorded(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)
	s.SetQuiet(true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()

	waitFor(t, func() bool { return countEvents(t, s, audit.EventServeStart) == 1 })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("server did not shut down")
	}
	waitFor(t, func() bool { return countEvents(t, s, audit.EventServeStop) == 1 })

	rows, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventServeStart})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	details := map[string]any{}
	if err := json.Unmarshal([]byte(rows[0].Details), &details); err != nil {
		t.Fatalf("details %q is not JSON: %v", rows[0].Details, err)
	}
	if addr, _ := details["addr"].(string); !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("addr = %v, want the bound address", details["addr"])
	}
	if rows[0].Actor == "" {
		t.Error("actor is empty; the row cannot say who started the server")
	}
}

func insertToken(t *testing.T, s *Server, id, token string, expires *time.Time) {
	t.Helper()
	if err := s.auditDB.InsertToken(context.Background(), id, id,
		audit.HashToken(token, s.pepper), "", expires); err != nil {
		t.Fatalf("insert token: %v", err)
	}
}

// assertNoSecret fails if any column of any row carries the credential or its
// full hash. Every tool is a security tool, and an audit trail that leaks the
// token it rejected is worse than no row at all.
func assertNoSecret(t *testing.T, s *Server, token, fullHash string) {
	t.Helper()
	rows, err := s.auditDB.Query(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	for _, row := range rows {
		blob := strings.Join([]string{row.Details, row.Status, row.UserAgent,
			row.PkgName, row.PkgType, row.ClientIP, row.Actor}, "\x00")
		if strings.Contains(blob, token) {
			t.Errorf("row %d carries the bearer token", row.ID)
		}
		if strings.Contains(blob, fullHash) {
			t.Errorf("row %d carries the full token hash", row.ID)
		}
	}
}

func countEvents(t *testing.T, s *Server, ev audit.EventType) int64 {
	t.Helper()
	rows, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: ev})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return int64(len(rows))
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within 10s")
}
