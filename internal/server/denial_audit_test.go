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
		// Start refuses an unencrypted listener nobody requested; these tests
		// are about audit rows, so they make the request. See guardPlaintext.
		AllowPlaintext: true,
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

// TestDenialRecordedAfterClientHangsUp drives the context net/http cancels when
// a client closes the connection before reading the response. Firing a request
// and hanging up is ordinary scanner behavior, so a row written on the request
// context is missing exactly for the callers it exists to name. Every other
// test in this file drives a context that is never cancelled and passes either
// way (#106).
func TestDenialRecordedAfterClientHangsUp(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("DELETE", "/api/v1/packages/apt/hello", nil).WithContext(ctx)
	req.RemoteAddr = "127.0.0.1:33333"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	wantOneDenial(t, s, audit.DenialIPNotPermitted, "203.0.113.9")
}

// TestFrozenDeleteDenialRecorded covers the one refusal-class 403 that lives in
// a handler rather than the middleware chain. Freeze is a protection control,
// so the row answers "who tried to remove a pinned artifact" (#107).
func TestFrozenDeleteDenialRecorded(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)
	if err := s.store.AddVersion(t.Context(), manifest.TypeApt, "hello", manifest.VersionEntry{
		Version: "1.0",
		Frozen:  true,
	}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}

	rec := doRequest(s, "DELETE", "/api/v1/packages/apt/hello", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}

	details := wantOneDenial(t, s, audit.DenialFrozenEntry, "127.0.0.1")
	if details["pkg_name"] != "hello" || details["pkg_type"] != "apt" {
		t.Errorf("details = %v, want the frozen entry named", details)
	}
	if row := denials(t, s)[0]; row.PkgType != "apt" || row.PkgName != "hello" {
		t.Errorf("pkg = %q/%q, want apt/hello", row.PkgType, row.PkgName)
	}
}

// TestVersionConstraintDenialsRecorded covers the two 403s a version constraint
// produces. They read as a broken client until a row names the constraint that
// refused (#104).
func TestVersionConstraintDenialsRecorded(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pkgType    string
		pkgName    string
		entryVer   string
		path       string
		wantReqVer string
	}{
		{
			name: "gomod", pkgType: manifest.TypeGomod, pkgName: "example.com/mod",
			entryVer: "v1.2.0", path: "/go/example.com/mod/@v/v9.9.9.info", wantReqVer: "v9.9.9",
		},
		{
			name: "npm", pkgType: manifest.TypeNpm, pkgName: "leftpad",
			entryVer: "1.2.0", path: "/npm/leftpad/-/leftpad-9.9.9.tgz", wantReqVer: "9.9.9",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)
			if err := s.store.AddVersion(t.Context(), tc.pkgType, tc.pkgName, manifest.VersionEntry{
				Version:           tc.entryVer,
				VersionConstraint: manifest.ConstraintExact,
				Mode:              manifest.ModeProxy,
			}); err != nil {
				t.Fatalf("seed manifest: %v", err)
			}

			rec := doRequest(s, "GET", tc.path, nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
			}

			details := wantOneDenial(t, s, audit.DenialVersionConstraint, "127.0.0.1")
			if details["constraint"] != manifest.ConstraintExact || details["entry_version"] != tc.entryVer {
				t.Errorf("details = %v, want the constraint and the entry version", details)
			}
			row := denials(t, s)[0]
			if row.PkgType != tc.pkgType || row.PkgName != tc.pkgName {
				t.Errorf("pkg = %q/%q, want %q/%q", row.PkgType, row.PkgName, tc.pkgType, tc.pkgName)
			}
			if row.PkgVersion != tc.wantReqVer {
				t.Errorf("pkg_version = %q, want the refused version %q", row.PkgVersion, tc.wantReqVer)
			}
		})
	}
}

// TestServerAppliesAuditConfigToItsOwnHandle covers the split nobody could see
// from outside: newServer opened its *audit.DB and never called SetEventFilter
// or SetTimezone, so audit_events limited nothing the server wrote and timezone
// never reached GET /api/v1/audit. Only the CLI's handle was configured (#103).
func TestServerAppliesAuditConfigToItsOwnHandle(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		AptCodename:     "noble",
		LogDir:          dir,
		AuditDB:         filepath.Join(dir, "audit.db"),
		AdminPermitCIDR: []string{"127.0.0.0/8"},
		AllowPlaintext:  true,
		Timezone:        "America/New_York",
		AuditEvents:     []string{string(audit.EventServeFetch)},
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB == nil {
		t.Fatal("audit DB not opened; the test would assert nothing")
	}
	t.Cleanup(func() { _ = s.auditDB.Close() })

	if loc := s.auditDB.DisplayLocation().String(); loc != "America/New_York" {
		t.Errorf("display timezone = %q, want America/New_York", loc)
	}
	if s.auditDB.ShouldRecord(audit.EventDenied) {
		t.Error("audit_events listing only serve_fetch still records denials")
	}

	// End to end: the filter has to reach the write, not just the handle.
	rec := doRequest(s, "DELETE", "/api/v1/packages/apt/hello", map[string]string{"X-Real-IP": "203.0.113.9"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — the filter must not change what the server answers", rec.Code)
	}
	if rows := denials(t, s); len(rows) != 0 {
		t.Errorf("denial rows = %d, want 0 — audit_events excluded the type (%+v)", len(rows), rows)
	}
}
