package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// newSinkServer builds a server whose event stream goes to sink, with the
// embedded store in its own temp tree.
func newSinkServer(t *testing.T, sink, dsn string) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		AptCodename:    "noble",
		LogDir:         dir,
		AuditDB:        filepath.Join(dir, "audit.db"),
		StoragePath:    dir,
		AuditSink:      sink,
		AuditSinkDSN:   dsn,
		AllowPlaintext: true,
		// config.Load supplies these; a hand-built Config does not, and the
		// admin gate runs ahead of the sink check, so without them every case
		// here would assert against a 403.
		AdminPermitCIDR: []string{"127.0.0.0/8", "::1/128"},
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), storage.NewSingle(storage.NewMemory()),
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() {
		if s.auditDB != nil {
			_ = s.auditDB.Close()
		}
	})
	return s
}

// GET /api/v1/audit must say which sink cannot answer. An empty 200 on a
// server that is recording everything is the worst available answer, and a 503
// would promise a condition that never clears.
func TestAuditAPIRefusesUnderAWriteOnlySink(t *testing.T) {
	jsonlPath := filepath.Join(t.TempDir(), "audit.jsonl")
	s := newSinkServer(t, audit.SinkJSONL, jsonlPath)
	if s.auditErr != nil {
		t.Fatalf("jsonl sink did not open: %v", s.auditErr)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/api/v1/audit") //nolint:noctx // test client
	if err != nil {
		t.Fatalf("GET /api/v1/audit: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["sink"] != audit.SinkJSONL {
		t.Errorf("sink field = %q, want %q", body["sink"], audit.SinkJSONL)
	}
	// The operator has to be able to act on this without reading the source.
	for _, want := range []string{audit.SinkJSONL, audit.SinkPostgres, "write-only"} {
		if !strings.Contains(body["error"], want) {
			t.Errorf("error does not mention %q: %s", want, body["error"])
		}
	}
}

// The control for the case above: the same endpoint answers under the default
// sink, so the 501 is a property of the sink and not of the route.
func TestAuditAPIAnswersUnderSQLite(t *testing.T) {
	s := newSinkServer(t, audit.SinkSQLite, "")
	if s.auditErr != nil {
		t.Fatalf("sqlite sink did not open: %v", s.auditErr)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/api/v1/audit") //nolint:noctx // test client
	if err != nil {
		t.Fatalf("GET /api/v1/audit: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// A write-only sink still records. The refusal above is about reading back,
// and a test that only asserted the 501 would pass against a sink that dropped
// every event on the floor.
func TestWriteOnlySinkStillRecords(t *testing.T) {
	jsonlPath := filepath.Join(t.TempDir(), "audit.jsonl")
	s := newSinkServer(t, audit.SinkJSONL, jsonlPath)
	if err := s.auditDB.Record(context.Background(), audit.Event{
		EventType: audit.EventDenied,
		Status:    audit.DenialTokenExpired,
		ClientIP:  "10.9.8.7",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	b, err := os.ReadFile(jsonlPath) //nolint:gosec // G304: this test's own temp file.
	if err != nil {
		t.Fatalf("read jsonl: %v", err)
	}
	line := strings.TrimSpace(string(b))
	if !strings.Contains(line, `"client_ip":"10.9.8.7"`) || !strings.Contains(line, `"status":"token_expired"`) {
		t.Errorf("event did not reach the jsonl sink: %s", line)
	}
}

// A sink that will not connect is fatal for serve, held on auditErr and
// returned before the listener binds. Logging it and continuing is what left a
// server answering /healthz while dropping the record of what it refuses.
func TestUnreachableSinkIsFatalForServe(t *testing.T) {
	// Port 1 on loopback: nothing listens, and the connection is refused
	// rather than timing out, so the case does not wait on the ping bound.
	s := newSinkServer(t, audit.SinkPostgres, "postgres://bodega@127.0.0.1:1/bodega?sslmode=disable&connect_timeout=2")
	if s.auditErr == nil {
		t.Fatal("newServer accepted an unreachable postgres sink; serve would start with no audit trail")
	}
	for _, want := range []string{"audit_sink", audit.SinkPostgres, "audit_db"} {
		if !strings.Contains(s.auditErr.Error(), want) {
			t.Errorf("auditErr does not mention %q: %v", want, s.auditErr)
		}
	}
	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("Start bound a listener with a failed audit sink")
	}
	if !strings.Contains(err.Error(), "audit") {
		t.Errorf("Start returned %v, want the audit refusal", err)
	}
}
