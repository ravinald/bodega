package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// spoolTestServer is the smallest Server spoolUpstream needs: a limiter over a
// temp directory and a logger. Nothing else on the proxy path is exercised.
func spoolTestServer(t *testing.T, maxArtifact, budget int64) *Server {
	t.Helper()
	dir := t.TempDir()
	return &Server{
		spool:  newSpoolLimiter(dir, maxArtifact, budget),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// dirBytes totals what the spool directory is holding right now. The budget is
// a claim about bytes on disk, so the assertion has to read the disk.
//
// It takes no *testing.T and reports no error because the sampler below calls
// it from its own goroutine, where a t.Fatal would be a race rather than a
// failure. A file removed between the listing and the stat is the ordinary
// case: that is a spool closing.
func dirBytes(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		total += info.Size()
	}
	return total
}

// largeArtifactUpstream serves n bytes of filler at any path, with the length
// declared. Callers give each fetch its own path so nothing coalesces: the apt
// mirror's per-key lock is the only thing in bodega that merges concurrent
// fetches, and it covers neither distinct keys nor any other type.
func largeArtifactUpstream(t *testing.T, n int) *httptest.Server {
	t.Helper()
	body := bytes.Repeat([]byte("A"), n)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		//nolint:gosec // G705: fixture bytes with an explicit Content-Type; nothing here comes from the request.
		_, _ = w.Write(body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// Eight concurrent fetches of eight distinct 256 KiB artifacts against a
// 768 KiB budget. Three are admitted, five are refused, and the spool directory
// never holds more than the budget while that happens.
//
// The stub serves the same filler byte at every path, with Content-Length
// declared, which is what lets the budget be claimed whole before the copy
// starts rather than discovered partway through it. The paths differ so that
// nothing coalesces; the bytes need not.
func TestConcurrentSpoolsStayUnderTheBudget(t *testing.T) {
	allowLoopbackUpstream(t)

	// Kilobytes rather than megabytes: the assertions are about the
	// arithmetic of the budget, not about throughput, and `go test ./...`
	// runs package binaries side by side — a few megabytes of concurrent
	// copying here is CPU and I/O taken from whatever is running next to it.
	const (
		artifact = 256 << 10
		budget   = 3 * artifact
		fetches  = 8
	)
	ts := largeArtifactUpstream(t, artifact)
	s := spoolTestServer(t, 2*artifact, budget)

	// Sampled from a second goroutine rather than checked at the end: the
	// interesting claim is that the directory is under the budget while the
	// copies are running, and a total taken after they finish would hold even
	// if every fetch had been admitted and then cleaned up.
	var (
		watchMu sync.Mutex
		peakOn  int64
	)
	stop := make(chan struct{})
	var watcher sync.WaitGroup
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			n := dirBytes(s.spool.dir)
			watchMu.Lock()
			if n > peakOn {
				peakOn = n
			}
			watchMu.Unlock()
			time.Sleep(2 * time.Millisecond)
		}
	}()

	var (
		mu       sync.Mutex
		held     []*spooledUpstream
		refusals []error
		wg       sync.WaitGroup
		release  = make(chan struct{})
	)
	for i := 0; i < fetches; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			up, err := openUpstream(t.Context(), fmt.Sprintf("%s/%d/artifact.bin", ts.URL, i))
			if err != nil {
				t.Errorf("openUpstream: %v", err)
				return
			}
			defer up.body.Close()
			sp, err := s.spoolUpstream(up)
			mu.Lock()
			if err != nil {
				refusals = append(refusals, err)
			} else {
				held = append(held, sp)
			}
			mu.Unlock()
			if err == nil {
				// Hold the spool open until every goroutine has had its
				// answer. Closing early would return the bytes to the budget
				// and let a later fetch in, which is correct behavior and the
				// wrong thing to measure here.
				<-release
			}
		}(i)
	}

	// The admitted fetches are parked on release; the refused ones are done.
	// Waiting for len(held)+len(refusals) == fetches rather than for wg is
	// what lets the assertions run while the budget is still held.
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(held)+len(refusals) == fetches
	})

	mu.Lock()
	admitted, refused := len(held), len(refusals)
	sample := refusals
	mu.Unlock()

	if admitted != budget/artifact {
		t.Errorf("admitted = %d, want %d — the budget takes exactly that many whole artifacts", admitted, budget/artifact)
	}
	if refused != fetches-budget/artifact {
		t.Errorf("refused = %d, want %d", refused, fetches-budget/artifact)
	}
	for _, err := range sample {
		if got := spoolDenialReason(err); got != audit.DenialSpoolBudget {
			t.Errorf("refusal %q maps to reason %q, want %q", err, got, audit.DenialSpoolBudget)
		}
		if !strings.Contains(err.Error(), "spool_max_total_bytes") {
			t.Errorf("refusal = %q, want it to name the key an operator would raise", err)
		}
	}

	st := s.spool.stats()
	if st.UsedBytes != int64(admitted)*artifact {
		t.Errorf("stats used_bytes = %d, want %d", st.UsedBytes, int64(admitted)*artifact)
	}
	if st.RefusedBudget != int64(refused) {
		t.Errorf("stats refused_budget = %d, want %d", st.RefusedBudget, refused)
	}
	if st.InFlight != admitted {
		t.Errorf("stats in_flight = %d, want %d", st.InFlight, admitted)
	}

	close(release)
	wg.Wait()
	close(stop)
	watcher.Wait()

	watchMu.Lock()
	peak := peakOn
	watchMu.Unlock()
	if peak > budget {
		t.Errorf("spool directory peaked at %d bytes, over the %d-byte budget", peak, budget)
	}
	if peak == 0 {
		t.Error("the watcher never saw a byte in the spool directory, so it proved nothing")
	}

	for _, sp := range held {
		sp.close()
	}
	if n := dirBytes(s.spool.dir); n != 0 {
		t.Errorf("spool directory holds %d bytes after every spool closed, want 0", n)
	}
	if used := s.spool.stats().UsedBytes; used != 0 {
		t.Errorf("stats used_bytes = %d after every spool closed, want 0", used)
	}
}

// A declared length over the per-artifact ceiling is refused before the copy.
// The stub declares more than it sends, so a refusal that had waited for the
// body would have come back as the cut-transfer error instead — which is what
// makes "before" falsifiable rather than asserted.
func TestDeclaredLengthOverTheArtifactCeilingIsRefusedBeforeTheCopy(t *testing.T) {
	allowLoopbackUpstream(t)

	s := spoolTestServer(t, 1024, 0)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer ts.Close()

	up, err := openUpstream(t.Context(), ts.URL)
	if err != nil {
		t.Fatalf("openUpstream: %v", err)
	}
	defer up.body.Close()

	sp, err := s.spoolUpstream(up)
	if err == nil {
		sp.close()
		t.Fatal("spoolUpstream accepted an artifact whose declared length is over the ceiling")
	}
	if got := spoolDenialReason(err); got != audit.DenialSpoolArtifactTooLarge {
		t.Errorf("reason = %q, want %q", got, audit.DenialSpoolArtifactTooLarge)
	}
	if !strings.Contains(err.Error(), "declares 4096 bytes") {
		t.Errorf("error = %q, want it to name the declared length rather than what was read", err)
	}
	if n := dirBytes(s.spool.dir); n != 0 {
		t.Errorf("spool directory holds %d bytes, want none written", n)
	}
	if st := s.spool.stats(); st.InFlight != 0 || st.UsedBytes != 0 {
		t.Errorf("stats = %+v, want nothing in flight after a refusal", st)
	}
}

// A chunked response declares no length, so the ceiling can only be enforced
// on the way through. That is the shape of every transparently-decompressed
// upstream body and of an upstream that simply omits Content-Length.
func TestUndeclaredBodyOverTheArtifactCeilingIsRefusedDuringTheCopy(t *testing.T) {
	allowLoopbackUpstream(t)

	s := spoolTestServer(t, 4096, 0)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		for i := 0; i < 16; i++ {
			_, _ = w.Write(bytes.Repeat([]byte("y"), 2048))
		}
	}))
	defer ts.Close()

	up, err := openUpstream(t.Context(), ts.URL)
	if err != nil {
		t.Fatalf("openUpstream: %v", err)
	}
	defer up.body.Close()
	if up.contentLength >= 0 {
		t.Fatalf("upstream declared %d bytes; the test needs the undeclared case", up.contentLength)
	}

	sp, err := s.spoolUpstream(up)
	if err == nil {
		sp.close()
		t.Fatal("spoolUpstream accepted an undeclared body over the per-artifact ceiling")
	}
	if got := spoolDenialReason(err); got != audit.DenialSpoolArtifactTooLarge {
		t.Errorf("reason = %q, want %q", got, audit.DenialSpoolArtifactTooLarge)
	}
	if !strings.Contains(err.Error(), "declared no length") {
		t.Errorf("error = %q, want it to say the ceiling could only be caught on the way through", err)
	}
	if n := dirBytes(s.spool.dir); n != 0 {
		t.Errorf("spool directory holds %d bytes after the refusal, want 0", n)
	}
	if used := s.spool.stats().UsedBytes; used != 0 {
		t.Errorf("stats used_bytes = %d after the refusal, want 0", used)
	}
}

// The refusal has to reach an operator. A 503 with Retry-After answers the
// client, a denial row answers "why did that fetch not happen" from the same
// table every other refusal reaches, and GET /api/v1/status carries the gauge.
func TestSpoolRefusalAnswers503AndWritesItsRow(t *testing.T) {
	allowLoopbackUpstream(t)

	const pkg = "leftpad"
	key := manifest.NpmTarballKey(pkg, "1.2.0")
	ts := largeArtifactUpstream(t, 4096)

	s := newDiscoveryServer(t)
	// A budget of one byte: any artifact at all is over it, which is the
	// state a host under fleet load reaches on its own.
	s.spool = newSpoolLimiter(t.TempDir(), 0, 1)
	var logged bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelError}))

	req := httptest.NewRequest(http.MethodGet, "/npm/"+pkg+"/-/"+pkg+"-1.2.0.tgz", nil)
	req.RemoteAddr = "10.9.9.9:44444"
	rec := httptest.NewRecorder()
	s.proxyOrResolve(rec, req, storage.NewMemory(), key,
		func(context.Context) (string, error) { return ts.URL + "/1/leftpad.tgz", nil },
		"", manifest.TypeNpm, pkg, pkg, false, true)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != spoolRetryAfter {
		t.Errorf("Retry-After = %q, want %q", got, spoolRetryAfter)
	}
	if !strings.Contains(rec.Body.String(), "spool_max_total_bytes") {
		t.Errorf("body = %q, want it to name the key that refused", rec.Body.String())
	}

	// Error rather than Warn: the shipped default log_level prints only
	// Error, so a refusal logged any quieter reaches nobody by default.
	line := logged.String()
	for _, want := range []string{"spool is at its bound", audit.DenialSpoolBudget, "spool_max_total_bytes", key} {
		if !strings.Contains(line, want) {
			t.Errorf("log = %q, want it to carry %q", line, want)
		}
	}

	rows := denials(t, s)
	if len(rows) != 1 {
		t.Fatalf("denial rows = %d, want 1 (%+v)", len(rows), rows)
	}
	if rows[0].Status != audit.DenialSpoolBudget {
		t.Errorf("status = %q, want %q", rows[0].Status, audit.DenialSpoolBudget)
	}
	if rows[0].ClientIP != "10.9.9.9" {
		t.Errorf("client_ip = %q, want 10.9.9.9", rows[0].ClientIP)
	}
	if !strings.Contains(rows[0].Details, "spool_max_total_bytes") {
		t.Errorf("details = %q, want the budget in the row", rows[0].Details)
	}

	gauge := statusSpool(t, s, "127.0.0.1:5555")
	if gauge.RefusedBudget != 1 || gauge.BudgetBytes != 1 {
		t.Errorf("status spool = %+v, want the refusal counted against the configured budget", gauge)
	}

	// The bounds the process started with ride on the lifecycle row, so a
	// reader of the denial table can tell a run at this budget from the one
	// after someone raised it.
	s.recordLifecycle(audit.EventServeStart, "127.0.0.1:0", false)
	starts, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventServeStart})
	if err != nil {
		t.Fatalf("query serve_start: %v", err)
	}
	if len(starts) != 1 {
		t.Fatalf("serve_start rows = %d, want 1", len(starts))
	}
	var lifecycle struct {
		SpoolDir   string `json:"spool_dir"`
		SpoolTotal int64  `json:"spool_max_total_bytes"`
	}
	if err := json.Unmarshal([]byte(starts[0].Details), &lifecycle); err != nil {
		t.Fatalf("decode serve_start details: %v", err)
	}
	if lifecycle.SpoolDir != s.spool.dir || lifecycle.SpoolTotal != 1 {
		t.Errorf("serve_start details = %s, want the spool directory and budget", starts[0].Details)
	}
}

// statusSpool reads the spool block off GET /api/v1/status as seen from one
// client address.
func statusSpool(t *testing.T, s *Server, remoteAddr string) spoolStats {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	s.handleAPIStatus(rec, req)
	var body struct {
		Spool spoolStats `json:"spool"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode GET /api/v1/status: %v", err)
	}
	return body.Spool
}

// GET /api/v1/status answers any client that can reach the server, so the
// spool block withholds the one field that is a fact about the host rather
// than about what it serves. The counters stay visible: a client acting on a
// 503 has to be able to see why it got one.
func TestStatusSpoolBlockWithholdsThePathFromNonAdmins(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)
	s.spool = newSpoolLimiter(t.TempDir(), 4096, 8192)

	admin := statusSpool(t, s, "127.0.0.1:5555")
	if admin.Dir != s.spool.dir {
		t.Errorf("status spool.dir = %q for an admin caller, want %q", admin.Dir, s.spool.dir)
	}

	public := statusSpool(t, s, "203.0.113.7:5555")
	if public.Dir != "" {
		t.Errorf("status spool.dir = %q for a caller outside admin_permit_cidr, want it withheld", public.Dir)
	}
	if public.BudgetBytes != 8192 || public.MaxArtifactBytes != 4096 {
		t.Errorf("status spool = %+v for a non-admin caller, want the ceilings kept", public)
	}
}

// The spool is disk this process spends on behalf of every proxy client, so a
// location it cannot write is a startup condition and not a per-request
// surprise. A file where the directory should be fails identically for root
// and for the serving user, which chmod does not.
func TestStartRefusesAnUnwritableSpoolDir(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("in the way\n"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	cfg := &config.Config{
		AptCodename:    "noble",
		LogDir:         dir,
		StoragePath:    dir,
		SpoolDir:       filepath.Join(blocked, "tmp"),
		AllowPlaintext: true,
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB != nil {
		t.Cleanup(func() { _ = s.auditDB.Close() })
	}

	err := s.Start(t.Context())
	if err == nil {
		t.Fatal("Start bound a listener over a spool directory it cannot create")
	}
	if !strings.Contains(err.Error(), "spool_dir") {
		t.Errorf("error = %q, want it to name spool_dir", err)
	}
	if !strings.Contains(err.Error(), "proxied artifact") {
		t.Errorf("error = %q, want it to say what the directory is for", err)
	}
}

// <storage_path>/tmp is the default, and build_root does not displace it even
// when set. docs/bodega.service runs ProtectSystem=strict with ReadWritePaths
// naming storage_path and log_dir alone, so a spool under build_root's
// /opt/bodega default is a directory the service cannot create: serve refused
// to start on the deployment the shipped unit describes. Deriving it from
// $TMPDIR instead would put the artifact traffic on a filesystem nobody chose.
func TestSpoolDirDefaultsUnderStoragePath(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		AptCodename: "noble",
		LogDir:      t.TempDir(),
		StoragePath: root,
		BuildRoot:   filepath.Join(t.TempDir(), "unwritable-by-the-unit"),
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB != nil {
		t.Cleanup(func() { _ = s.auditDB.Close() })
	}
	if s.spoolErr != nil {
		t.Fatalf("spool refused a writable build root: %v", s.spoolErr)
	}
	want := filepath.Join(root, "tmp")
	if s.spool.dir != want {
		t.Errorf("spool dir = %q, want %q", s.spool.dir, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Errorf("spool dir was not created at startup: %v", err)
	}
}
