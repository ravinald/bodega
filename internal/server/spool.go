package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/ravinald/bodega/internal/audit"
)

// The two ways a spool is refused. Callers match on these to decide the status
// code and the audit reason; the wrapping error carries the numbers.
var (
	errSpoolArtifactTooLarge = errors.New("over the per-artifact spool ceiling")
	errSpoolBudgetExhausted  = errors.New("the spool byte budget is exhausted")
)

// spoolRetryAfter is what a client over the budget is told to wait. Short
// because the budget clears as in-flight fetches finish, not on a timer.
const spoolRetryAfter = "5"

// spoolLimiter is the disk bound on proxy fetches: where spool files land, how
// large one artifact may be, and how many bytes every in-flight spool may hold
// between them.
//
// The shared bound is bytes rather than a count of concurrent fetches because
// bytes are what runs the filesystem out. Eight fetches in flight is 8 MB or
// 64 GB depending on what was requested, so a count tuned for one artifact
// size is the wrong bound for the next one.
//
// A request over the bound is refused, not queued. Queuing turns a disk bound
// into a latency bound: a fleet running apt-get update off one cron minute
// would hold a goroutine and a connection each behind the 90s upstream
// timeout, and the clients would time out anyway with nothing recorded about
// why. A 503 with Retry-After is an answer apt can act on.
type spoolLimiter struct {
	dir         string
	maxArtifact int64 // 0 removes the per-artifact ceiling
	budget      int64 // 0 removes the shared budget

	mu       sync.Mutex
	used     int64
	peak     int64
	inFlight int

	refusedTooLarge int64
	refusedBudget   int64
}

// spoolStats is the live gauge behind GET /api/v1/status. An operator whose
// fetches start refusing reads the reason in the log line and the row, and
// reads how close the spool is to its bound here.
//
// Dir is omitted for a caller outside admin_permit_cidr, and the rest is not.
// GET /api/v1/status answers any client that can reach the server, and a
// server filesystem path is a fact about the host rather than about what it
// serves. The byte counters stay: "this instance is busy" is what the endpoint
// is for, and a client acting on a 503 has to be able to see it.
type spoolStats struct {
	Dir              string `json:"dir,omitempty"`
	InFlight         int    `json:"in_flight"`
	UsedBytes        int64  `json:"used_bytes"`
	PeakBytes        int64  `json:"peak_bytes"`
	BudgetBytes      int64  `json:"budget_bytes"`
	MaxArtifactBytes int64  `json:"max_artifact_bytes"`
	RefusedTooLarge  int64  `json:"refused_too_large"`
	RefusedBudget    int64  `json:"refused_budget"`
}

func newSpoolLimiter(dir string, maxArtifact, budget int64) *spoolLimiter {
	return &spoolLimiter{dir: dir, maxArtifact: maxArtifact, budget: budget}
}

func (l *spoolLimiter) stats() spoolStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return spoolStats{
		Dir:              l.dir,
		InFlight:         l.inFlight,
		UsedBytes:        l.used,
		PeakBytes:        l.peak,
		BudgetBytes:      l.budget,
		MaxArtifactBytes: l.maxArtifact,
		RefusedTooLarge:  l.refusedTooLarge,
		RefusedBudget:    l.refusedBudget,
	}
}

// begin admits one fetch. declared is the upstream's Content-Length, or a
// negative number where it stated none.
//
// A declared length over the per-artifact ceiling is refused here, before a
// byte is read: the cheap check ahead of the expensive one, and the only place
// a client learns the artifact is too large without waiting for the whole
// transfer. A length the upstream did not declare is caught by the returned
// reservation as the copy crosses the ceiling instead.
func (l *spoolLimiter) begin(declared int64) (*spoolReservation, error) {
	if l.maxArtifact > 0 && declared > l.maxArtifact {
		l.mu.Lock()
		l.refusedTooLarge++
		l.mu.Unlock()
		return nil, fmt.Errorf("upstream declares %d bytes, %w of %d (spool_max_artifact_bytes) — nothing was cached; raise the key or leave this artifact to a direct download",
			declared, errSpoolArtifactTooLarge, l.maxArtifact)
	}
	r := &spoolReservation{lim: l}
	l.mu.Lock()
	l.inFlight++
	l.mu.Unlock()
	if declared > 0 {
		if err := r.cover(declared); err != nil {
			r.release()
			return nil, err
		}
	}
	return r, nil
}

// spoolReservation is one fetch's claim on the shared budget. It grows as the
// copy proceeds so an upstream that declared no length is charged for what it
// actually sends rather than for the ceiling it might have reached.
type spoolReservation struct {
	lim  *spoolLimiter
	held int64
	done bool
}

// cover grows the claim to n bytes, refusing when the budget cannot carry it.
// Charging before the write rather than after is what keeps the bytes on disk
// under the budget at every instant instead of on average.
func (r *spoolReservation) cover(n int64) error {
	if n <= r.held {
		return nil
	}
	l := r.lim
	l.mu.Lock()
	defer l.mu.Unlock()
	delta := n - r.held
	if l.budget > 0 && l.used+delta > l.budget {
		l.refusedBudget++
		return fmt.Errorf("%w: %d of %d bytes (spool_max_total_bytes) are held by %d fetch(es) already in flight — nothing was cached; retry",
			errSpoolBudgetExhausted, l.used, l.budget, l.inFlight)
	}
	l.used += delta
	r.held = n
	if l.used > l.peak {
		l.peak = l.used
	}
	return nil
}

// release returns the claim. Safe to call twice: the spool file is removed on
// several paths and a double release would hand the budget away for free.
func (r *spoolReservation) release() {
	if r == nil || r.done {
		return
	}
	r.done = true
	l := r.lim
	l.mu.Lock()
	l.used -= r.held
	l.inFlight--
	l.mu.Unlock()
	r.held = 0
}

// spoolWriter charges the reservation for every byte before it reaches the
// file, and enforces the per-artifact ceiling on the running count. It is what
// bounds a chunked or transparently-decompressed response, which declares no
// length for begin to check.
type spoolWriter struct {
	w   io.Writer
	res *spoolReservation
	max int64
	n   int64
}

func (sw *spoolWriter) Write(p []byte) (int, error) {
	want := sw.n + int64(len(p))
	if sw.max > 0 && want > sw.max {
		l := sw.res.lim
		l.mu.Lock()
		l.refusedTooLarge++
		l.mu.Unlock()
		return 0, fmt.Errorf("upstream body passed %d bytes, %w of %d (spool_max_artifact_bytes) — nothing was cached; the upstream declared no length, so this could only be caught on the way through",
			want, errSpoolArtifactTooLarge, sw.max)
	}
	if err := sw.res.cover(want); err != nil {
		return 0, err
	}
	n, err := sw.w.Write(p)
	sw.n += int64(n)
	return n, err
}

// spoolDenialReason maps a spool refusal onto the audit status that names it,
// and returns "" for anything else. The two reasons stay distinct because they
// call for opposite responses: one key is too low for what this archive
// publishes, the other says the host is carrying more concurrent fetches than
// its spool volume was sized for.
func spoolDenialReason(err error) string {
	switch {
	case errors.Is(err, errSpoolArtifactTooLarge):
		return audit.DenialSpoolArtifactTooLarge
	case errors.Is(err, errSpoolBudgetExhausted):
		return audit.DenialSpoolBudget
	default:
		return ""
	}
}

// recordSpoolRefusal reports the pressure on both channels an operator already
// watches: the log, at Error so the shipped default log_level prints it, and
// the denial table every other refusal reaches. Neither is optional. Without
// them the first symptom of a spool at its bound is a client retrying, and the
// second is an ENOSPC from whatever wrote to that filesystem next.
func (s *Server) recordSpoolRefusal(r *http.Request, pkgType, pkgName, s3Key, reason string, err error) {
	st := s.spool.stats()
	s.logger.Error("proxy fetch refused: the spool is at its bound",
		"key", s3Key, "reason", reason, "error", err,
		"spool_dir", st.Dir, "spool_used_bytes", st.UsedBytes, "spool_in_flight", st.InFlight,
		"spool_max_total_bytes", st.BudgetBytes, "spool_max_artifact_bytes", st.MaxArtifactBytes)
	recordDenialFor(s.auditDB, r, pkgType, pkgName, "", reason, map[string]string{
		"key":                   s3Key,
		"spool_used_bytes":      strconv.FormatInt(st.UsedBytes, 10),
		"spool_in_flight":       strconv.Itoa(st.InFlight),
		"spool_max_total_bytes": strconv.FormatInt(st.BudgetBytes, 10),
	})
}

// ensureSpoolDir creates the spool directory and proves this process can write
// in it, so Start can refuse on the same terms it refuses an unreadable admin
// list or an unwritable audit database.
//
// Left to the first fetch, a misplaced or unwritable spool surfaces as an
// ENOSPC or a permission error inside one proxy request, on a filesystem that
// by default also holds the audit database and the local store — which means
// the next thing to fail is something unrelated.
func ensureSpoolDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create spool_dir %s: %w\n"+
			"every proxied artifact is copied through it. Point spool_dir at a directory this user can create, or set build_root somewhere writable", dir, err)
	}
	f, err := os.CreateTemp(dir, ".bodega-spool-probe-*")
	if err != nil {
		return fmt.Errorf("spool_dir %s is not writable by this process (uid %d): %w\n"+
			"every proxied artifact is copied through it, so every upstream fetch would fail. Give the serving user write access, or point spool_dir somewhere it has it", dir, os.Getuid(), err)
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}
