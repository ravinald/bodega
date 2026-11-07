package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

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
	s.logFor(r.Context()).Error("proxy fetch refused: the spool is at its bound",
		"key", s3Key, "reason", reason, "error", err,
		"spool_dir", st.Dir, "spool_used_bytes", st.UsedBytes, "spool_in_flight", st.InFlight,
		"spool_max_total_bytes", st.BudgetBytes, "spool_max_artifact_bytes", st.MaxArtifactBytes)
	if isOwnRead(r) {
		return
	}
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

// spoolFilePrefix names every file a proxy fill spools into. Nothing else in
// the spool directory starts with it, which is what lets startup sweep it.
const spoolFilePrefix = "bodega-upstream-"

// spoolLockName is the file a serving process holds an exclusive flock on
// for as long as Start runs. It is never removed: unlinking a held lock lets
// the next process lock a fresh inode while the old holder still believes it
// owns the directory.
const spoolLockName = ".bodega-spool.lock"

// errSpoolLockUnsupported marks a filesystem that refuses flock outright
// (some NFS and FUSE mounts). Start serves anyway and skips the sweep, since
// without the lock nothing proves no other server is streaming there.
var errSpoolLockUnsupported = errors.New("the spool filesystem does not support flock")

// lockSpoolDir takes the exclusive lock that entitles this process to sweep
// dir. Closing the returned file releases it, and so does the process dying,
// which is what lets the next start after a SIGKILL sweep.
//
// The unlinked file a sweep would remove is not safe to lose while a request
// streams into it: the fill reopens it by path to publish it to storage and to
// verify go module checksums, so a second server sweeping the directory would
// fail the first server's live fetches. Hence a competing start refuses here,
// before anything is deleted, rather than relying on open descriptors.
func lockSpoolDir(dir string) (*os.File, error) {
	path := filepath.Join(dir, spoolLockName)
	// O_NOFOLLOW: a spool directory other users can write must not let a
	// planted symlink make this process create or truncate a file elsewhere.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open spool lock %s: %w\n"+
			"the proxy spool cannot be claimed for this server. Remove whatever sits at that path if it is not a regular file, or point spool_dir somewhere this user owns", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("spool_dir %s is in use by another bodega server (it holds %s)\n"+
				"two servers sharing a spool would delete each other's in-flight fetches. Stop the other server, or give this one its own spool_dir", dir, path)
		}
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOLCK) || errors.Is(err, syscall.EINVAL) {
			return nil, fmt.Errorf("%w: %s: %w", errSpoolLockUnsupported, path, err)
		}
		return nil, fmt.Errorf("lock spool %s: %w", path, err)
	}
	return f, nil
}

// sweepSpoolLeftovers removes the spool files a killed or crashed process
// never reached its own removal for. Callers hold the lockSpoolDir lock and
// call it before the listener opens, so no request of any live server can own
// one.
//
// Only regular files go. A symlink is skipped rather than followed, and if a
// file is swapped for one between the check and the removal, os.Remove unlinks
// the link itself and never touches its target. The move-*.part files bodega
// move writes here, and anything else, are left alone.
//
// Every record is at Error: the shipped default log_level maps to
// slog.LevelError, and a sweep reported at Info or Warn printed nothing on the
// installs whose disk it frees.
func sweepSpoolLeftovers(dir string, logger *slog.Logger) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger.Error("proxy spool leftovers not swept; spool files from a killed process stay on disk until removed by hand",
			"spool_dir", dir, "error", err)
		return
	}
	var removed int
	var total int64
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), spoolFilePrefix) || !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		var size int64
		if info, err := e.Info(); err == nil {
			size = info.Size()
		}
		if err := os.Remove(path); err != nil {
			logger.Error("proxy spool leftover not removed; delete it by hand", "path", path, "error", err)
			continue
		}
		removed++
		total += size
	}
	if removed > 0 {
		logger.Error("removed proxy spool files left by an earlier process",
			"spool_dir", dir, "files", removed, "bytes", total)
	}
}
