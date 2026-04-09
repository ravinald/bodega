// Package logging provides structured build logging for bodega.
//
// Each build session writes to a dated session log. Individual package builds
// write to their own per-package log file and simultaneously to the session
// log via an io.MultiWriter. An append-only audit.log records one-line events
// for every completed package action.
//
// All file operations are best-effort: if the log directory is unavailable,
// callers receive a writer that discards output (no panic, no error propagation
// into the build path).
package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// BuildLogger manages the open file handles for a single build session.
type BuildLogger struct {
	logDir     string
	sessionLog *os.File
	auditLog   *os.File
	errorLog   *os.File
	timestamp  string
	mu         sync.Mutex
}

// SessionLogPath returns the path to the current session log file.
func (bl *BuildLogger) SessionLogPath() string {
	if bl.sessionLog != nil {
		return bl.sessionLog.Name()
	}
	return ""
}

// NewBuildLogger creates a new BuildLogger rooted at logDir.
//
// It opens two files:
//   - <logDir>/build-<timestamp>.log  (session log, truncated on creation)
//   - <logDir>/audit.log              (audit log, opened for append)
//
// When logDir does not exist or is not writable, NewBuildLogger returns a
// BuildLogger whose writers silently discard all output — callers must not
// treat a non-nil return as proof that logging succeeded.
func NewBuildLogger(logDir string) (*BuildLogger, error) {
	bl := &BuildLogger{
		logDir:    logDir,
		timestamp: time.Now().Format("20060102-150405"),
	}

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		// Non-fatal: return a logger that discards all output.
		return bl, fmt.Errorf("create log dir %s: %w", logDir, err)
	}

	sessionPath := filepath.Join(logDir, "build-"+bl.timestamp+".log")
	sf, err := os.OpenFile(sessionPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return bl, fmt.Errorf("open session log %s: %w", sessionPath, err)
	}
	bl.sessionLog = sf

	auditPath := filepath.Join(logDir, "audit.log")
	af, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return bl, fmt.Errorf("open audit log %s: %w", auditPath, err)
	}
	bl.auditLog = af

	errorPath := filepath.Join(logDir, "error.log")
	ef, err := os.OpenFile(errorPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return bl, fmt.Errorf("open error log %s: %w", errorPath, err)
	}
	bl.errorLog = ef

	return bl, nil
}

// StartPackage creates a per-package log file at
// <logDir>/packages/<typ>/<name>/<timestamp>.log and returns an io.MultiWriter
// that writes to both the package log and the session log.
//
// On any failure the returned writer falls back to just the session log (or
// discards if the session log is also unavailable).
func (bl *BuildLogger) StartPackage(typ, name string) io.Writer {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	var writers []io.Writer

	// Session log writes go through a synchronized wrapper to prevent
	// interleaving when multiple packages build concurrently.
	if bl.sessionLog != nil {
		writers = append(writers, &syncWriter{f: bl.sessionLog, mu: &bl.mu})
	}

	pkgDir := filepath.Join(bl.logDir, "packages", typ, name)
	if err := os.MkdirAll(pkgDir, 0o755); err == nil {
		pkgLogPath := filepath.Join(pkgDir, bl.timestamp+".log")
		pf, err := os.OpenFile(pkgLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err == nil {
			writers = append(writers, pf)
		}
	}

	if len(writers) == 0 {
		return io.Discard
	}
	if len(writers) == 1 {
		return writers[0]
	}
	return io.MultiWriter(writers...)
}

// syncWriter serializes writes to an underlying file through a mutex.
// This prevents interleaved output when multiple goroutines write concurrently.
type syncWriter struct {
	f  *os.File
	mu *sync.Mutex
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Write(p)
}

// SessionWriter returns the session log writer. Output written here appears in
// the session log but not in any per-package log. When the session log is
// unavailable, io.Discard is returned.
func (bl *BuildLogger) SessionWriter() io.Writer {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	if bl.sessionLog != nil {
		return &syncWriter{f: bl.sessionLog, mu: &bl.mu}
	}
	return io.Discard
}

// Audit writes a single timestamped line to audit.log. The format is:
//
//	2006-01-02T15:04:05Z07:00  <message>
//
// Write errors are silently discarded so that audit failures never propagate
// into the build path.
func (bl *BuildLogger) Audit(format string, args ...interface{}) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	if bl.auditLog == nil {
		return
	}
	ts := time.Now().Format(time.RFC3339)
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(bl.auditLog, "%s  %s\n", ts, msg)
}

// Error writes a structured error entry to error.log with full context
// for debugging. The format is:
//
//	═══ ERROR ═══════════════════════════════════════
//	Time:       2026-04-06T03:15:05Z
//	Operation:  fetch
//	Entry:      git/netbox@v4.5.5
//	Error:      git worktree add: exit status 128
//	Build root: /opt/bodega
//
//	Output:
//	    fatal: invalid reference: v4.5.5
//	═════════════════════════════════════════════════
//
// Write errors are silently discarded.
func (bl *BuildLogger) Error(operation, entryType, entryName string, err error, output string) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	if bl.errorLog == nil {
		return
	}

	ts := time.Now().Format(time.RFC3339)
	entry := entryType
	if entryName != "" {
		entry += "/" + entryName
	}

	_, _ = fmt.Fprintf(bl.errorLog, "\n═══ ERROR ═══════════════════════════════════════\n")
	_, _ = fmt.Fprintf(bl.errorLog, "Time:       %s\n", ts)
	_, _ = fmt.Fprintf(bl.errorLog, "Operation:  %s\n", operation)
	_, _ = fmt.Fprintf(bl.errorLog, "Entry:      %s\n", entry)
	_, _ = fmt.Fprintf(bl.errorLog, "Error:      %v\n", err)
	_, _ = fmt.Fprintf(bl.errorLog, "Build root: %s\n", bl.logDir)
	if output != "" {
		_, _ = fmt.Fprintf(bl.errorLog, "\nOutput:\n")
		for _, line := range splitLines(output) {
			_, _ = fmt.Fprintf(bl.errorLog, "    %s\n", line)
		}
	}
	_, _ = fmt.Fprintf(bl.errorLog, "═════════════════════════════════════════════════\n")
}

// splitLines splits a string on newlines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// Close flushes and closes all open file handles. Subsequent calls to
// StartPackage and SessionWriter return io.Discard.
func (bl *BuildLogger) Close() {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	if bl.sessionLog != nil {
		_ = bl.sessionLog.Close()
		bl.sessionLog = nil
	}
	if bl.auditLog != nil {
		_ = bl.auditLog.Close()
		bl.auditLog = nil
	}
	if bl.errorLog != nil {
		_ = bl.errorLog.Close()
		bl.errorLog = nil
	}
}
