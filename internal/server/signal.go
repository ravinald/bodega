package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// NotifyReload reads the PID file from logDir and sends SIGHUP to the
// running bodega server process, causing it to reload manifests.
// Returns nil if no server is running or the PID file doesn't exist.
func NotifyReload(logDir string) error {
	pidPath := filepath.Join(logDir, "bodega.pid")
	data, err := os.ReadFile(pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no server running
		}
		return fmt.Errorf("read PID file: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("parse PID file: %w", err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		// Process doesn't exist -- stale PID file.
		_ = os.Remove(pidPath)
		return nil
	}

	if err := proc.Signal(syscall.SIGHUP); err != nil {
		// Process exists but can't be signaled -- stale PID file.
		_ = os.Remove(pidPath)
		return nil
	}

	return nil
}

// CleanStalePID removes the PID file if the recorded process is not running.
func CleanStalePID(logDir string) {
	pidPath := filepath.Join(logDir, "bodega.pid")
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		_ = os.Remove(pidPath)
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		_ = os.Remove(pidPath)
		return
	}
	// Signal 0 checks if process exists without actually sending a signal.
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		_ = os.Remove(pidPath)
	}
}
