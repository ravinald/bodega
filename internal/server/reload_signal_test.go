package server

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
)

// TestSIGHUPHandlerDiesWithTheServer drives a start, a SIGHUP, a stop and a
// second SIGHUP, and asserts the second one reloads nothing.
//
// The handler goroutine used to outlive Start: nothing called signal.Stop and
// nothing closed the channel, so every server ever started in a process stayed
// registered and every later SIGHUP woke all of them. They then raced each
// other through loadAptSigner and the package-level key paths it reads, which
// is how a second test starting a server turned an unrelated rescan test into
// an intermittent -race failure. Under a long-running bodega the same leak
// makes a stop-and-restart in one process reload a server that no longer
// serves anything.
//
// The first SIGHUP is the control. Without it a broken signal.Notify would
// pass the second assertion for the wrong reason.
func TestSIGHUPHandlerDiesWithTheServer(t *testing.T) {
	// The test binary installs no SIGHUP handler of its own, so the default
	// disposition kills it. This channel also proves each raise was delivered
	// rather than trusting a sleep to have covered it.
	delivered := make(chan os.Signal, 1)
	signal.Notify(delivered, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(delivered) })

	var buf syncBuffer
	addr := reservePort(t)
	s := newGuardServer(t, &config.Config{AllowPlaintext: true, LogDir: t.TempDir()}, addr)
	s.logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	waitFor(t, func() bool { return probePlain(addr) })

	raiseSIGHUP(t, delivered)
	waitFor(t, func() bool { return strings.Contains(buf.String(), "reload complete") })

	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Start did not return within 30s of cancellation")
	}

	before := strings.Count(buf.String(), "reload requested")
	raiseSIGHUP(t, delivered)
	// A signal delivered is not a goroutine scheduled, so the assertion needs
	// a window rather than a single read. The control above lands in
	// milliseconds; a second is several orders past it.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := strings.Count(buf.String(), "reload requested"); got > before {
			t.Fatalf("a stopped server reloaded on SIGHUP: its handler goroutine outlived Start\n%s", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// raiseSIGHUP signals the process and waits for the runtime to hand the signal
// to the test's own channel, so a caller never asserts on a signal still in
// flight.
func raiseSIGHUP(t *testing.T, delivered <-chan os.Signal) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("raise SIGHUP: %v", err)
	}
	select {
	case <-delivered:
	case <-time.After(10 * time.Second):
		t.Fatal("SIGHUP was never delivered to the test's own channel")
	}
}
