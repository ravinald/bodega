package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
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

// TestReloadInstallsBindingsWhileTheAptBuildIsHeld starts a server whose apt
// rebuild is parked on an upstream that does not answer and asserts that each
// reload installs its identity binding within a second regardless.
//
// The first reload is sent before Start, standing for one that arrives while
// New is still building the first index: it has to be held and acted on, not
// lost and not fatal. The second arrives while the first one's rebuild is
// parked, which is the case suite 56 measured at 23s: one goroutine ran both
// halves of every reload, so a binding waited for the rebuild queued ahead of
// it.
func TestReloadInstallsBindingsWhileTheAptBuildIsHeld(t *testing.T) {
	s, archive := aptProfileServer(t)
	// A profile scoping the mirrored codename is what makes a rebuild read
	// the upstream at all.
	aptProfileBind(t, s, "fleet", "block", "nginx")
	s.addr = reservePort(t)
	s.SetQuiet(true)
	release := archive.hold(t)
	s.aptUpstreamIdx.Clear()
	snap := s.aptSnap.Load()

	sig := make(chan os.Signal, 1)
	s.SetReloadSignals(sig)

	bindCIDR(t, s, "192.0.2.0/24", "early-host")
	sig <- syscall.SIGHUP
	requested := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	t.Cleanup(func() {
		release()
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("Start did not return within 30s of cancellation")
		}
	})
	waitForIdentity(t, s, "192.0.2.7", "early-host", requested)

	waitFor(t, func() bool { return archiveHits(archive) > 0 })
	bindCIDR(t, s, "198.51.100.0/24", "late-host")
	sig <- syscall.SIGHUP
	waitForIdentity(t, s, "198.51.100.7", "late-host", time.Now())

	if s.aptSnap.Load() != snap {
		t.Fatal("the apt snapshot changed while the upstream was held, so nothing here proves a build was still running")
	}
	release()
	waitFor(t, func() bool { return s.aptSnap.Load() != snap })
}

func bindCIDR(t *testing.T, s *Server, cidr, identity string) {
	t.Helper()
	if _, err := s.auditDB.AddIdentityBinding(t.Context(),
		audit.IdentityBinding{Kind: audit.BindCIDR, Key: cidr, Identity: identity}); err != nil {
		t.Fatalf("bind %s to %s: %v", cidr, identity, err)
	}
}

// waitForIdentity reads the identity the 403 on /client/plan reads, through
// identityMatchFor, and fails unless ip resolves to want within a second of
// requested.
func waitForIdentity(t *testing.T, s *Server, ip, want string, requested time.Time) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/client/plan?os=linux", nil)
	req.RemoteAddr = ip + ":40000"
	for {
		if got := s.identityMatchFor(req).Identity; got == want {
			return
		}
		if time.Since(requested) > time.Second {
			t.Fatalf("%s resolves to %q a second after its binding's reload, want %q: the reload is waiting on the apt build",
				ip, s.identityMatchFor(req).Identity, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func archiveHits(a *fixtureArchive) int64 {
	var n int64
	a.hits.Range(func(_, v any) bool {
		n += v.(*atomic.Int64).Load()
		return true
	})
	return n
}
