package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// TestEveryRunnableCommandIsClassified is what stops the sixth verb from
// repeating the fifth's mistake. hide, freeze, refresh and remove each shipped
// without the notifyServer call their neighbours had, and nothing failed:
// a missing call site looks exactly like a verb that does not need one.
// Here it looks like a build failure instead.
func TestEveryRunnableCommandIsClassified(t *testing.T) {
	var missing []string
	var walk func(*cobra.Command)
	walk = func(parent *cobra.Command) {
		for _, cmd := range parent.Commands() {
			switch cmd.Name() {
			case "help", "completion": // cobra's own, added at Execute
				continue
			}
			if cmd.Runnable() {
				if _, ok := reloadIntent(cmd); !ok {
					missing = append(missing, cmd.CommandPath())
				}
			}
			walk(cmd)
		}
	}
	walk(newRootCmd())

	if len(missing) > 0 {
		t.Errorf("commands with no reload classification:\n  %s\n"+
			"wrap each in signalsReload() or noReloadSignal() where it is registered",
			strings.Join(missing, "\n  "))
	}
}

// TestWithdrawalVerbsSignal names the four that did not. Only hide is driven
// end to end below; this is what says the other three sit on the same path.
func TestWithdrawalVerbsSignal(t *testing.T) {
	want := map[string]string{
		"pkg hide":    reloadSignal,
		"pkg freeze":  reloadSignal,
		"pkg refresh": reloadSignal,
		"pkg remove":  reloadSignal,
	}
	root := newRootCmd()
	for path, intent := range want {
		cmd, _, err := root.Find(strings.Fields(path))
		if err != nil {
			t.Errorf("find %q: %v", path, err)
			continue
		}
		if got, ok := reloadIntent(cmd); !ok || got != intent {
			t.Errorf("%s = %q (found=%v), want %q", path, got, ok, intent)
		}
	}
}

// TestReloadIntentInheritsAndOverrides pins the two edges the classification
// rests on: a group answers for its subtree, and a run that changed nothing
// can take its own verb back out of the signal path.
func TestReloadIntentInheritsAndOverrides(t *testing.T) {
	group := noReloadSignal(&cobra.Command{Use: "group"})
	leaf := &cobra.Command{Use: "leaf", Run: func(*cobra.Command, []string) {}}
	group.AddCommand(leaf)

	if intent, ok := reloadIntent(leaf); !ok || intent != reloadQuiet {
		t.Errorf("leaf inherited %q (found=%v), want %q", intent, ok, reloadQuiet)
	}

	signalsReload(leaf)
	if intent, _ := reloadIntent(leaf); intent != reloadSignal {
		t.Errorf("leaf override = %q, want %q", intent, reloadSignal)
	}

	suppressReload(leaf)
	if intent, _ := reloadIntent(leaf); intent != reloadQuiet {
		t.Errorf("suppressed leaf = %q, want %q", intent, reloadQuiet)
	}
}

// TestHideWithdrawsFromServedPackages drives the whole withdrawal path: the
// CLI writes the manifest, the post-run hook signals, the server reloads and
// the entry leaves the served index.
//
// It is deliberately not a test of notifyServer. That function was always
// correct; what was missing was anything calling it from hide, and a test of
// the function alone passes against a tree where the server keeps publishing
// a package the operator was told is hidden.
func TestHideWithdrawsFromServedPackages(t *testing.T) {
	dir := t.TempDir()
	manifestDir := filepath.Join(dir, "manifests")
	storagePath := filepath.Join(dir, "storage")
	logDir := filepath.Join(dir, "log")

	// New() reads a signing key and a pepper from host-wide paths, so without
	// this the test writes into the config directory of whoever runs it.
	keyPath, pepperPaths := aptsign.SystemKeyPath, audit.DefaultPepperPaths
	aptsign.SystemKeyPath = filepath.Join(dir, "etc", aptsign.KeyFileName)
	audit.DefaultPepperPaths = []string{filepath.Join(dir, "etc", "pepper")}
	t.Cleanup(func() {
		aptsign.SystemKeyPath, audit.DefaultPepperPaths = keyPath, pepperPaths
	})

	seedAptEntry(t, manifestDir, storagePath)

	port := freePort(t)
	writeTestConfig(t, dir, manifestDir, storagePath, logDir, port)

	cfg, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// The server holds its own store, as it does in production: the CLI's
	// copy is a separate process there and a separate object here.
	srvStore := manifest.NewLocalStore(cfg.ManifestDir)
	if err := srvStore.LoadIndex(t.Context()); err != nil {
		t.Fatalf("server LoadIndex: %v", err)
	}
	stores, err := storage.NewResolver(t.Context(), cfg)
	if err != nil {
		t.Fatalf("storage resolver: %v", err)
	}

	// The signal lands on this process, because the PID file the server
	// writes carries this process's PID. Registering here as well closes the
	// window before Start installs its own handler, in which the default
	// disposition would kill the test binary.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(hup) })

	srv := server.New(cfg, srvStore, stores, fmt.Sprintf("127.0.0.1:%d", port), nil)
	srv.SetQuiet(true)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Start(ctx) }()

	packagesURL := fmt.Sprintf("http://127.0.0.1:%d/apt/dists/noble/main/binary-amd64/Packages", port)
	if !eventually(t, func() bool { return strings.Contains(httpGet(t, packagesURL), "Package: hello") }) {
		select {
		case err := <-serveErr:
			t.Fatalf("server exited: %v", err)
		default:
		}
		t.Fatalf("hello never appeared in the served index:\n%s", httpGet(t, packagesURL))
	}

	root := newRootCmd()
	root.SetArgs([]string{"pkg", "hide", "apt", "hello"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.Execute(); err != nil {
		t.Fatalf("pkg hide: %v", err)
	}

	// The reload runs on the server's own goroutine, so the withdrawal is
	// prompt rather than synchronous.
	if !eventually(t, func() bool { return !strings.Contains(httpGet(t, packagesURL), "Package: hello") }) {
		t.Errorf("hidden package is still published:\n%s", httpGet(t, packagesURL))
	}
}

// seedAptEntry writes one apt entry and the pool object it names. The index
// is generated from the two together: a manifest entry whose pool key nobody
// wrote is dropped from the index and would pass this test for free.
func seedAptEntry(t *testing.T, manifestDir, storagePath string) {
	t.Helper()
	store := manifest.NewLocalStore(manifestDir)
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "hello", manifest.VersionEntry{
		Version:      "1.0.0",
		SourceName:   "hello",
		ArtifactSize: 4,
		Description:  "greeting",
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   "pool/main/h/hello/hello_1.0.0_amd64.deb",
		},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	deb := filepath.Join(storagePath, "packages", "apt", "pool", "main", "h", "hello", "hello_1.0.0_amd64.deb")
	if err := os.MkdirAll(filepath.Dir(deb), 0o755); err != nil {
		t.Fatalf("create pool dir: %v", err)
	}
	if err := os.WriteFile(deb, []byte("\x00deb"), 0o600); err != nil {
		t.Fatalf("write pool object: %v", err)
	}
}

func writeTestConfig(t *testing.T, dir, manifestDir, storagePath, logDir string, port int) {
	t.Helper()
	body := fmt.Sprintf(`{
  "storage_backend": "local",
  "storage_path": %q,
  "manifest_dir": %q,
  "log_dir": %q,
  "listen_addr": "127.0.0.1:%d",
  "allow_plaintext": true,
  "apt_codename": "noble"
}`, storagePath, manifestDir, logDir, port)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)
}

// freePort returns a port nothing is listening on. The server needs a real
// listener for the signal path to mean anything, and reports the port it
// bound only to its log.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listener: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	return port
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

// eventually polls cond until it holds or the budget runs out.
func eventually(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
