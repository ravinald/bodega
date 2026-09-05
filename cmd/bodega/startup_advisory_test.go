package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/logging"
)

// The level is the point of every test in this file. Each condition below was
// logged where the shipped default log_level could not print it, so a test
// that raised the verbosity would have passed against the defect. defaultLog
// builds the handler serve builds, at log_level 0.
func defaultLog(t *testing.T) (*slog.Logger, *strings.Builder) {
	t.Helper()
	var buf strings.Builder
	return slog.New(logging.NewHandler(&buf, logging.SlogLevel(0))), &buf
}

// loadFrom writes a config file, points $BODEGA_CONFIG_FILE at it and returns
// what the real loader makes of it, so the snapshot RawFileValue reads is the
// one a running bodega would hold.
func loadFrom(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BODEGA_CONFIG_FILE", path)
	cfg, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

// TestStartupStorageNamesTheBackendAndTheError covers the state that put a
// server into "up, apt 503s, logs empty": a storage_path that cannot be
// created is not fatal, so the message is the only thing an operator gets.
// It has to name the configured backend, because the 503 body deliberately
// names none, and the underlying error, because "unavailable" alone sends
// them to the wrong layer.
func TestStartupStorageNamesTheBackendAndTheError(t *testing.T) {
	// A regular file where the storage root should be: MkdirAll fails with
	// ENOTDIR, which is a real failure rather than a permission the test would
	// have to run as another user to produce.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadFrom(t, `{"storage_backend":"local","storage_path":`+quote(filepath.Join(blocker, "storage"))+`}`)

	logger, buf := defaultLog(t)
	if stores := startupStorage(context.Background(), cfg, logger); stores != nil {
		t.Fatal("startupStorage returned a resolver over a root it could not create")
	}
	out := buf.String()
	for _, want := range []string{"ERROR", "503", "backend=local", "create storage root"} {
		if !strings.Contains(out, want) {
			t.Errorf("log at the default level does not name %q:\n%s", want, out)
		}
	}
}

// TestStartupStorageSilentWhenItWorks keeps the rule from collapsing into
// "log at Error on every start". A backend that builds changes nothing about
// what is served and earns no line.
func TestStartupStorageSilentWhenItWorks(t *testing.T) {
	cfg := loadFrom(t, `{"storage_backend":"local","storage_path":`+quote(t.TempDir())+`}`)

	logger, buf := defaultLog(t)
	if stores := startupStorage(context.Background(), cfg, logger); stores == nil {
		t.Fatal("startupStorage refused a writable local root")
	}
	if got := buf.String(); got != "" {
		t.Errorf("a working backend logged at the default level:\n%s", got)
	}
}

// TestRetiredAutocertReachesTheDefaultLevel covers the config file left behind
// by the retirement. tls_autocert is no longer a field, and Save preserves
// keys it did not parse, so without this the value sits in the file looking
// like a setting in force.
//
// The two cases split on whether serving changes. No certificate pair means
// the key that used to promise TLS now promises nothing and this server is
// about to bind in the clear or refuse: Error. With a pair the listener does
// what the operator wanted and only the key is dead: Warn, which the default
// level does not print, and that is correct.
func TestRetiredAutocertReachesTheDefaultLevel(t *testing.T) {
	t.Run("no certificate pair", func(t *testing.T) {
		cfg := loadFrom(t, `{"tls_autocert":true,"allow_plaintext":true}`)
		logger, buf := defaultLog(t)
		reportRetiredTLSKeys(cfg, nil, logger)

		out := buf.String()
		for _, want := range []string{"ERROR", "tls_autocert was removed", "no ACME client", "tls_cert"} {
			if !strings.Contains(out, want) {
				t.Errorf("log at the default level does not name %q:\n%s", want, out)
			}
		}
	})

	t.Run("certificate pair configured", func(t *testing.T) {
		cfg := loadFrom(t, `{"tls_autocert":true}`)
		cfg.TLSCert, cfg.TLSKey = "/etc/bodega/cert.pem", "/etc/bodega/key.pem"
		logger, buf := defaultLog(t)
		reportRetiredTLSKeys(cfg, nil, logger)

		if got := buf.String(); got != "" {
			t.Errorf("a dead key over a working listener printed at the default level:\n%s", got)
		}
	})

	t.Run("key absent", func(t *testing.T) {
		cfg := loadFrom(t, `{"allow_plaintext":true}`)
		logger, buf := defaultLog(t)
		reportRetiredTLSKeys(cfg, nil, logger)

		if got := buf.String(); got != "" {
			t.Errorf("a config that never mentioned autocert printed:\n%s", got)
		}
	})
}

// TestAutocertIsNotAnOfferedFlag pins the retirement at the surface an
// operator meets. #113 was not that autocert was missing but that three places
// offered it and a fourth refused it.
//
// Offered is the test, not registered. Unregistering the flags met #113 and
// cost an upgraded unit file its start: "unknown flag: --tls-autocert", exit 1,
// and under Restart=always a crash loop naming nothing to set instead. Hidden
// and deprecated offers nobody anything and still parses.
func TestAutocertIsNotAnOfferedFlag(t *testing.T) {
	cmd := newServeCmd(&globalFlags{})
	for _, name := range retiredTLSFlagNames {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("serve no longer parses --%s; an upgraded unit file exits 1 with \"unknown flag\"", name)
			continue
		}
		if !f.Hidden {
			t.Errorf("--%s is on --help, which offers a feature bodega does not have", name)
		}
		if f.Deprecated == "" {
			t.Errorf("--%s is not marked deprecated, so pflag says nothing at parse time", name)
		}
	}
	if strings.Contains(cmd.Long, "autocert") {
		t.Error("serve help still offers autocert")
	}
	// The template is written, not exported, so this reads what a fresh
	// install would actually get.
	t.Setenv("BODEGA_CONFIG_FILE", filepath.Join(t.TempDir(), "config.json"))
	path, err := config.EnsureConfigFile()
	if err != nil {
		t.Fatalf("write default config: %v", err)
	}
	shipped, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(shipped), "tls_autocert") {
		t.Error("the shipped config template still carries tls_autocert")
	}
}

func quote(s string) string { return `"` + s + `"` }

// TestRetiredAutocertFlagsReachTheDefaultLevel covers the other half: a unit
// file that still passes the flags. Unregistered they exited 1 with "unknown
// flag: --tls-autocert" and nothing to set instead, which under
// Restart=always is a crash loop whose only output names the flag.
func TestRetiredAutocertFlagsReachTheDefaultLevel(t *testing.T) {
	// The real serve flag set, so a rename of either flag fails here rather
	// than silently reporting nothing.
	givenFlags := func(t *testing.T, args ...string) []string {
		t.Helper()
		cmd := newServeCmd(&globalFlags{})
		if err := cmd.Flags().Parse(args); err != nil {
			t.Fatalf("serve refused %v: %v", args, err)
		}
		return retiredTLSFlags(cmd.Flags())
	}

	t.Run("both flags, no certificate pair", func(t *testing.T) {
		cfg := loadFrom(t, `{"allow_plaintext":true}`)
		logger, buf := defaultLog(t)
		reportRetiredTLSKeys(cfg, givenFlags(t, "--tls-autocert", "--tls-domain", "x"), logger)

		out := buf.String()
		for _, want := range []string{"ERROR", "--tls-autocert and --tls-domain", "were removed", "no ACME client", "tls_cert", "tls_key", "allow_plaintext"} {
			if !strings.Contains(out, want) {
				t.Errorf("log at the default level does not name %q:\n%s", want, out)
			}
		}
	})

	t.Run("one flag names only itself", func(t *testing.T) {
		cfg := loadFrom(t, `{"allow_plaintext":true}`)
		logger, buf := defaultLog(t)
		reportRetiredTLSKeys(cfg, givenFlags(t, "--tls-domain", "x"), logger)

		out := buf.String()
		if !strings.Contains(out, "--tls-domain was removed") {
			t.Errorf("log does not name the flag that was given:\n%s", out)
		}
		if strings.Contains(out, "--tls-autocert") {
			t.Errorf("log names a flag nobody passed:\n%s", out)
		}
	})

	t.Run("flags absent", func(t *testing.T) {
		cfg := loadFrom(t, `{"allow_plaintext":true}`)
		logger, buf := defaultLog(t)
		reportRetiredTLSKeys(cfg, givenFlags(t), logger)

		if got := buf.String(); got != "" {
			t.Errorf("a command line that never mentioned autocert printed:\n%s", got)
		}
	})
}
