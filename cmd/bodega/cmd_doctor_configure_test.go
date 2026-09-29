package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/config"
)

// planServer answers /client/plan with one install record per file, at a
// path under the caller's home, and serves each file at the URL it names.
func planServer(t *testing.T, files map[string]string) (*httptest.Server, *[]string) {
	t.Helper()
	var queries []string
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		var plan clientconf.Plan
		for sys, content := range files {
			sum := sha256.Sum256([]byte(content))
			plan.Records = append(plan.Records, clientconf.PlanRecord{
				Identity: "web-host", Profile: "web", Match: "cidr:192.0.2.1/32",
				System: sys, Action: clientconf.PlanInstall, Path: "~/" + sys + ".conf",
				URL: srv.URL + "/client/" + sys, SHA256: hex.EncodeToString(sum[:]),
			})
		}
		_ = json.NewEncoder(w).Encode(plan)
	})
	mux.HandleFunc("GET /client/{system}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, files[r.PathValue("system")])
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &queries
}

func runDoctor(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"manifest_dir":"/nonexistent/f31/manifests"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvConfigFile, cfgPath)
	cmd := newDoctorCmd(&globalFlags{})
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	var err error
	out := capture(t, func() { err = cmd.Execute() })
	return out, err
}

// --configure is a dry run until --apply: the same contract as the setup
// script, so an operator who learned one is not surprised by the other.
func TestDoctorConfigureDiffsThenAppliesWithABackup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	srv, _ := planServer(t, map[string]string{"npm": "registry=https://b/npm/\n"})
	target := filepath.Join(home, "npm.conf")
	if err := os.WriteFile(target, []byte("registry=https://registry.npmjs.org/\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runDoctor(t, "--configure", "npm", "--url", srv.URL, "--allow-plaintext")
	if err != nil || !strings.Contains(out, "+registry=https://b/npm/") || !strings.Contains(out, "Dry run: nothing was written") {
		t.Fatalf("dry run = %v:\n%s", err, out)
	}
	if got, _ := os.ReadFile(target); !strings.Contains(string(got), "npmjs") {
		t.Fatalf("the dry run wrote %s", target)
	}

	out, err = runDoctor(t, "--configure", "npm", "--url", srv.URL, "--allow-plaintext", "--apply")
	if err != nil || !strings.Contains(out, "backed up") {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	if got, _ := os.ReadFile(target); string(got) != "registry=https://b/npm/\n" {
		t.Errorf("%s = %q after --apply", target, got)
	}
	backups, _ := filepath.Glob(target + ".bodega-*")
	if len(backups) != 1 {
		t.Errorf("backups = %v, want one beside the original", backups)
	}

	out, err = runDoctor(t, "--configure", "npm", "--url", srv.URL, "--allow-plaintext", "--apply")
	if err != nil || !strings.Contains(out, "Nothing to change") {
		t.Errorf("second --apply = %v:\n%s", err, out)
	}
	if again, _ := filepath.Glob(target + ".bodega-*"); len(again) != 1 {
		t.Errorf("a second --apply with nothing to change made another backup: %v", again)
	}

	_, err = runDoctor(t, "--configure", "pypi", "--url", srv.URL, "--allow-plaintext")
	if err == nil || !strings.Contains(err.Error(), "It lists: npm") {
		t.Errorf("--configure pypi against a plan without it = %v, want the plan's list", err)
	}
}

// The two old write flags are --configure with --apply, and together they
// are one run rather than a mutual-exclusion error.
func TestDoctorWriteFlagsAreConfigureAliases(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	srv, queries := planServer(t, map[string]string{"apt": "Types: deb\n", "freebsd": "bodega: {}\n"})

	out, err := runDoctor(t, "--write-apt-sources", "--write-pkg-repo", "--suite", "noble", "--abi", "FreeBSD:15:amd64",
		"--release", "14", "--url", srv.URL, "--allow-plaintext")
	if err != nil {
		t.Fatalf("--write-apt-sources --write-pkg-repo = %v:\n%s", err, out)
	}
	for _, f := range []string{"apt.conf", "freebsd.conf"} {
		if _, err := os.Stat(filepath.Join(home, f)); err != nil {
			t.Errorf("the alias did not apply %s: %v", f, err)
		}
	}
	q := strings.Join(*queries, "&")
	for _, want := range []string{"codename=noble", "abi=FreeBSD%3A15%3Aamd64", "release=14"} {
		if !strings.Contains(q, want) {
			t.Errorf("plan query %q lacks %s", q, want)
		}
	}
}

func TestDoctorConfigureRefusesMixedOrOrphanedFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--write-credentials", "--configure", "npm", "--token", "t"}, "one write at a time"},
		{[]string{"--write-credentials", "--write-apt-sources", "--token", "t"}, "one write at a time"},
		{[]string{"--apply"}, "--apply applies to --configure"},
		{[]string{"--suite", "noble"}, "--suite applies to --configure"},
	} {
		_, err := runDoctor(t, tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("doctor %v = %v, want %q", tc.args, err, tc.want)
		}
	}
}
