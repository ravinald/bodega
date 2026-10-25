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
	"strconv"
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

// B142: a server serving two suites refuses a plan that names none, and
// doctor's refusal names its own flag rather than only the query parameter.
// The host's codename is suggested when served, and never sent unasked.
func TestDoctorConfigureNamesSuiteOnAMultiSuiteServer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var queries []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		_ = json.NewEncoder(w).Encode(clientconf.Plan{Records: []clientconf.PlanRecord{{
			Identity: "web-host", Profile: "web", Match: "cidr:192.0.2.1/32",
			System: "apt", Action: clientconf.PlanSkip,
			Reason: clientconf.AptSuiteChoiceReason([]string{"noble", "resolute"}),
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	osRelease := filepath.Join(t.TempDir(), "os-release")
	prev := doctorOSRelease
	doctorOSRelease = osRelease
	t.Cleanup(func() { doctorOSRelease = prev })

	for _, tc := range []struct{ codename, hint string }{
		{"noble", "re-run with --suite noble"},
		{"trixie", ""},
		{"", ""},
	} {
		if err := os.WriteFile(osRelease, []byte("ID=ubuntu\nVERSION_CODENAME="+tc.codename+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		queries = nil
		_, err := runDoctor(t, "--configure", "apt", "--url", srv.URL, "--allow-plaintext")
		if err == nil {
			t.Fatalf("VERSION_CODENAME=%q: doctor accepted a skipped apt plan", tc.codename)
		}
		msg := err.Error()
		for _, want := range []string{"--suite <suite>", "codename=<suite>", "(noble, resolute)"} {
			if !strings.Contains(msg, want) {
				t.Errorf("VERSION_CODENAME=%q: refusal lacks %q:\n%s", tc.codename, want, msg)
			}
		}
		if tc.hint != "" && !strings.Contains(msg, tc.hint) {
			t.Errorf("VERSION_CODENAME=%q: refusal lacks %q:\n%s", tc.codename, tc.hint, msg)
		}
		if tc.hint == "" && strings.Contains(msg, "VERSION_CODENAME") {
			t.Errorf("VERSION_CODENAME=%q is not served, yet the refusal suggests it:\n%s", tc.codename, msg)
		}
		if len(queries) != 1 || strings.Contains(queries[0], "codename") {
			t.Errorf("VERSION_CODENAME=%q: plan queries %q, want one with no codename", tc.codename, queries)
		}
	}
}

// B142: the --suite hint follows the apt skip that blocked the run, so a
// refusal for any other system, or one Select raises before reading a single
// record, carries no suggestion that --suite would fix it.
func TestDoctorConfigureSuiteHintOnlyOnTheAptRefusal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(clientconf.Plan{Records: []clientconf.PlanRecord{
			{System: "apt", Action: clientconf.PlanSkip, Reason: clientconf.AptSuiteChoiceReason([]string{"noble", "resolute"})},
			{System: "freebsd", Action: clientconf.PlanSkip, Reason: "this host runs linux"},
			{System: "osquery", Action: clientconf.PlanSkip, Reason: "no osquery profile"},
		}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	osRelease := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(osRelease, []byte("ID=ubuntu\nVERSION_CODENAME=noble\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := doctorOSRelease
	doctorOSRelease = osRelease
	t.Cleanup(func() { doctorOSRelease = prev })

	for _, tc := range []struct {
		systems string
		hint    bool
	}{
		{"freebsd", false},
		{"osquery", false},
		{"apt,osquery", false},
		{"apt,npm", false},
		{"apt", true},
		{"apt,freebsd", true},
	} {
		_, err := runDoctor(t, "--configure", tc.systems, "--url", srv.URL, "--allow-plaintext")
		if err == nil {
			t.Fatalf("--configure %s: doctor accepted a plan that installs nothing", tc.systems)
		}
		if got := strings.Contains(err.Error(), "--suite noble"); got != tc.hint {
			t.Errorf("--configure %s: hint present = %v, want %v:\n%s", tc.systems, got, tc.hint, err)
		}
	}
}

// E22 R3, R4: --archive reaches the plan as archives=, repeated or
// comma-joined, and --apply writes the stanza and the key it brings. The plan
// roots both paths under a fixture directory, since the real ones are /etc's.
func TestDoctorConfigureAppliesAVendorArchive(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	stanza := clientconf.AptArchive("https://bodega.internal", "stable", []string{"main"}).Content
	files := map[string]string{
		"/stanza": stanza,
		"/key":    "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n-----END PGP PUBLIC KEY BLOCK-----\n",
	}
	paths := map[string]string{
		"/stanza": filepath.Join(root, clientconf.AptArchiveSourcesPath("stable")),
		"/key":    filepath.Join(root, clientconf.AptArchiveKeyPath("stable")),
	}
	var queries []string
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("archives"))
		var plan clientconf.Plan
		for _, u := range []string{"/stanza", "/key"} {
			sum := sha256.Sum256([]byte(files[u]))
			plan.Records = append(plan.Records, clientconf.PlanRecord{
				Identity: "web-host", Match: "cidr:192.0.2.1/32", System: "apt", Action: clientconf.PlanInstall,
				Path: paths[u], URL: srv.URL + u, SHA256: hex.EncodeToString(sum[:]),
			})
		}
		_ = json.NewEncoder(w).Encode(plan)
	})
	for u, body := range files {
		mux.HandleFunc("GET "+u, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
	}
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	out, err := runDoctor(t, "--configure", "apt", "--archive", "stable", "--archive", "noble-pgdg",
		"--url", srv.URL, "--allow-plaintext", "--apply")
	if err != nil {
		t.Fatalf("doctor --archive --apply = %v:\n%s", err, out)
	}
	if len(queries) != 1 || queries[0] != "stable,noble-pgdg" {
		t.Errorf("plan archives= %q, want one request naming both", queries)
	}
	for u, path := range paths {
		if got, err := os.ReadFile(path); err != nil || string(got) != files[u] {
			t.Errorf("%s = %q (%v), want %q", path, got, err, files[u])
		}
	}
	if !strings.Contains(out, "Apply it:  apt-get update") {
		t.Errorf("no apt-get update hint after writing a .sources file:\n%s", out)
	}

	if _, err := runDoctor(t, "--configure", "npm", "--archive", "stable", "--url", srv.URL); err == nil ||
		!strings.Contains(err.Error(), "--configure apt --archive") {
		t.Errorf("--archive without apt = %v, want a refusal naming --configure apt", err)
	}
}

// An install record's reason is a note the operator reads before applying,
// such as why npm's plan leaves node-gyp's mirror out, so doctor prints it.
func TestDoctorConfigurePrintsAnInstallRecordsNote(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const content = "registry=https://b/npm/\n"
	sum := sha256.Sum256([]byte(content))
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(clientconf.Plan{Records: []clientconf.PlanRecord{{
			Identity: "web-host", System: "npm", Action: clientconf.PlanInstall, Path: "~/.npmrc",
			URL: srv.URL + "/client/npm", SHA256: hex.EncodeToString(sum[:]), Reason: "node-gyp is left pointing at nodejs.org",
		}}})
	})
	mux.HandleFunc("GET /client/npm", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, content) })
	out, err := runDoctor(t, "--configure", "npm", "--url", srv.URL, "--allow-plaintext")
	if err != nil || !strings.Contains(out, "note       npm        node-gyp is left pointing at nodejs.org") {
		t.Errorf("--configure npm = %v:\n%s", err, out)
	}
}

// F82 R2: --configure rubygems --apply writes ~/.gemrc and Bundler's config
// under the running user's home, and backs up each file it replaces.
func TestDoctorConfigureRubygemsWritesBothFilesWithBackups(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	files := clientconf.Rubygems(srv.URL)
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		var plan clientconf.Plan
		for i, f := range files {
			sum := sha256.Sum256([]byte(f.Content))
			plan.Records = append(plan.Records, clientconf.PlanRecord{
				Identity: "web-host", Profile: "web", Match: "cidr:192.0.2.1/32",
				System: "rubygems", Action: clientconf.PlanInstall, Path: f.Path(clientconf.OSLinux),
				URL: srv.URL + "/client/rubygems?n=" + strconv.Itoa(i), SHA256: hex.EncodeToString(sum[:]),
			})
		}
		_ = json.NewEncoder(w).Encode(plan)
	})
	mux.HandleFunc("GET /client/rubygems", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		_, _ = io.WriteString(w, files[n].Content)
	})
	for _, old := range []struct{ path, content string }{
		{".gemrc", "---\n:sources:\n- https://rubygems.org/\n"},
		{".bundle/config", "---\nBUNDLE_PATH: \"vendor/bundle\"\n"},
	} {
		p := filepath.Join(home, old.path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(old.content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	out, err := runDoctor(t, "--configure", "rubygems", "--url", srv.URL, "--allow-plaintext", "--apply")
	if err != nil {
		t.Fatalf("--configure rubygems --apply = %v:\n%s", err, out)
	}
	for _, f := range files {
		target := filepath.Join(home, strings.TrimPrefix(f.Path(clientconf.OSLinux), "~/"))
		if got, _ := os.ReadFile(target); string(got) != f.Content {
			t.Errorf("%s = %q, want %q", target, got, f.Content)
		}
		if backups, _ := filepath.Glob(target + ".bodega-*"); len(backups) != 1 {
			t.Errorf("backups of %s = %v, want one", target, backups)
		}
	}
}

// F87 R2/R3: --configure maven --apply merges bodega's mirror into an
// existing settings.xml, keeping its profile, writes the init script, backs
// up the file it replaces, and prints the wrapper note.
func TestDoctorConfigureMavenMergesSettingsAndPrintsTheWrapperNote(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	files := clientconf.Maven(srv.URL, nil)
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		var plan clientconf.Plan
		for i, f := range files {
			sum := sha256.Sum256([]byte(f.Content))
			plan.Records = append(plan.Records, clientconf.PlanRecord{
				Identity: "ci-host", System: "maven", Action: clientconf.PlanInstall, Path: f.Path(clientconf.OSLinux),
				URL: srv.URL + "/client/maven?n=" + strconv.Itoa(i), SHA256: hex.EncodeToString(sum[:]),
				Reason: strings.Join(f.Notes, ". "),
			})
		}
		_ = json.NewEncoder(w).Encode(plan)
	})
	mux.HandleFunc("GET /client/maven", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		_, _ = io.WriteString(w, files[n].Content)
	})
	settings := filepath.Join(home, ".m2", "settings.xml")
	const existing = "<settings>\n  <mirrors>\n    <mirror><id>old</id><mirrorOf>*</mirrorOf><url>https://old/</url></mirror>\n  </mirrors>\n" +
		"  <profiles><profile><id>keep-me</id></profile></profiles>\n</settings>\n"
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runDoctor(t, "--configure", "maven", "--url", srv.URL, "--allow-plaintext", "--apply")
	if err != nil {
		t.Fatalf("--configure maven --apply = %v:\n%s", err, out)
	}
	if !strings.Contains(out, "gradle/wrapper/gradle-wrapper.properties") || !strings.Contains(out, "distributionUrl="+srv.URL+"/binaries/") {
		t.Errorf("output lacks the wrapper note:\n%s", out)
	}
	got, _ := os.ReadFile(settings)
	if !strings.Contains(string(got), "<id>keep-me</id>") || !strings.Contains(string(got), "<url>"+srv.URL+"/maven/</url>") || strings.Contains(string(got), "https://old/") {
		t.Errorf("settings.xml after apply:\n%s", got)
	}
	if backups, _ := filepath.Glob(settings + ".bodega-*"); len(backups) != 1 {
		t.Errorf("backups of %s = %v, want one", settings, backups)
	}
	if init, _ := os.ReadFile(filepath.Join(home, ".gradle", "init.d", "bodega.gradle")); string(init) != files[1].Content {
		t.Errorf("init script = %q, want the planned file", init)
	}
}
