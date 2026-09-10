package main

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ravinald/bodega/internal/hostpkg"
)

// pinFixtureInventory is one host's dpkg-query output covering the whole
// split: a package served at the installed version, one served only at another
// version, one no suite has, one that is Architecture: all, and one row that
// is in the dpkg database without being installed.
const pinFixtureInventory = "apparmor\t3.0.4-2ubuntu2.5\tamd64\tinstall ok installed\n" +
	"fwupd\t1.7.9-1~22.04.3\tamd64\tinstall ok installed\n" +
	"sosreport\t4.3-1ubuntu1.22.04.1\tamd64\tinstall ok installed\n" +
	"zerofree\t1.1.1-1build3\tamd64\tinstall ok installed\n" +
	"ca-certificates\t20230311ubuntu0.22.04.1\tall\tinstall ok installed\n" +
	"linux-image-5.15.0-100-generic\t5.15.0-100.110\tamd64\tdeinstall ok config-files\n"

// pinFixtureServer answers the two routes the command reads: the status
// endpoint that names the served suites, and the dists/ tree.
//
// jammy publishes Packages.gz only, the way a mirrored Ubuntu archive does.
// local publishes plain Packages, the way bodega's own generated suite does,
// so one fixture drives both halves of the compressed-first fallback.
func pinFixtureServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()

	// ca-certificates is Architecture: all and lives inside binary-amd64,
	// which is where every archive publishes it. Nothing publishes binary-all.
	jammy := "Package: apparmor\nVersion: 3.0.4-2ubuntu2.5\nArchitecture: amd64\nFilename: pool/main/a/apparmor/apparmor_3.0.4-2ubuntu2.5_amd64.deb\n\n" +
		"Package: ca-certificates\nVersion: 20230311ubuntu0.22.04.1\nArchitecture: all\nFilename: pool/main/c/ca-certificates/ca-certificates_20230311ubuntu0.22.04.1_all.deb\n\n" +
		"Package: bash\nVersion: 5.1-6ubuntu1\nArchitecture: amd64\n"
	local := "Package: fwupd\nVersion: 1.9.0-1\nArchitecture: amd64\n\n" +
		"Package: zerofree\nVersion: 1.1.1-1build3\nArchitecture: amd64\n"

	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write([]byte(jammy)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	var (
		mu        sync.Mutex
		requested []string
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"healthy":true,"apt":{"suites":["local"],"mirrored":["jammy"]}}`))
	})
	mux.HandleFunc("/apt/dists/jammy/Release", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Origin: Ubuntu\nSuite: jammy\nComponents: main\nArchitectures: amd64 i386\n"))
	})
	mux.HandleFunc("/apt/dists/jammy/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gz.Bytes())
	})
	mux.HandleFunc("/apt/dists/local/Release", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Origin: bodega\nSuite: local\nComponents: main\nArchitectures: amd64\n"))
	})
	mux.HandleFunc("/apt/dists/local/main/binary-amd64/Packages", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(local))
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.URL.Path)
		mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &requested
}

// runPinApt drives the real command against a scratch config, returning what
// it wrote to each stream.
func runPinApt(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	dir := t.TempDir()
	inventory := filepath.Join(dir, "installed.txt")
	if err := os.WriteFile(inventory, []byte(pinFixtureInventory), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(
		`{"manifest_dir":"/nonexistent/f9/manifests","storage_path":"/nonexistent/f9/storage","bucket":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BODEGA_CONFIG_FILE", cfgPath)

	var out, errBuf bytes.Buffer
	cmd := newPinCmd(&globalFlags{})
	cmd.SetArgs(append([]string{"apt", inventory}, args...))
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	err = cmd.Execute()
	return out.String(), errBuf.String(), err
}

// TestPinAptSplitsServedFromSuperseded is the whole point of the command. All
// four outcomes are asserted together because pinning everything is what the
// ad-hoc script did, and a command that gets three of the four right produces
// an apt configuration that reads fine until the next upgrade.
func TestPinAptSplitsServedFromSuperseded(t *testing.T) {
	srv, requested := pinFixtureServer(t)
	stdout, stderr, err := runPinApt(t, "--server", srv.URL, "--allow-plaintext")
	if err != nil {
		t.Fatalf("pin apt: %v\n%s", err, stderr)
	}

	// Served at the installed version.
	if !strings.Contains(stdout, "Package: apparmor\nPin: version 3.0.4-2ubuntu2.5\nPin-Priority: 1001\n") {
		t.Errorf("a package served at its installed version was not pinned:\n%s", stdout)
	}
	// Architecture: all, published under binary-amd64. A (name, arch) match
	// misses this one, and on the host this fixture comes from that was 158
	// packages.
	if !strings.Contains(stdout, "Package: ca-certificates\nPin: version 20230311ubuntu0.22.04.1\nPin-Priority: 1001\n") {
		t.Errorf("an Architecture: all package published under binary-amd64 was not pinned:\n%s", stdout)
	}
	// Served, but only at another version.
	if strings.Contains(stdout, "fwupd") {
		t.Errorf("a package served only at a different version must not be pinned:\n%s", stdout)
	}
	// In no served suite at all.
	if strings.Contains(stdout, "sosreport") {
		t.Errorf("a package no served suite carries must not be pinned:\n%s", stdout)
	}

	if !strings.Contains(stderr, "pin apt: 5 installed, 3 pinned, 2 unresolved") {
		t.Errorf("coverage counts missing from stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "apt-mark hold fwupd sosreport") {
		t.Errorf("the unresolved names must reach stderr as a hold list:\n%s", stderr)
	}

	// An "all" package is looked for inside binary-amd64, never in a
	// binary-all directory of its own. No archive publishes one, so a lookup
	// driven by the host row's architecture 404s and reports the package as
	// superseded when it is sitting in the index that was already fetched.
	var joined = strings.Join(*requested, " ")
	if strings.Contains(joined, "binary-all") {
		t.Errorf("the command asked for a binary-all index, which no archive publishes: %s", joined)
	}
	if !strings.Contains(joined, "/apt/dists/jammy/main/binary-amd64/Packages.gz") {
		t.Errorf("the compressed index was not read: %s", joined)
	}
}

// TestPinResolvesAcrossArchitectures drives the match rule directly, which is
// where the "all" question is actually decided. Both directions matter: an
// index entry marked "all" answers a native host row, and a host row marked
// "all" is answered by whichever binary-<arch> index carried it. A rule that
// ignored the architecture entirely would satisfy those two and fail the last.
func TestPinResolvesAcrossArchitectures(t *testing.T) {
	idx := servedIndex{}
	add := func(name, version string, arches ...string) {
		idx[pinKey{name, version}] = arches
	}
	add("ca-certificates", "20230311", "all")
	add("tzdata", "2024a", "amd64")
	add("libfoo", "1.0", "i386")

	for _, tc := range []struct {
		name string
		row  hostpkg.AptRow
		want bool
	}{
		{"all in the index answers an all host row", hostpkg.AptRow{Name: "ca-certificates", Version: "20230311", Arch: "all"}, true},
		{"all in the index answers a native host row", hostpkg.AptRow{Name: "ca-certificates", Version: "20230311", Arch: "amd64"}, true},
		{"an all host row is answered by the index that carried it", hostpkg.AptRow{Name: "tzdata", Version: "2024a", Arch: "all"}, true},
		{"another architecture is not a match", hostpkg.AptRow{Name: "libfoo", Version: "1.0", Arch: "amd64"}, false},
		{"another version is not a match", hostpkg.AptRow{Name: "tzdata", Version: "2023c", Arch: "amd64"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := idx.resolves(tc.row); got != tc.want {
				t.Errorf("resolves(%+v) = %v, want %v", tc.row, got, tc.want)
			}
		})
	}
}

// TestPinAptDropsRowsThatAreNotInstalled keeps one rule for "installed". The
// count and the wording come from hostpkg, which is what 'pkg convert apt'
// reports, so the two commands cannot disagree about a host.
func TestPinAptDropsRowsThatAreNotInstalled(t *testing.T) {
	srv, _ := pinFixtureServer(t)
	stdout, stderr, err := runPinApt(t, "--server", srv.URL, "--allow-plaintext")
	if err != nil {
		t.Fatalf("pin apt: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "skipped 1 package(s) present in the dpkg database but not installed") {
		t.Errorf("the skipped count must be reported the way convert reports it:\n%s", stderr)
	}
	if strings.Contains(stdout, "linux-image-5.15.0-100-generic") {
		t.Errorf("a deinstall ok config-files row reached the preferences file:\n%s", stdout)
	}
}

// TestPinAptWritesBothArtifacts covers requirement 3's split: the preferences
// file and the list of names that did not resolve are two files, because the
// second one is an input to 'apt-mark hold' rather than a comment.
func TestPinAptWritesBothArtifacts(t *testing.T) {
	srv, _ := pinFixtureServer(t)
	dir := t.TempDir()
	prefs := filepath.Join(dir, "bodega-pin")
	hold := filepath.Join(dir, "bodega-hold")

	_, stderr, err := runPinApt(t, "--server", srv.URL, "--allow-plaintext", "-o", prefs, "--unresolved", hold)
	if err != nil {
		t.Fatalf("pin apt: %v\n%s", err, stderr)
	}

	prefsBody, err := os.ReadFile(prefs)
	if err != nil {
		t.Fatalf("read preferences: %v", err)
	}
	if !strings.Contains(string(prefsBody), "Package: apparmor") {
		t.Errorf("preferences file missing its stanzas:\n%s", prefsBody)
	}
	// Requirement 3's header: why 1001 and not 1000, in the file the operator
	// reads six months from now with no runbook in hand.
	if !strings.Contains(string(prefsBody), "1001 rather than 1000") || !strings.Contains(string(prefsBody), "downgrade") {
		t.Errorf("the header must say why 1001 rather than 1000:\n%s", prefsBody)
	}

	holdBody, err := os.ReadFile(hold)
	if err != nil {
		t.Fatalf("read unresolved list: %v", err)
	}
	if got := strings.TrimSpace(string(holdBody)); got != "fwupd\nsosreport" {
		t.Errorf("unresolved list = %q, want fwupd and sosreport one per line", got)
	}
}

// TestPinAptUnresolvedIsNotAFailure pins the exit status. A superseded version
// is the expected result, not an error, and a non-zero exit here would stop
// every configuration-management run that wraps this command.
func TestPinAptUnresolvedIsNotAFailure(t *testing.T) {
	srv, _ := pinFixtureServer(t)
	if _, stderr, err := runPinApt(t, "--server", srv.URL, "--allow-plaintext", "--suite", "jammy"); err != nil {
		t.Fatalf("unresolved packages failed the command: %v\n%s", err, stderr)
	}
}

// TestPinAptPriorityOverride covers --priority, and that the header stops
// claiming a downgrade the chosen value will not perform.
func TestPinAptPriorityOverride(t *testing.T) {
	srv, _ := pinFixtureServer(t)
	stdout, stderr, err := runPinApt(t, "--server", srv.URL, "--allow-plaintext", "--priority", "990")
	if err != nil {
		t.Fatalf("pin apt: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Pin-Priority: 990") || strings.Contains(stdout, "Pin-Priority: 1001") {
		t.Errorf("--priority did not reach the stanzas:\n%s", stdout)
	}
	if strings.Contains(stdout, "1001 rather than 1000") {
		t.Errorf("the header explains 1001 under a priority that is not 1001:\n%s", stdout)
	}
}

// TestPinAptReadsTheServerFromTheEnvironment covers the reach half of
// requirement 2: a host being pinned has no config file worth the name, and
// $BODEGA_SERVER is how 'pkg import --server' already gets its target.
func TestPinAptReadsTheServerFromTheEnvironment(t *testing.T) {
	srv, _ := pinFixtureServer(t)
	t.Setenv("BODEGA_SERVER", srv.URL)
	stdout, stderr, err := runPinApt(t, "--allow-plaintext")
	if err != nil {
		t.Fatalf("pin apt: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "$BODEGA_SERVER") {
		t.Errorf("the resolved target must name the setting that supplied it:\n%s", stderr)
	}
	if !strings.Contains(stdout, "Package: apparmor") {
		t.Errorf("the environment target resolved nothing:\n%s", stdout)
	}
}

// TestPinAptSuiteFlagNarrowsTheMatch proves the indices are read per suite
// rather than pooled: zerofree resolves against the local suite in the run
// above and drops out here, which is also the assertion that keeps the
// fixture's uncompressed Packages route exercised.
func TestPinAptSuiteFlagNarrowsTheMatch(t *testing.T) {
	srv, _ := pinFixtureServer(t)
	stdout, stderr, err := runPinApt(t, "--server", srv.URL, "--allow-plaintext", "--suite", "jammy")
	if err != nil {
		t.Fatalf("pin apt: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Package: apparmor") {
		t.Errorf("--suite jammy dropped a package jammy publishes:\n%s", stdout)
	}
	if strings.Contains(stdout, "zerofree") {
		t.Errorf("--suite jammy pinned a package only the local suite publishes:\n%s", stdout)
	}
	if !strings.Contains(stderr, "2 pinned, 3 unresolved") {
		t.Errorf("counts under --suite jammy:\n%s", stderr)
	}
}
