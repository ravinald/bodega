package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// aptStub puts an apt-get and an apt-cache on PATH so the pin the fetch passes
// is observable without an archive. apt-get appends its argv to a log and
// writes debName into its working directory, which is the tempdir
// aptGetDownloadViaTemp downloads into; apt-cache prints the policy text the
// caller supplies. Returns the argv log path.
func aptStub(t *testing.T, policy, debName string) string {
	t.Helper()
	dir := t.TempDir()
	argvLog := filepath.Join(dir, "argv.log")
	policyFile := filepath.Join(dir, "policy.txt")
	if err := os.WriteFile(policyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o700); err != nil { //nolint:gosec // test-owned shim
			t.Fatal(err)
		}
	}
	produce := ""
	if debName != "" {
		produce = "echo bytes > " + debName + "\n"
	}
	write("apt-get", "echo \"$@\" >> "+argvLog+"\n"+produce)
	write("apt-cache", "echo \"$@\" >> "+argvLog+"\ncat "+policyFile+"\n")

	// Prepended rather than replacing PATH: the shims are /bin/sh scripts and
	// a PATH holding only them leaves the shell without the externals it runs.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argvLog
}

const helloPolicy = `hello:
  Installed: (none)
  Candidate: 2.10-3
  Version table:
     2.10-3 500
        500 http://archive.example/ubuntu noble/main amd64 Packages
     2.10-2 500
        500 http://archive.example/ubuntu noble/main amd64 Packages
`

func aptPinned(version string) *manifest.PackageManifest {
	return &manifest.PackageManifest{
		Type:     manifest.TypeApt,
		Name:     "hello",
		Versions: []manifest.VersionEntry{{Version: version}},
	}
}

func readArgv(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test-owned path
	if err != nil {
		return ""
	}
	return string(b)
}

func aptPoolDebs(t *testing.T, cfg *Config) []string {
	t.Helper()
	d := buildDirs(cfg.rootFor(manifest.TypeApt))
	got, err := filepath.Glob(filepath.Join(d.sources, "*", "*.deb"))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// R1: `apt-get download hello` takes the archive's candidate, so an entry
// pinning 2.10-2 stored 2.10-3 whenever the archive had moved on, under a pool
// key and an index entry both rendered from the manifest version.
func TestAptFetchPassesThePinToAptGetDownload(t *testing.T) {
	argvLog := aptStub(t, helloPolicy, "hello_2.10-2_amd64.deb")
	cfg, store, _ := pinEnv(t, aptPinned("2.10-2"))

	if s := FetchApt(cfg, store, "hello"); s.Failures != 0 {
		t.Fatalf("fetch reported %d failures: %+v", s.Failures, s.Results)
	}
	argv := readArgv(t, argvLog)
	if !strings.Contains(argv, "download hello=2.10-2") {
		t.Errorf("apt-get was called with %q, want the pin on the argv as hello=2.10-2", argv)
	}
}

// R2: a pin the local cache does not offer fails the entry rather than
// resolving to the candidate, and names what is installable instead.
func TestAptFetchRefusesAPinTheCacheDoesNotOffer(t *testing.T) {
	argvLog := aptStub(t, helloPolicy, "hello_2.10-3_amd64.deb")
	cfg, store, _ := pinEnv(t, aptPinned("2.10-1"))

	s := FetchApt(cfg, store, "hello")
	if s.Failures == 0 {
		t.Fatal("a pin absent from the cache was accepted")
	}
	err := s.Results[0].Err.Error()
	for _, want := range []string{"apt/hello", "2.10-1", "2.10-3", "2.10-2"} {
		if !strings.Contains(err, want) {
			t.Errorf("the refusal does not name %q: %s", want, err)
		}
	}
	if strings.Contains(readArgv(t, argvLog), "download") {
		t.Errorf("the refusal still ran a download: %s", readArgv(t, argvLog))
	}
	if got := aptPoolDebs(t, cfg); len(got) != 0 {
		t.Errorf("the refused entry left %v in the pool", got)
	}
}

// R3: apt-get exiting 0 says a .deb arrived, not that the pinned one did. What
// landed is checked before it moves out of the tempdir.
func TestAptFetchRefusesASubstitutedDeb(t *testing.T) {
	aptStub(t, helloPolicy, "hello_2.10-3_arm64.deb")
	cfg, store, _ := pinEnv(t, aptPinned("2.10-2"))

	s := FetchApt(cfg, store, "hello")
	if s.Failures == 0 {
		t.Fatal("a .deb of another version was stored under the pinned entry")
	}
	err := s.Results[0].Err.Error()
	for _, want := range []string{"apt/hello", "2.10-2", "hello_2.10-3_arm64.deb"} {
		if !strings.Contains(err, want) {
			t.Errorf("the refusal does not name %q: %s", want, err)
		}
	}
	if got := aptPoolDebs(t, cfg); len(got) != 0 {
		t.Errorf("the refused fetch left %v in the pool", got)
	}
}

func TestAptPolicyVersionsReadsTheVersionTable(t *testing.T) {
	got := aptPolicyVersions(helloPolicy)
	want := []string{"2.10-3", "2.10-2"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("aptPolicyVersions = %v, want %v", got, want)
	}
	// The installed row carries *** and a dpkg status origin rather than a URL.
	installed := `hello:
  Installed: 2.10-2
  Candidate: 2.10-2
  Version table:
 *** 2.10-2 100
        100 /var/lib/dpkg/status
`
	if got := aptPolicyVersions(installed); len(got) != 1 || got[0] != "2.10-2" {
		t.Errorf("aptPolicyVersions on an installed package = %v, want [2.10-2]", got)
	}
}

// aptSourceStub puts an apt-get on PATH that writes each argv element to its
// own line of a log, then either exits 100 as apt does on a version it cannot
// supply or leaves dsc in its working directory, plus a dpkg-source that
// unpacks to an empty tree. Returns the argv log path.
func aptSourceStub(t *testing.T, dsc string, fail bool) string {
	t.Helper()
	dir := t.TempDir()
	argvLog := filepath.Join(dir, "argv.log")
	result := "touch " + dsc + "\n"
	if fail {
		result = "echo \"E: Can not find version '2.10-2' of package 'hello'\" >&2\nexit 100\n"
	}
	for name, body := range map[string]string{
		"apt-get":     "printf '%s\\n' \"$@\" >> " + argvLog + "\n" + result,
		"dpkg-source": "mkdir -p \"$3\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o700); err != nil { //nolint:gosec // test-owned shim
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argvLog
}

func aptSourcePinned(version string) *manifest.PackageManifest {
	return &manifest.PackageManifest{
		Type:     manifest.TypeApt,
		Name:     "hello",
		Versions: []manifest.VersionEntry{{Version: version, BuildCmd: "true"}},
	}
}

// `apt-get source hello` takes the archive's candidate, so an entry pinning a
// version the archive has moved past could never build.
func TestAptSourceFetchPassesThePinToAptGetSource(t *testing.T) {
	argvLog := aptSourceStub(t, "hello_2.10-2.dsc", false)
	cfg, store, _ := pinEnv(t, aptSourcePinned("2.10-2"))

	if s := FetchApt(cfg, store, "hello"); s.Failures != 0 {
		t.Fatalf("fetch reported %d failures: %+v", s.Failures, s.Results)
	}
	if got, want := readArgv(t, argvLog), "source\n--download-only\nhello=2.10-2\n"; got != want {
		t.Errorf("apt-get argv = %q, want %q", got, want)
	}
}

func TestAptSourceFetchNamesThePinAptCannotSupply(t *testing.T) {
	aptSourceStub(t, "", true)
	cfg, store, _ := pinEnv(t, aptSourcePinned("2.10-2"))

	s := FetchApt(cfg, store, "hello")
	if s.Failures != 1 || s.Results[0].Err == nil {
		t.Fatalf("a version apt cannot supply did not fail the fetch: %+v", s.Results)
	}
	err := s.Results[0].Err.Error()
	for _, want := range []string{"apt/hello", "hello version 2.10-2", "apt-cache showsrc hello"} {
		if !strings.Contains(err, want) {
			t.Errorf("the refusal does not name %q: %s", want, err)
		}
	}
}

func TestAptSourceFetchRefusesANonDebianVersion(t *testing.T) {
	for _, v := range []string{"1.0 extra", "v1.0", "1.0/noble", "1.0=2", "-1", "1:"} {
		argvLog := aptSourceStub(t, "hello_1.0.dsc", false)
		cfg, store, _ := pinEnv(t, aptSourcePinned(v))

		s := FetchApt(cfg, store, "hello")
		if s.Failures != 1 || s.Results[0].Err == nil || !strings.Contains(s.Results[0].Err.Error(), "not a Debian version") {
			t.Errorf("version %q: want a refusal naming the syntax, got %+v", v, s.Results)
		}
		if got := readArgv(t, argvLog); got != "" {
			t.Errorf("version %q reached apt-get as %q", v, got)
		}
	}
}

func TestDebianVersionAcceptsPolicyVersions(t *testing.T) {
	for _, v := range []string{"2.10-2", "1:2.3.4-1ubuntu0.1", "2:1.0~rc1+dfsg-3", "0.9", "1:1.2:3-4"} {
		if !debianVersion.MatchString(v) {
			t.Errorf("debianVersion refused %q", v)
		}
	}
}
