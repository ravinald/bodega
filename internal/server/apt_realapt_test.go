//go:build apt_integration

package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
)

// Requirement 4's other half. Every other test in this package asserts on the
// document bodega serves; this one asserts what apt does with it, because the
// document and the outcome are the same thing only if apt reads a filtered
// index the way the item claims it does.
//
// Tagged rather than skipped, and off by default: it pulls an image, installs
// dpkg-dev inside it and talks to archive.ubuntu.com, none of which belongs in
// the merge gate. `make test-apt` runs it.
//
//	go test -tags apt_integration -run TestRealApt -count=1 ./internal/server/
//
// The packages are built with dpkg-deb and indexed with dpkg-scanpackages, so
// the bytes filterAptPackages runs over are an index dpkg wrote rather than a
// fixture written to match what the filter expects. bodega then serves the
// filtered result under its own signed codename, and a real apt-get upgrade
// inside the container decides what to do about it.
const (
	realAptImage = "ubuntu:24.04"

	// The container reaches the test's listener through this name on both
	// Docker Desktop and a Linux daemon, the second by way of host-gateway.
	// The listener binds 0.0.0.0 for the same reason: host-gateway resolves
	// to the bridge address, which never reaches a loopback-bound socket.
	realAptHostAlias = "host.docker.internal"
)

// realAptBuild is the first container run: five .debs and the upstream index
// that names them, written into the mounted work directory.
//
// demo-app 2.0 is the package under test. It depends on demo-extra, which the
// profile does not list, so the filter drops demo-extra and apt meets a
// dependency nothing offers. demo-tool 2.0 depends on nothing and is what
// proves the rest of the transaction still goes through.
const realAptBuild = `set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends dpkg-dev >/dev/null
arch=$(dpkg --print-architecture)

mkdeb() { # name version depends outdir
  root=$(mktemp -d)
  mkdir -p "$root/DEBIAN" "$root/usr/share/bodega-fixture"
  {
    echo "Package: $1"
    echo "Version: $2"
    echo "Architecture: $arch"
    echo "Maintainer: bodega fixture <fixture@example.invalid>"
    if [ -n "$3" ]; then echo "Depends: $3"; fi
    echo "Description: $1 fixture package"
    echo " Built by bodega's apt integration test."
  } > "$root/DEBIAN/control"
  echo "$1 $2" > "$root/usr/share/bodega-fixture/$1"
  mkdir -p "$4"
  dpkg-deb --build --root-owner-group "$root" "$4" >/dev/null
}

mkdeb demo-app  1.0 ""           /work/v1
mkdeb demo-tool 1.0 ""           /work/v1
mkdeb demo-app  2.0 "demo-extra" /work/archive/pool/main/d/demo-app
mkdeb demo-tool 2.0 ""           /work/archive/pool/main/d/demo-tool
mkdeb demo-extra 1.0 ""          /work/archive/pool/main/d/demo-extra

mkdir -p /work/index
cd /work/archive && dpkg-scanpackages -m pool > /work/index/Packages
chmod -R a+rwX /work
`

// realAptUpgrade is the second container run: a host holding version 1.0 of
// both packages, pointed at one bodega codename and told to upgrade.
//
// The distro's own sources go first. What is under test is what one filtered
// codename offers, and archive.ubuntu.com answering beside it would supply the
// dependency the filter dropped.
const realAptUpgrade = `set -eu
export DEBIAN_FRONTEND=noninteractive
rm -f /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*
mkdir -p /etc/apt/keyrings
cp /work/client/bodega-archive-keyring.gpg /etc/apt/keyrings/
cp /work/client/bodega.sources /etc/apt/sources.list.d/
dpkg -i /work/v1/*.deb >/dev/null
apt-get update
echo "---- upgrade ----"
apt-get upgrade -y --with-new-pkgs
echo "---- installed ----"
dpkg-query -W -f '${Package} ${Version}\n' demo-app demo-tool
`

func TestRealAptHoldsBackTheDependentPackageAndUpgradesTheRest(t *testing.T) {
	work := t.TempDir()
	writeScript(t, work, "build.sh", realAptBuild)
	writeScript(t, work, "upgrade.sh", realAptUpgrade)

	arch := strings.TrimSpace(dockerRun(t, "read the container's architecture",
		"run", "--rm", realAptImage, "dpkg", "--print-architecture"))
	dockerRun(t, "build the fixture packages", "run", "--rm", "-v", work+":/work", realAptImage, "bash", "/work/build.sh")

	index, err := os.ReadFile(filepath.Join(work, "index", "Packages"))
	if err != nil {
		t.Fatalf("read the index dpkg-scanpackages wrote: %v", err)
	}
	if !strings.Contains(string(index), "Package: demo-extra") {
		t.Fatalf("the upstream index does not carry the dependency this test drops:\n%s", index)
	}

	s, _ := aptProfileServerWith(t, arch, string(index), realAptPool(t, work))
	base := serveOnAllInterfaces(t, s)
	s.cfg.PublicURL = base

	// Two profiles over one base, which is also the second run: the first
	// lists neither the dependency nor a reason apt could satisfy it, the
	// second lists it and the same upgrade completes.
	held := aptProfileBind(t, s, "held", audit.ExpansionBlock, "demo-app", "demo-tool")
	whole := aptProfileBind(t, s, "whole", audit.ExpansionBlock, "demo-app", "demo-tool", "demo-extra")

	installClient(t, s, work, base, held.token, "fixture-held")
	out := dockerRun(t, "upgrade under the filtered codename", "run", "--rm",
		"--add-host="+realAptHostAlias+":host-gateway", "-v", work+":/work", realAptImage, "bash", "/work/upgrade.sh")
	if !strings.Contains(out, "kept back") || !strings.Contains(heldBackLine(out), "demo-app") {
		t.Errorf("apt did not report demo-app kept back. A 403 at the pool aborts the whole run instead, which is the outcome this item exists to avoid:\n%s", out)
	}
	if got := installedVersion(t, out, "demo-app"); got != "1.0" {
		t.Errorf("demo-app upgraded to %s; its dependency is outside the profile and it should have stayed at 1.0:\n%s", got, out)
	}
	if got := installedVersion(t, out, "demo-tool"); got != "2.0" {
		t.Errorf("demo-tool is at %s, want 2.0: one held package must not take the rest of the transaction with it:\n%s", got, out)
	}

	installClient(t, s, work, base, whole.token, "fixture-whole")
	out = dockerRun(t, "upgrade with the dependency in the profile", "run", "--rm",
		"--add-host="+realAptHostAlias+":host-gateway", "-v", work+":/work", realAptImage, "bash", "/work/upgrade.sh")
	if strings.Contains(out, "kept back") {
		t.Errorf("apt still held a package back with every dependency in the profile, so the first run proved something other than the filter:\n%s", out)
	}
	for pkg, want := range map[string]string{"demo-app": "2.0", "demo-tool": "2.0"} {
		if got := installedVersion(t, out, pkg); got != want {
			t.Errorf("%s is at %s, want %s once the profile carries the dependency:\n%s", pkg, got, want, out)
		}
	}
}

// installClient writes the two files bodega tells a host to install: the
// keyring the stanza's Signed-By: names, and the stanza the running instance
// composed for that host's own profile. Both are taken off the server rather
// than written here, so the test drives what `bodega doctor --write-apt-sources`
// would install.
func installClient(t *testing.T, s *Server, work, base, token, wantSuite string) {
	t.Helper()
	dir := filepath.Join(work, "client")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create the client directory: %v", err)
	}

	code, keyring := getWithToken(t, s, token, "/apt/bodega-archive-keyring.gpg")
	if code != http.StatusOK || len(keyring) == 0 {
		t.Fatalf("GET the keyring = %d with %d bytes, want 200 and a key", code, len(keyring))
	}
	if err := os.WriteFile(filepath.Join(dir, "bodega-archive-keyring.gpg"), []byte(keyring), 0o644); err != nil {
		t.Fatalf("write the keyring: %v", err)
	}

	code, body := getWithToken(t, s, token, "/api/v1/status")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/status = %d, want 200", code)
	}
	var payload struct {
		Apt struct {
			Host *struct {
				Suite  string `json:"suite"`
				Deb822 string `json:"deb822"`
			} `json:"host"`
		} `json:"apt"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	if payload.Apt.Host == nil || payload.Apt.Host.Suite != wantSuite {
		t.Fatalf("status named %+v, want the stanza for %s", payload.Apt.Host, wantSuite)
	}
	stanza := payload.Apt.Host.Deb822
	if !strings.Contains(stanza, "Signed-By:") || strings.Contains(stanza, "Trusted: yes") {
		t.Fatalf("the stanza would have apt verify nothing:\n%s", stanza)
	}
	if !strings.Contains(stanza, base) {
		t.Fatalf("the stanza names a URL the container cannot reach:\n%s", stanza)
	}
	if err := os.WriteFile(filepath.Join(dir, "bodega.sources"), []byte(stanza+"\n"), 0o644); err != nil {
		t.Fatalf("write the stanza: %v", err)
	}
}

// serveOnAllInterfaces starts the server on an address a container can reach
// and returns its base URL. httptest binds loopback, which host-gateway cannot
// route to.
func serveOnAllInterfaces(t *testing.T, s *Server) string {
	t.Helper()
	ts := httptest.NewUnstartedServer(s.Handler())
	if err := ts.Listener.Close(); err != nil {
		t.Fatalf("close the loopback listener: %v", err)
	}
	//nolint:gosec // G102 is the point: host-gateway resolves to the bridge address, which cannot reach a loopback-bound listener.
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen on every interface: %v", err)
	}
	ts.Listener = l
	ts.Start()
	t.Cleanup(ts.Close)
	port := l.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf("http://%s:%d", realAptHostAlias, port)
}

// realAptPool reads the .debs the build run produced into the object map the
// fixture archive serves, keyed by the pool path the index names.
func realAptPool(t *testing.T, work string) map[string]string {
	t.Helper()
	root := filepath.Join(work, "archive")
	pool := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".deb") {
			return err
		}
		body, err := os.ReadFile(path) //nolint:gosec // G122: the tree walked is this test's own TempDir, written by the build run above.
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		pool[filepath.ToSlash(rel)] = string(body)
		return nil
	})
	if err != nil {
		t.Fatalf("read the fixture pool: %v", err)
	}
	if len(pool) != 3 {
		t.Fatalf("pool holds %d .debs, want 3", len(pool))
	}
	return pool
}

func writeScript(t *testing.T, work, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o755); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// dockerRun runs one container to completion. A missing daemon fails the test
// rather than skipping it: this tag is opted into by name, and a run that
// reports success without having driven apt is the report requirement 4 was
// sent back for.
func dockerRun(t *testing.T, what string, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("could not %s: docker %s: %v\n%s", what, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// heldBackLine is apt's "The following packages have been kept back:" list,
// which names the packages on the line after the header.
func heldBackLine(out string) string {
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.Contains(l, "kept back") && i+1 < len(lines) {
			return lines[i+1]
		}
	}
	return ""
}

// installedVersion reads one package's version out of the dpkg-query block the
// upgrade script prints last.
func installedVersion(t *testing.T, out, pkg string) string {
	t.Helper()
	_, tail, ok := strings.Cut(out, "---- installed ----")
	if !ok {
		t.Fatalf("the upgrade run printed no installed versions:\n%s", out)
	}
	for _, l := range strings.Split(tail, "\n") {
		if name, version, ok := strings.Cut(strings.TrimSpace(l), " "); ok && name == pkg {
			return version
		}
	}
	t.Fatalf("%s is not in the installed list:\n%s", pkg, tail)
	return ""
}
