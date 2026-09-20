package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
)

// serveTreeEnv hands the child the install the parent built. A second account
// is the whole point of this test, so the serve side is a process rather than
// a goroutine: a uid is a property of a process and nothing inside one can
// model it.
const (
	serveTreeEnv = "BODEGA_TEST_SERVE_TREE"
	serveAddrEnv = "BODEGA_TEST_SERVE_ADDR"
)

// TestTokenMintedAsRootValidatesAgainstAnotherAccount is QUICKSTART §12 end to
// end, and requirement 5. Root mints through `bodega token generate`, a second
// account runs `bodega serve` over the same install, and the minted token is
// presented over HTTP.
//
// Measured on 2026-09-14 against 122f9e7, that request answered 401 "invalid
// token": the pepper landed 0600 root:root, the server could not read it, and
// it hashed against a second pepper under its own home with nothing in any log
// naming either file.
func TestTokenMintedAsRootValidatesAgainstAnotherAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mint as one account and serve as another; test/e2e ACC-06b and ACC-10 measure the same path on a real install")
	}
	svc := unprivilegedAccount(t)
	tree := installTree(t, svc)

	t.Setenv("BODEGA_CONFIG_FILE", filepath.Join(tree, "etc", "config.json"))
	t.Setenv(audit.ServiceUserEnv, svc.Username)
	pepper := filepath.Join(tree, "etc", "pepper")
	usePepperPaths(t, tree)

	token := mintAsRoot(t)

	// What token generate left behind, before anything is asked to read it.
	fi, err := os.Stat(pepper)
	if err != nil {
		t.Fatalf("stat pepper: %v", err)
	}
	sys := fi.Sys().(*syscall.Stat_t)
	if sys.Uid != 0 {
		t.Errorf("pepper owned by uid %d, want root: the account that serves must not be able to rewrite it", sys.Uid)
	}
	if mode := fi.Mode().Perm(); mode != 0o640 {
		t.Errorf("pepper mode %04o, want 0640", mode)
	}
	if got := strconv.Itoa(int(sys.Gid)); got != svc.Gid {
		t.Errorf("pepper gid %s, want %s (%s)", got, svc.Gid, svc.Username)
	}

	handTreeTo(t, tree, svc, pepper)
	base, _ := serveAs(t, svc, tree)

	const body = `{"config_version":1,"name":"two-account-probe","type":"binary",` +
		`"versions":[{"version":"1.0.0","url":"https://example.invalid/x"}]}`

	// A bogus token first. Without it a 201 proves only that the mutation
	// path is open to loopback, which is a different install and a passing
	// test either way.
	if code := post(t, base, "not-a-real-token", body); code != http.StatusUnauthorized {
		t.Fatalf("a bogus bearer token got %d, want 401: this server is not gating on the token at all", code)
	}
	if code := post(t, base, token, body); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("the token root minted got %d from a server running as %q: the pepper it was hashed against "+
			"is not the one %s loaded", code, svc.Username, svc.Username)
	}
}

// TestABrokenSecondPepperDoesNotUnseatTheFirstOverHTTP is requirement 3 at the
// only altitude that settles it. Two peppers on one host is the state this
// defect creates, so an upgrade meets it; the resolver used to abandon the
// whole search when a candidate behind the winner would not open, and the
// server then came up with no pepper at all and answered 401 to the token it
// had been reading fine a minute earlier.
func TestABrokenSecondPepperDoesNotUnseatTheFirstOverHTTP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mint as one account and serve as another")
	}
	svc := unprivilegedAccount(t)
	tree := installTree(t, svc)

	t.Setenv("BODEGA_CONFIG_FILE", filepath.Join(tree, "etc", "config.json"))
	t.Setenv(audit.ServiceUserEnv, svc.Username)
	pepper := filepath.Join(tree, "etc", "pepper")
	usePepperPaths(t, tree)

	token := mintAsRoot(t)

	// The loser, after the mint: a self-referential symlink is a path that
	// opens for nobody, root included, which is what separates this from the
	// permission cases.
	xdg := pepperPaths(tree)[1]
	if err := os.MkdirAll(filepath.Dir(xdg), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(xdg), err)
	}
	if err := os.Symlink("pepper", xdg); err != nil {
		t.Fatalf("symlink %s: %v", xdg, err)
	}

	handTreeTo(t, tree, svc, pepper)
	base, serveLog := serveAs(t, svc, tree)

	const body = `{"config_version":1,"name":"shadow-probe","type":"binary",` +
		`"versions":[{"version":"1.0.0","url":"https://example.invalid/x"}]}`
	if code := post(t, base, token, body); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("the token root minted got %d from a server running as %q with a broken pepper further down "+
			"the search order: %s is still readable and still the one in force", code, svc.Username, pepper)
	}
	if !strings.Contains(serveLog(), xdg) {
		t.Errorf("serve never named the second pepper at %s:\n%s", xdg, serveLog())
	}
}

// TestServeAsTheServiceAccountHelper is the child half. It is a test only
// because that is how a process re-enters this binary; -test.run selects it and
// the environment gate keeps it out of an ordinary run.
func TestServeAsTheServiceAccountHelper(t *testing.T) {
	tree := os.Getenv(serveTreeEnv)
	if tree == "" {
		t.Skip("child half of TestTokenMintedAsRootValidatesAgainstAnotherAccount")
	}
	audit.DefaultPepperPaths = pepperPaths(tree)
	// The config lives in the install the parent built and handed to a second
	// uid, so it cannot come from this process's t.TempDir(). Naming it here
	// rather than trusting the inherited environment means a direct
	// -test.run of this helper resolves the tree's config, not /etc's.
	t.Setenv("BODEGA_CONFIG_FILE", filepath.Join(tree, "etc", "config.json"))
	cmd := newServeCmd(&globalFlags{})
	cmd.SetArgs([]string{"--addr", os.Getenv(serveAddrEnv), "--allow-plaintext", "--quiet"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("serve: %v", err)
	}
}

// unprivilegedAccount names an account that is not root and exists here.
func unprivilegedAccount(t *testing.T) *user.User {
	t.Helper()
	for _, name := range []string{"bodega", "nobody", "daemon", "games", "bin"} {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		if uid, err := strconv.Atoi(u.Uid); err == nil && uid > 0 {
			return u
		}
	}
	t.Skip("this host has no second account to serve as")
	return nil
}

// pepperPaths is the shipped search order relocated under tree: the privileged
// path first, the serving account's own XDG path second.
func pepperPaths(tree string) []string {
	return []string{
		filepath.Join(tree, "etc", "pepper"),
		filepath.Join(tree, "var", ".config", "bodega", "pepper"),
	}
}

func usePepperPaths(t *testing.T, tree string) {
	t.Helper()
	prev := audit.DefaultPepperPaths
	audit.DefaultPepperPaths = pepperPaths(tree)
	t.Cleanup(func() { audit.DefaultPepperPaths = prev })
}

// installTree lays out the three directories the unit header describes, under
// a root every uid can walk into.
func installTree(t *testing.T, svc *user.User) string {
	t.Helper()
	tree, err := os.MkdirTemp("/tmp", "bodega-two-account")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tree) })
	for _, d := range []string{"etc", "var", "log"} {
		if err := os.MkdirAll(filepath.Join(tree, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.Chmod(tree, 0o755); err != nil {
		t.Fatalf("chmod %s: %v", tree, err)
	}

	// admin_permit_cidr reaches past loopback on purpose: that is what turns
	// the Bearer requirement on, and a loopback-only install would accept the
	// request with no token and prove nothing about the pepper.
	cfg := fmt.Sprintf(`{"config_version":1,"manifest_dir":%s,"log_dir":%s,"audit_db":%s,`+
		`"allow_plaintext":true,"admin_permit_cidr":["127.0.0.1/32","10.0.0.0/8"]}`,
		strconv.Quote(filepath.Join(tree, "var")),
		strconv.Quote(filepath.Join(tree, "log")),
		strconv.Quote(filepath.Join(tree, "log", "audit.db")))
	if err := os.WriteFile(filepath.Join(tree, "etc", "config.json"), []byte(cfg+"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return tree
}

// mintAsRoot runs the privileged command itself rather than the three calls
// inside it: what this item is about is what `bodega token generate` leaves on
// disk, and a test that reassembles the body cannot catch the command growing
// a fourth step.
func mintAsRoot(t *testing.T) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	stdout := os.Stdout
	os.Stdout = w
	cmd := newTokenGenerateCmd(&globalFlags{})
	cmd.SetArgs([]string{"two-account-probe", "expiry", "1d"})
	runErr := cmd.Execute()
	os.Stdout = stdout
	_ = w.Close()
	out, _ := io.ReadAll(r)
	_ = r.Close()
	if runErr != nil {
		t.Fatalf("token generate: %v\n%s", runErr, out)
	}

	for _, line := range strings.Split(string(out), "\n") {
		if _, rest, ok := strings.Cut(strings.TrimSpace(line), "Token:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("token generate printed no token:\n%s", out)
	return ""
}

// handTreeTo is the ownership pass docs/bodega.service describes: the writable
// trees go to the service account, and the pepper does not. Its group carries
// the read and root keeps the write, which is the posture under test.
func handTreeTo(t *testing.T, tree string, svc *user.User, keepRootOwned string) {
	t.Helper()
	uid, _ := strconv.Atoi(svc.Uid)
	gid, _ := strconv.Atoi(svc.Gid)

	paths := []string{tree}
	for _, d := range []string{"etc", "var", "log"} {
		dir := filepath.Join(tree, d)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		paths = append(paths, dir)
		for _, e := range entries {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	for _, p := range paths {
		if p == keepRootOwned {
			continue
		}
		if err := os.Chown(p, uid, gid); err != nil {
			t.Fatalf("chown %s to %s: %v", p, svc.Username, err)
		}
	}
}

// serveAs starts the server as svc and returns the base URL once it answers,
// with an accessor for everything the child wrote.
func serveAs(t *testing.T, svc *user.User, tree string) (string, func() string) {
	t.Helper()
	uid, _ := strconv.Atoi(svc.Uid)
	gid, _ := strconv.Atoi(svc.Gid)
	addr := freeAddr(t)

	cmd := exec.Command(os.Args[0], "-test.run=TestServeAsTheServiceAccountHelper", "-test.timeout=120s")
	cmd.Env = append(os.Environ(), serveTreeEnv+"="+tree, serveAddrEnv+"="+addr,
		"BODEGA_CONFIG_FILE="+filepath.Join(tree, "etc", "config.json"),
		audit.ServiceUserEnv+"="+svc.Username, "HOME="+tree)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uint32(uid), Gid: uint32(gid), //nolint:gosec // ids this test read back out of /etc/passwd
	}}
	var log strings.Builder
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatalf("start serve as %s: %v", svc.Username, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("serve as %s:\n%s", svc.Username, log.String())
		}
	})

	base := "http://" + addr
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			return base, log.String
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("server as %s never answered on %s:\n%s", svc.Username, addr, log.String())
	return "", log.String
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

func post(t *testing.T, base, token, body string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/packages/binary", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
