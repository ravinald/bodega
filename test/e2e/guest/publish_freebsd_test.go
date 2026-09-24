package guest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/ravinald/bodega/internal/storage"
)

// The tests in this file run on freebsd-server, against a ZFS dataset
// test/e2e/suites/48-freebsd-server.sh creates with aclmode=passthrough and
// aclinherit=passthrough. They reach internal/storage the way a deployment
// does, through storage.NewLocal and Put, so what they grade is the object a
// reader finds rather than the syscalls that built it.
//
// zfsACLEnv names the aclmode/aclinherit pair TMPDIR's dataset must carry. It
// is required rather than detected for the reason guest_freebsd_test.go gives:
// a test that detected it would pass on whichever dataset it landed on.
const zfsACLEnv = "BODEGA_FREEBSD_GUEST_ZFS_ACL"

// principalEnv names the account every fixture here grants or denies.
// test/e2e/suites/48-freebsd-server.sh creates it for the run and removes it
// afterwards, and explains why it is not nobody.
const principalEnv = "BODEGA_FREEBSD_GUEST_PRINCIPAL"

// uidNobody is nobody's uid on FreeBSD. A user:nobody deny entry does not stop
// nobody reading the file on freebsd-server, so a read as that uid proves
// nothing about the ACL.
const uidNobody = 65534

type principal struct {
	name string
	uid  int
}

// requireZFSACL fails unless TMPDIR sits on a dataset carrying exactly the
// aclmode and aclinherit zfsACLEnv names.
func requireZFSACL(t *testing.T, aclmode, aclinherit string) {
	t.Helper()
	want := os.Getenv(zfsACLEnv)
	if want == "" {
		t.Skipf("%s is unset; test/e2e/suites/48-freebsd-server.sh sets it", zfsACLEnv)
	}
	if want != aclmode+"/"+aclinherit {
		t.Fatalf("%s=%q; this test needs aclmode=%s and aclinherit=%s", zfsACLEnv, want, aclmode, aclinherit)
	}
	dir := os.TempDir()
	out, err := exec.Command("/sbin/zfs", "get", "-H", "-o", "value", "aclmode,aclinherit", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("zfs get aclmode,aclinherit %s: %v: %s", dir, err, out)
	}
	if got := strings.Join(strings.Fields(string(out)), "/"); got != want {
		t.Fatalf("TMPDIR (%s) is on a dataset with aclmode/aclinherit %s, and %s names %s", dir, got, zfsACLEnv, want)
	}
}

func lookupPrincipal(t *testing.T) principal {
	t.Helper()
	name := os.Getenv(principalEnv)
	if name == "" {
		t.Fatalf("%s is unset; test/e2e/suites/48-freebsd-server.sh creates the account and sets it", principalEnv)
	}
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatalf("look up %s=%s: %v", principalEnv, name, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("uid of %s is %q: %v", name, u.Uid, err)
	}
	if uid == os.Geteuid() || uid == 0 || uid == uidNobody {
		t.Fatalf("%s is uid %d, which is this process, root or nobody: a read as it proves nothing about the ACL", name, uid)
	}
	return principal{name: u.Username, uid: uid}
}

// storeRoot is a storage root the principal can traverse. t.TempDir is 0700,
// and a read refused at the directory would pass any denial assertion here.
func storeRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "publish-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("chmod %s: %v", root, err)
	}
	return root
}

func setfacl(t *testing.T, target string, args ...string) {
	t.Helper()
	out, err := exec.Command("/bin/setfacl", append(args, target)...).CombinedOutput()
	if err != nil {
		t.Fatalf("setfacl %q %s: %v: %s", args, target, err, out)
	}
}

// aclEntry is one line of getfacl -n on an NFSv4 ACL.
type aclEntry struct {
	tag, id, perms, flags, kind string
}

func (e aclEntry) String() string {
	return strings.Join([]string{e.tag, e.id, e.perms, e.flags, e.kind}, ":")
}

// entriesFor returns path's entries naming uid, as getfacl renders them.
func entriesFor(t *testing.T, path string, uid int) []aclEntry {
	t.Helper()
	out, err := exec.Command("/bin/getfacl", "-nq", path).CombinedOutput()
	if err != nil {
		t.Fatalf("getfacl %s: %v: %s", path, err, out)
	}
	var named []aclEntry
	for line := range strings.Lines(string(out)) {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) == 5 && f[0] == "user" && f[1] == strconv.Itoa(uid) {
			named = append(named, aclEntry{f[0], f[1], f[2], f[3], f[4]})
		}
	}
	return named
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// readAs reads path as p, through sudo, and returns what cat printed.
func readAs(p principal, path string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("sudo", "-n", "-u", p.name, "/bin/cat", path)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Under aclinherit=passthrough an inherited entry is the parent's entry, with
// every permission it named. The default, restricted, strips write_acl and
// write_owner on the way down, so an entry granting both is how this test
// tells the two apart: it fails on a dataset that did not pass them through,
// and on one that inherited nothing. A fresh object is the staging file
// renamed, so it carries what its directory handed down; a replacement is a
// new inode, so it carries the entry only if publication restated it.
func TestZFSPassthroughPublishKeepsANamedInheritedEntry(t *testing.T) {
	requireZFSACL(t, "passthrough", "passthrough")
	who := lookupPrincipal(t)
	root := storeRoot(t)
	setfacl(t, root, "-a0", fmt.Sprintf("user:%d:rxcCo:fd:allow", who.uid))
	parent := entriesFor(t, root, who.uid)
	if len(parent) != 1 || !strings.Contains(parent[0].flags, "f") || !strings.Contains(parent[0].flags, "d") {
		t.Fatalf("the fixture on %s reads back as %v; want one file- and directory-inheritable entry for %s", root, parent, who.name)
	}

	store := storage.NewLocal(root)
	const key = "pool/inherited/object"
	obj := filepath.Join(root, filepath.FromSlash(key))
	check := func(when string) {
		t.Helper()
		got := entriesFor(t, obj, who.uid)
		if len(got) != 1 {
			t.Fatalf("%s: the published object carries %d entries for %s (%v); want the one %s handed down (%v)",
				when, len(got), who.name, got, root, parent[0])
		}
		if got[0].perms != parent[0].perms || got[0].kind != parent[0].kind || !strings.Contains(got[0].flags, "I") {
			t.Errorf("%s: the published object's entry for %s is %v; want %v's permissions and type, marked inherited",
				when, who.name, got[0], parent[0])
		}
	}

	if err := store.Put(context.Background(), key, []byte("first\n")); err != nil {
		t.Fatalf("Put (fresh): %v", err)
	}
	check("fresh object")
	before := inode(t, obj)
	if err := store.Put(context.Background(), key, []byte("second\n")); err != nil {
		t.Fatalf("Put (replacement): %v", err)
	}
	if inode(t, obj) == before {
		t.Fatalf("the replacement reused inode %d; publication wrote in place and this test graded nothing", before)
	}
	check("replacement")
}

// A deny entry that survives publication is text until something is denied
// by it. The control object is published beside it the same way, at the same
// mode, without the entry, and has to be readable by the same principal:
// otherwise the path or the mode is what refused the read, and the ACL was
// never consulted.
func TestZFSPassthroughPublishedDenyEntryDeniesItsPrincipal(t *testing.T) {
	requireZFSACL(t, "passthrough", "passthrough")
	who := lookupPrincipal(t)
	root := storeRoot(t)
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })

	store := storage.NewLocal(root)
	body := []byte("denied body\n")
	const denied, control = "pool/denied", "pool/control"
	for _, key := range []string{denied, control} {
		if err := store.Put(context.Background(), key, body); err != nil {
			t.Fatalf("Put %s (fresh): %v", key, err)
		}
	}
	deniedPath := filepath.Join(root, filepath.FromSlash(denied))
	controlPath := filepath.Join(root, filepath.FromSlash(control))
	setfacl(t, deniedPath, "-a0", fmt.Sprintf("user:%d:r::deny", who.uid))

	before := inode(t, deniedPath)
	for _, key := range []string{denied, control} {
		if err := store.Put(context.Background(), key, body); err != nil {
			t.Fatalf("Put %s (replacement): %v", key, err)
		}
	}
	if inode(t, deniedPath) == before {
		t.Fatalf("the replacement reused inode %d; publication wrote in place and this test graded nothing", before)
	}
	if got := entriesFor(t, deniedPath, who.uid); len(got) != 1 || got[0].kind != "deny" {
		t.Fatalf("the replacement carries %v for %s; want the deny entry its predecessor had", got, who.name)
	}

	got, err := readAs(who, controlPath)
	if err != nil {
		t.Fatalf("%s cannot read the control object %s (%v), so a refused read below would prove nothing about the ACL", who.name, controlPath, err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("%s read %q from the control object, want %q", who.name, got, body)
	}
	if got, err := readAs(who, deniedPath); err == nil {
		t.Errorf("%s read %q from %s, whose ACL denies it read_data", who.name, got, deniedPath)
	} else if !strings.Contains(err.Error(), "Permission denied") {
		t.Errorf("%s's read of %s failed as %v; want the kernel's Permission denied", who.name, deniedPath, err)
	}
}
