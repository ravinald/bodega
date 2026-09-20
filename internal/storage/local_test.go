package storage

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLocalRoundTrip(t *testing.T) {
	root := t.TempDir()
	l := NewLocal(root)
	ctx := t.Context()

	const key = "packages/apt/pool/main/a/acme/acme_1.0_amd64.deb"
	body := []byte("\x00deb-content")

	if err := l.Put(ctx, key, body); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := l.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("Get = %q, want %q", got, body)
	}

	info, err := l.Head(ctx, key)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if !info.Exists || info.Size != int64(len(body)) {
		t.Errorf("Head = %+v, want Exists=true Size=%d", info, len(body))
	}

	stream, err := l.GetStream(ctx, key)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	streamed, _ := io.ReadAll(stream.Body)
	_ = stream.Body.Close()
	if string(streamed) != string(body) {
		t.Errorf("GetStream body = %q, want %q", streamed, body)
	}
	if stream.ContentLength != int64(len(body)) {
		t.Errorf("GetStream ContentLength = %d, want %d", stream.ContentLength, len(body))
	}

	keys, err := l.List(ctx, "packages/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Errorf("List = %v, want [%s]", keys, key)
	}

	if err := l.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got, err := l.Get(ctx, key); err != nil || got != nil {
		t.Errorf("Get after Delete = (%q, %v), want (nil, nil)", got, err)
	}
	// Delete is idempotent: a second call on a missing key is not an error.
	if err := l.Delete(ctx, key); err != nil {
		t.Errorf("Delete on missing key: %v", err)
	}
}

func TestLocalGetMissingReturnsNilNil(t *testing.T) {
	l := NewLocal(t.TempDir())
	ctx := t.Context()

	data, err := l.Get(ctx, "nope/missing.bin")
	if err != nil || data != nil {
		t.Errorf("Get = (%v, %v), want (nil, nil)", data, err)
	}
	stream, err := l.GetStream(ctx, "nope/missing.bin")
	if err != nil || stream != nil {
		t.Errorf("GetStream = (%v, %v), want (nil, nil)", stream, err)
	}
	info, err := l.Head(ctx, "nope/missing.bin")
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if info.Exists {
		t.Error("Head reported Exists=true for a missing key")
	}
}

func TestLocalPutFile(t *testing.T) {
	root := t.TempDir()
	l := NewLocal(root)
	ctx := t.Context()

	src := filepath.Join(t.TempDir(), "wheel.whl")
	if err := os.WriteFile(src, []byte("wheel-bytes"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := l.PutFile(ctx, src, "pypi/wheels/wheel.whl"); err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	got, err := l.Get(ctx, "pypi/wheels/wheel.whl")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "wheel-bytes" {
		t.Errorf("Get = %q, want %q", got, "wheel-bytes")
	}
}

func TestLocalSyncDir(t *testing.T) {
	root := t.TempDir()
	l := NewLocal(root)
	ctx := t.Context()

	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "main", "a"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "Release"), []byte("release"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "main", "a", "acme.deb"), []byte("deb"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out strings.Builder
	n, err := l.SyncDir(ctx, &out, src, "packages/apt/")
	if err != nil {
		t.Fatalf("SyncDir: %v", err)
	}
	if n != 2 {
		t.Errorf("SyncDir uploaded %d files, want 2", n)
	}

	keys, err := l.List(ctx, "packages/apt/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	sort.Strings(keys)
	want := []string{"packages/apt/Release", "packages/apt/main/a/acme.deb"}
	if len(keys) != len(want) || keys[0] != want[0] || keys[1] != want[1] {
		t.Errorf("List = %v, want %v", keys, want)
	}
	// Relative paths survive the walk; the progress writer names the destination.
	if !strings.Contains(out.String(), "packages/apt/main/a/acme.deb") {
		t.Errorf("SyncDir progress output missing nested key:\n%s", out.String())
	}
}

// List walks the parent and string-filters when the prefix names no directory,
// so a partial segment must still match as a true prefix across siblings.
func TestLocalListPrefixSemantics(t *testing.T) {
	l := NewLocal(t.TempDir())
	ctx := t.Context()

	seed := []string{
		"packages/apt/acme.deb",
		"packages/apple/pie.deb",
		"packages/npm/left-pad.tgz",
		"repos/widget/widget.bundle",
	}
	for _, k := range seed {
		if err := l.Put(ctx, k, []byte("x")); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}

	cases := []struct {
		prefix string
		want   []string
	}{
		{"packages/ap", []string{"packages/apple/pie.deb", "packages/apt/acme.deb"}},
		{"packages/apt", []string{"packages/apt/acme.deb"}},
		{"packages/", []string{"packages/apple/pie.deb", "packages/apt/acme.deb", "packages/npm/left-pad.tgz"}},
		{"packages/zz", nil},
		{"nothing/here", nil},
	}
	for _, tc := range cases {
		got, err := l.List(ctx, tc.prefix)
		if err != nil {
			t.Fatalf("List(%q): %v", tc.prefix, err)
		}
		sort.Strings(got)
		if len(got) != len(tc.want) {
			t.Errorf("List(%q) = %v, want %v", tc.prefix, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("List(%q) = %v, want %v", tc.prefix, got, tc.want)
				break
			}
		}
	}
}

func TestLocalPathTraversalRejected(t *testing.T) {
	root := t.TempDir()
	l := NewLocal(filepath.Join(root, "store"))
	ctx := t.Context()

	for _, key := range []string{
		"../escaped.txt",
		"packages/../../escaped.txt",
		"a\x00/../../escaped.txt",
		"..",
	} {
		if err := l.Put(ctx, key, []byte("pwned")); err == nil {
			t.Errorf("Put(%q) succeeded, want rejection", key)
		}
		if _, err := l.Get(ctx, key); err == nil {
			t.Errorf("Get(%q) succeeded, want rejection", key)
		}
		if _, err := l.Head(ctx, key); err == nil {
			t.Errorf("Head(%q) succeeded, want rejection", key)
		}
		if err := l.Delete(ctx, key); err == nil {
			t.Errorf("Delete(%q) succeeded, want rejection", key)
		}
	}

	if _, err := os.Stat(filepath.Join(root, "escaped.txt")); !os.IsNotExist(err) {
		t.Error("a rejected key still wrote outside the storage root")
	}
}

// An absolute key is not an escape: Join re-roots it under the store. Assert
// containment rather than an error, so nobody "fixes" this into a rejection
// and breaks callers that pass a leading slash.
func TestLocalAbsoluteKeyStaysInRoot(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(root, "store")
	l := NewLocal(store)
	ctx := t.Context()

	if err := l.Put(ctx, "/etc/passwd", []byte("contained")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store, "etc", "passwd")); err != nil {
		t.Errorf("absolute key did not land under the root: %v", err)
	}
}

// TestLocalLabel pins the resolved form rather than the configured one. On
// macOS t.TempDir() hands back a /var/folders path whose first component is a
// symlink to /private, so asserting the string that went in would assert the
// absence of the canonicalization pkg move depends on.
func TestLocalLabel(t *testing.T) {
	root := t.TempDir()
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve %s: %v", root, err)
	}
	if got, want := NewLocal(root).Label(), "file://"+resolved; got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
}

// TestLocalTrailingSlashRootStillWrites covers the second defect the trailing
// slash produced. path() tests its result against root + "/", so an
// unnormalized "/srv/store/" root refused every key it was handed and the
// artifact survived a move only by accident.
func TestLocalTrailingSlashRootStillWrites(t *testing.T) {
	root := t.TempDir()
	l := NewLocal(root + string(filepath.Separator))
	if err := l.Put(t.Context(), "a/b.txt", []byte("x")); err != nil {
		t.Fatalf("Put on a root with a trailing slash: %v", err)
	}
	got, err := l.Get(t.Context(), "a/b.txt")
	if err != nil || string(got) != "x" {
		t.Fatalf("Get = %q, %v; want \"x\", nil", got, err)
	}
}

// localWriters drives the three entry points that publish an object, so a
// guarantee about publication is asserted against every writer that has one
// rather than against whichever was reached first.
// localWriter is one of the three ways an object reaches the local backend.
// Publication makes the same promises through all of them, so every test of
// one runs against all three.
type localWriter struct {
	name  string
	write func(t *testing.T, l *Local, key string, body []byte) error
}

func localWriters() []localWriter {
	return []localWriter{
		{"Put", func(t *testing.T, l *Local, key string, body []byte) error {
			return l.Put(t.Context(), key, body)
		}},
		{"PutFile", func(t *testing.T, l *Local, key string, body []byte) error {
			src := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(src, body, 0o600); err != nil {
				t.Fatalf("write source: %v", err)
			}
			return l.PutFile(t.Context(), src, key)
		}},
		{"SyncDir", func(t *testing.T, l *Local, key string, body []byte) error {
			dir, base := path.Split(key)
			src := t.TempDir()
			if err := os.WriteFile(filepath.Join(src, base), body, 0o600); err != nil {
				t.Fatalf("write source: %v", err)
			}
			_, err := l.SyncDir(t.Context(), nil, src, dir)
			return err
		}},
	}
}

// mustWrite is every test that is not about a refusal.
func (w localWriter) mustWrite(t *testing.T, l *Local, key string, body []byte) {
	t.Helper()
	if err := w.write(t, l, key, body); err != nil {
		t.Fatalf("%s: %v", w.name, err)
	}
}

// withUmask installs a umask for the duration of one test. The umask is
// process-global, so a test calling this must not run in parallel with
// anything that creates a file.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	previous := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(previous) })
}

// publishedMode is the permission bits and the three above them. A set-group
// bit is a grant like any other, and Go spells it outside the low nine.
func publishedMode(t *testing.T, root, key string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(key)))
	if err != nil {
		t.Fatalf("stat published object: %v", err)
	}
	return fi.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
}

// An object published through a staging file and a rename carries no mode from
// the destination it lands on, so the umask that filtered os.Create has to be
// applied to the staging file instead. A server under umask 077 stored private
// artifacts before publication became atomic and must still.
func TestLocalPublishHonorsUmaskOnAFreshObject(t *testing.T) {
	for _, w := range localWriters() {
		t.Run(w.name, func(t *testing.T) {
			withUmask(t, 0o077)
			root := t.TempDir()
			const key = "packages/npm/private.tgz"
			w.mustWrite(t, NewLocal(root), key, []byte("secret"))
			if got := publishedMode(t, root, key); got != 0o600 {
				t.Errorf("published mode = %04o, want 0600", got)
			}
		})
	}
}

// A refill is not a decision to publish an artifact the operator restricted,
// so replacement keeps the mode that was there. 0644 under umask 077 is the
// case the umask alone gets wrong: it clips the staging file, and only the
// destination's own mode says how wide the object is meant to be.
func TestLocalPublishKeepsTheModeOfTheObjectItReplaces(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644, 0o640 | os.ModeSetgid} {
		for _, w := range localWriters() {
			t.Run(fmt.Sprintf("%v/%s", mode, w.name), func(t *testing.T) {
				withUmask(t, 0o077)
				root := t.TempDir()
				const key = "packages/npm/refilled.tgz"
				w.mustWrite(t, NewLocal(root), key, []byte("first"))
				p := filepath.Join(root, filepath.FromSlash(key))
				if err := os.Chmod(p, mode); err != nil {
					t.Fatalf("chmod: %v", err)
				}

				w.mustWrite(t, NewLocal(root), key, []byte("second"))

				if got := publishedMode(t, root, key); got != mode {
					t.Errorf("published mode = %v, want %v", got, mode)
				}
				got, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("read replaced object: %v", err)
				}
				if string(got) != "second" {
					t.Errorf("replaced object = %q, want %q", got, "second")
				}
			})
		}
	}
}

// aclEntry is one row of a POSIX ACL in the binary form the kernel keeps in
// system.posix_acl_access. Tests build ACLs this way rather than shelling out
// to setfacl, which is not installed everywhere the suite runs.
type aclEntry struct {
	tag  uint16
	perm uint16
	qual uint32
}

const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclMask     = 0x10
	aclOther    = 0x20
	aclNoQual   = 0xFFFFFFFF

	accessACL  = "system.posix_acl_access"
	defaultACL = "system.posix_acl_default"
)

// posixACL serializes entries, which must already be in the order the kernel
// stores them: owner, named users, owning group, named groups, mask, other.
func posixACL(entries ...aclEntry) []byte {
	buf := binary.LittleEndian.AppendUint32(nil, 2) // ACL_EA_VERSION
	for _, e := range entries {
		buf = binary.LittleEndian.AppendUint16(buf, e.tag)
		buf = binary.LittleEndian.AppendUint16(buf, e.perm)
		buf = binary.LittleEndian.AppendUint32(buf, e.qual)
	}
	return buf
}

// requirePOSIXACL sets an ACL through the Linux interface for one, and skips
// where there is none. macOS keeps its ACLs in com.apple.system.Security,
// which the kernel refuses to hand to getxattr from user space, so publication
// moves them with getattrlist and setattrlist there (see acl_darwin.go) and
// denyNamedReader goes through chmod on that platform.
func requirePOSIXACL(t *testing.T, target, name string, acl []byte) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("POSIX ACLs are set through %s, which is Linux's interface for them", name)
	}
	err := unix.Setxattr(target, name, acl, 0)
	if unsupportedXattr(err) {
		t.Skipf("set %s on %s: %v", name, target, err)
	}
	if err != nil {
		t.Fatalf("set %s on %s: %v", name, target, err)
	}
}

// denyNamedReader puts an ACL on target that refuses one principal the mode
// bits would let in. The principal is never the test process: an ACL it could
// not read past would stop publication before it reached the part under test.
func denyNamedReader(t *testing.T, target string) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		chmodACL(t, target, "group:_guest deny read")
		return
	}
	requirePOSIXACL(t, target, accessACL, posixACL(
		aclEntry{aclUserObj, 6, aclNoQual},
		//nolint:gosec // G115: a uid this process does not have, which is all the entry needs.
		aclEntry{aclUser, 0, uint32(os.Getuid() + 1)},
		aclEntry{aclGroupObj, 4, aclNoQual},
		aclEntry{aclMask, 4, aclNoQual},
		aclEntry{aclOther, 4, aclNoQual},
	))
}

// denyInheritedReader puts an ACL on a directory that every file created in it
// afterwards is born with, which is where a staging file gets restrictions the
// object it replaces never had.
func denyInheritedReader(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		chmodACL(t, dir, "group:_guest deny read,file_inherit")
		return
	}
	// A named entry keeps the inherited ACL from being equivalent to the mode
	// bits, which is the case a filesystem drops rather than stores.
	requirePOSIXACL(t, dir, defaultACL, posixACL(
		aclEntry{aclUserObj, 6, aclNoQual},
		//nolint:gosec // G115: a uid this process does not have, which is all the entry needs.
		aclEntry{aclUser, 0, uint32(os.Getuid() + 1)},
		aclEntry{aclGroupObj, 0, aclNoQual},
		aclEntry{aclMask, 6, aclNoQual},
		aclEntry{aclOther, 0, aclNoQual},
	))
}

func chmodACL(t *testing.T, target, entry string) {
	t.Helper()
	if out, err := exec.Command("/bin/chmod", "+a", entry, target).CombinedOutput(); err != nil {
		t.Skipf("chmod +a %q on %s: %v: %s", entry, target, err, out)
	}
}

// objectACL reads back whatever ACL an object carries, in whichever form the
// platform will show one, and returns an empty string where it carries none.
func objectACL(t *testing.T, target string) string {
	t.Helper()
	if runtime.GOOS == "darwin" {
		listing, err := exec.Command("/bin/ls", "-led", target).Output()
		if err != nil {
			t.Fatalf("ls -led %s: %v", target, err)
		}
		_, acl, _ := strings.Cut(string(listing), "\n")
		return acl
	}
	acl, err := readXattr(t, target, accessACL)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", acl)
}

func readXattr(t *testing.T, target, name string) ([]byte, error) {
	t.Helper()
	size, err := unix.Getxattr(target, name, nil)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	n, err := unix.Getxattr(target, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func statOwner(t *testing.T, target string) (int, int) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(target, &st); err != nil {
		t.Fatalf("stat %s: %v", target, err)
	}
	return int(st.Uid), int(st.Gid)
}

// secondGroup returns a group the process belongs to that is not the one its
// files are created in, which is the only group a test can hand an object
// without being root.
func secondGroup(t *testing.T) int {
	t.Helper()
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatalf("getgroups: %v", err)
	}
	for _, gid := range groups {
		if gid != os.Getgid() {
			return gid
		}
	}
	t.Skip("the process belongs to one group, so no test can move an object to another")
	return 0
}

func stagingLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var left []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			left = append(left, e.Name())
		}
	}
	return left
}

// A mode says who may read an object only until an ACL disagrees with it. An
// artifact at 0644 that denies one named user is denying them; a replacement
// that carried the 0644 and dropped the ACL would hand that user the artifact
// and report nothing, because every bit anybody looks at is unchanged.
func TestLocalPublishKeepsTheAccessACLOfTheObjectItReplaces(t *testing.T) {
	for _, w := range localWriters() {
		t.Run(w.name, func(t *testing.T) {
			root := t.TempDir()
			const key = "packages/npm/restricted.tgz"
			w.mustWrite(t, NewLocal(root), key, []byte("first"))
			p := filepath.Join(root, filepath.FromSlash(key))
			if err := os.Chmod(p, 0o644); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			denyNamedReader(t, p)
			want := objectACL(t, p)
			if want == "" {
				t.Fatalf("the fixture set no ACL on %s", p)
			}

			w.mustWrite(t, NewLocal(root), key, []byte("second"))

			if got := objectACL(t, p); got != want {
				t.Errorf("access ACL = %s, want %s", got, want)
			}
			if mode := publishedMode(t, root, key); mode != 0o644 {
				t.Errorf("published mode = %04o, want 0644", mode)
			}
			if body, err := os.ReadFile(p); err != nil || string(body) != "second" {
				t.Errorf("replaced object = %q (%v), want %q", body, err, "second")
			}
		})
	}
}

// The other direction, and the reason a staging file's attributes are not
// merely added to: a directory carrying a default ACL gives every file created
// in it an access ACL, including the staging file. Publishing that ACL onto an
// object that had none denies readers the object allowed.
func TestLocalPublishDropsAnACLTheObjectNeverHad(t *testing.T) {
	for _, w := range localWriters() {
		t.Run(w.name, func(t *testing.T) {
			root := t.TempDir()
			const key = "packages/npm/plain.tgz"
			w.mustWrite(t, NewLocal(root), key, []byte("first"))
			p := filepath.Join(root, filepath.FromSlash(key))
			denyInheritedReader(t, filepath.Dir(p))
			before := publishedMode(t, root, key)

			w.mustWrite(t, NewLocal(root), key, []byte("second"))

			if got := objectACL(t, p); got != "" {
				t.Errorf("the replacement inherited an ACL the object never had: %s", got)
			}
			if mode := publishedMode(t, root, key); mode != before {
				t.Errorf("published mode = %04o, want %04o", mode, before)
			}

			// A fresh object in the same directory is a new file and does
			// inherit, which publication has no business undoing.
			const fresh = "packages/npm/inherits.tgz"
			w.mustWrite(t, NewLocal(root), fresh, []byte("fresh"))
			if objectACL(t, filepath.Join(root, filepath.FromSlash(fresh))) == "" {
				t.Error("a fresh object did not inherit the directory's ACL")
			}
		})
	}
}

// An artifact at 0640 owned by root:deploy is readable by the deploy group and
// by nothing else. The group is the whole grant, and a replacement that landed
// it root:root would take it away from every reader it had.
func TestLocalPublishKeepsTheGroupOfTheObjectItReplaces(t *testing.T) {
	for _, w := range localWriters() {
		t.Run(w.name, func(t *testing.T) {
			gid := secondGroup(t)
			root := t.TempDir()
			const key = "packages/npm/grouped.tgz"
			w.mustWrite(t, NewLocal(root), key, []byte("first"))
			p := filepath.Join(root, filepath.FromSlash(key))
			if err := os.Chown(p, -1, gid); err != nil {
				t.Skipf("chgrp %s to %d: %v", p, gid, err)
			}
			if err := os.Chmod(p, 0o640); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			w.mustWrite(t, NewLocal(root), key, []byte("second"))

			if _, got := statOwner(t, p); got != gid {
				t.Errorf("published group = %d, want %d", got, gid)
			}
			if mode := publishedMode(t, root, key); mode != 0o640 {
				t.Errorf("published mode = %04o, want 0640", mode)
			}
		})
	}
}

// Where the ownership cannot be restated, publication fails rather than
// landing the bytes under different access rights. The kernel decides that:
// an unprivileged owner cannot hand a file to a group it does not belong to,
// and no test can create that file without being root, so the call is stubbed.
func TestLocalPublishRefusesWhenOwnershipCannotFollow(t *testing.T) {
	for _, w := range localWriters() {
		t.Run(w.name, func(t *testing.T) {
			gid := secondGroup(t)
			root := t.TempDir()
			const key = "packages/npm/grouped.tgz"
			w.mustWrite(t, NewLocal(root), key, []byte("first"))
			p := filepath.Join(root, filepath.FromSlash(key))
			if err := os.Chown(p, -1, gid); err != nil {
				t.Skipf("chgrp %s to %d: %v", p, gid, err)
			}
			if err := os.Chmod(p, 0o640); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			restore := fchown
			fchown = func(int, int, int) error { return unix.EPERM }
			t.Cleanup(func() { fchown = restore })

			err := w.write(t, NewLocal(root), key, []byte("second"))

			if err == nil {
				t.Fatalf("%s replaced an object whose ownership it could not carry", w.name)
			}
			if !strings.Contains(err.Error(), "ownership") {
				t.Errorf("error = %v, want one naming the ownership it could not restore", err)
			}
			if body, readErr := os.ReadFile(p); readErr != nil || string(body) != "first" {
				t.Errorf("object = %q (%v), want the previous %q", body, readErr, "first")
			}
			if mode := publishedMode(t, root, key); mode != 0o640 {
				t.Errorf("mode = %04o, want the previous 0640", mode)
			}
			if _, got := statOwner(t, p); got != gid {
				t.Errorf("group = %d, want the previous %d", got, gid)
			}
			if left := stagingLeftovers(t, filepath.Dir(p)); len(left) != 0 {
				t.Errorf("staging files left behind: %v", left)
			}
		})
	}
}

// otherIdentity is the account the cross-identity tests read as. It owns
// nothing, and every check below is a read of a file in a temporary directory.
const otherIdentity = "nobody"

// requireOtherIdentity skips unless this host will run a command as somebody
// else without asking, which is what it takes to test an access boundary by
// crossing it rather than by reading the metadata that describes it.
func requireOtherIdentity(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the fixture sets a POSIX ACL and a group through Linux's interfaces for them")
	}
	if err := exec.Command("sudo", "-n", "-u", otherIdentity, "true").Run(); err != nil {
		t.Skipf("this host will not run a command as %s without a password: %v", otherIdentity, err)
	}
}

func identityID(t *testing.T, flag string) uint32 {
	t.Helper()
	out, err := exec.Command("id", flag, otherIdentity).Output()
	if err != nil {
		t.Skipf("id %s %s: %v", flag, otherIdentity, err)
	}
	id, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32)
	if err != nil {
		t.Fatalf("id %s %s = %q: %v", flag, otherIdentity, out, err)
	}
	return uint32(id)
}

// reachable asks the kernel, as otherIdentity, whether it can read the object.
func reachable(t *testing.T, p string) bool {
	t.Helper()
	return exec.Command("sudo", "-n", "-u", otherIdentity, "cat", p).Run() == nil
}

// traversable opens the temporary tree far enough for another account to reach
// an object in it. Go makes a test's directory private, which would deny every
// read below for a reason that has nothing to do with the object.
func traversable(t *testing.T, root string) {
	t.Helper()
	for dir := root; strings.HasPrefix(dir, os.TempDir()+"/"); dir = filepath.Dir(dir) {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatalf("open %s to traversal: %v", dir, err)
		}
	}
}

// The regression the mode bits cannot show: a replacement that keeps 0644 and
// drops the ACL under it, or keeps 0640 and moves the object to a group its
// readers are not in. Both publish successfully, report nothing, and change
// who holds the artifact — so the test asks the kernel, as somebody else,
// rather than asking the metadata.
//
// Where publication cannot restate the ownership it refuses, and the answer is
// the same either way: the object an identity could read before a refill is
// the object it can read after one.
func TestLocalPublishKeepsWhoCanReadTheObject(t *testing.T) {
	for _, w := range localWriters() {
		t.Run(w.name+"/denied by an ACL", func(t *testing.T) {
			requireOtherIdentity(t)
			root := t.TempDir()
			traversable(t, root)
			const key = "packages/npm/denied.tgz"
			w.mustWrite(t, NewLocal(root), key, []byte("first"))
			p := filepath.Join(root, filepath.FromSlash(key))
			if err := os.Chmod(p, 0o644); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			requirePOSIXACL(t, p, accessACL, posixACL(
				aclEntry{aclUserObj, 6, aclNoQual},
				aclEntry{aclUser, 0, identityID(t, "-u")},
				aclEntry{aclGroupObj, 4, aclNoQual},
				aclEntry{aclMask, 4, aclNoQual},
				aclEntry{aclOther, 4, aclNoQual},
			))
			if reachable(t, p) {
				t.Fatalf("the fixture does not deny %s: it read the object before any replacement", otherIdentity)
			}

			w.mustWrite(t, NewLocal(root), key, []byte("second"))

			if reachable(t, p) {
				t.Errorf("%s reads an artifact the object denied it, at mode %04o", otherIdentity, publishedMode(t, root, key))
			}
		})

		t.Run(w.name+"/granted by a group", func(t *testing.T) {
			requireOtherIdentity(t)
			root := t.TempDir()
			traversable(t, root)
			const key = "packages/npm/grouped.tgz"
			w.mustWrite(t, NewLocal(root), key, []byte("first"))
			p := filepath.Join(root, filepath.FromSlash(key))
			gid := identityID(t, "-g")
			if out, err := exec.Command("sudo", "-n", "chgrp", fmt.Sprint(gid), p).CombinedOutput(); err != nil {
				t.Skipf("chgrp %s to %d: %v: %s", p, gid, err, out)
			}
			if err := os.Chmod(p, 0o640); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			if !reachable(t, p) {
				t.Fatalf("the fixture does not grant %s: it could not read the object before any replacement", otherIdentity)
			}

			// Restating that group needs privilege this process may not have.
			// Refusing is an answer; publishing under a group the reader is
			// not in is not.
			if err := w.write(t, NewLocal(root), key, []byte("second")); err != nil {
				t.Logf("%s refused the replacement: %v", w.name, err)
				if body, readErr := os.ReadFile(p); readErr != nil || string(body) != "first" {
					t.Errorf("object = %q (%v), want the previous %q", body, readErr, "first")
				}
				if left := stagingLeftovers(t, filepath.Dir(p)); len(left) != 0 {
					t.Errorf("staging files left behind: %v", left)
				}
			}
			if _, got := statOwner(t, p); got != int(gid) {
				t.Errorf("published group = %d, want %d", got, gid)
			}
			if !reachable(t, p) {
				t.Errorf("%s lost an artifact the object granted it, at mode %04o", otherIdentity, publishedMode(t, root, key))
			}
		})
	}
}

// grantInheritedReader puts an ACL on a directory that every file created in
// it afterwards is born with, granting a principal this process is not.
//
// The other inheritance fixtures inherit a denial, which a staging file can
// carry harmlessly: the publication drops it again before the rename and
// nobody was let in meanwhile. A grant is the direction that discloses, and it
// discloses the one thing a staging file holds that no object does yet: a
// replacement body under the writer's access state rather than the object's.
func grantInheritedReader(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		chmodACL(t, dir, "group:everyone allow read,file_inherit,directory_inherit")
		return
	}
	requirePOSIXACL(t, dir, defaultACL, posixACL(
		aclEntry{aclUserObj, 6, aclNoQual},
		//nolint:gosec // G115: a uid this process does not have, which is all the entry needs.
		aclEntry{aclUser, 4, uint32(os.Getuid() + 1)},
		aclEntry{aclGroupObj, 4, aclNoQual},
		aclEntry{aclMask, 6, aclNoQual},
		aclEntry{aclOther, 4, aclNoQual},
	))
}

// stagingBody returns the staging file a publication is filling, once it holds
// something. A publication in flight is the only moment a staging inode's own
// grants can be read off it: after the rename there is no staging file left.
func stagingBody(t *testing.T, dir string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var found string
		for _, name := range stagingLeftovers(t, dir) {
			//nolint:errcheck // a half-created enclosure is the case this polls through.
			filepath.WalkDir(filepath.Join(dir, name), func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil //nolint:nilerr // an unreadable entry is not yet the one being filled.
				}
				if fi, statErr := d.Info(); statErr == nil && fi.Size() > 0 {
					found = p
				}
				return nil
			})
		}
		if found != "" {
			return found
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("no staging file under %s took the body", dir)
	return ""
}

// assertStagingIsPrivate checks every path component from the object's own
// directory down to the staging file. A mode or an ACL on any of them is what
// somebody else would traverse or read through, and the staging file is the
// one inode in the tree whose access state belongs to nobody yet.
func assertStagingIsPrivate(t *testing.T, dir, staged string) {
	t.Helper()
	for p := staged; p != dir; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if mode := fi.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("staging path %s is at mode %04o, which grants somebody other than this server", p, mode)
		}
		if acl := objectACL(t, p); acl != "" {
			t.Errorf("staging path %s carries an inherited ACL: %s", p, acl)
		}
	}
}

// The first of the two staging exposures: a directory granting read by
// inheritance — a POSIX default ACL on Linux, a file_inherit ACE on macOS —
// gives the staging file that grant at creation, and Fchmod does not take an
// ACE away. So the replacement body is written under a grant the object being
// replaced never gave, and a reader holding it sees an artifact mid-refill.
//
// The source is a FIFO because the window is the write. PutFile blocks on it,
// so the staging file exists and holds a body for as long as the test wants to
// look at it.
func TestLocalPublishHidesTheStagingBodyFromAnInheritedGrant(t *testing.T) {
	root := t.TempDir()
	const key = "packages/npm/inherited.tgz"
	l := NewLocal(root)
	if err := l.Put(t.Context(), key, []byte("first")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	p := filepath.Join(root, filepath.FromSlash(key))
	dir := filepath.Dir(p)
	grantInheritedReader(t, dir)

	fifo := filepath.Join(t.TempDir(), "source")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo %s: %v", fifo, err)
	}
	done := make(chan error, 1)
	go func() { done <- l.PutFile(context.Background(), fifo, key) }()

	// Opening the write end releases PutFile's own open of the source, so the
	// publication is under way from here; it blocks again on the next read.
	w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open the write end of %s: %v", fifo, err)
	}
	if _, err := w.Write([]byte("a replacement body being written")); err != nil {
		w.Close()
		t.Fatalf("write to %s: %v", fifo, err)
	}

	assertStagingIsPrivate(t, dir, stagingBody(t, dir))

	if err := w.Close(); err != nil {
		t.Fatalf("close the write end: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	if body, err := os.ReadFile(p); err != nil || string(body) != "a replacement body being written" {
		t.Errorf("published object = %q (%v), want the replacement", body, err)
	}
}

// requireRootWithOtherIdentity skips unless this host will both hand a file to
// another account and read it back as that account. Only root can create the
// fixture: an object owned by somebody else, at a mode that denies its own
// owner, is what makes the ownership window visible at all.
func requireRootWithOtherIdentity(t *testing.T) {
	t.Helper()
	requireOtherIdentity(t)
	if os.Getuid() != 0 {
		t.Skip("only root can give an object to another account, which is what opens the window under test")
	}
}

// The second staging exposure, at the other end of the write. applyTo hands
// the staging file to the object's owner before it restores the object's mode,
// so between the two syscalls a populated replacement sits at the writer's
// 0600 under an owner the object's own mode may deny outright. Mode 0000 is
// the clearest case of that and a real one: an operator who takes an artifact
// away from everybody still owns it.
//
// The window is a syscall wide, so the test wraps the syscall. /proc/self/fd
// is how the staging path is recovered from the descriptor, which is all the
// seam is handed.
func TestLocalPublishHidesTheStagingFileAcrossTheOwnershipChange(t *testing.T) {
	requireRootWithOtherIdentity(t)
	for _, w := range localWriters() {
		t.Run(w.name, func(t *testing.T) {
			root := t.TempDir()
			traversable(t, root)
			const key = "packages/npm/handed-over.tgz"
			w.mustWrite(t, NewLocal(root), key, []byte("first"))
			p := filepath.Join(root, filepath.FromSlash(key))
			if err := os.Chown(p, int(identityID(t, "-u")), int(identityID(t, "-g"))); err != nil {
				t.Fatalf("chown %s: %v", p, err)
			}
			if err := os.Chmod(p, 0); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			var disclosed []string
			restore := fchown
			fchown = func(fd, uid, gid int) error {
				err := restore(fd, uid, gid)
				staged, linkErr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
				if linkErr != nil {
					t.Errorf("resolve the staging path from fd %d: %v", fd, linkErr)
					return err
				}
				if reachable(t, staged) {
					disclosed = append(disclosed, staged)
				}
				return err
			}
			t.Cleanup(func() { fchown = restore })

			w.mustWrite(t, NewLocal(root), key, []byte("a replacement the object's own owner may not read"))

			if len(disclosed) != 0 {
				t.Errorf("%s read the staging file between the ownership change and the mode that denies it: %v", otherIdentity, disclosed)
			}
			if mode := publishedMode(t, root, key); mode != 0 {
				t.Errorf("published mode = %04o, want the previous 0000", mode)
			}
			if reachable(t, p) {
				t.Errorf("%s reads the published object, which is at mode %04o", otherIdentity, publishedMode(t, root, key))
			}
			if left := stagingLeftovers(t, filepath.Dir(p)); len(left) != 0 {
				t.Errorf("staging entries left behind: %v", left)
			}
		})
	}
}

// A staging enclosure is readable by the writer alone, so every other account
// walking the same root is refused entry to it. A listing that descended would
// turn one process's in-flight publication into another process's error, and
// the enclosure holds nothing a listing would have returned anyway.
//
// Mode 0000 is what that refusal looks like from inside the test, without a
// second identity to run the walk as.
func TestLocalListSkipsAStagingEnclosureItCannotEnter(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root traverses a directory at mode 0000, so the refusal under test cannot be staged")
	}
	root := t.TempDir()
	l := NewLocal(root)
	const key = "packages/npm/real.tgz"
	if err := l.Put(t.Context(), key, []byte("an object a listing must still return")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	enclosure := filepath.Join(root, "packages", "npm", tmpPrefix+"ENCLOSURE")
	if err := os.Mkdir(enclosure, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", enclosure, err)
	}
	if err := os.WriteFile(filepath.Join(enclosure, tmpPrefix+"staged"), []byte("a body mid-write"), 0o600); err != nil {
		t.Fatalf("write the staging file: %v", err)
	}
	if err := os.Chmod(enclosure, 0); err != nil {
		t.Fatalf("close %s to entry: %v", enclosure, err)
	}
	// t.TempDir's own cleanup cannot remove a directory it may not enter.
	t.Cleanup(func() { _ = os.Chmod(enclosure, 0o700) })

	keys, err := l.List(t.Context(), "packages/")
	if err != nil {
		t.Fatalf("List while a publication holds an enclosure: %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Errorf("List = %v, want exactly [%s]", keys, key)
	}
}
