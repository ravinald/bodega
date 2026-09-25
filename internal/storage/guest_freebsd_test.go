package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The tests in this file run on a FreeBSD guest, against the kernel, and are
// what test/e2e/suites/48-freebsd-server.sh drives: once per filesystem the
// guest keeps ACLs on, and once each as an unprivileged user and as root.
// Everything else this package asserts about FreeBSD is an encoder or decoder
// checked against a reading of a man page; these are the calls themselves.
//
// guestFSEnv names the filesystem TMPDIR sits on. It is required rather than
// detected, because a test that detected it would pass on whichever filesystem
// it happened to land on and skip the half it was meant to cover.
const guestFSEnv = "BODEGA_FREEBSD_GUEST_FS"

// nobodyUID is the named principal every fixture here grants or denies. It is
// never the test process, as root or as the unprivileged user the suite runs.
//
// These tests compare ACL structure: what the kernel stored, and what it reads
// back. They say nothing about access, and on ZFS they could not: ZFS on
// FreeBSD 15.1 ignores entries naming uid 65534 in both directions, so a deny
// for nobody on a 0644 file leaves it readable and an allow on a 0600 file
// grants nothing. Structure is all these need, and nobody exists on every
// FreeBSD host without the suite creating an account. Whether an entry grants
// or denies a read is test/e2e/guest's to prove, as a principal ZFS honors.
const nobodyUID = 65534

// guestACLType returns the acl_type_t the filesystem under TMPDIR must keep,
// and fails when that filesystem keeps a different one.
func guestACLType(t *testing.T) uint32 {
	t.Helper()
	fs := os.Getenv(guestFSEnv)
	var want uint32
	switch fs {
	case "":
		t.Skipf("%s is unset; test/e2e/suites/48-freebsd-server.sh sets it to zfs or ufs", guestFSEnv)
	case "zfs":
		want = aclTypeNFS4
	case "ufs":
		want = aclTypeAccess
	default:
		t.Fatalf("%s=%q; want zfs or ufs", guestFSEnv, fs)
	}
	dir := t.TempDir()
	var sfs unix.Statfs_t
	if err := unix.Statfs(dir, &sfs); err != nil {
		t.Fatalf("statfs %s: %v", dir, err)
	}
	if got := unix.ByteSliceToString(sfs.Fstypename[:]); got != fs {
		t.Fatalf("TMPDIR (%s) is on %s, and %s names %s", dir, got, guestFSEnv, fs)
	}
	f := guestFile(t, dir, "probe")
	got, err := aclTypeOfFd(int(f.Fd()))
	if err != nil {
		t.Fatalf("aclTypeOfFd on %s: %v", fs, err)
	}
	if got != want {
		t.Fatalf("%s under TMPDIR keeps %s ACLs; this suite needs it mounted to keep %s ACLs",
			fs, aclTypeName(got), aclTypeName(want))
	}
	return want
}

func guestFile(t *testing.T, dir, name string) *os.File {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func guestSetfacl(t *testing.T, target string, args ...string) {
	t.Helper()
	out, err := exec.Command("/bin/setfacl", append(args, target)...).CombinedOutput()
	if err != nil {
		t.Fatalf("setfacl %q %s: %v: %s", args, target, err, out)
	}
}

// guestGetACL reads fd's ACL of aclType straight from __acl_get_fd.
func guestGetACL(t *testing.T, fd int, aclType uint32) []byte {
	t.Helper()
	acl := blankACL()
	if err := aclSyscall(unix.SYS___ACL_GET_FD, fd, int(aclType), acl); err != nil {
		t.Fatalf("__acl_get_fd(%s): %v", aclTypeName(aclType), err)
	}
	return acl
}

type guestEntry struct {
	tag, id, perm uint32
	kind, flags   uint16
}

// guestEntries decodes a struct acl at the offsets freebsdfmt.go declares. A
// wrong offset there reads garbage here, which no assertion below accepts.
func guestEntries(t *testing.T, acl []byte) []guestEntry {
	t.Helper()
	cnt := binary.NativeEndian.Uint32(acl[4:8])
	if cnt > aclMaxEntries {
		t.Fatalf("acl_cnt = %d, past the %d entries a struct acl holds", cnt, aclMaxEntries)
	}
	entries := make([]guestEntry, cnt)
	for i := range entries {
		off := aclEntryStart + i*aclEntrySize
		entries[i] = guestEntry{
			tag:   binary.NativeEndian.Uint32(acl[off:]),
			id:    binary.NativeEndian.Uint32(acl[off+4:]),
			perm:  binary.NativeEndian.Uint32(acl[off+8:]),
			kind:  binary.NativeEndian.Uint16(acl[off+12:]),
			flags: binary.NativeEndian.Uint16(acl[off+14:]),
		}
	}
	return entries
}

func namedEntries(entries []guestEntry) []guestEntry {
	var named []guestEntry
	for _, e := range entries {
		if e.tag == tagUser || e.tag == tagGroup {
			named = append(named, e)
		}
	}
	return named
}

func hasNobody(entries []guestEntry) bool {
	return slices.ContainsFunc(entries, func(e guestEntry) bool { return e.tag == tagUser && e.id == nobodyUID })
}

// grantInheritedNobody gives dir an ACL every file and directory created in it
// is born carrying: a named grant to nobody, in the form the filesystem keeps.
func grantInheritedNobody(t *testing.T, dir string, aclType uint32) {
	t.Helper()
	if aclType == aclTypeNFS4 {
		guestSetfacl(t, dir, "-a0", fmt.Sprintf("user:%d:rw:fd:allow", nobodyUID))
		return
	}
	guestSetfacl(t, dir, "-d", "-m", fmt.Sprintf("user::rwx,group::---,other::---,mask::rw-,user:%d:rw-", nobodyUID))
}

// A struct acl this package lays out wrong is not refused loudly: __acl_set_fd
// answers EINVAL, and clearACL reads EINVAL as a filesystem with no POSIX.1e
// ACL. So the layout is pinned to the header the kernel was built from rather
// than to a reading of it.
func TestFreeBSDGuestStructACLMatchesSysACLH(t *testing.T) {
	guestACLType(t)
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatalf("no cc on this guest to compile sys/acl.h with: %v", err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "probe.c")
	const probe = `#define _ACL_PRIVATE
#include <sys/types.h>
#include <sys/acl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#define P(n, v) printf("%s %ld\n", n, (long)(v))
int main(void) {
	P("sizeof_acl", sizeof(struct acl));
	P("acl_maxcnt", offsetof(struct acl, acl_maxcnt));
	P("acl_cnt", offsetof(struct acl, acl_cnt));
	P("acl_entry", offsetof(struct acl, acl_entry));
	P("sizeof_entry", sizeof(struct acl_entry));
	P("ae_tag", offsetof(struct acl_entry, ae_tag));
	P("ae_id", offsetof(struct acl_entry, ae_id));
	P("ae_perm", offsetof(struct acl_entry, ae_perm));
	P("ae_entry_type", offsetof(struct acl_entry, ae_entry_type));
	P("ae_flags", offsetof(struct acl_entry, ae_flags));
	P("ACL_MAX_ENTRIES", ACL_MAX_ENTRIES);
	P("OLDACL_MAX_ENTRIES", OLDACL_MAX_ENTRIES);
	P("ACL_TYPE_ACCESS", ACL_TYPE_ACCESS);
	P("ACL_TYPE_DEFAULT", ACL_TYPE_DEFAULT);
	P("ACL_TYPE_NFS4", ACL_TYPE_NFS4);
	P("ACL_USER_OBJ", ACL_USER_OBJ);
	P("ACL_USER", ACL_USER);
	P("ACL_GROUP_OBJ", ACL_GROUP_OBJ);
	P("ACL_GROUP", ACL_GROUP);
	P("ACL_MASK", ACL_MASK);
	P("ACL_OTHER", ACL_OTHER);
	P("ACL_EVERYONE", ACL_EVERYONE);
	P("ACL_UNDEFINED_ID", (unsigned int)ACL_UNDEFINED_ID);
	P("ACL_ENTRY_TYPE_ALLOW", ACL_ENTRY_TYPE_ALLOW);
	P("ACL_ENTRY_TYPE_DENY", ACL_ENTRY_TYPE_DENY);
	P("ACL_ENTRY_TYPE_AUDIT", ACL_ENTRY_TYPE_AUDIT);
	P("ACL_ENTRY_TYPE_ALARM", ACL_ENTRY_TYPE_ALARM);
	P("ACL_EXECUTE", ACL_EXECUTE);
	P("ACL_READ_DATA", ACL_READ_DATA);
	P("ACL_WRITE_DATA", ACL_WRITE_DATA);
	P("ACL_APPEND_DATA", ACL_APPEND_DATA);
	P("ACL_READ_NAMED_ATTRS", ACL_READ_NAMED_ATTRS);
	P("ACL_WRITE_NAMED_ATTRS", ACL_WRITE_NAMED_ATTRS);
	P("ACL_READ_ATTRIBUTES", ACL_READ_ATTRIBUTES);
	P("ACL_WRITE_ATTRIBUTES", ACL_WRITE_ATTRIBUTES);
	P("ACL_READ_ACL", ACL_READ_ACL);
	P("ACL_WRITE_ACL", ACL_WRITE_ACL);
	P("ACL_WRITE_OWNER", ACL_WRITE_OWNER);
	P("ACL_SYNCHRONIZE", ACL_SYNCHRONIZE);
	P("ACL_ENTRY_INHERIT_FLAGS", ACL_ENTRY_FILE_INHERIT | ACL_ENTRY_DIRECTORY_INHERIT | ACL_ENTRY_NO_PROPAGATE_INHERIT | ACL_ENTRY_INHERIT_ONLY | ACL_ENTRY_INHERITED);
	P("_PC_ACL_EXTENDED", _PC_ACL_EXTENDED);
	P("_PC_ACL_NFS4", _PC_ACL_NFS4);
	return 0;
}
`
	if err := os.WriteFile(src, []byte(probe), 0o600); err != nil {
		t.Fatalf("write %s: %v", src, err)
	}
	bin := filepath.Join(dir, "probe")
	if out, err := exec.Command(cc, "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("cc sys/acl.h probe: %v: %s", err, out)
	}
	out, err := exec.Command(bin).Output()
	if err != nil {
		t.Fatalf("run the sys/acl.h probe: %v", err)
	}
	got := map[string]int64{}
	for line := range strings.Lines(string(out)) {
		name, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			t.Fatalf("probe line %q", line)
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("probe line %q: %v", line, err)
		}
		got[name] = n
	}
	want := map[string]int64{
		"sizeof_acl":              aclSize,
		"acl_maxcnt":              0,
		"acl_cnt":                 4,
		"acl_entry":               aclEntryStart,
		"sizeof_entry":            aclEntrySize,
		"ae_tag":                  0,
		"ae_id":                   4,
		"ae_perm":                 8,
		"ae_entry_type":           12,
		"ae_flags":                14,
		"ACL_MAX_ENTRIES":         aclMaxEntries,
		"OLDACL_MAX_ENTRIES":      posix1eMaxEntries,
		"ACL_TYPE_ACCESS":         aclTypeAccess,
		"ACL_TYPE_DEFAULT":        aclTypeDefault,
		"ACL_TYPE_NFS4":           aclTypeNFS4,
		"ACL_USER_OBJ":            tagUserObj,
		"ACL_USER":                tagUser,
		"ACL_GROUP_OBJ":           tagGroupObj,
		"ACL_GROUP":               tagGroup,
		"ACL_MASK":                tagMask,
		"ACL_OTHER":               tagOther,
		"ACL_EVERYONE":            tagEveryone,
		"ACL_UNDEFINED_ID":        undefinedID,
		"ACL_ENTRY_TYPE_ALLOW":    entryAllow,
		"ACL_ENTRY_TYPE_DENY":     entryDeny,
		"ACL_ENTRY_TYPE_AUDIT":    entryAudit,
		"ACL_ENTRY_TYPE_ALARM":    entryAlarm,
		"ACL_EXECUTE":             nfs4Execute,
		"ACL_READ_DATA":           nfs4ReadData,
		"ACL_WRITE_DATA":          nfs4WriteData,
		"ACL_APPEND_DATA":         nfs4AppendData,
		"ACL_READ_NAMED_ATTRS":    nfs4ReadNamedAttrs,
		"ACL_WRITE_NAMED_ATTRS":   nfs4WriteNamedAttrs,
		"ACL_READ_ATTRIBUTES":     nfs4ReadAttributes,
		"ACL_WRITE_ATTRIBUTES":    nfs4WriteAttributes,
		"ACL_READ_ACL":            nfs4ReadACL,
		"ACL_WRITE_ACL":           nfs4WriteACL,
		"ACL_WRITE_OWNER":         nfs4WriteOwner,
		"ACL_SYNCHRONIZE":         nfs4Synchronize,
		"ACL_ENTRY_INHERIT_FLAGS": nfs4InheritFlags,
		"_PC_ACL_EXTENDED":        pcACLExtended,
		"_PC_ACL_NFS4":            pcACLNFS4,
	}
	if !reflect.DeepEqual(got, want) {
		for name, w := range want {
			if got[name] != w {
				t.Errorf("%s: sys/acl.h says %d, freebsdfmt.go says %d", name, got[name], w)
			}
		}
		if len(got) != len(want) {
			t.Errorf("probe printed %d values, want %d", len(got), len(want))
		}
	}
}

// The kernel accepts the struct acl this package builds, for the type the
// filesystem keeps, and refuses one whose acl_maxcnt is not ACL_MAX_ENTRIES.
// An ACL read through readACL and put back through applyACL lands whole, and
// its named entry sits at the offset freebsdfmt.go decodes it from.
func TestFreeBSDGuestKernelTakesTheStructACLThisPackageBuilds(t *testing.T) {
	aclType := guestACLType(t)
	dir := t.TempDir()
	src := guestFile(t, dir, "src")
	dst := guestFile(t, dir, "dst")

	if aclType == aclTypeNFS4 {
		guestSetfacl(t, src.Name(), "-a0", fmt.Sprintf("user:%d:r::deny", nobodyUID))
	} else {
		guestSetfacl(t, src.Name(), "-m", fmt.Sprintf("user:%d:r--,mask::r--", nobodyUID))
	}

	blob, err := readACL(int(src.Fd()))
	if err != nil {
		t.Fatalf("readACL: %v", err)
	}
	gotType, acl, err := untagACL(blob)
	if err != nil {
		t.Fatalf("untagACL on what readACL returned: %v", err)
	}
	if gotType != aclType {
		t.Fatalf("readACL tagged the ACL %s, want %s", aclTypeName(gotType), aclTypeName(aclType))
	}
	entries := guestEntries(t, acl)
	if !hasNobody(entries) {
		t.Fatalf("no user:%d entry decoded from the struct acl the kernel returned: %+v", nobodyUID, entries)
	}
	if aclType == aclTypeNFS4 && !slices.ContainsFunc(entries, func(e guestEntry) bool { return e.id == nobodyUID && e.kind == entryDeny }) {
		t.Errorf("the NFSv4 deny entry decoded without its entry type: %+v", entries)
	}

	if err := applyACL(int(dst.Fd()), blob); err != nil {
		t.Fatalf("applyACL: %v", err)
	}
	if got := guestGetACL(t, int(dst.Fd()), aclType); !reflect.DeepEqual(guestEntries(t, got), entries) {
		t.Errorf("the ACL applyACL wrote reads back as %+v, want %+v", guestEntries(t, got), entries)
	}

	wrong := slices.Clone(acl)
	binary.NativeEndian.PutUint32(wrong[:4], aclMaxEntries-1)
	err = aclSyscall(unix.SYS___ACL_SET_FD, int(dst.Fd()), int(aclType), wrong)
	if !errors.Is(err, unix.EINVAL) {
		t.Errorf("__acl_set_fd with acl_maxcnt %d = %v, want EINVAL: the kernel does not check the field freebsdfmt.go pins",
			aclMaxEntries-1, err)
	}
}

// clearACL strips on its own, without the chmod restrictStaged follows it
// with. On ZFS at its default aclmode=discard the chmod would strip an NFSv4
// ACL anyway, so a test of restrictStaged there passes whether clearACL did
// anything or not; at aclmode=passthrough the chmod keeps every inherited
// entry, and clearACL is all that stands between them and the staging inode.
func TestFreeBSDGuestClearACLStripsWithoutAChmod(t *testing.T) {
	aclType := guestACLType(t)
	parent := t.TempDir()
	grantInheritedNobody(t, parent, aclType)

	f := guestFile(t, parent, "staged")
	sub := filepath.Join(parent, "enclosure")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	d, err := os.Open(sub)
	if err != nil {
		t.Fatalf("open %s: %v", sub, err)
	}
	t.Cleanup(func() { _ = d.Close() })

	if aclType == aclTypeNFS4 {
		plain := guestFile(t, t.TempDir(), "plain")
		want := guestEntries(t, guestGetACL(t, int(plain.Fd()), aclTypeNFS4))
		if got := guestEntries(t, trivialNFS4ACL(0o640)); !reflect.DeepEqual(got, want) {
			t.Errorf("trivialNFS4ACL(0640) = %+v; the kernel gives a 0640 file with nothing to inherit %+v", got, want)
		}
	}

	for _, h := range []*os.File{f, d} {
		fd := int(h.Fd())
		if !hasNobody(guestEntries(t, guestGetACL(t, fd, aclType))) {
			t.Fatalf("the fixture did not reach %s: its directory's inherited grant to %d is missing", h.Name(), nobodyUID)
		}
		if err := clearACL(fd); err != nil {
			t.Fatalf("clearACL on %s: %v", h.Name(), err)
		}
		entries := guestEntries(t, guestGetACL(t, fd, aclType))
		if named := namedEntries(entries); len(named) != 0 {
			t.Errorf("%s kept named entries after clearACL alone: %+v", h.Name(), named)
		}
		if i, ok := grantBeyondMode(guestGetACL(t, fd, aclType)); ok {
			t.Errorf("%s kept an entry past its mode after clearACL alone: entry %d of %+v", h.Name(), i, entries)
		}
	}
}

// A staging file is born with whatever its directory hands down, and
// restrictStaged is what takes it away. clearACL reduces the access ACL to a
// minimal one rather than deleting it, and deletes a directory's default ACL.
func TestFreeBSDGuestRestrictStagedLeavesNoNamedEntry(t *testing.T) {
	aclType := guestACLType(t)
	parent := t.TempDir()
	grantInheritedNobody(t, parent, aclType)

	f := guestFile(t, parent, "staged")
	if !hasNobody(guestEntries(t, guestGetACL(t, int(f.Fd()), aclType))) {
		t.Fatalf("the fixture did not reach the staging file: its directory's inherited grant to %d is missing", nobodyUID)
	}
	if err := restrictStaged(f, stagedPerm); err != nil {
		t.Fatalf("restrictStaged on a file: %v", err)
	}
	if named := namedEntries(guestEntries(t, guestGetACL(t, int(f.Fd()), aclType))); len(named) != 0 {
		t.Errorf("the staging file kept named entries after restrictStaged: %+v", named)
	}

	sub := filepath.Join(parent, "enclosure")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	d, err := os.Open(sub)
	if err != nil {
		t.Fatalf("open %s: %v", sub, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if !hasNobody(guestEntries(t, guestGetACL(t, int(d.Fd()), aclType))) {
		t.Fatalf("the fixture did not reach the enclosure directory")
	}
	if err := restrictStaged(d, stagedDirPerm); err != nil {
		t.Fatalf("restrictStaged on a directory: %v", err)
	}
	if named := namedEntries(guestEntries(t, guestGetACL(t, int(d.Fd()), aclType))); len(named) != 0 {
		t.Errorf("the enclosure kept named entries after restrictStaged: %+v", named)
	}
	if aclType == aclTypeAccess {
		if def := guestEntries(t, guestGetACL(t, int(d.Fd()), aclTypeDefault)); len(def) != 0 {
			t.Errorf("the enclosure kept a default ACL after restrictStaged: %+v", def)
		}
	}
}

// guestNoACLEnv names the filesystem the no-ACL test runs on, which the ACL
// tests above refuse: a UFS mounted without acls or nfsv4acls.
const guestNoACLEnv = "ufs-noacl"

// A filesystem that reports neither ACL type gives clearACL nothing to read
// back, so it refuses, and a replacement there fails before its body is
// written. The previous object is what the failure leaves, byte for byte and
// mode for mode, and no staging enclosure outlives it. A fresh object is not
// staged in an enclosure and still publishes.
func TestFreeBSDGuestNoACLFilesystemRefusesAReplacement(t *testing.T) {
	if fs := os.Getenv(guestFSEnv); fs != guestNoACLEnv {
		t.Skipf("%s=%q; this test runs where test/e2e/suites/48-freebsd-server.sh sets it to %s", guestFSEnv, fs, guestNoACLEnv)
	}
	dir := t.TempDir()
	var sfs unix.Statfs_t
	if err := unix.Statfs(dir, &sfs); err != nil {
		t.Fatalf("statfs %s: %v", dir, err)
	}
	if got := unix.ByteSliceToString(sfs.Fstypename[:]); got != "ufs" {
		t.Fatalf("TMPDIR (%s) is on %s; %s=%s names ufs", dir, got, guestFSEnv, guestNoACLEnv)
	}
	f := guestFile(t, dir, "probe")
	if got, err := aclTypeOfFd(int(f.Fd())); err != nil || got != 0 {
		t.Fatalf("aclTypeOfFd = %s (%v); this test needs a UFS mounted without acls or nfsv4acls", aclTypeName(got), err)
	}
	if err := clearACL(int(f.Fd())); err == nil {
		t.Error("clearACL returned nil on a filesystem that reports neither ACL type")
	}

	root := filepath.Join(dir, "store")
	l := NewLocal(root)
	ctx := t.Context()
	if err := l.Put(ctx, "obj", []byte("PRIOR BODY\n")); err != nil {
		t.Fatalf("a fresh object on a filesystem without ACLs: %v", err)
	}
	obj := filepath.Join(root, "obj")
	if err := os.Chmod(obj, 0o640); err != nil {
		t.Fatalf("chmod %s: %v", obj, err)
	}
	if err := l.Put(ctx, "obj", []byte("REPLACEMENT BODY\n")); err == nil {
		t.Error("a replacement published on a filesystem whose staging inode cannot be confirmed free of inherited grants")
	} else {
		t.Logf("replacement refused: %v", err)
	}
	if got, err := os.ReadFile(obj); err != nil || string(got) != "PRIOR BODY\n" {
		t.Errorf("after the refused replacement the object reads %q (%v), want the prior body", got, err)
	}
	if fi, err := os.Stat(obj); err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("after the refused replacement the object is %v (%v), want 0640", fi.Mode().Perm(), err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			t.Errorf("the refused replacement left %s behind", e.Name())
		}
	}
}

// extattr_list_fd answers with one length byte per name, the name, no
// terminator and no namespace. The names here span a length byte above 0x7f,
// and the answer is checked twice: raw, against that format, and through
// listXattr, which must return each name qualified so that a read takes it.
func TestFreeBSDGuestExtattrListIsLengthPrefixedAndUnqualified(t *testing.T) {
	guestACLType(t)
	f := guestFile(t, t.TempDir(), "attrs")
	fd := int(f.Fd())
	names := []string{"a", "bodega.sha256", strings.Repeat("n", 200)}
	for _, n := range names {
		if err := unix.Fsetxattr(fd, "user."+n, []byte(n), 0); err != nil {
			t.Fatalf("set user.%.20s: %v", n, err)
		}
	}

	raw := guestExtattrList(t, fd, unix.EXTATTR_NAMESPACE_USER)
	if want := len(names) + len(strings.Join(names, "")); len(raw) != want {
		t.Errorf("extattr_list_fd answered %d bytes, want %d: one length byte per name and no terminator", len(raw), want)
	}
	decoded, err := splitExtattrNames(raw, "user.")
	if err != nil {
		t.Fatalf("splitExtattrNames on the kernel's answer: %v", err)
	}
	want := make([]string, len(names))
	for i, n := range names {
		want[i] = "user." + n
	}
	slices.Sort(decoded)
	slices.Sort(want)
	if !reflect.DeepEqual(decoded, want) {
		t.Errorf("decoded %q, want %q", decoded, want)
	}

	root := os.Geteuid() == 0
	if root {
		if err := unix.Fsetxattr(fd, "system.bodega.probe", []byte("sys"), 0); err != nil {
			t.Fatalf("set system.bodega.probe as root: %v", err)
		}
		want = append(want, "system.bodega.probe")
		slices.Sort(want)
	} else {
		_, err := unix.ExtattrListFd(fd, unix.EXTATTR_NAMESPACE_SYSTEM, 0, 0)
		if !errors.Is(err, unix.EPERM) {
			t.Errorf("an unprivileged list of the system namespace = %v, want the EPERM listXattr skips", err)
		}
	}

	listed, err := listXattr(fd)
	if err != nil {
		t.Fatalf("listXattr (root=%v): %v", root, err)
	}
	slices.Sort(listed)
	if !reflect.DeepEqual(listed, want) {
		t.Errorf("listXattr (root=%v) = %q, want %q", root, listed, want)
	}
	a, err := readAccess(f)
	if err != nil {
		t.Fatalf("readAccess: %v", err)
	}
	for _, n := range want {
		if _, ok := a.xattrs[n]; !ok {
			t.Errorf("readAccess dropped %.30s: the name listXattr returned does not read back", n)
		}
	}
}

// UFS exposes a POSIX.1e ACL as system.posix1e.acl_access and
// system.posix1e.acl_default, and __acl_get_fd owns both. listXattr leaves
// them out so publication does not carry the same ACL twice, once through a
// call that needs PRIV_VFS_EXTATTR_SYSTEM to write it back. ZFS exposes no ACL
// as an attribute, so there the assertion is that none surfaces.
func TestFreeBSDGuestListXattrLeavesTheACLToTheACLCalls(t *testing.T) {
	aclType := guestACLType(t)
	dir := t.TempDir()
	grantInheritedNobody(t, dir, aclType)
	d, err := os.Open(dir)
	if err != nil {
		t.Fatalf("open %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	f := guestFile(t, dir, "acl")
	if aclType == aclTypeAccess {
		guestSetfacl(t, f.Name(), "-m", fmt.Sprintf("user:%d:r--,mask::rw-", nobodyUID))
	}

	root := os.Geteuid() == 0
	for _, o := range []struct {
		what string
		fd   int
		kept string
	}{
		{"file", int(f.Fd()), "posix1e.acl_access"},
		{"directory", int(d.Fd()), "posix1e.acl_default"},
	} {
		if root {
			raw, err := splitExtattrNames(guestExtattrList(t, o.fd, unix.EXTATTR_NAMESPACE_SYSTEM), "")
			if err != nil {
				t.Fatalf("decode the system namespace of the %s: %v", o.what, err)
			}
			exposed := slices.Contains(raw, o.kept)
			if aclType == aclTypeAccess && !exposed {
				t.Errorf("UFS does not expose the %s's ACL as system.%s (it lists %q); aclXattrs guards a name that never appears", o.what, o.kept, raw)
			}
			if aclType == aclTypeNFS4 && exposed {
				t.Errorf("ZFS exposes the %s's ACL as system.%s", o.what, o.kept)
			}
		}
		listed, err := listXattr(o.fd)
		if err != nil {
			t.Fatalf("listXattr on the %s (root=%v): %v", o.what, root, err)
		}
		// Spelled out rather than read from aclXattrs, which is the thing
		// under test: a name dropped from that map would drop out of this
		// check with it.
		for _, n := range listed {
			switch n {
			case "system.posix1e.acl_access", "system.posix1e.acl_default", "system.nfs4.acl":
				t.Errorf("listXattr on the %s returned %s, which __acl_get_fd owns", o.what, n)
			}
		}
	}
}

// guestExtattrList returns the raw extattr_list_fd answer for one namespace.
func guestExtattrList(t *testing.T, fd, ns int) []byte {
	t.Helper()
	size, err := unix.ExtattrListFd(fd, ns, 0, 0)
	if err != nil {
		t.Fatalf("extattr_list_fd(ns %d) size: %v", ns, err)
	}
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	//nolint:gosec // G103: ExtattrListFd takes the destination as a uintptr.
	n, err := unix.ExtattrListFd(fd, ns, uintptr(unsafe.Pointer(&buf[0])), len(buf))
	if err != nil {
		t.Fatalf("extattr_list_fd(ns %d): %v", ns, err)
	}
	return buf[:n]
}
