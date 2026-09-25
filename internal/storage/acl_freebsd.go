//go:build freebsd

package storage

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FreeBSD keeps a POSIX.1e ACL in the system extended-attribute namespace, and
// publication does not go at it that way. Writing EXTATTR_NAMESPACE_SYSTEM
// needs PRIV_VFS_EXTATTR_SYSTEM, so a server running as its own user could
// read an object's ACL and never put it back, and raw bytes written there skip
// the kernel's own check of the ACL. __acl_get_fd and __acl_set_fd are the
// syscalls acl_get_fd_np(3) and acl_set_fd_np(3) make: they validate what they
// are handed, and they need no privilege past ownership of the file. libc is
// out of reach of a CGO_ENABLED=0 build, so they are invoked directly.

// errNoAttr is what a read of an attribute a file does not carry returns.
// FreeBSD spells it ENOATTR, as macOS does, and has no ENODATA at all.
const errNoAttr = unix.ENOATTR

// fpathconf names FreeBSD answers "which ACL does this filesystem keep" with,
// from sys/unistd.h. x/sys/unix carries neither.
const (
	pcACLExtended = 59 // _PC_ACL_EXTENDED
	pcACLNFS4     = 64 // _PC_ACL_NFS4
)

// readACL returns the object's ACL, tagged with its type, or nil where the
// filesystem keeps none.
//
// The filesystem is asked which type it keeps before the ACL is read, because
// a refusal cannot answer that. ZFS answers a request for a POSIX.1e ACL with
// EINVAL, the errno a UFS mounted without acls gives, and reading that as "no
// ACL" published every ZFS object with the staging file's trivial ACL in place
// of its own. Once the filesystem has named a type, any failure to read it is
// a failure.
func readACL(fd int) ([]byte, error) {
	aclType, err := aclTypeOfFd(fd)
	if err != nil {
		return nil, fmt.Errorf("read the ACL: %w", err)
	}
	if aclType == 0 {
		return nil, nil
	}
	acl := blankACL()
	if err := aclSyscall(unix.SYS___ACL_GET_FD, fd, int(aclType), acl); err != nil {
		return nil, fmt.Errorf("read the %s ACL: %w", aclTypeName(aclType), err)
	}
	return tagACL(aclType, acl), nil
}

// applyACL puts acl on fd, or reduces fd's ACL to its mode bits when acl is
// nil. The second case is the one a directory carrying a default ACL creates:
// the staging file is born with an ACL the object being replaced never had.
//
// An ACL whose type the staging file's filesystem does not keep is refused
// rather than dropped. A replacement lands on the filesystem of the object it
// replaces, so a mismatch means the ACL was read from somewhere the object no
// longer is: an NFSv4 ACL carried onto a UFS holding POSIX.1e, or onto one
// holding none. Neither type translates into the other without deciding
// something the object's owner never decided, and landing the object without
// it hands it to whoever the ACL denied.
func applyACL(fd int, blob []byte) error {
	if blob == nil {
		return clearACL(fd)
	}
	aclType, acl, err := untagACL(blob)
	if err != nil {
		return fmt.Errorf("write the ACL: %w", err)
	}
	holds, err := aclTypeOfFd(fd)
	if err != nil {
		return fmt.Errorf("write the ACL: %w", err)
	}
	if holds != aclType {
		return fmt.Errorf("the object's %s ACL cannot travel to a filesystem that keeps %s ACLs",
			aclTypeName(aclType), aclTypeName(holds))
	}
	if err := aclSyscall(unix.SYS___ACL_SET_FD, fd, int(aclType), acl); err != nil {
		return fmt.Errorf("write the %s ACL: %w", aclTypeName(aclType), err)
	}
	return nil
}

// aclTypeOfFd asks the filesystem holding fd which ACL type it keeps.
func aclTypeOfFd(fd int) (uint32, error) {
	nfs4, err := unix.Fpathconf(fd, pcACLNFS4)
	if err != nil {
		return 0, fmt.Errorf("ask the filesystem whether it keeps NFSv4 ACLs: %w", err)
	}
	posix1e, err := unix.Fpathconf(fd, pcACLExtended)
	if err != nil {
		return 0, fmt.Errorf("ask the filesystem whether it keeps POSIX.1e ACLs: %w", err)
	}
	return aclTypeFor(nfs4, posix1e)
}

// clearACL takes away an ACL an inode inherited from the directory it was
// created in, in whichever type the filesystem keeps.
//
// An NFSv4 inode (ZFS, UFS mounted -o nfsv4acls) is born carrying every
// inheritable entry of its parent, and a chmod does not take them away
// everywhere: ZFS at aclmode=passthrough keeps them, so a mode of 0600 still
// lets a named user in. The ACL is set to its trivial form rather than
// deleted, because __acl_delete_fd(ACL_TYPE_NFS4) on ZFS returns success and
// leaves every entry in place.
//
// A POSIX.1e access ACL is reduced to the three entries the mode bits already
// grant rather than deleted: a minimal ACL is what every POSIX.1e
// implementation holds for a file with no entries past the mode, while
// __acl_delete_fd's answer for ACL_TYPE_ACCESS is the filesystem's to decide.
// The default ACL exists only on a directory and has no minimal form, so that
// one is deleted.
//
// Either way the ACL is read back afterwards. A strip that returned success
// and left a grant behind is the failure this exists to prevent, and the
// syscall's answer alone has already been wrong about that once.
//
// A filesystem that reports neither type is refused rather than passed. The
// strip is only as good as the read-back that confirms it, and there is
// nothing to read back: a filesystem that keeps no ACL and one whose answer
// to fpathconf is wrong look the same from here, and passing the second is
// the silent no-op this function replaced.
func clearACL(fd int) error {
	aclType, err := aclTypeOfFd(fd)
	if err != nil {
		return fmt.Errorf("remove the inherited ACL: %w", err)
	}
	if aclType == 0 {
		return fmt.Errorf("the filesystem reports that it keeps neither NFSv4 nor POSIX.1e ACLs, so a staging inode on it " +
			"cannot be read back to confirm it inherited no grant; the write is refused and the previous object is unchanged. " +
			"Keep the storage root on ZFS, or on UFS mounted with -o acls or -o nfsv4acls")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	name := aclTypeName(aclType)
	strip := minimalACL(uint32(st.Mode))
	if aclType == aclTypeNFS4 {
		strip = trivialNFS4ACL(uint32(st.Mode))
	}
	if err := aclSyscall(unix.SYS___ACL_SET_FD, fd, int(aclType), strip); err != nil {
		return fmt.Errorf("remove the inherited %s ACL: %w", name, err)
	}
	if aclType == aclTypeAccess && st.Mode&unix.S_IFMT == unix.S_IFDIR {
		if _, _, errno := unix.Syscall(unix.SYS___ACL_DELETE_FD, uintptr(fd), uintptr(aclTypeDefault), 0); errno != 0 {
			return fmt.Errorf("remove the inherited default ACL: %w", errno)
		}
	}
	got := blankACL()
	if err := aclSyscall(unix.SYS___ACL_GET_FD, fd, int(aclType), got); err != nil {
		return fmt.Errorf("read back the %s ACL after removing what it inherited: %w", name, err)
	}
	if i, ok := grantBeyondMode(got); ok {
		return fmt.Errorf("the %s ACL still carries a named or inheritable entry (entry %d) after the filesystem accepted a trivial one; "+
			"the staging inode would be readable past its mode, so the write is refused", name, i)
	}
	return nil
}

func aclSyscall(trap uintptr, fd, aclType int, acl []byte) error {
	//nolint:gosec // G103: the ACL syscalls take struct acl by pointer, so there is no other form to hand them one.
	_, _, errno := unix.Syscall(trap, uintptr(fd), uintptr(aclType), uintptr(unsafe.Pointer(&acl[0])))
	if errno != 0 {
		return errno
	}
	return nil
}
