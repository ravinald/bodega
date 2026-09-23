//go:build freebsd

package storage

import (
	"errors"
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
// created in. A new file is born with the parent's default ACL as its own
// access ACL, and a new directory is born with both.
//
// The access ACL is reduced to the three entries the mode bits already grant
// rather than deleted: a minimal ACL is what every POSIX.1e implementation
// holds for a file with no entries past the mode, while __acl_delete_fd's
// answer for ACL_TYPE_ACCESS is the filesystem's to decide. The default ACL
// exists only on a directory and has no minimal form, so that one is deleted.
func clearACL(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if err := aclSyscall(unix.SYS___ACL_SET_FD, fd, aclTypeAccess, minimalACL(uint32(st.Mode))); err != nil && !unsupportedACL(err) {
		return fmt.Errorf("remove the inherited ACL: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil
	}
	_, _, errno := unix.Syscall(unix.SYS___ACL_DELETE_FD, uintptr(fd), uintptr(aclTypeDefault), 0)
	if errno != 0 && !unsupportedACL(errno) {
		return fmt.Errorf("remove the inherited default ACL: %w", errno)
	}
	return nil
}

// unsupportedACL reports a filesystem that keeps no POSIX.1e ACL: UFS mounted
// without acls, and ZFS, which keeps an NFSv4 ACL instead and refuses the
// POSIX.1e types outright. Only clearACL may read it that way, since a staging
// inode that cannot carry a POSIX.1e ACL has none to strip. It cannot tell a
// filesystem with no ACL from one keeping the other type, so reading or
// carrying an object's ACL asks aclTypeOfFd instead.
func unsupportedACL(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL)
}

func aclSyscall(trap uintptr, fd, aclType int, acl []byte) error {
	//nolint:gosec // G103: the ACL syscalls take struct acl by pointer, so there is no other form to hand them one.
	_, _, errno := unix.Syscall(trap, uintptr(fd), uintptr(aclType), uintptr(unsafe.Pointer(&acl[0])))
	if errno != 0 {
		return errno
	}
	return nil
}
