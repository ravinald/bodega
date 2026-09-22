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

const (
	aclTypeAccess  = 0x2 // ACL_TYPE_ACCESS
	aclTypeDefault = 0x3 // ACL_TYPE_DEFAULT
)

// readACL returns the object's access ACL as the kernel's own struct acl, or
// nil where there is none to carry. A filesystem that keeps no POSIX.1e ACL
// answers the question with a refusal rather than with an empty ACL, and an
// object that cannot hold one has none to lose.
func readACL(fd int) ([]byte, error) {
	acl := blankACL()
	if err := aclSyscall(unix.SYS___ACL_GET_FD, fd, aclTypeAccess, acl); err != nil {
		if unsupportedACL(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read the ACL: %w", err)
	}
	return acl, nil
}

// applyACL puts acl on fd, or reduces fd's ACL to its mode bits when acl is
// nil. The second case is the one a directory carrying a default ACL creates:
// the staging file is born with an ACL the object being replaced never had.
func applyACL(fd int, acl []byte) error {
	if acl == nil {
		return clearACL(fd)
	}
	if err := checkStructACL(acl); err != nil {
		return fmt.Errorf("write the ACL: %w", err)
	}
	if err := aclSyscall(unix.SYS___ACL_SET_FD, fd, aclTypeAccess, acl); err != nil && !unsupportedACL(err) {
		return fmt.Errorf("write the ACL: %w", err)
	}
	return nil
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
// POSIX.1e types outright. An object that cannot carry one has none to lose
// and none to strip, so a publication there is not a failed publication.
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
