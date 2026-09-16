package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// macOS keeps a file's ACL in com.apple.system.Security, which the kernel
// refuses to hand to getxattr from user space, and clonefile does not copy it
// either. getattrlist is the interface that reads one, and x/sys/unix exposes
// only the setting half, so the read goes through the syscall directly.
//
// The bytes are a kauth_filesec: a magic number, the owner and group GUIDs,
// then the ACL itself. Publication moves the blob from one file to another
// without reading into it, so nothing here depends on the layout past the
// entry count, which is the field that says "no ACL" when it is set to
// KAUTH_FILESEC_NOACL.
// errNoAttr is what a read of an attribute a file does not carry returns.
// macOS spells it ENOATTR and gives ENODATA to something else entirely.
const errNoAttr = unix.ENOATTR

const (
	filesecMagic  = 0x012cc16d
	filesecNoACL  = 0xFFFFFFFF
	filesecHeader = 44 // magic, two GUIDs, entry count and flags

	// maxACL bounds what publication will move between two files. An ACL runs
	// to a few dozen bytes an entry; anything past this is a buffer that does
	// not hold what the read asked for.
	maxACL = 1 << 20
)

// readACL returns the ACL on fd, or nil where the object has none. A volume
// with no extended security at all reports that as a refusal rather than as an
// empty answer, and an object that cannot carry an ACL has none to lose.
func readACL(fd int) ([]byte, error) {
	buf := make([]byte, 1024)
	for range 10 {
		if err := attrlist(syscall.SYS_FGETATTRLIST, fd, buf); err != nil {
			if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL) {
				return nil, nil
			}
			return nil, fmt.Errorf("read the ACL: %w", err)
		}
		total := int(binary.LittleEndian.Uint32(buf[:4]))
		if total > maxACL {
			return nil, fmt.Errorf("read the ACL: %d bytes is not an ACL", total)
		}
		if total > len(buf) {
			buf = make([]byte, total)
			continue
		}
		offset := 4 + int(binary.LittleEndian.Uint32(buf[4:8]))
		length := int(binary.LittleEndian.Uint32(buf[8:12]))
		if length == 0 {
			return nil, nil
		}
		if offset < 12 || length > maxACL || offset+length > len(buf) {
			return nil, fmt.Errorf("read the ACL: the answer points %d bytes past a %d-byte read", offset+length-len(buf), len(buf))
		}
		acl := make([]byte, length)
		copy(acl, buf[offset:offset+length])
		return acl, nil
	}
	return nil, fmt.Errorf("read the ACL: it kept growing under the read")
}

// applyACL puts acl on fd, or takes fd's ACL away when acl is nil. Removing is
// the case a directory carrying an inheritable entry creates: the staging file
// is born with an ACL the object being replaced never had.
func applyACL(fd int, acl []byte) error {
	if acl == nil {
		current, err := readACL(fd)
		if err != nil || current == nil {
			return err
		}
		acl = make([]byte, filesecHeader)
		binary.LittleEndian.PutUint32(acl[:4], filesecMagic)
		binary.LittleEndian.PutUint32(acl[36:40], filesecNoACL)
	}
	if len(acl) > maxACL {
		return fmt.Errorf("write the ACL: %d bytes is not an ACL", len(acl))
	}
	buf := make([]byte, 8+len(acl))
	binary.LittleEndian.PutUint32(buf[:4], 8) // the data follows the reference
	//nolint:gosec // G115: maxACL bounds the length a line above.
	binary.LittleEndian.PutUint32(buf[4:8], uint32(len(acl)))
	copy(buf[8:], acl)
	if err := attrlist(syscall.SYS_FSETATTRLIST, fd, buf); err != nil {
		return fmt.Errorf("write the ACL: %w", err)
	}
	return nil
}

func attrlist(trap uintptr, fd int, buf []byte) error {
	list := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	//nolint:gosec // G103: x/sys/unix exposes setattrlist and not getattrlist, so the pair goes through one path.
	_, _, errno := syscall.Syscall6(trap, uintptr(fd), uintptr(unsafe.Pointer(&list)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
