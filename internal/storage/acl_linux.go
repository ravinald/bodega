package storage

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// errNoAttr is what a read of an attribute a file does not carry returns.
// Linux spells it ENODATA; macOS spells it ENOATTR and gives ENODATA to
// something else entirely.
const errNoAttr = unix.ENODATA

// readACL and applyACL have nothing to do on Linux, which keeps a POSIX ACL in
// system.posix_acl_access: it travels with the rest of the extended
// attributes, and a second interface to the same bytes could only disagree
// with the first.
func readACL(_ int) ([]byte, error) { return nil, nil }

func applyACL(_ int, _ []byte) error { return nil }

// clearACL takes away an ACL an inode inherited from the directory it was
// created in. Both live in the extended attributes on Linux: the access ACL
// the new inode carries, and on a directory the default ACL it would go on to
// give its own children. A filesystem that holds neither has nothing to clear.
func clearACL(fd int) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		if err := unix.Fremovexattr(fd, name); err != nil && !unsupportedXattr(err) {
			return fmt.Errorf("remove the inherited %s: %w", name, err)
		}
	}
	return nil
}
