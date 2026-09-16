package storage

import "golang.org/x/sys/unix"

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
