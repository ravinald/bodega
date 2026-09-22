//go:build freebsd

package storage

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// xattrNamespaces is every namespace bodega enumerates, each with the prefix
// unix.Fgetxattr needs to find its way back to it. extattr_list_fd(2) lists
// one namespace per call and names the attributes in it without that prefix,
// so the caller is the only thing that still knows which namespace a name
// came from.
var xattrNamespaces = [...]struct {
	id     int
	prefix string
}{
	{unix.EXTATTR_NAMESPACE_USER, "user."},
	{unix.EXTATTR_NAMESPACE_SYSTEM, "system."},
}

// aclXattrs is where UFS keeps a POSIX.1e ACL, and publication does not move
// it as an attribute. acl_freebsd.go carries it through __acl_get_fd and
// __acl_set_fd, which validate what they are given and need no privilege past
// ownership of the file; copying the same bytes a second time would need
// PRIV_VFS_EXTATTR_SYSTEM to write them back and could only disagree with the
// first copy.
var aclXattrs = map[string]bool{
	"system.posix1e.acl_access":  true,
	"system.posix1e.acl_default": true,
}

// listXattr returns the attribute names on fd, each qualified by the namespace
// it lives in, so that the name a list returns is the name a read takes.
//
// unix.Flistxattr cannot answer this. It concatenates the two namespaces' raw
// buffers, so by the time it returns nothing says which namespace a name came
// from, and its FlistxattrNS returns the nil named return in place of the
// syscall's error, so a refusal from extattr_list_fd arrives as an empty list.
// unix.ExtattrListFd is the same call with its error intact.
func listXattr(fd int) ([]string, error) {
	var names []string
	for _, ns := range xattrNamespaces {
		found, err := listXattrNS(fd, ns.id, ns.prefix)
		if unsupportedXattr(err) {
			continue
		}
		// The system namespace is privileged to read, and a server that
		// cannot read it has no attributes there to carry. The user namespace
		// goes with read access to the file, so a refusal there is a refusal
		// to answer rather than an empty answer.
		if errors.Is(err, unix.EPERM) && ns.id != unix.EXTATTR_NAMESPACE_USER {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, name := range found {
			if !aclXattrs[name] {
				names = append(names, name)
			}
		}
	}
	return names, nil
}

func listXattrNS(fd, nsid int, prefix string) ([]string, error) {
	for range 10 {
		size, err := unix.ExtattrListFd(fd, nsid, 0, 0)
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return nil, nil
		}
		buf := make([]byte, size)
		//nolint:gosec // G103: ExtattrListFd takes the destination as a uintptr, so there is no other form to hand it one.
		n, err := unix.ExtattrListFd(fd, nsid, uintptr(unsafe.Pointer(&buf[0])), len(buf))
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n > len(buf) {
			return nil, fmt.Errorf("list extended attributes: the kernel reported %d bytes written into a %d-byte answer", n, len(buf))
		}
		return splitExtattrNames(buf[:n], prefix)
	}
	return nil, fmt.Errorf("list extended attributes: the set kept changing under the read")
}
