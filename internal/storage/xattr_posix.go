//go:build linux || darwin

package storage

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// listXattr returns the attribute names on fd. A filesystem that holds no
// attributes at all reports that as an error rather than as an empty list, and
// an object with nothing to preserve is not a failure to preserve it.
//
// Both kernels answer with one NUL-terminated name after another, already
// namespace-qualified, so the name a list returns is the name a read takes.
// FreeBSD answers a different shape entirely; see xattr_freebsd.go.
func listXattr(fd int) ([]string, error) {
	for range 10 {
		size, err := unix.Flistxattr(fd, nil)
		if unsupportedXattr(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return nil, nil
		}
		buf := make([]byte, size)
		n, err := unix.Flistxattr(fd, buf)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var names []string
		for _, name := range strings.Split(string(buf[:n]), "\x00") {
			if name != "" {
				names = append(names, name)
			}
		}
		return names, nil
	}
	return nil, fmt.Errorf("list extended attributes: the set kept changing under the read")
}
