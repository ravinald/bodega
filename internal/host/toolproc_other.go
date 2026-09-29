//go:build !freebsd

package host

import (
	"errors"
	"syscall"
)

// ownDescendants, off FreeBSD, owns the tool's process group and nothing
// that leaves it. doctor asks pkg and make only on FreeBSD, so this serves
// the tests that exercise the runner elsewhere.
func ownDescendants() (end func(pid int) error, release func(), err error) {
	return killGroup, func() {}, nil
}

func killGroup(pgid int) error {
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
