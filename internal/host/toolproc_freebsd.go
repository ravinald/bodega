package host

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// procctl(2) reaper requests and the structures they take, from
// <sys/procctl.h>. Neither the syscall package nor x/sys wraps them.
const (
	pPID = 0 // P_PID, the first member of idtype_t

	procReapAcquire = 2
	procReapRelease = 3
	procReapStatus  = 4
	procReapGetpids = 5
	procReapKill    = 6

	reaperStatusOwned  = 0x1
	reaperPidinfoValid = 0x1
	reaperPidinfoChild = 0x2
	reaperKillSubtree  = 0x2
)

type reaperStatus struct {
	flags       uint32
	children    uint32
	descendants uint32
	reaper      int32
	pid         int32
	_           [15]uint32
}

type reaperPidinfo struct {
	pid     int32
	subtree int32
	flags   uint32
	_       [15]uint32
}

type reaperPids struct {
	count uint32
	_     [15]uint32
	pids  *reaperPidinfo
}

type reaperKill struct {
	sig     int32
	flags   uint32
	subtree int32
	killed  uint32
	fpid    int32
	_       [15]uint32
}

// reaping serializes tool runs, so one run's release cannot hand another
// run's descendants to doctor's own reaper while that run still needs them.
var reaping sync.Mutex

// ownDescendants makes doctor the reaper of everything it starts until
// release. A process group or session is something a descendant can leave
// by calling setsid, as daemon(8) does; the reaper subtree cannot be left.
// Every process the tool forks, however detached, carries the tool's pid as
// its subtree id and reparents to doctor when its parent exits, so end
// signals that subtree alone and reaps it, touching no process doctor did
// not start through this tool.
func ownDescendants() (end func(pid int) error, release func(), err error) {
	reaping.Lock()
	var st reaperStatus
	if err := procctl(procReapStatus, unsafe.Pointer(&st)); err != nil {
		reaping.Unlock()
		return nil, nil, fmt.Errorf("procctl PROC_REAP_STATUS: %w", err)
	}
	acquired := st.flags&reaperStatusOwned == 0
	if acquired {
		if err := procctl(procReapAcquire, nil); err != nil {
			reaping.Unlock()
			return nil, nil, fmt.Errorf("procctl PROC_REAP_ACQUIRE: %w, so doctor cannot end what the tool leaves running", err)
		}
	}
	release = func() {
		if acquired {
			_ = procctl(procReapRelease, nil)
		}
		reaping.Unlock()
	}
	return endSubtree, release, nil
}

// endSubtree kills every process in the tool's subtree and reaps the ones
// that reparented to doctor, until the subtree holds nothing but the tool.
// It signals on every pass because a process can fork while the previous
// pass is delivered, and PROC_REAP_KILL counts a process that is already
// exiting as killed, so the count cannot say when to stop; the subtree's
// membership can. The tool itself belongs to os/exec, which reaps it.
func endSubtree(tool int) error {
	deadline := time.Now().Add(toolWaitDelay)
	for {
		rk := reaperKill{sig: int32(syscall.SIGKILL), flags: reaperKillSubtree, subtree: int32(tool)}
		if err := procctl(procReapKill, unsafe.Pointer(&rk)); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("procctl PROC_REAP_KILL: %w (pid %d)", err, rk.fpid)
		}
		left, err := subtree(tool)
		if err != nil {
			return err
		}
		for _, p := range left {
			if p.child {
				var ws syscall.WaitStatus
				_, _ = syscall.Wait4(p.pid, &ws, syscall.WNOHANG, nil)
			}
		}
		if len(left) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%d processes under %d had not exited %s after SIGKILL", len(left), tool, toolWaitDelay)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type descendant struct {
	pid   int
	child bool
}

// subtree lists the processes, live or zombie, in the tool's subtree other
// than the tool itself, and which of them are doctor's children to reap.
func subtree(tool int) ([]descendant, error) {
	var st reaperStatus
	if err := procctl(procReapStatus, unsafe.Pointer(&st)); err != nil {
		return nil, fmt.Errorf("procctl PROC_REAP_STATUS: %w", err)
	}
	info := make([]reaperPidinfo, st.descendants+16)
	rp := reaperPids{count: uint32(len(info)), pids: &info[0]}
	err := procctl(procReapGetpids, unsafe.Pointer(&rp))
	runtime.KeepAlive(info)
	if err != nil {
		return nil, fmt.Errorf("procctl PROC_REAP_GETPIDS: %w", err)
	}
	var left []descendant
	for _, pi := range info {
		if pi.flags&reaperPidinfoValid != 0 && int(pi.subtree) == tool && int(pi.pid) != tool {
			left = append(left, descendant{pid: int(pi.pid), child: pi.flags&reaperPidinfoChild != 0})
		}
	}
	return left, nil
}

func procctl(cmd int, data unsafe.Pointer) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PROCCTL, pPID, uintptr(os.Getpid()), uintptr(cmd), uintptr(data), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
