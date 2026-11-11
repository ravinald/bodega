package host

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// toolTimeout bounds one pkg or make run. Both answer in well under a second
// on a stock host; a makefile that blocks must not hang doctor.
// toolWaitDelay bounds the wait for pipes a descendant still holds after
// the tool itself exits.
const (
	toolTimeout   = 30 * time.Second
	toolWaitDelay = 2 * time.Second
)

func runTool(stdin, name string, args ...string) ([]byte, error) {
	return runToolWithin(toolTimeout, stdin, name, args...)
}

// runToolWithin runs the tool and ends every process it started, on timeout
// and again once the tool exits. make runs != assignments and .BEGIN recipes
// through sh, whose children inherit make's pipes and may leave its process
// group or session: killing make alone leaves them running, and leaves the
// read of those pipes waiting on them. ownDescendants says which processes
// count as the tool's.
func runToolWithin(timeout time.Duration, stdin, name string, args ...string) ([]byte, error) {
	return runToolWaiting(timeout, toolWaitDelay, stdin, name, args...)
}

// runToolWaiting is runToolWithin with the wait for held pipes as a
// parameter, so a test can tell waiting out the delay from not waiting by a
// margin no slow process start can close.
func runToolWaiting(timeout, waitDelay time.Duration, stdin, name string, args ...string) ([]byte, error) {
	end, release, err := ownDescendants()
	if err != nil {
		return nil, fmt.Errorf("doctor did not run %s: %w", name, err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return end(cmd.Process.Pid) }
	cmd.WaitDelay = waitDelay
	out, err := cmd.Output()
	if cmd.Process != nil {
		if endErr := end(cmd.Process.Pid); endErr != nil && err == nil {
			err = fmt.Errorf("%s answered, but doctor could not end the processes it left: %w", name, endErr)
		}
	}
	switch {
	case err == nil:
		return out, nil
	case ctx.Err() != nil:
		return out, fmt.Errorf("%s did not answer within %s", name, timeout)
	case stderr.Len() > 0:
		return out, fmt.Errorf("%w: %s", err, oneLine(stderr.String()))
	}
	return out, err
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(strings.TrimSpace(s), "\n", "; ")), " ")
}
