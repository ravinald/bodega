package clientconf

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Plan actions. install is a file to write; refuse is a system the host's
// profile excludes; skip is a system with nothing to install on this host,
// for a reason that is not the profile's: the wrong operating system, nothing
// configured on the server, or a choice only the operator can make.
const (
	PlanInstall = "install"
	PlanRefuse  = "refuse"
	PlanSkip    = "skip"
)

// PlanRecord is one line of a client plan: one file for one system, or the
// reason a system has none. The host's identity rides on every record rather
// than on a header line, so a loop reading plan.txt needs one case, not two.
type PlanRecord struct {
	Identity string `json:"identity"`
	Profile  string `json:"profile"`
	Match    string `json:"match"`
	System   string `json:"system"`
	Action   string `json:"action"`
	Path     string `json:"path"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Reason   string `json:"reason"`
}

// Fields is the record in plan.txt's column order.
func (p PlanRecord) Fields() []string {
	return []string{p.Identity, p.Profile, p.Match, p.System, p.Action, p.Path, p.URL, p.SHA256, p.Reason}
}

// Plan is GET /client/plan. The records are plan.txt's lines, field for
// field, so a tool can switch encodings without reinterpreting anything.
type Plan struct {
	Records []PlanRecord `json:"records"`
}

// Systems names each system the plan lists, once, in plan order.
func (p Plan) Systems() []string {
	var out []string
	for _, r := range p.Records {
		if !slices.Contains(out, r.System) {
			out = append(out, r.System)
		}
	}
	return out
}

// Select narrows the plan to systems, every record when systems is empty. A
// name the plan does not list is an error naming the ones it does, and so is
// a named system the plan refuses or skips: the operator asked for it, and a
// run that quietly configures the rest reads as one that configured it.
func (p Plan) Select(systems []string) ([]PlanRecord, error) {
	if len(systems) == 0 {
		return p.Records, nil
	}
	listed := p.Systems()
	for _, s := range systems {
		if !slices.Contains(listed, s) {
			return nil, fmt.Errorf("the plan lists no system named %q. It lists: %s", s, strings.Join(listed, ", "))
		}
	}
	var out []PlanRecord
	var blocked []string
	for _, r := range p.Records {
		if !slices.Contains(systems, r.System) {
			continue
		}
		if r.Action != PlanInstall {
			blocked = append(blocked, fmt.Sprintf("  %s (%s): %s", r.System, r.Action, r.Reason))
			continue
		}
		out = append(out, r)
	}
	if len(blocked) > 0 {
		return nil, fmt.Errorf("the plan installs nothing for a system you named, so nothing was written:\n%s", strings.Join(blocked, "\n"))
	}
	return out, nil
}

// Change is one install record fetched, checked and read against the host.
type Change struct {
	Record PlanRecord
	// Target is Record.Path with a leading ~/ resolved against the home
	// directory the change was built for.
	Target  string
	Old     []byte
	Existed bool
	New     []byte
}

// Unchanged reports whether the host already holds the planned bytes.
func (c Change) Unchanged() bool {
	return c.Existed && string(c.Old) == string(c.New)
}

// NewChange checks content against the record's digest and reads what the
// host holds at its path. A digest mismatch is refused here, before anything
// is compared or written, and the error names both digests.
func NewChange(rec PlanRecord, content []byte, home string) (Change, error) {
	sum := sha256.Sum256(content)
	if got := hex.EncodeToString(sum[:]); got != rec.SHA256 {
		return Change{}, fmt.Errorf("%s: %s does not match the plan, so nothing on this host was changed.\n"+
			"  plan says:  %s\n"+
			"  file is:    %s\n"+
			"  The file changed between the plan and the fetch, or something between this host and the server rewrote it.\n"+
			"  Re-run to rule out the first. If it repeats, fetch %s from another host and compare before trusting this path",
			rec.System, rec.URL, rec.SHA256, got, rec.URL)
	}
	target, err := TargetPath(rec.Path, home)
	if err != nil {
		return Change{}, fmt.Errorf("%s: %w", rec.System, err)
	}
	c := Change{Record: rec, Target: target, New: content}
	info, err := os.Stat(target)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return c, nil
	case err != nil:
		return Change{}, fmt.Errorf("read %s: %w", target, err)
	case !info.Mode().IsRegular():
		return Change{}, fmt.Errorf("%s exists and is not a regular file; move it aside, then re-run. Nothing was written", target)
	}
	if c.Old, err = os.ReadFile(target); err != nil {
		return Change{}, fmt.Errorf("read %s: %w", target, err)
	}
	c.Existed = true
	return c, nil
}

// TargetPath resolves a plan path for this host. The plan writes a per-user
// file as ~/..., because only the host knows whose home it is.
func TargetPath(path, home string) (string, error) {
	switch {
	case strings.HasPrefix(path, "~/"):
		if home == "" {
			return "", fmt.Errorf("the plan puts this file in %s and no home directory is known", path)
		}
		return filepath.Join(home, path[2:]), nil
	case filepath.IsAbs(path):
		return path, nil
	}
	return "", fmt.Errorf("the plan names %q, which is not an absolute path; refusing to write it", path)
}

// Diff is the unified diff from what the host holds to the planned file, as
// diff(1) -u prints it: the setup script shells out to the same tool, so both
// paths show an operator one format.
func (c Change) Diff() (string, error) {
	tmp, err := os.CreateTemp("", "bodega-plan-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(c.New); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	old := os.DevNull
	if c.Existed {
		old = c.Target
	}
	out, err := exec.Command("diff", "-u", "-L", c.Target, "-L", c.Target+" (bodega)", old, tmp.Name()).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return string(out), nil
	}
	if err != nil {
		return "", fmt.Errorf("diff %s: %w", c.Target, err)
	}
	return string(out), nil
}

// BackupSuffix is what a replaced file's copy is named with, beside it.
func BackupSuffix(t time.Time) string {
	return ".bodega-" + t.UTC().Format("20060102T150405Z")
}

// Applied is one file Apply wrote, and its backup when it replaced one.
type Applied struct {
	Target string
	Backup string
}

// Apply writes every change that differs from the host, backing up each file
// it replaces beside the original with suffix.
//
// Every target is checked writable before the first write, so a run lacking
// root for /etc stops before it has changed ~ and left /etc behind. The
// changes are then written last to first, because a plan lists a system's own
// file before the companion it depends on (the keyring a Signed-By: line
// names, the check make.conf includes): writing the dependency first means a
// failure leaves the old configuration working rather than pointing at a
// file that is not there.
func Apply(changes []Change, suffix string) ([]Applied, error) {
	var todo []Change
	for _, c := range changes {
		if !c.Unchanged() {
			todo = append(todo, c)
		}
	}
	for _, c := range todo {
		if err := writable(c.Target); err != nil {
			return nil, fmt.Errorf("cannot write %s: %w. Nothing was written. Re-run as the account that owns it, or as root for paths under /etc and /usr/local/etc", c.Target, err)
		}
	}
	var done []Applied
	for i := len(todo) - 1; i >= 0; i-- {
		c := todo[i]
		a := Applied{Target: c.Target}
		if err := os.MkdirAll(filepath.Dir(c.Target), 0o755); err != nil {
			return done, fmt.Errorf("create %s: %w", filepath.Dir(c.Target), err)
		}
		if c.Existed {
			a.Backup = c.Target + suffix
			if err := copyFile(c.Target, a.Backup); err != nil {
				return done, fmt.Errorf("back up %s, so it was not written: %w", c.Target, err)
			}
		}
		// In place rather than renamed over: the file keeps its owner and
		// mode, which a rename would replace with this process's.
		if err := os.WriteFile(c.Target, c.New, 0o644); err != nil {
			return done, fmt.Errorf("write %s: %w; restore it from %s", c.Target, err, a.Backup)
		}
		done = append(done, a)
	}
	return done, nil
}

// wOK is W_OK from <unistd.h>, the same value on every unix bodega builds for.
const wOK = 0x2

// writable asks whether this process could write path, creating its parent
// directories if they are missing.
func writable(path string) error {
	if _, err := os.Stat(path); err == nil {
		if err := syscall.Access(path, wOK); err != nil {
			return err
		}
	}
	dir := filepath.Dir(path)
	for {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return syscall.Access(dir, wOK)
}

// copyFile copies src to dst with src's mode, refusing to overwrite dst.
func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
