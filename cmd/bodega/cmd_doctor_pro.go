package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/host"
)

// esmHookConf is ubuntu-pro-client's apt hook. Its APT::Update::Pre-Invoke
// starts apt-news.service and esm-cache.service, and its AptCli upgrade hook
// runs apt-esm-json-hook; all three reach esm.ubuntu.com whatever the apt
// sources say, so a host reading apt only from bodega still calls out on every
// update.
const esmHookConf = "/etc/apt/apt.conf.d/20apt-esm-hook.conf"

// Each quiet step is named by what it changes, and its undo is fixed rather
// than recorded: a step is planned only when the host is not already in the
// quiet state, and apt_news defaults to true and an unmasked unit falls back
// to whatever its unit file says, so the undo returns the host to what it was.
const (
	proStepAptNews  = "apt_news"
	proStepESMCache = "esm-cache"
)

var proStepArgv = map[string]struct{ do, undo []string }{
	proStepAptNews: {
		do:   []string{"pro", "config", "set", "apt_news=false"},
		undo: []string{"pro", "config", "set", "apt_news=true"},
	},
	proStepESMCache: {
		do:   []string{"systemctl", "mask", "esm-cache.service"},
		undo: []string{"systemctl", "unmask", "esm-cache.service"},
	},
}

// proHost is the Ubuntu Pro surface doctor reads and changes. A struct so a
// test can point it at a fixture root, a scratch record and a scripted pro.
type proHost struct {
	// root prefixes esmHookConf.
	root string
	// record holds the steps --quiet-ubuntu-pro ran, which is the whole of
	// what --restore-ubuntu-pro undoes.
	record string
	// run executes one tool and returns its combined output.
	run func(argv []string) (string, error)
}

var ubuntuPro = &proHost{
	root:   "/",
	record: "/etc/bodega/doctor-ubuntu-pro.json",
	run:    runProTool,
}

// runProTool bounds every call: an unattached `pro status` can ask
// Canonical's contract server, and on the egress-locked host this row exists
// for that would otherwise hang doctor on a resolver timeout.
func runProTool(argv []string) (string, error) {
	ctx, cancel := context.WithTimeout(backgroundCtx(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

type proRecord struct {
	Steps []string `json:"steps"`
}

// finding reports the ESM hook on a host Ubuntu Pro is not attached to. A
// host without the hook, and an attached one, which is paying for what the
// hook fetches, get no row at all.
func (h *proHost) finding() (host.Finding, bool) {
	f := host.Finding{Check: "ubuntu-pro-hook"}
	hook := filepath.Join(h.root, esmHookConf)
	if _, err := os.Stat(hook); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return f, false
		}
		f.Status = host.StatusSkip
		f.Detail = "could not stat " + hook + ": " + err.Error()
		f.Remediation = skipRemedy(hook, err)
		return f, true
	}
	attached, err := h.attached()
	if err != nil {
		f.Status = host.StatusSkip
		f.Detail = esmHookConf + " is present and " + err.Error()
		f.Remediation = "run `pro status --format json` to see why it fails, then re-run `bodega doctor`"
		return f, true
	}
	if attached {
		return f, false
	}
	f.Status = host.StatusWarn
	f.Detail = esmHookConf + " starts apt-news.service and esm-cache.service on every apt update and runs " +
		"apt-esm-json-hook on upgrade, and each contacts esm.ubuntu.com whatever the apt sources say; " +
		"Ubuntu Pro is not attached, so they fetch nothing this host uses"
	f.Remediation = "pro config set apt_news=false and systemctl mask esm-cache.service, " +
		"or bodega doctor --configure apt --quiet-ubuntu-pro --apply, which records both for --restore-ubuntu-pro"
	return f, true
}

func (h *proHost) attached() (bool, error) {
	out, err := h.run([]string{"pro", "status", "--format", "json"})
	if err != nil {
		return false, fmt.Errorf("`pro status --format json` failed (%v): %s", err, out)
	}
	var st struct {
		Attached *bool `json:"attached"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.Attached == nil {
		return false, fmt.Errorf("`pro status --format json` printed no attached field this doctor can read")
	}
	return *st.Attached, nil
}

// quietSteps plans what --quiet-ubuntu-pro changes on this host. It plans
// nothing, and says why, where doctor would report no row, and leaves out a
// step whose end state the host already has, so the record never claims a
// change somebody else made.
func (h *proHost) quietSteps() (steps []string, why string, err error) {
	switch f, ok := h.finding(); {
	case !ok:
		return nil, "no " + esmHookConf + ", or Ubuntu Pro is attached", nil
	case f.Status != host.StatusWarn:
		return nil, "", fmt.Errorf("--quiet-ubuntu-pro cannot plan: %s", f.Detail)
	}
	news, err := h.run([]string{"pro", "config", "show", "apt_news"})
	if err != nil {
		return nil, "", fmt.Errorf("--quiet-ubuntu-pro cannot read apt_news: `pro config show apt_news` failed (%v): %s", err, news)
	}
	if fields := strings.Fields(news); len(fields) != 2 || !strings.EqualFold(fields[1], "false") {
		steps = append(steps, proStepAptNews)
	}
	// is-enabled exits non-zero for a masked unit, so its answer is the output.
	state, err := h.run([]string{"systemctl", "is-enabled", "esm-cache.service"})
	if state == "" {
		return nil, "", fmt.Errorf("--quiet-ubuntu-pro cannot read esm-cache.service: `systemctl is-enabled` printed nothing (%v)", err)
	}
	if !strings.HasPrefix(state, "masked") {
		steps = append(steps, proStepESMCache)
	}
	if len(steps) == 0 {
		why = "apt_news is already false and esm-cache.service already masked"
	}
	return steps, why, nil
}

// printQuietPlan writes the steps into the plan output, each beside its undo,
// before anything is written.
func printQuietPlan(steps []string, why string) {
	if len(steps) == 0 {
		fmt.Printf("\nubuntu-pro  nothing to quiet: %s\n", why)
		return
	}
	fmt.Println()
	for _, s := range steps {
		a := proStepArgv[s]
		fmt.Printf("ubuntu-pro  %s  (undo: %s)\n", strings.Join(a.do, " "), strings.Join(a.undo, " "))
	}
}

// quiet runs steps and adds each one that succeeded to the record, so a run
// that fails halfway can still be undone for the part it changed.
func (h *proHost) quiet(steps []string) error {
	rec, err := h.load()
	if err != nil {
		return err
	}
	var runErr error
	for _, s := range steps {
		argv := proStepArgv[s].do
		if out, err := h.run(argv); err != nil {
			runErr = fmt.Errorf("%s failed (%v): %s; nothing after it ran. Re-run as root", strings.Join(argv, " "), err, out)
			break
		}
		fmt.Printf("ran        %s\n", strings.Join(argv, " "))
		if !slices.Contains(rec.Steps, s) {
			rec.Steps = append(rec.Steps, s)
		}
	}
	if err := h.save(rec); err != nil {
		return errors.Join(runErr, err)
	}
	return runErr
}

// restore undoes the recorded steps and nothing else, and deletes the record
// once every undo succeeded.
func (h *proHost) restore() error {
	rec, err := h.load()
	if err != nil {
		return err
	}
	if len(rec.Steps) == 0 {
		fmt.Printf("Nothing to restore: %s records no step --quiet-ubuntu-pro ran on this host.\n", h.record)
		return nil
	}
	for len(rec.Steps) > 0 {
		argv := proStepArgv[rec.Steps[0]].undo
		if out, err := h.run(argv); err != nil {
			return errors.Join(
				fmt.Errorf("%s failed (%v): %s. Re-run as root; %s still records what is left", strings.Join(argv, " "), err, out, h.record),
				h.save(rec))
		}
		fmt.Printf("ran        %s\n", strings.Join(argv, " "))
		rec.Steps = rec.Steps[1:]
	}
	if err := os.Remove(h.record); err != nil {
		return fmt.Errorf("every step was undone, and removing %s failed: %w", h.record, err)
	}
	return nil
}

func (h *proHost) load() (proRecord, error) {
	var rec proRecord
	b, err := os.ReadFile(h.record)
	if errors.Is(err, fs.ErrNotExist) {
		return rec, nil
	}
	if err != nil {
		return rec, fmt.Errorf("read %s: %w", h.record, err)
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, fmt.Errorf("%s is not the record --quiet-ubuntu-pro writes (%v); move it aside, then re-run", h.record, err)
	}
	for _, s := range rec.Steps {
		if _, ok := proStepArgv[s]; !ok {
			return rec, fmt.Errorf("%s names a step this doctor does not know, %q; move it aside, then re-run", h.record, s)
		}
	}
	return rec, nil
}

func (h *proHost) save(rec proRecord) error {
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(h.record), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(h.record), err)
	}
	if err := os.WriteFile(h.record, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("record the Ubuntu Pro steps in %s: %w; undo them by hand with the commands printed above", h.record, err)
	}
	return nil
}
